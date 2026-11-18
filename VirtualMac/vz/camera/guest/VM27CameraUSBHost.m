#import "VM27CameraUSBHost.h"
#import <IOUSBHost/IOUSBHostControllerInterface.h>
#import <IOUSBHost/IOUSBHostControllerInterfaceHelpers.h>
#import <IOUSBHost/IOUSBHostCIDeviceStateMachine.h>
#import <IOUSBHost/IOUSBHostCIEndpointStateMachine.h>
#import <mach/mach_time.h>
#import <objc/runtime.h>

@protocol VM27CameraTransferCursor
- (void)setCurrentTransferMessage:(const IOUSBHostCIMessage *)message;
@end

typedef struct {
    uint8_t setup[8];
    uint8_t bytes[256];
    size_t expected;
    size_t length;
    size_t offset;
    BOOL input;
    BOOL pending;
} VM27CameraControl;

@implementation VM27CameraUSBHost {
    HvUsbCamera *_camera;
    IOUSBHostControllerInterface *_controller;
    IOUSBHostCIDeviceStateMachine *_device;
    NSMutableDictionary<NSNumber *, IOUSBHostCIEndpointStateMachine *> *_endpoints;
    dispatch_queue_t _queue;
    dispatch_source_t _retry;
    VM27CameraControl _control;
    uint64_t _startTime;
    unsigned _transferFailures;
}

- (instancetype)initWithDevice:(HvUsbCamera *)camera {
    self = [super init];
    if (self) {
        _camera = camera;
        _queue = dispatch_queue_create("com.virtualmac.camera.usb", DISPATCH_QUEUE_SERIAL);
        _endpoints = [NSMutableDictionary dictionary];
    }
    return self;
}

- (BOOL)startWithError:(NSError **)error {
    if (!_camera || _controller) return NO;
    Method cursorMethod = class_getInstanceMethod(IOUSBHostCIEndpointStateMachine.class, @selector(setCurrentTransferMessage:));
    const char *cursorType = cursorMethod ? method_getTypeEncoding(cursorMethod) : NULL;
    if (!cursorType || strcmp(cursorType, "v24@0:8r^{IOUSBHostCIMessage=IIQ}16")) {
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOTSUP userInfo:@{
            NSLocalizedDescriptionKey: @"This macOS build does not expose the camera's UserHCI transfer cursor."}];
        return NO;
    }
    static const IOUSBHostCIMessage capabilities[] = {
        {.control = (IOUSBHostCIMessageTypeControllerCapabilities << IOUSBHostCIMessageControlTypePhase) |
            IOUSBHostCIMessageControlNoResponse | IOUSBHostCIMessageControlValid |
            (1 << IOUSBHostCICapabilitiesMessageControlPortCountPhase),
         .data0 = (1 << IOUSBHostCICapabilitiesMessageData0CommandTimeoutThresholdPhase) |
            (2 << IOUSBHostCICapabilitiesMessageData0ConnectionLatencyPhase)},
        {.control = (IOUSBHostCIMessageTypePortCapabilities << IOUSBHostCIMessageControlTypePhase) |
            IOUSBHostCIMessageControlNoResponse | IOUSBHostCIMessageControlValid |
            (1 << IOUSBHostCIPortCapabilitiesMessageControlPortNumberPhase),
         .data0 = (63 << IOUSBHostCIPortCapabilitiesMessageData0MaxPowerPhase)},
    };
    _startTime = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    __weak VM27CameraUSBHost *weakSelf = self;
    _controller = [[IOUSBHostControllerInterface alloc]
        initWithCapabilities:[NSData dataWithBytes:capabilities length:sizeof(capabilities)]
        queue:_queue interruptRateHz:1000 error:error
        commandHandler:^(IOUSBHostControllerInterface *interface, IOUSBHostCIMessage command) {
            [weakSelf handleCommand:&command interface:interface];
        } doorbellHandler:^(IOUSBHostControllerInterface *interface, IOUSBHostCIDoorbell *doorbells, uint32_t count) {
            (void)interface;
            [weakSelf handleDoorbells:doorbells count:count];
        } interestHandler:NULL];
    return _controller != nil;
}

- (void)stop {
    // The controller belongs to one guest process. It invalidates its port,
    // endpoints and memory mappings during destroy.
    if (!_controller) return;
    dispatch_sync(_queue, ^{
        if (self->_retry) dispatch_source_cancel(self->_retry);
        self->_retry = nil;
    });
    [_controller destroy];
    _controller = nil;
    [_endpoints removeAllObjects];
    _device = nil;
}

- (void)handleCommand:(const IOUSBHostCIMessage *)command interface:(IOUSBHostControllerInterface *)interface {
    IOUSBHostCIMessageType type = IOUSBHostCIMessageTypeFromMessage(command);
    NSError *error = nil;
    if (type <= IOUSBHostCIMessageTypeControllerFrameNumber) {
        IOUSBHostCIControllerStateMachine *state = interface.controllerStateMachine;
        if ([state inspectCommand:command error:&error]) {
            if (type == IOUSBHostCIMessageTypeControllerFrameNumber) {
                uint64_t elapsed = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - _startTime;
                [state respondToCommand:command status:IOUSBHostCIMessageStatusSuccess
                                  frame:elapsed / NSEC_PER_MSEC timestamp:mach_absolute_time() error:&error];
            } else [state respondToCommand:command status:IOUSBHostCIMessageStatusSuccess error:&error];
        }
    } else if (type >= IOUSBHostCIMessageTypePortPowerOn && type <= IOUSBHostCIMessageTypePortStatus) {
        IOUSBHostCIPortStateMachine *port = [interface getPortStateMachineForCommand:command error:&error];
        if (port && [port inspectCommand:command error:&error]) {
            IOUSBHostCIMessageStatus status = IOUSBHostCIMessageStatusSuccess;
            switch (type) {
                case IOUSBHostCIMessageTypePortPowerOn:
                    port.powered = YES;
                    break;
                case IOUSBHostCIMessageTypePortPowerOff:
                    port.connected = NO;
                    port.powered = NO;
                    break;
                case IOUSBHostCIMessageTypePortReset:
                    hv_usb_camera_reset(_camera);
                    memset(&_control, 0, sizeof(_control));
                    if (![port updateLinkState:IOUSBHostCILinkStateU0 speed:IOUSBHostCIDeviceSpeedHigh
                         inhibitLinkStateChange:YES error:&error]) status = IOUSBHostCIMessageStatusError;
                    break;
                case IOUSBHostCIMessageTypePortResume:
                case IOUSBHostCIMessageTypePortSuspend:
                case IOUSBHostCIMessageTypePortDisable: {
                    IOUSBHostCILinkState link = type == IOUSBHostCIMessageTypePortResume ? IOUSBHostCILinkStateU0 :
                        type == IOUSBHostCIMessageTypePortSuspend ? IOUSBHostCILinkStateU3 : IOUSBHostCILinkStateDisabled;
                    if (![port updateLinkState:link speed:port.speed inhibitLinkStateChange:YES error:&error])
                        status = IOUSBHostCIMessageStatusError;
                    break;
                }
                default: break;
            }
            BOOL replied = [port respondToCommand:command status:status error:&error];
            if (replied && type == IOUSBHostCIMessageTypePortPowerOn) port.connected = YES;
        }
    } else if (type >= IOUSBHostCIMessageTypeDeviceCreate && type <= IOUSBHostCIMessageTypeDeviceUpdate) {
        if (type == IOUSBHostCIMessageTypeDeviceCreate && !_device) {
            _device = [[IOUSBHostCIDeviceStateMachine alloc] initWithInterface:interface command:command error:&error];
            if (_device && [_device inspectCommand:command error:&error])
                [_device respondToCommand:command status:IOUSBHostCIMessageStatusSuccess deviceAddress:1 error:&error];
        } else if (_device && [_device inspectCommand:command error:&error]) {
            [_device respondToCommand:command status:IOUSBHostCIMessageStatusSuccess error:&error];
            if (type == IOUSBHostCIMessageTypeDeviceDestroy) {
                [_endpoints removeAllObjects];
                _device = nil;
            }
        }
    } else if (type >= IOUSBHostCIMessageTypeEndpointCreate && type <= IOUSBHostCIMessageTypeEndpointSetNextTransfer) {
        if (type == IOUSBHostCIMessageTypeEndpointCreate) {
            IOUSBHostCIEndpointStateMachine *state = [[IOUSBHostCIEndpointStateMachine alloc]
                initWithInterface:interface command:command error:&error];
            if (state && [state inspectCommand:command error:&error]) {
                [state respondToCommand:command status:IOUSBHostCIMessageStatusSuccess error:&error];
                _endpoints[@(state.endpointAddress)] = state;
            }
        } else {
            for (NSNumber *key in _endpoints.allKeys) {
                IOUSBHostCIEndpointStateMachine *state = _endpoints[key];
                error = nil;
                if (![state inspectCommand:command error:&error]) continue;
                [state respondToCommand:command status:IOUSBHostCIMessageStatusSuccess error:&error];
                if (type == IOUSBHostCIMessageTypeEndpointDestroy) [_endpoints removeObjectForKey:key];
                break;
            }
        }
    }
    if (error) fprintf(stderr, "Camera USB command 0x%x: %s\n", type, error.localizedDescription.UTF8String);
}

- (IOUSBHostCIMessageStatus)controlTransfer:(const IOUSBHostCIMessage *)message actual:(size_t *)actual {
    IOUSBHostCIMessageType type = IOUSBHostCIMessageTypeFromMessage(message);
    if (type == IOUSBHostCIMessageTypeSetupTransfer) {
        memset(&_control, 0, sizeof(_control));
        for (unsigned i = 0; i < sizeof(_control.setup); i++) _control.setup[i] = message->data1 >> (i * 8);
        _control.input = (_control.setup[0] & 0x80) != 0;
        _control.expected = (size_t)_control.setup[6] | ((size_t)_control.setup[7] << 8);
        int length = hv_usb_camera_control(_camera, _control.setup, _control.bytes, sizeof(_control.bytes));
        if (length < 0 || (!_control.input && _control.expected > sizeof(_control.bytes)))
            return IOUSBHostCIMessageStatusStallError;
        _control.pending = YES;
        _control.length = (size_t)length;
        return IOUSBHostCIMessageStatusSuccess;
    }
    if (!_control.pending) return IOUSBHostCIMessageStatusStallError;
    if (type == IOUSBHostCIMessageTypeStatusTransfer) {
        _control.pending = NO;
        return IOUSBHostCIMessageStatusSuccess;
    }
    if (type != IOUSBHostCIMessageTypeNormalTransfer) return IOUSBHostCIMessageStatusProtocolError;
    size_t capacity = message->data0 & IOUSBHostCINormalTransferData0Length;
    void *buffer = (void *)(uintptr_t)message->data1;
    if (!buffer && capacity) return IOUSBHostCIMessageStatusBadArgument;
    if (_control.input) {
        *actual = MIN(capacity, _control.length - _control.offset);
        if (*actual) memcpy(buffer, _control.bytes + _control.offset, *actual);
    } else {
        size_t remaining = _control.expected - _control.offset;
        if (capacity > remaining) return IOUSBHostCIMessageStatusStallError;
        *actual = capacity;
        if (capacity) memcpy(_control.bytes + _control.offset, buffer, capacity);
        if (capacity == remaining && hv_usb_camera_control_out(_camera, _control.setup, _control.bytes, _control.expected) < 0)
            return IOUSBHostCIMessageStatusStallError;
    }
    _control.offset += *actual;
    return IOUSBHostCIMessageStatusSuccess;
}

- (BOOL)processEndpoint:(IOUSBHostCIEndpointStateMachine *)state {
    for (unsigned transfer = 0; transfer < 128 && state.endpointState == IOUSBHostCIEndpointStateActive; transfer++) {
        const IOUSBHostCIMessage *message = state.currentTransferMessage;
        if (!message || !(message->control & IOUSBHostCIMessageControlValid)) return NO;
        const IOUSBHostCIMessage details = *message;
        if (IOUSBHostCIMessageTypeFromMessage(&details) == IOUSBHostCIMessageTypeLink) {
            // The kernel publishes the next user-mapped ring address in a
            // no-response Link. Treat it as a cursor move, not a completion.
            const IOUSBHostCIMessage *next = (const void *)(uintptr_t)details.data1;
            if (!(details.control & IOUSBHostCIMessageControlNoResponse) || !next || next == message ||
                ((uintptr_t)next % _Alignof(IOUSBHostCIMessage)) ||
                ![state respondsToSelector:@selector(setCurrentTransferMessage:)]) return NO;
            [(id<VM27CameraTransferCursor>)state setCurrentTransferMessage:next];
            continue;
        }
        size_t actual = 0;
        IOUSBHostCIMessageStatus status = IOUSBHostCIMessageStatusProtocolError;
        if (state.endpointAddress == 0 || state.endpointAddress == 0x80) {
            status = [self controlTransfer:message actual:&actual];
        } else if (state.endpointAddress == 0x81 && IOUSBHostCIMessageTypeFromMessage(message) == IOUSBHostCIMessageTypeNormalTransfer) {
            size_t capacity = message->data0 & IOUSBHostCINormalTransferData0Length;
            if (message->data1 && capacity >= 7) {
                actual = hv_usb_camera_read(_camera, (void *)(uintptr_t)message->data1, MIN(capacity, HV_CAMERA_PAYLOAD),
                                            clock_gettime_nsec_np(CLOCK_UPTIME_RAW));
                if (!actual) return YES;
                status = IOUSBHostCIMessageStatusSuccess;
            }
        }
        NSError *error = nil;
        if (![state enqueueTransferCompletionForMessage:message status:status transferLength:actual error:&error]) {
            if (_transferFailures++ < 12)
                fprintf(stderr, "Camera USB transfer 0x%02lx type=0x%x flags=0x%x posted=%u actual=%zu status=%u: %s (%ld)\n",
                        (unsigned long)state.endpointAddress, IOUSBHostCIMessageTypeFromMessage(&details),
                        details.control & (IOUSBHostCIMessageControlValid | IOUSBHostCIMessageControlNoResponse),
                        details.data0 & IOUSBHostCINormalTransferData0Length, actual, status,
                        error.localizedDescription.UTF8String ?: "completion failed", (long)error.code);
            return NO;
        }
    }
    return state.endpointState == IOUSBHostCIEndpointStateActive;
}

- (void)handleDoorbells:(IOUSBHostCIDoorbell *)doorbells count:(uint32_t)count {
    for (uint32_t i = 0; i < count; i++) {
        IOUSBHostCIDoorbell bell = doorbells[i];
        if ((bell & IOUSBHostCIDoorbellDeviceAddress) != 1 || (bell & IOUSBHostCIDoorbellStreamID)) continue;
        NSNumber *key = @((bell & IOUSBHostCIDoorbellEndpointAddress) >> IOUSBHostCIDoorbellEndpointAddressPhase);
        IOUSBHostCIEndpointStateMachine *state = _endpoints[key];
        NSError *error = nil;
        if ([state processDoorbell:bell error:&error] && [self processEndpoint:state] && state.endpointAddress == 0x81)
            [self scheduleBulkRetry];
    }
}

- (void)scheduleBulkRetry {
    if (_retry) return;
    _retry = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    dispatch_source_set_timer(_retry, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC), NSEC_PER_MSEC, NSEC_PER_MSEC / 2);
    __weak VM27CameraUSBHost *weakSelf = self;
    dispatch_source_set_event_handler(_retry, ^{ [weakSelf retryBulk]; });
    dispatch_resume(_retry);
}

- (void)retryBulk {
    if ([self processEndpoint:_endpoints[@0x81]]) return;
    dispatch_source_cancel(_retry);
    _retry = nil;
}
@end
