#import "VM27SharedRadioVZBridgeV1.h"
#import "VM27SharedRadioStreamV1.h"
#include "../exclusive/VM27ExclusiveBluetoothRelayV1.h"
#include "../common/vm27_shared_radio_wire_v1.h"
#include <objc/runtime.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <unistd.h>

@protocol VM27RadioActualVMV1 <NSObject>
@property(readonly) dispatch_queue_t queue;
@property(readonly,copy) NSArray *socketDevices;
@property(readonly) NSInteger state;
@end
@protocol VM27RadioActualSocketDeviceV1 <NSObject>
- (void)connectToPort:(uint32_t)port completionHandler:(void (^)(id, NSError *))handler;
@end
@protocol VM27RadioActualSocketConnectionV1 <NSObject>
@property(readonly) int fileDescriptor;
- (void)close;
@end

static char RadioOwnerKey;
static IMP OriginalSSHClose;
static BOOL Genuine(id object, NSString *image) {
    // VZ installs KVO subclasses on a live VM. Validate the declared native
    // class and object membership, as the existing SSH bridge does.
    Class native = Nil;
    const char *names[] = {"VZVirtualMachine", "VZVirtioSocketDevice", "VZVirtioSocketConnection"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Class candidate = objc_getClass(names[i]);
        if (candidate && [object isKindOfClass:candidate]) { native = candidate; break; }
    }
    const char *path = native ? class_getImageName(native) : NULL;
    char actual[PATH_MAX], expected[PATH_MAX];
    return path && image.isAbsolutePath && realpath(path, actual) &&
        realpath(image.fileSystemRepresentation, expected) && !strcmp(actual, expected);
}
static NSError *RadioError(int code, NSString *message) {
    return [NSError errorWithDomain:@"VM27SharedRadioBridgeV1" code:code
        userInfo:@{NSLocalizedDescriptionKey:message}];
}

@interface VM27SharedRadioVZBridgeV1 : NSObject {
    __weak id<VM27RadioActualVMV1> _vm;
    id<VM27RadioActualSocketDeviceV1> _device;
    id<VM27RadioActualSocketConnectionV1> _connection;
    id<VM27RadioActualSocketConnectionV1> _peerConnection;
    BOOL _peerConnecting;
    id<VM27RadioActualSocketConnectionV1> _rawConnection;
    BOOL _rawConnecting,_rawActive;
    int _rawCancellation[2];
    dispatch_queue_t _queue;
    dispatch_source_t _retry;
    NSString *_image;
    NSMutableArray<void (^)(NSError *)> *_closeReplies;
    int _cancellation[2];
    BOOL _connecting, _active, _closing, _closed;
    uint64_t _generation;
    char _queueKey;
}
@property(atomic,strong) VM27SharedRadioHostV1 *host;
- (instancetype)initWithVM:(id<VM27RadioActualVMV1>)vm image:(NSString *)image;
- (void)connectIfReady;
- (void)closeWithCompletion:(void (^)(NSError *))completion;
- (void)finishSession:(int)status generation:(uint64_t)generation;
- (void)finishClose;
- (void)connectPeerIfReady;
- (BOOL)closePeer;
- (void)connectRawIfReady;
@end

@implementation VM27SharedRadioVZBridgeV1
- (instancetype)initWithVM:(id<VM27RadioActualVMV1>)vm image:(NSString *)image {
    if (!(self = [super init])) return nil;
    _cancellation[0] = _cancellation[1] = -1;
    _rawCancellation[0]=_rawCancellation[1]=-1;
    if (!Genuine(vm, image) || ![vm respondsToSelector:@selector(queue)] ||
        vm.socketDevices.count != 1 || !Genuine(vm.socketDevices[0], image)) {
        fprintf(stderr, "[SharedRadio] admission vm=%s genuineVM=%d queueGetter=%d sockets=%lu genuineSocket=%d\n",
            object_getClassName(vm), Genuine(vm, image), [vm respondsToSelector:@selector(queue)],
            (unsigned long)vm.socketDevices.count, vm.socketDevices.count == 1 && Genuine(vm.socketDevices[0], image));
        return nil;
    }
    _vm = vm; _queue = vm.queue; _image = [image copy];
    _device = vm.socketDevices[0];
    Method connect = class_getInstanceMethod(object_getClass(_device), @selector(connectToPort:completionHandler:));
    if (!connect || method_getNumberOfArguments(connect) != 4) {
        fprintf(stderr, "[SharedRadio] admission missing native connectToPort ABI\n"); return nil;
    }
    _closeReplies = [NSMutableArray array];
    dispatch_queue_set_specific(_queue, &_queueKey, &_queueKey, NULL);
    _retry = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    dispatch_source_set_timer(_retry, DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC, 200 * NSEC_PER_MSEC);
    __weak VM27SharedRadioVZBridgeV1 *weakSelf = self;
    dispatch_source_set_event_handler(_retry, ^{ [weakSelf connectIfReady]; });
    dispatch_resume(_retry);
    return self;
}
- (void)connectIfReady {
    if (_closing || _closed || !_vm || _vm.state != 1) return;
    if (_active) {
        if(!access("/var/run/VirtualMacRadioOwned-v1/exclusive-bluetooth.sock",W_OK))[self connectRawIfReady];
        else [self connectPeerIfReady];return;
    }
    if (_connecting) return;
    _connecting = YES;
    uint64_t generation = ++_generation;
    [_device connectToPort:VM27_RADIO_VSOCK_PORT completionHandler:^(id object, NSError *error) {
        dispatch_async(self->_queue, ^{
            if (generation != self->_generation || self->_closing || self->_closed) {
                if (object && Genuine(object, self->_image)) [(id<VM27RadioActualSocketConnectionV1>)object close];
                self->_connecting = NO;
                if (self->_closing) [self finishClose];
                return;
            }
            self->_connecting = NO;
            if (error || !Genuine(object, self->_image)) {
                if (object && Genuine(object, self->_image)) [(id<VM27RadioActualSocketConnectionV1>)object close];
                return;
            }
            id<VM27RadioActualSocketConnectionV1> connection = object;
            int descriptor = fcntl(connection.fileDescriptor, F_DUPFD_CLOEXEC, 0);
            if (descriptor < 0) { [connection close]; return; }
            int one = 1;
            if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) || pipe(self->_cancellation)) {
                close(descriptor); [connection close]; return;
            }
            for (unsigned i = 0; i < 2; ++i) {
                int flags = fcntl(self->_cancellation[i], F_GETFL);
                if (flags < 0 || fcntl(self->_cancellation[i], F_SETFL, flags | O_NONBLOCK)) {
                    close(descriptor); close(self->_cancellation[0]); close(self->_cancellation[1]);
                    self->_cancellation[0] = self->_cancellation[1] = -1;
                    [connection close]; return;
                }
            }
            self->_connection = connection; self->_active = YES;
            int cancellation = self->_cancellation[0];
            dispatch_async(dispatch_get_main_queue(), ^{
                VM27SharedRadioHostV1 *host = [VM27SharedRadioHostV1 new];
                self.host = host;
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                    int status = VM27SharedRadioServeStreamV1(descriptor, descriptor, cancellation, host);
                    close(descriptor);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [host invalidate]; self.host = nil;
                        dispatch_async(self->_queue, ^{ [self finishSession:status generation:generation]; });
                    });
                });
            });
            fprintf(stderr, "[SharedRadio] native VZ stream connected port=%u generation=%llu\n",
                VM27_RADIO_VSOCK_PORT, (unsigned long long)generation);
        });
    }];
}
- (void)connectRawIfReady {
    if(_closing||_closed||!_active||_rawConnecting||_rawActive||!self.host)return;
    if(_peerConnecting||![self closePeer])return;
    _rawConnecting=YES;uint64_t generation=_generation;
    [_device connectToPort:39031 completionHandler:^(id object,NSError *error){dispatch_async(self->_queue,^{
        self->_rawConnecting=NO;
        if(generation!=self->_generation||self->_closing||self->_closed||!self->_active||error||!Genuine(object,self->_image)) {
            if(object&&Genuine(object,self->_image))[(id<VM27RadioActualSocketConnectionV1>)object close];
            if(self->_closing)[self finishClose];return;
        }
        id<VM27RadioActualSocketConnectionV1> connection=object;
        int fd=fcntl(connection.fileDescriptor,F_DUPFD_CLOEXEC,0);
        if(fd<0||pipe(self->_rawCancellation)){if(fd>=0)close(fd);[connection close];return;}
        for(unsigned i=0;i<2;++i)fcntl(self->_rawCancellation[i],F_SETFL,O_NONBLOCK);
        self->_rawConnection=connection;self->_rawActive=YES;int cancellation=self->_rawCancellation[0];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            int status=VM27ExclusiveBluetoothRelayV1(fd,cancellation);close(fd);
            dispatch_async(self->_queue,^{
                [connection close];self->_rawConnection=nil;self->_rawActive=NO;
                for(unsigned i=0;i<2;++i){if(self->_rawCancellation[i]>=0)close(self->_rawCancellation[i]);self->_rawCancellation[i]=-1;}
                fprintf(stderr,"[ExclusiveBluetooth] native VZ lease drained errno=%d\n",status);
                if(self->_closing)[self finishClose];
            });
        });
        fprintf(stderr,"[ExclusiveBluetooth] native VZ raw stream connected port=39031\n");
    });}];
}
- (void)connectPeerIfReady {
    if(_closing||_closed||!_active||_peerConnecting||_peerConnection||!self.host)return;
    _peerConnecting=YES;uint64_t generation=_generation;
    [_device connectToPort:39030 completionHandler:^(id object,NSError *error){dispatch_async(self->_queue,^{
        self->_peerConnecting=NO;
        if(generation!=self->_generation||self->_closing||self->_closed||!self->_active||error||!Genuine(object,self->_image)) {
            if(object&&Genuine(object,self->_image))[(id<VM27RadioActualSocketConnectionV1>)object close];
            if(self->_closing)[self finishClose];return;
        }
        id<VM27RadioActualSocketConnectionV1> connection=object;
        int fd=fcntl(connection.fileDescriptor,F_DUPFD_CLOEXEC,0);
        if(fd<0){[connection close];return;}
        self->_peerConnection=connection;
        __weak typeof(self) weakSelf=self;
        dispatch_async(dispatch_get_main_queue(),^{
            VM27SharedRadioHostV1 *host=self.host;
            if(!host){close(fd);dispatch_async(self->_queue,^{[self closePeer];});return;}
            [host adoptBluetoothPeerFD:fd closed:^{typeof(self) owner=weakSelf;if(!owner)return;dispatch_async(owner->_queue,^{
                if(owner->_peerConnection==connection)[owner closePeer];
                if(owner->_closing)[owner finishClose];
            });}];
        });
        fprintf(stderr,"[SharedBluetooth] native VZ peer stream connected port=39030\n");
    });}];
}
- (BOOL)closePeer {
    if(!_peerConnection)return YES;
    @try {
        [_peerConnection close];
        if(_peerConnection.fileDescriptor!=-1){fprintf(stderr,"[SharedBluetooth] native peer close remains unresolved\n");return NO;}
    } @catch(NSException *exception){fprintf(stderr,"[SharedBluetooth] native peer close failed: %s\n",exception.name.UTF8String);return NO;}
    _peerConnection=nil;return YES;
}
- (void)finishSession:(int)status generation:(uint64_t)generation {
    if (dispatch_get_specific(&_queueKey) != &_queueKey || generation != _generation) return;
    if(![self closePeer])return;
    if(_rawCancellation[1]>=0){uint8_t byte=1;ssize_t ignored=write(_rawCancellation[1],&byte,1);(void)ignored;}
    @try {
        [_connection close];
        if (_connection && _connection.fileDescriptor != -1) {
            fprintf(stderr, "[SharedRadio] native connection close remains unresolved\n");
            return;
        }
    } @catch (NSException *exception) {
        fprintf(stderr, "[SharedRadio] native close failed: %s\n", exception.name.UTF8String); return;
    }
    _connection = nil; _active = NO;
    for (unsigned i = 0; i < 2; ++i) {
        if (_cancellation[i] >= 0) close(_cancellation[i]);
        _cancellation[i] = -1;
    }
    fprintf(stderr, "[SharedRadio] stream drained errno=%d generation=%llu\n", status, (unsigned long long)generation);
    if (_closing) [self finishClose];
}
- (void)finishClose {
    if (_active || _connecting || _peerConnecting || _rawConnecting || _rawActive || ![self closePeer]) return;
    _closed = YES; _connecting = NO; ++_generation;
    _device = nil; _vm = nil;
    dispatch_queue_set_specific(_queue, &_queueKey, NULL, NULL);
    NSArray *callbacks = [_closeReplies copy]; [_closeReplies removeAllObjects];
    for (void (^callback)(NSError *) in callbacks) callback(nil);
}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if (_closed) { completion(nil); return; }
    if (dispatch_get_specific(&_queueKey) != &_queueKey) {
        completion(RadioError(EPERM, @"Radio close must run on the actual VM queue")); return;
    }
    [_closeReplies addObject:[completion copy]];
    if (_closing) return;
    _closing = YES;
    [self closePeer];
    if (_retry) { dispatch_source_cancel(_retry); _retry = nil; }
    if (_active) {
        uint8_t byte = 1; ssize_t ignored = write(_cancellation[1], &byte, 1); (void)ignored;
        if(_rawCancellation[1]>=0){ssize_t rawIgnored=write(_rawCancellation[1],&byte,1);(void)rawIgnored;}
        dispatch_async(dispatch_get_main_queue(), ^{ [self.host invalidate]; });
    } else [self finishClose];
}
@end

static char IndependentRadioOwnerKey;
BOOL VM27HasSharedRadioOwnerV1(id vm) {
    return vm && objc_getAssociatedObject(vm,&IndependentRadioOwnerKey)!=nil;
}
BOOL VM27SharedRadioRequestForVMV1(id vm, NSDictionary *request, void (^completion)(NSDictionary *)) {
    if(!NSThread.isMainThread||!vm||!completion||![request isKindOfClass:NSDictionary.class])return NO;
    VM27SharedRadioVZBridgeV1 *owner=objc_getAssociatedObject(vm,&IndependentRadioOwnerKey);
    VM27SharedRadioHostV1 *host=owner.host;
    if(!owner||!host)return NO;[host request:request completion:completion];return YES;
}
BOOL VM27AttachSharedRadiosToVMV1(id vm, NSString *image, NSError **error) {
    if (!vm || VM27HasSharedRadioOwnerV1(vm)) {
        if(error)*error=RadioError(EALREADY,@"An actual shared-radio owner already exists.");return NO;
    }
    VM27SharedRadioVZBridgeV1 *radio=[[VM27SharedRadioVZBridgeV1 alloc]initWithVM:vm image:image];
    if (!radio) { if(error)*error=RadioError(ENODEV,@"The selected VM's radio socket could not be admitted.");return NO; }
    objc_setAssociatedObject(vm,&IndependentRadioOwnerKey,radio,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return YES;
}
void VM27CloseSharedRadiosForVMV1(id vm, void (^completion)(NSError *)) {
    VM27SharedRadioVZBridgeV1 *radio=objc_getAssociatedObject(vm,&IndependentRadioOwnerKey);
    if (!radio) { completion(nil); return; }
    [radio closeWithCompletion:^(NSError *error) {
        if (!error && objc_getAssociatedObject(vm,&IndependentRadioOwnerKey)==radio)
            objc_setAssociatedObject(vm,&IndependentRadioOwnerKey,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        else if (!error) error=RadioError(EIO,@"The retained radio owner changed during drain.");
        completion(error);
    }];
}

static void CloseSSHWithRadios(id object, SEL selector, void (^completion)(NSError *)) {
    VM27SharedRadioVZBridgeV1 *radio = objc_getAssociatedObject(object, &RadioOwnerKey);
    void (*original)(id, SEL, void (^)(NSError *)) = (void *)OriginalSSHClose;
    if (!radio) { original(object, selector, completion); return; }
    [radio closeWithCompletion:^(NSError *error) {
        if (error) { completion(error); return; }
        objc_setAssociatedObject(object, &RadioOwnerKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        original(object, selector, completion);
    }];
}
BOOL VM27CreateGenuineVZSSHBridgeV3WithSharedRadiosV1(id vm, NSString *image,
    uint32_t idleMilliseconds, uint16_t tcpPort, unsigned scope, unsigned families,
    VM27GenuineVZSSHBridgeV1 **owner, NSError **error) {
    BOOL result = VM27CreateGenuineVZSSHBridgeV3(vm, image, idleMilliseconds, tcpPort, scope, families, owner, error);
    if (!result || !owner || !*owner || ![vm respondsToSelector:@selector(queue)]) return result;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method method = class_getInstanceMethod(VM27GenuineVZSSHBridgeV1.class, @selector(closeWithCompletion:));
        if (!method || method_getNumberOfArguments(method) != 3) return;
        char type[16] = {0}; method_getReturnType(method, type, sizeof(type));
        if (strcmp(type, "v")) return;
        OriginalSSHClose = method_setImplementation(method, (IMP)CloseSSHWithRadios);
    });
    if (!OriginalSSHClose) return result;
    VM27SharedRadioVZBridgeV1 *radio = [[VM27SharedRadioVZBridgeV1 alloc] initWithVM:vm image:image];
    if (radio) objc_setAssociatedObject(*owner, &RadioOwnerKey, radio, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    else fprintf(stderr, "[SharedRadio] native VZ radio bridge admission failed\n");
    return result;
}
