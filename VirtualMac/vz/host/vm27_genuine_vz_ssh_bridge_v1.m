#import "vm27_genuine_vz_ssh_bridge_v1.h"
#include "../guest/vm27_guest_vsock_ssh_helper_v1.h"
#import <objc/runtime.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* These own protocols express the actual MacOSX27.0 SDK signatures. No VZ
 * class is defined here, and no Apple class symbols are substituted or linked.
 */
@protocol VM27ActualSocketVMV1 <NSObject>
@property(readonly,nonatomic) dispatch_queue_t queue;
@property(readonly,copy) NSArray *socketDevices;
@end
@protocol VM27ActualSocketDeviceV1 <NSObject>
- (void)setSocketListener:(id)listener forPort:(uint32_t)port;
- (void)removeSocketListenerForPort:(uint32_t)port;
@end
@protocol VM27ActualSocketConnectionV1 <NSObject>
@property(readonly) int fileDescriptor;
@property(readonly) uint32_t destinationPort;
- (void)close;
@end
@protocol VM27ActualSocketListenerV1 <NSObject>
@property(nullable,weak) id delegate;
@end
@class VM27GenuineVZSSHBridgeV1;
@interface VM27VZSSHConnectionLeaseV1 : NSObject
@property(strong) id<VM27ActualSocketConnectionV1> connection;
@property(strong) VM27GenuineVZSSHBridgeV1 *owner;
@end
@implementation VM27VZSSHConnectionLeaseV1 @end
static char VM27VZSSHVMOwnerKeyV1;

@interface VM27GenuineVZSSHBridgeV1 () {
@public /* TU-local C factory/callback access; these ivars are absent from the public header. */
    id<VM27ActualSocketVMV1> _vm;
    id<VM27ActualSocketDeviceV1> _device;
    id<VM27ActualSocketListenerV1> _listener;
    dispatch_queue_t _queue;
    Class _connectionClass;
    struct vm27_host_ssh_owner_v1 *_engine;
    NSMutableArray<VM27VZSSHConnectionLeaseV1 *> *_leases;
    VM27GenuineVZSSHBridgeV1 *_keepAlive;
    NSMutableArray<void (^)(NSError *)> *_closeCallbacks;
    NSError *_cleanupError;
    BOOL _closing, _engineDrained, _closed, _registered, _admissionFailed;
    char _queueKey;
}
- (void)releaseConnectionOnQueue:(VM27VZSSHConnectionLeaseV1 *)lease;
- (void)finishCloseOnQueue;
@end
static NSError *bridge_error(int code,NSString *detail) {
    return [NSError errorWithDomain:@"VM27GenuineVZSSHBridgeV1" code:code
        userInfo:@{NSLocalizedDescriptionKey:detail}];
}
static BOOL genuine_class(Class cls,NSString *expected) {
    const char *path=cls?class_getImageName(cls):NULL;
    return path && [expected isEqualToString:[NSString stringWithUTF8String:path]];
}
static void release_connection(void *context) {
    VM27VZSSHConnectionLeaseV1 *lease=CFBridgingRelease(context);
    VM27GenuineVZSSHBridgeV1 *owner=lease.owner;
    dispatch_async(owner->_queue,^{[owner releaseConnectionOnQueue:lease];});
}
@implementation VM27GenuineVZSSHBridgeV1
- (int)copySnapshot:(struct vm27_host_ssh_snapshot_v1 *)snapshot {
    if(dispatch_get_specific(&_queueKey)!=&_queueKey)return EPERM;
    if(!snapshot)return EINVAL;
    if(_closing||_closed)return ECANCELED;
    return vm27_host_ssh_owner_v1_snapshot(_engine,snapshot);
}
- (BOOL)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(id)device {
    if(dispatch_get_specific(&_queueKey)!=&_queueKey || _closing || _closed || _admissionFailed ||
        listener!=_listener || device!=_device || ![connection isKindOfClass:_connectionClass])return NO;
    id<VM27ActualSocketConnectionV1> actual=connection;
    if(actual.destinationPort!=VM27_SSH_VSOCK_HOST_PORT || actual.fileDescriptor<0)return NO;
    int copy=fcntl(actual.fileDescriptor,F_DUPFD_CLOEXEC,0);if(copy<0)return NO;
    VM27VZSSHConnectionLeaseV1 *lease=[VM27VZSSHConnectionLeaseV1 new];
    lease.connection=actual;lease.owner=self;
    void *context=(void *)CFBridgingRetain(lease);
    int rc=vm27_host_ssh_owner_v1_admit(_engine,copy,release_connection,context);
    if(rc){close(copy);CFRelease(context);return NO;}
    [_leases addObject:lease];return YES;
}
- (void)releaseConnectionOnQueue:(VM27VZSSHConnectionLeaseV1 *)lease {
    if(dispatch_get_specific(&_queueKey)!=&_queueKey || ![_leases containsObject:lease]) {
        _cleanupError=bridge_error(EPERM,@"Connection cleanup lost its actual VM queue or lease.");return;
    }
    @try {
        [lease.connection close];
        if(lease.connection.fileDescriptor!=-1) {
            _cleanupError=bridge_error(EIO,@"Actual VZ connection remains open after close.");return;
        }
        [_leases removeObjectIdenticalTo:lease];lease.connection=nil;lease.owner=nil;
    } @catch(NSException *exception) {
        _cleanupError=bridge_error(EIO,[NSString stringWithFormat:@"Actual VZ close failed: %@",exception.reason]);
    }
}
- (void)finishCloseOnQueue {
    if(!_engineDrained)return;
    /* Retry only retained genuine leases; never claim a failed close succeeded. */
    _cleanupError=nil;
    for(VM27VZSSHConnectionLeaseV1 *lease in [_leases copy])[self releaseConnectionOnQueue:lease];
    if(!_leases.count && !_registered) {
        @try {
            if(objc_getAssociatedObject(_vm,&VM27VZSSHVMOwnerKeyV1)!=self)
                @throw [NSException exceptionWithName:@"VM27VZSSHOwnerLost" reason:@"Actual VM owner registration changed." userInfo:nil];
            _listener.delegate=nil;
            objc_setAssociatedObject(_vm,&VM27VZSSHVMOwnerKeyV1,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            _closed=YES;_listener=nil;_device=nil;_vm=nil;
            dispatch_queue_set_specific(_queue,&_queueKey,NULL,NULL);
        } @catch(NSException *exception){_cleanupError=bridge_error(EIO,exception.reason?:@"Actual delegate cleanup failed.");}
    }
    if(!_closed && !_cleanupError)_cleanupError=bridge_error(EIO,@"Actual listener or connection cleanup remains retained.");
    NSArray *callbacks=[_closeCallbacks copy];[_closeCallbacks removeAllObjects];
    for(void (^callback)(NSError *) in callbacks)callback(_cleanupError);
    if(_closed)_keepAlive=nil;
}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(_closed){dispatch_async(_queue,^{completion(nil);});return;}
    if(dispatch_get_specific(&_queueKey)!=&_queueKey && !_closed) {
        completion(bridge_error(EPERM,@"Close must execute on actual VM.queue."));return;
    }
    [_closeCallbacks addObject:[completion copy]];
    if(_engineDrained) {
        if(_registered) {
            @try {[_device removeSocketListenerForPort:VM27_SSH_VSOCK_HOST_PORT];_registered=NO;}
            @catch(NSException *exception){_cleanupError=bridge_error(EIO,exception.reason?:@"Actual listener removal failed.");}
        }
        [self finishCloseOnQueue];return;
    }
    if(_closing)return;
    _closing=YES;
    @try {[_device removeSocketListenerForPort:VM27_SSH_VSOCK_HOST_PORT];_registered=NO;}
    @catch(NSException *exception){_cleanupError=bridge_error(EIO,exception.reason?:@"Actual listener removal failed.");}
    vm27_host_ssh_owner_v1_cancel(_engine);
    struct vm27_host_ssh_owner_v1 *engine=_engine;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        vm27_host_ssh_owner_v1_destroy(engine);
        /* All release callbacks were enqueued before this completion on the
         * same actual serial VM queue; no worker still borrows a descriptor. */
        dispatch_async(self->_queue,^{self->_engine=NULL;self->_engineDrained=YES;[self finishCloseOnQueue];});
    });
}
@end

BOOL VM27CreateGenuineVZSSHBridgeV1(id actualVM,NSString *expected,uint32_t idle,
                                 VM27GenuineVZSSHBridgeV1 **outOwner,NSError **error) {
    if(error)*error=nil;
    if(!outOwner){if(error)*error=bridge_error(EINVAL,@"An owned output lease is required.");return NO;}
    *outOwner=nil;
    Class vmClass=objc_getClass("VZVirtualMachine"),deviceClass=objc_getClass("VZVirtioSocketDevice");
    Class listenerClass=objc_getClass("VZVirtioSocketListener"),connectionClass=objc_getClass("VZVirtioSocketConnection");
    if(!expected.isAbsolutePath || !genuine_class(vmClass,expected) || !genuine_class(deviceClass,expected)||
       !genuine_class(listenerClass,expected)||!genuine_class(connectionClass,expected)||
       ![actualVM isKindOfClass:vmClass] || ![actualVM respondsToSelector:@selector(queue)]) {
        if(error)*error=bridge_error(EINVAL,@"Actual verified VZ image/classes/VM are required.");return NO;
    }
    VM27GenuineVZSSHBridgeV1 *o=[VM27GenuineVZSSHBridgeV1 new];
    o->_vm=actualVM;o->_queue=o->_vm.queue;o->_connectionClass=connectionClass;
    if(!o->_queue){if(error)*error=bridge_error(EINVAL,@"Actual VM has no control queue.");return NO;}
    dispatch_queue_set_specific(o->_queue,&o->_queueKey,&o->_queueKey,NULL);
    if(dispatch_get_specific(&o->_queueKey)!=&o->_queueKey) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(EPERM,@"Create must execute on actual VM.queue.");return NO;
    }
    if(objc_getAssociatedObject(actualVM,&VM27VZSSHVMOwnerKeyV1)) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(EALREADY,@"This actual VM already has a retained SSH bridge owner.");return NO;
    }
    Protocol *delegateProtocol=objc_getProtocol("VZVirtioSocketListenerDelegate");
    if(!delegateProtocol) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(ENOSYS,@"Actual VZ listener delegate protocol is not loaded.");return NO;
    }
    if(!class_conformsToProtocol([VM27GenuineVZSSHBridgeV1 class],delegateProtocol))
        class_addProtocol([VM27GenuineVZSSHBridgeV1 class],delegateProtocol);
    if(!class_conformsToProtocol([VM27GenuineVZSSHBridgeV1 class],delegateProtocol)) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(EINVAL,@"Own delegate cannot conform to the actual VZ protocol.");return NO;
    }
    NSArray *devices=o->_vm.socketDevices;
    if(devices.count!=1 || ![devices.firstObject isKindOfClass:deviceClass]) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(ENODEV,@"Exactly one actual VZVirtioSocketDevice is required.");return NO;
    }
    o->_device=devices.firstObject;o->_leases=[NSMutableArray new];o->_closeCallbacks=[NSMutableArray new];
    o->_listener=[[listenerClass alloc] init];
    if(!o->_listener) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(ENOMEM,@"Actual VZ listener allocation failed.");return NO;
    }
    int rc=vm27_host_ssh_owner_v1_create(22222,idle,&o->_engine);
    if(rc) {
        dispatch_queue_set_specific(o->_queue,&o->_queueKey,NULL,NULL);
        if(error)*error=bridge_error(rc,@"Real loopback TCP22222 owner creation failed.");return NO;
    }
    o->_keepAlive=o;*outOwner=o;
    objc_setAssociatedObject(actualVM,&VM27VZSSHVMOwnerKeyV1,o,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    @try {
        o->_listener.delegate=o;
        /* SDK requires exclusive ownership: set replaces any existing listener. */
        o->_registered=YES;
        [o->_device setSocketListener:o->_listener forPort:VM27_SSH_VSOCK_HOST_PORT];
    } @catch(NSException *exception) {
        if(error)*error=bridge_error(EIO,exception.reason?:@"Actual VZ listener registration failed.");
        o->_admissionFailed=YES;vm27_host_ssh_owner_v1_cancel(o->_engine);return NO;
    }
    return YES;
}
