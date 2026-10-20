/* Included after the real GuestTools connection state. All methods execute on
 * the actual private serial QGA queue; each send/read validates one old socket.
 * V6 retains the private V5 class ABI for the unchanged owned SSH service. */
#include <stdio.h>
static unsigned gGuestActualExitLogsV6,gGuestNormalNonzeroLogsV6,gGuestCancelLogsV6;
static dispatch_queue_t gGuestQGAQueueV3;
static char gGuestQGAQueueKeyV3;
static pthread_once_t gGuestQGAQueueOnceV3=PTHREAD_ONCE_INIT;
static uint64_t gGuestConnectionEpochV3;
static void QGAQueueInitV3(void) {
    gGuestQGAQueueV3=dispatch_queue_create("VirtualMac.owned.QGA.v3",DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(gGuestQGAQueueV3,&gGuestQGAQueueKeyV3,&gGuestQGAQueueKeyV3,NULL);
}
static dispatch_queue_t QGAQueueV3(void) {pthread_once(&gGuestQGAQueueOnceV3,QGAQueueInitV3);return gGuestQGAQueueV3;}
static void QGASyncV3(dispatch_block_t block) {
    if(dispatch_get_specific(&gGuestQGAQueueKeyV3)==&gGuestQGAQueueKeyV3)block();else dispatch_sync(QGAQueueV3(),block);
}
@interface VM27OwnedQGAOperationV5 : NSObject {
@public VM27OwnedQGALeaseV3 _lease;
    id _connection;
    NSMutableDictionary *_dictionary;
    NSMutableSet *_identifiers;
    void (^_completion)(BOOL,NSData *);
    BOOL _finished;
    /* Valid only after one actual command status, until the next request. */
    BOOL _actualCommandExitKnownV6;
    long long _actualCommandExitCodeV6;
@public VM27QGAResultV3 _cleanupResult;
}
- (instancetype)initWithCompletion:(void (^)(BOOL,NSData *))completion;
- (BOOL)isLive;
- (void)cancel:(NSString *)reason;
- (void)finish:(BOOL)success output:(NSData *)output;
@end
static VM27OwnedQGAOperationV5 *gGuestOwnedOperationV3;
/* Set only by a real native cleanup failure. Reset must not fabricate recovery;
 * admission stays poisoned until this App process ends or a future exact native
 * cleanup protocol proves all retained resources gone. */
static BOOL gGuestCleanupUnresolvedV5;
static BOOL OwnedQGAReadGateV3(void) {return !gGuestOwnedOperationV3 || [gGuestOwnedOperationV3 isLive];}

@implementation VM27OwnedQGAOperationV5
- (instancetype)initWithCompletion:(void (^)(BOOL,NSData *))completion {
    if((self=[super init])) {
        _lease.ownedFD=-1;_lease.originalFD=-1;
        if(dispatch_get_specific(&gGuestQGAQueueKeyV3)!=&gGuestQGAQueueKeyV3 ||
           !gGuestSocketConnection || !gGuestCallbacks || gGuestReadDescriptor!=gGuestWriteDescriptor ||
           VM27OwnedQGALeaseCreateV3(&_lease,gGuestWriteDescriptor,gGuestConnectionEpochV3,
                __atomic_load_n(&gGuestProvisioningGeneration,__ATOMIC_ACQUIRE))!=VM27QGAValidV3) {
            if(_lease.active)VM27OwnedQGALeaseCloseV3(&_lease,false);[self release];return nil;
        }
        _connection=[gGuestSocketConnection retain];_dictionary=[gGuestCallbacks retain];
        _identifiers=[NSMutableSet new];_completion=[completion copy];
    }
    return self;
}
- (BOOL)isLive {
    if(_finished)return NO;
    BOOL live=dispatch_get_specific(&gGuestQGAQueueKeyV3)==&gGuestQGAQueueKeyV3 &&
        gGuestOwnedOperationV3==self && gGuestSocketConnection==_connection && gGuestCallbacks==_dictionary &&
        gGuestReadDescriptor==gGuestWriteDescriptor &&
        VM27OwnedQGALeaseCheckV3(&_lease,gGuestWriteDescriptor,gGuestConnectionEpochV3,
            __atomic_load_n(&gGuestProvisioningGeneration,__ATOMIC_ACQUIRE))==VM27QGAValidV3;
    if(!live)[self cancel:@"actual connection identity/epoch/generation/FD/deadline unavailable"];
    return live;
}
- (void)complete:(BOOL)success output:(NSData *)output shutdown:(BOOL)stop {
    if(_finished)return;_finished=YES;
    [self retain];
    for(NSNumber *identifier in _identifiers)[_dictionary removeObjectForKey:identifier];
    [_identifiers removeAllObjects];
    VM27QGAResultV3 closed=VM27OwnedQGALeaseCloseV3(&_lease,stop);_cleanupResult=closed;
    BOOL sameConnection=gGuestSocketConnection==_connection && gGuestConnectionEpochV3==_lease.epoch;
    if(stop && sameConnection) {
        if(gGuestConnectionEpochV3!=UINT64_MAX)++gGuestConnectionEpochV3;
        else gGuestConnectionEpochV3=UINT64_MAX;
        if(gGuestProvisioningGeneration!=UINT64_MAX)++gGuestProvisioningGeneration;
        gGuestReadDescriptor=-1;gGuestWriteDescriptor=-1;gGuestProvisioningStarted=NO;
        if(gGuestOutputSource)dispatch_source_cancel(gGuestOutputSource);
        /* These callbacks belong to the same now-shutdown connection. They
         * cannot be rebound to a later SDK connection or an unrelated PID. */
        NSArray *callbacks=[_dictionary.allValues copy];[_dictionary removeAllObjects];
        NSDictionary *failed=@{@"error":@{@"class":@"VM27OwnedQGAConnectionCancelled",@"desc":@"actual previous QGA socket closed"}};
        for(VZGuestAgentResponse callback in callbacks)callback(failed);
        [callbacks release];
    }
    if(gGuestOwnedOperationV3==self) {gGuestOwnedOperationV3=nil;[self release];}
    void (^callback)(BOOL,NSData *)=[_completion copy];[_completion release];_completion=nil;
    if(closed!=VM27QGAValidV3) {
        gGuestCleanupUnresolvedV5=YES;
        if(!stop && sameConnection) {
            if(gGuestConnectionEpochV3!=UINT64_MAX)++gGuestConnectionEpochV3;
            if(gGuestProvisioningGeneration!=UINT64_MAX)++gGuestProvisioningGeneration;
            gGuestReadDescriptor=-1;gGuestWriteDescriptor=-1;gGuestProvisioningStarted=NO;
            if(gGuestOutputSource)dispatch_source_cancel(gGuestOutputSource);
        }
        success=NO;
        output=[@"VM27_GUEST_HELPER_QGA_CLEANUP_UNRESOLVED owningNormalVMLifecycle=1 guestSSHAuthenticated=0\n" dataUsingEncoding:NSUTF8StringEncoding];
        /* Retain the SDK owner if native FD ownership cannot be closed safely. */
        [self retain];
    } else {[_connection release];_connection=nil;}
    if(callback) {callback(success,output ?: [NSData data]);[callback release];}
    [self release];
}
- (void)finish:(BOOL)success output:(NSData *)output {
    /* A guest command's ordinary nonzero exit is not a broken connection.
     * No upload/local-validation failure may reuse an earlier command status:
     * every actual request clears this marker before sending. */
    BOOL normalNonzero=!success && _actualCommandExitKnownV6 && _actualCommandExitCodeV6!=0;
    if(!_finished && normalNonzero && gGuestNormalNonzeroLogsV6<4) {
        ++gGuestNormalNonzeroLogsV6;const int saved=errno;
        dprintf(STDERR_FILENO,"[GuestTools] QGA6 normal-command-nonzero exitcode=%lld epoch=%llu generation=%llu shutdownRequested=0 callbackSuccess=0\n",
            _actualCommandExitCodeV6,(unsigned long long)_lease.epoch,(unsigned long long)_lease.generation);
        errno=saved;
    }
    [self complete:success output:output shutdown:!success && !normalNonzero];
}
- (void)cancel:(NSString *)reason {
    if(_finished)return;
    if(gGuestCancelLogsV6<4) {
        ++gGuestCancelLogsV6;const int saved=errno;
        dprintf(STDERR_FILENO,"[GuestTools] QGA6 cancel epoch=%llu generation=%llu shutdownRequested=1 reason=%.160s\n",
            (unsigned long long)_lease.epoch,(unsigned long long)_lease.generation,reason.UTF8String ?: "(none)");
        errno=saved;
    }
    NSString *message=[NSString stringWithFormat:@"VM27_GUEST_HELPER_QGA_CANCELLED reason=%@ uncertainRemoteLaunch=1 owningNormalVMLifecycle=1 guestSSHAuthenticated=0\n",reason];
    [self complete:NO output:[message dataUsingEncoding:NSUTF8StringEncoding] shutdown:YES];
}
- (void)dealloc {[_connection release];[_dictionary release];[_identifiers release];[_completion release];[super dealloc];}
@end

static BOOL OwnedQGASendV3(VM27OwnedQGAOperationV5 *owner,NSString *command,NSDictionary *arguments,VZGuestAgentResponse callback) {
    if(![owner isLive])return NO;
    owner->_actualCommandExitKnownV6=NO;owner->_actualCommandExitCodeV6=0;
    if(owner->_dictionary.count) {[owner cancel:@"another request is still outstanding on this owned stream"];return NO;}
    if(gGuestRequestIdentifier==UINT64_MAX){[owner cancel:@"request identifier exhausted"];return NO;}
    NSNumber *identifier=@(++gGuestRequestIdentifier);
    NSMutableDictionary *request=[NSMutableDictionary dictionaryWithObject:command forKey:@"execute"];
    if(arguments.count)request[@"arguments"]=arguments;request[@"id"]=identifier;
    NSError *error=nil;NSMutableData *data=[[[NSJSONSerialization dataWithJSONObject:request options:0 error:&error] mutableCopy] autorelease];
    if(!data){[owner cancel:@"JSON request encoding failed"];return NO;}[data appendBytes:"\n" length:1];
    [owner->_identifiers addObject:identifier];
    VZGuestAgentResponse guarded=^(NSDictionary *response) {
        [owner->_identifiers removeObject:identifier];
        if([owner isLive] && callback)callback(response);
    };
    [owner->_dictionary setObject:[[guarded copy] autorelease] forKey:identifier];
    VM27QGAResultV3 sent=VM27OwnedQGALeaseSendV3(&owner->_lease,gGuestWriteDescriptor,gGuestConnectionEpochV3,
        __atomic_load_n(&gGuestProvisioningGeneration,__ATOMIC_ACQUIRE),data.bytes,data.length);
    if(sent!=VM27QGAValidV3) {[owner cancel:@"partial/native/expired request send failed; no retry"];return NO;}
    return YES;
}
static void OwnedQGAPollV3(VM27OwnedQGAOperationV5 *owner,NSNumber *pid,VZGuestCommandCompletion completion) {
    if(![owner isLive])return;
    OwnedQGASendV3(owner,@"guest-exec-status",@{@"pid":pid},^(NSDictionary *response) {
        NSDictionary *r=response[@"return"];
        if(![r isKindOfClass:NSDictionary.class] || response[@"error"]) {[owner cancel:@"actual exec-status failed"];return;}
        if([r[@"exited"] boolValue]) {
            owner->_actualCommandExitKnownV6=[r[@"exited"] isKindOfClass:NSNumber.class] &&
                [r[@"exitcode"] isKindOfClass:NSNumber.class];
            if(owner->_actualCommandExitKnownV6) {
                owner->_actualCommandExitCodeV6=[r[@"exitcode"] longLongValue];
                if(gGuestActualExitLogsV6<4) {
                    ++gGuestActualExitLogsV6;const int saved=errno;
                    dprintf(STDERR_FILENO,"[GuestTools] QGA6 actual-command-exit pid=%llu exitcode=%lld epoch=%llu generation=%llu exitedStatusKnown=1\n",
                        pid.unsignedLongLongValue,owner->_actualCommandExitCodeV6,
                        (unsigned long long)owner->_lease.epoch,(unsigned long long)owner->_lease.generation);
                    errno=saved;
                }
            }
            NSMutableData *out=[NSMutableData data];
            for(NSString *key in @[@"out-data",@"err-data"]) {
                NSString *encoded=r[key];if(![encoded isKindOfClass:NSString.class])continue;
                NSData *part=[[[NSData alloc] initWithBase64EncodedString:encoded options:0] autorelease];if(part)[out appendData:part];
            }
            completion([r[@"exitcode"] isKindOfClass:NSNumber.class] && [r[@"exitcode"] integerValue]==0,out);return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,200*NSEC_PER_MSEC),QGAQueueV3(),^{if([owner isLive])OwnedQGAPollV3(owner,pid,completion);});
    });
}
static void OwnedQGARunV3(VM27OwnedQGAOperationV5 *owner,NSString *path,NSArray *arguments,VZGuestCommandCompletion completion) {
    OwnedQGASendV3(owner,@"guest-exec",@{@"path":path,@"arg":arguments,@"capture-output":@YES},^(NSDictionary *response) {
        NSDictionary *result=response[@"return"];
        NSNumber *pid=[result isKindOfClass:NSDictionary.class]?result[@"pid"]:nil;
        if(![pid isKindOfClass:NSNumber.class] || pid.unsignedLongLongValue==0 || response[@"error"]) {[owner cancel:@"actual guest-exec PID unavailable"];return;}
        OwnedQGAPollV3(owner,pid,completion);
    });
}
static void OwnedQGAWriteChunksV3(VM27OwnedQGAOperationV5 *owner,NSNumber *handle,NSData *data,NSUInteger at,void (^completion)(BOOL)) {
    if(![owner isLive])return;
    if(at==data.length) {
        OwnedQGASendV3(owner,@"guest-file-close",@{@"handle":handle},^(NSDictionary *response){completion(response[@"error"]==nil);});return;
    }
    NSUInteger length=MIN((NSUInteger)4096,data.length-at);NSData *chunk=[data subdataWithRange:NSMakeRange(at,length)];
    OwnedQGASendV3(owner,@"guest-file-write",@{@"handle":handle,@"buf-b64":[chunk base64EncodedStringWithOptions:0]},^(NSDictionary *response) {
        NSDictionary *result=response[@"return"];
        NSNumber *written=[result isKindOfClass:NSDictionary.class]?result[@"count"]:nil;
        if(![written isKindOfClass:NSNumber.class] || written.unsignedIntegerValue!=length || response[@"error"]) {[owner cancel:@"actual upload chunk incomplete"];return;}
        OwnedQGAWriteChunksV3(owner,handle,data,at+length,completion);
    });
}
static void OwnedQGAWriteFileV3(VM27OwnedQGAOperationV5 *owner,NSString *path,NSData *data,void (^completion)(BOOL)) {
    OwnedQGASendV3(owner,@"guest-file-open",@{@"path":path,@"mode":@"w"},^(NSDictionary *response) {
        NSNumber *handle=response[@"return"];
        if(![handle isKindOfClass:NSNumber.class] || response[@"error"]) {[owner cancel:@"actual upload handle unavailable"];return;}
        OwnedQGAWriteChunksV3(owner,handle,data,0,completion);
    });
}

static VM27OwnedQGAOperationV5 *BeginQGAOperationV3(void (^completion)(BOOL,NSData *)) {
    if(gGuestCleanupUnresolvedV5 || gGuestOwnedOperationV3 || gGuestWriteDescriptor<0) {
        if(completion)completion(NO,[@"VM27_QGA_OWNER_UNAVAILABLE noRequestSent=1\n" dataUsingEncoding:NSUTF8StringEncoding]);
        return nil;
    }
    VM27OwnedQGAOperationV5 *owner=[[VM27OwnedQGAOperationV5 alloc] initWithCompletion:completion];
    if(!owner) {if(completion)completion(NO,[@"VM27_QGA_SOCKET_LEASE_UNAVAILABLE noRequestSent=1\n" dataUsingEncoding:NSUTF8StringEncoding]);return nil;}
    gGuestOwnedOperationV3=owner; /* This is the actual allocated operation retain. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,45*NSEC_PER_SEC),QGAQueueV3(),^{
        if(gGuestOwnedOperationV3==owner && !owner->_finished)[owner cancel:@"45 second monotonic operation bound expired"];
    });
    return owner;
}
