#import <AppKit/AppKit.h>
#import "VM27ClipboardGuest_v1.h"
#import "../shared/VM27ClipboardChannel_v1.h"
#include <sys/socket.h>
#include <sys/vsock.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <os/log.h>
@interface VM27ClipboardGuest : NSObject
- (void)start;
- (void)stop;
@end
@implementation VM27ClipboardGuest {
    VM27ClipboardChannel *_channel;
    NSTimer *_timer;
    dispatch_source_t _testSignal;
    int _connecting;
    unsigned _connectObservations;
    NSTimeInterval _deadline,_retry;
    NSInteger _seen;
    uint64_t _revision,_sequence,_pendingSequence,_deferredRevision;
    BOOL _enabled,_waiting,_sessionActive;
    NSArray *_deferred;
}
static BOOL integer(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value)==CFNumberGetTypeID() &&
        !CFNumberIsFloatType((__bridge CFNumberRef)value) && [value compare:@0]!=NSOrderedAscending;
}
static NSArray *readItems(void) {
    NSPasteboard *pasteboard=NSPasteboard.generalPasteboard;NSInteger change=pasteboard.changeCount;
    NSArray *source=pasteboard.pasteboardItems;if(source.count>16)return nil;
    NSMutableArray *result=[NSMutableArray new];
    for(NSPasteboardItem *item in source) {
        NSMutableDictionary *types=[NSMutableDictionary new];
        for(NSString *type in VM27ClipboardTypes()) {
            if(![item.types containsObject:type])continue;
            NSData *data=[item dataForType:type];if(data)types[type]=data;
        }
        if(types.count)[result addObject:types];
        if(!VM27ClipboardValidateItems(result))return nil;
    }
    if(source.count && !result.count)return nil;
    return change==pasteboard.changeCount?result:nil;
}
- (void)applyItems:(NSArray *)items {
    if(!_enabled || !_sessionActive)return;
    NSMutableArray *objects=[NSMutableArray new];
    for(NSDictionary *types in items) {
        NSPasteboardItem *item=[NSPasteboardItem new];
        for(NSString *type in types)[item setData:types[type] forType:type];
        [objects addObject:item];
    }
    NSPasteboard *pb=NSPasteboard.generalPasteboard;[pb clearContents];
    if(objects.count)[pb writeObjects:objects];_seen=pb.changeCount;
}
- (void)receive:(NSDictionary *)message {
    if(!integer(message[@"revision"]) || [message[@"revision"] unsignedLongLongValue]<_revision){[_channel close];return;}
    uint64_t revision=[message[@"revision"] unsignedLongLongValue];NSString *kind=message[@"kind"];
    if([kind isEqual:@"state"]) {
        os_log(OS_LOG_DEFAULT,"VM27ClipboardState enabled=%{public}d revision=%{public}llu",[message[@"enabled"]boolValue],(unsigned long long)revision);
        if(![message[@"enabled"] isKindOfClass:NSNumber.class]){[_channel close];return;}
        _revision=revision;_enabled=[message[@"enabled"] boolValue];
        _seen=NSPasteboard.generalPasteboard.changeCount;
        _waiting=NO;_deferred=nil;return;
    }
    if([kind isEqual:@"apply"] && VM27ClipboardValidateItems(message[@"items"])) {
        _revision=revision;
        if(!_enabled || !_sessionActive)return;
        if(_waiting || NSPasteboard.generalPasteboard.changeCount!=_seen) {
            _deferred=message[@"items"];_deferredRevision=revision;
        } else [self applyItems:message[@"items"]];
        return;
    }
    if([kind isEqual:@"ack"] && integer(message[@"sequence"]) &&
       [message[@"sequence"] unsignedLongLongValue]==_pendingSequence && _waiting &&
       [message[@"applied"] isKindOfClass:NSNumber.class]) {
        _revision=revision;_waiting=NO;
        if(_deferred && _deferredRevision==revision && ![message[@"applied"] boolValue] &&
           NSPasteboard.generalPasteboard.changeCount==_seen)[self applyItems:_deferred];
        _deferred=nil;return;
    }
    [_channel close];
}
- (void)connected:(int)fd {
    _connecting=-1;_enabled=NO;_waiting=NO;_revision=0;_sequence=0;
    _seen=NSPasteboard.generalPasteboard.changeCount;
    _channel=[[VM27ClipboardChannel alloc]initWithOwnedDescriptor:fd];
    os_log(OS_LOG_DEFAULT,"VM27ClipboardChannel initialized=%{public}d error=%{public}d",_channel!=nil,errno);
    __weak typeof(self) weak=self;
    _channel.received=^(NSDictionary *message){[weak receive:message];};
    _channel.disconnected=^{typeof(self) owner=weak;if(!owner)return;owner->_channel=nil;owner->_enabled=NO;owner->_waiting=NO;owner->_deferred=nil;owner->_retry=NSProcessInfo.processInfo.systemUptime+3;};
}
- (void)sessionChanged:(NSNotification *)notification {
    _sessionActive=[notification.name isEqualToString:NSWorkspaceSessionDidBecomeActiveNotification];
    _seen=NSPasteboard.generalPasteboard.changeCount;_deferred=nil;
}
- (void)tick {
    NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
    if(!_channel) {
        if(_connecting>=0) {
            struct pollfd p={.fd=_connecting,.events=POLLOUT};int result=poll(&p,1,0);
            if(_connectObservations<8)os_log(OS_LOG_DEFAULT,"VM27ClipboardConnect poll=%{public}d events=%{public}d",result,p.revents);
            if(result>0) {
                int error=0;socklen_t length=sizeof(error);
                if(getsockopt(_connecting,SOL_SOCKET,SO_ERROR,&error,&length)==0 && !error){[self connected:_connecting];return;}
                if(_connectObservations<8)os_log(OS_LOG_DEFAULT,"VM27ClipboardConnect pendingFailed socketError=%{public}d errno=%{public}d",error,errno);
                close(_connecting);_connecting=-1;_retry=now+3;
            } else if(now>_deadline){close(_connecting);_connecting=-1;_retry=now+3;}
            return;
        }
        if(now<_retry || !_sessionActive)return;
        int fd=socket(AF_VSOCK,SOCK_STREAM,0);if(fd<0){_retry=now+3;return;}
        if(fcntl(fd,F_SETFL,O_NONBLOCK)<0){close(fd);_retry=now+3;return;}
        struct sockaddr_vm address={0};address.svm_len=sizeof(address);address.svm_family=AF_VSOCK;
        address.svm_cid=VMADDR_CID_HOST;address.svm_port=VM27_CLIPBOARD_PORT;
        int result=connect(fd,(struct sockaddr *)&address,sizeof(address));
        if(_connectObservations++<8)os_log(OS_LOG_DEFAULT,"VM27ClipboardConnect result=%{public}d errno=%{public}d",result,errno);
        if(!result)[self connected:fd];
        else if(errno==EINPROGRESS){_connecting=fd;_deadline=now+5;}
        else {close(fd);_retry=now+3;}
        return;
    }
    if(!_enabled || !_sessionActive || _waiting)return;
    NSPasteboard *pb=NSPasteboard.generalPasteboard;NSInteger change=pb.changeCount;
    if(change==_seen)return;
    NSArray *items=readItems();
    if(!items){if(change==pb.changeCount)_seen=change;return;}
    if(change!=pb.changeCount)return;
    if(_sequence==UINT64_MAX){[_channel close];return;}
    _seen=change;_waiting=YES;_pendingSequence=++_sequence;_deferred=nil;
    [_channel send:@{@"v":@1,@"kind":@"offer",@"base":@(_revision),@"sequence":@(_sequence),@"items":items}];
}
- (void)requestSelfTest:(NSNotification *)notice {
    (void)notice;
    os_log(OS_LOG_DEFAULT,"VM27ClipboardTestRequest enabled=%{public}d sessionActive=%{public}d waiting=%{public}d connected=%{public}d",_enabled,_sessionActive,_waiting,_channel!=nil);
    if(_enabled && _sessionActive && !_waiting)[_channel send:@{@"v":@1,@"kind":@"selftest"}];
}
- (void)start {
    _connecting=-1;_sessionActive=YES;
    signal(SIGUSR1,SIG_IGN);
    _testSignal=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGUSR1,0,dispatch_get_main_queue());
    __weak typeof(self) signalOwner=self;
    dispatch_source_set_event_handler(_testSignal,^{[signalOwner requestSelfTest:nil];});
    dispatch_resume(_testSignal);
    [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(requestSelfTest:) name:@"com.mac.virtual.clipboard-sync.selftest" object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDrop];
    NSNotificationCenter *center=NSWorkspace.sharedWorkspace.notificationCenter;
    [center addObserver:self selector:@selector(sessionChanged:) name:NSWorkspaceSessionDidResignActiveNotification object:nil];
    [center addObserver:self selector:@selector(sessionChanged:) name:NSWorkspaceSessionDidBecomeActiveNotification object:nil];
    __weak typeof(self) weak=self;
    _timer=[NSTimer scheduledTimerWithTimeInterval:0.25 repeats:YES block:^(NSTimer *timer){(void)timer;[weak tick];}];
}
- (void)stop {
    if(_testSignal){dispatch_source_cancel(_testSignal);_testSignal=nil;}
    [NSDistributedNotificationCenter.defaultCenter removeObserver:self];
    [_timer invalidate];_timer=nil;[NSWorkspace.sharedWorkspace.notificationCenter removeObserver:self];
    [_channel close];_channel=nil;if(_connecting>=0){close(_connecting);_connecting=-1;}
}
@end
static VM27ClipboardGuest *client;
void VM27ClipboardGuestStart(void) {NSCAssert(NSThread.isMainThread,@"GUI pasteboard requires its user queue");if(!client){client=[VM27ClipboardGuest new];[client start];}}
void VM27ClipboardGuestStop(void) {[client stop];client=nil;}
