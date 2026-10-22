#import "vm27_clipboard_bridge_v1.h"
#import "../shared/VM27ClipboardChannel_v1.h"
#import "VZAppSettings.h"
#import "vm27_clipboard_provision_v1.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <fcntl.h>
#include <unistd.h>
@protocol VM27ClipboardVM <NSObject>
@property(nonatomic,readonly) dispatch_queue_t queue;
@property(nonatomic,readonly) NSArray *socketDevices;
@property(nonatomic,readonly) NSInteger state;
@end
@protocol VM27ClipboardDevice <NSObject>
- (void)setSocketListener:(id)listener forPort:(uint32_t)port;
- (void)removeSocketListenerForPort:(uint32_t)port;
@end
@protocol VM27ClipboardConnection <NSObject>
@property(nonatomic,readonly) int fileDescriptor;
@property(nonatomic,readonly) uint32_t destinationPort;
- (void)close;
@end
@protocol VM27ClipboardListener <NSObject>
@property(nonatomic,weak) id delegate;
@end
@implementation VM27ClipboardBridge {
    id<VM27ClipboardVM> _vm;
    id<VM27ClipboardDevice> _device;
    id<VM27ClipboardListener> _listener;
    id<VM27ClipboardConnection> _connection;
    VM27ClipboardChannel *_channel;
    NSTimer *_timer;
    Class _connectionClass;
    NSInteger _seen;
    uint64_t _revision;
    BOOL _active,_registered,_closed,_suspended,_provisionPending,_provisioned,_handshaken,_stateKnown;
    NSTimeInterval _acceptedAt,_lastPong,_lastPing;
    uint64_t _pingSequence,_awaitedPing;
    NSTimeInterval _nextProvision,_testDeadline;
    NSArray *_testOriginal;
    NSInteger _testWritten;
}
static NSArray *snapshot(void) {
    UIPasteboard *pasteboard=UIPasteboard.generalPasteboard;
    NSInteger before=pasteboard.changeCount;
    if(pasteboard.numberOfItems>16)return nil;
    NSMutableArray *items=[NSMutableArray new];
    for(NSInteger i=0;i<pasteboard.numberOfItems;++i) {
        NSMutableDictionary *representations=[NSMutableDictionary new];
        NSIndexSet *indices=[NSIndexSet indexSetWithIndex:(NSUInteger)i];
        NSArray *available=[pasteboard pasteboardTypesForItemSet:indices].firstObject;
        for(NSString *type in VM27ClipboardTypes()) {
            if(![available containsObject:type])continue;
            NSData *data=[pasteboard dataForPasteboardType:type inItemSet:indices].firstObject;
            if(data)representations[type]=data;
        }
        if(representations.count)[items addObject:representations];
        if(!VM27ClipboardValidateItems(items))return nil;
    }
    if(pasteboard.numberOfItems && !items.count)return nil;
    return before==pasteboard.changeCount?items:nil;
}
- (BOOL)admitted {
    return !_closed && !_suspended && _vm.state==1 && UIApplication.sharedApplication.applicationState==UIApplicationStateActive &&
        [VZAppSettings.sharedSettings boolForKey:@"ClipboardSynchronization"];
}
- (void)publishInitial:(BOOL)initial {
    if(![self admitted] || !_channel || !_handshaken)return;
    UIPasteboard *pb=UIPasteboard.generalPasteboard;NSInteger change=pb.changeCount;
    NSArray *items=snapshot();
    if(!items){if(pb.changeCount==change)_seen=change;return;}
    if(pb.changeCount!=change)return;
    _seen=change;
    if(initial && !items.count)return;
    if(_revision==UINT64_MAX){[self close];return;}
    ++_revision;
    [_channel send:@{@"v":@1,@"kind":@"apply",@"revision":@(_revision),@"items":items}];
}
- (void)setSuspended:(BOOL)suspended {
    if(suspended)[self finishTest:NO];
    _suspended=suspended;
    if(suspended){[_channel close];_active=NO;}else [self tick];
}
- (void)privacyChanged:(NSNotification *)notice {
    if([notice.name isEqualToString:UIApplicationWillResignActiveNotification] || ![self admitted]){[self finishTest:NO];[_channel close];_active=NO;}
}
- (void)tick {
    NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
    if(_testOriginal && now>=_testDeadline)[self finishTest:NO];
    if(_channel && ((!_handshaken && now-_acceptedAt>5) || (_handshaken && now-_lastPong>15))) {
        [_channel close];_active=NO;return;
    }
    if(_channel && _handshaken && now-_lastPing>=5) {
        if(_pingSequence==UINT64_MAX){[_channel close];return;}
        _lastPing=now;_awaitedPing=++_pingSequence;
        [_channel send:@{@"v":@1,@"kind":@"ping",@"revision":@(_revision),@"sequence":@(_awaitedPing)}];
    }
    if([self admitted] && !_provisioned && !_provisionPending && now>=_nextProvision) {
        _provisionPending=YES;_nextProvision=now+10;
        __weak typeof(self) weak=self;
        VM27ProvisionClipboardGuestV1(_vm,^(BOOL installed){
            typeof(self) owner=weak;if(!owner || owner->_closed)return;
            owner->_provisionPending=NO;owner->_provisioned=installed;
            if(installed){[owner->_channel close];owner->_active=NO;}
            if(installed)fprintf(stderr,"[Independent27ClipboardV1] GUI agent installation verified; channel required for sync\n");
        });
    }
    if(_active && ![self admitted]){[_channel close];_active=NO;return;}
    BOOL active=[self admitted] && _channel!=nil && _handshaken;
    if(_channel && _handshaken && (!_stateKnown || active!=_active)) {
        _stateKnown=YES;
        _active=active;
        [_channel send:@{@"v":@1,@"kind":@"state",@"enabled":@(active),@"revision":@(_revision)}];
        if(active)[self publishInitial:YES];
    }
    if(active && UIPasteboard.generalPasteboard.changeCount!=_seen)[self publishInitial:NO];
}
static BOOL number(id value) {
    return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value)==CFNumberGetTypeID() && !CFNumberIsFloatType((__bridge CFNumberRef)value) && [value compare:@0]!=NSOrderedAscending;
}
static NSString *testText(BOOL guest){return guest?@"VM27 guest → iPad 剪贴板 🧪 e\u0301":@"VM27 iPad → guest 剪贴板 🧪 e\u0301";}
static NSData *testImage(void){return [[NSData alloc]initWithBase64EncodedString:@"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lx8AAAAASUVORK5CYII=" options:0];}
static BOOL testMatches(BOOL guest){UIPasteboard *pb=UIPasteboard.generalPasteboard;return [pb.string isEqualToString:testText(guest)] && [[pb dataForPasteboardType:@"public.png"]isEqualToData:testImage()];}
- (void)finishTest:(BOOL)passed {
    if(!_testOriginal)return;
    if(UIApplication.sharedApplication.applicationState!=UIApplicationStateActive){_testOriginal=nil;_testDeadline=0;return;}
    UIPasteboard *pb=UIPasteboard.generalPasteboard;
    NSArray *original=_testOriginal;
    BOOL restore=pb.changeCount==_testWritten || testMatches(NO) || testMatches(YES);
    if(restore)[pb setItems:_testOriginal options:@{UIPasteboardOptionLocalOnly:@YES}];
    BOOL restored=restore && [pb.items isEqualToArray:original];
    _testOriginal=nil;_testDeadline=0;
    fprintf(stderr,"[Independent27ClipboardTestV1] actualGuestTextPNGReadback=%d originalRestored=%d contentLogged=0\n",passed,restored);
}
- (void)beginTest {
    if(_testOriginal || ![self admitted] || !_channel)return;
    UIPasteboard *pb=UIPasteboard.generalPasteboard;_testOriginal=pb.items;
    if(!_testOriginal)_testOriginal=@[];
    [pb setItems:@[@{@"public.utf8-plain-text":[testText(NO)dataUsingEncoding:NSUTF8StringEncoding],@"public.png":testImage()}] options:@{UIPasteboardOptionLocalOnly:@YES}];
    _testWritten=pb.changeCount;_testDeadline=NSProcessInfo.processInfo.systemUptime+30;
    BOOL written=testMatches(NO);
    fprintf(stderr,"[Independent27ClipboardTestV1] actualHostTextPNGWritten=%d originalInMemoryOnly=1 contentLogged=0\n",written);
    if(!written){[self finishTest:NO];return;}
    [self publishInitial:NO];
}
- (void)receive:(NSDictionary *)message {
    if([message[@"kind"]isEqual:@"hello"] && message.count==3 && [message[@"role"]isEqual:@"gui-clipboard-v1"] && !_handshaken) {
        _handshaken=YES;_lastPong=NSProcessInfo.processInfo.systemUptime;_stateKnown=NO;[self tick];return;
    }
    if(!_handshaken){[_channel close];return;}
    if([message[@"kind"]isEqual:@"pong"] && number(message[@"sequence"]) &&
       [message[@"sequence"]unsignedLongLongValue]==_awaitedPing) {
        _lastPong=NSProcessInfo.processInfo.systemUptime;return;
    }
    if([message[@"kind"] isEqual:@"selftest"] && message.count==2){[self beginTest];return;}
    if(![message[@"kind"] isEqual:@"offer"] || !number(message[@"base"]) ||
       !number(message[@"sequence"]) || ![message[@"sequence"] unsignedLongLongValue] ||
       !VM27ClipboardValidateItems(message[@"items"])) {[_channel close];return;}
    [self tick];
    if(![self admitted] || !_active)return;
    BOOL applied=NO;
    if([message[@"base"] unsignedLongLongValue]==_revision && _revision<UINT64_MAX) {
        [UIPasteboard.generalPasteboard setItems:message[@"items"] options:@{UIPasteboardOptionLocalOnly:@YES}];
        _seen=UIPasteboard.generalPasteboard.changeCount;++_revision;applied=YES;
    }
    [_channel send:@{@"v":@1,@"kind":@"ack",@"revision":@(_revision),
        @"sequence":message[@"sequence"],@"applied":@(applied)}];
    if(_testOriginal && applied && testMatches(YES))[self finishTest:YES];
}
- (BOOL)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(id)device {
    if(!NSThread.isMainThread || _closed || _channel || listener!=_listener || device!=_device ||
       ![connection isKindOfClass:_connectionClass])return NO;
    id<VM27ClipboardConnection> actual=connection;
    if(actual.destinationPort!=VM27_CLIPBOARD_PORT)return NO;
    int fd=fcntl(actual.fileDescriptor,F_DUPFD_CLOEXEC,0);if(fd<0)return NO;
    _handshaken=NO;_stateKnown=NO;_acceptedAt=NSProcessInfo.processInfo.systemUptime;
    _lastPing=_acceptedAt;_pingSequence=_awaitedPing=0;
    _connection=actual;_channel=[[VM27ClipboardChannel alloc]initWithOwnedDescriptor:fd];
    if(!_channel){_connection=nil;return NO;}
    __weak typeof(self) weak=self;
    _channel.received=^(NSDictionary *message){[weak receive:message];};
    _channel.disconnected=^{typeof(self) owner=weak;if(!owner)return;[owner->_connection close];owner->_connection=nil;owner->_channel=nil;owner->_active=NO;owner->_handshaken=NO;owner->_stateKnown=NO;};
    _active=NO;[self tick];
    fprintf(stderr,"[Independent27ClipboardV1] guest channel connected; payload logging disabled\n");
    return YES;
}
+ (instancetype)attachToVM:(id)vm expectedImage:(NSString *)path error:(NSError **)error {
    NSParameterAssert(NSThread.isMainThread);if(error)*error=nil;
    const char *names[]={"VZVirtualMachine","VZVirtioSocketDevice","VZVirtioSocketListener","VZVirtioSocketConnection"};
    Class classes[4];BOOL valid=path.isAbsolutePath;
    for(unsigned i=0;i<4;++i){classes[i]=objc_getClass(names[i]);const char *image=classes[i]?class_getImageName(classes[i]):NULL;valid=valid && image && [path isEqualToString:@(image)];}
    if(!valid || ![vm isKindOfClass:classes[0]] || [(id<VM27ClipboardVM>)vm queue]!=dispatch_get_main_queue() ||
       [(id<VM27ClipboardVM>)vm socketDevices].count!=1 || ![[(id<VM27ClipboardVM>)vm socketDevices].firstObject isKindOfClass:classes[1]]) {
        if(error)*error=[NSError errorWithDomain:@"VirtualMac.Clipboard" code:EINVAL userInfo:nil];return nil;
    }
    VM27ClipboardBridge *bridge=[self new];bridge->_vm=vm;
    bridge->_device=[(id<VM27ClipboardVM>)vm socketDevices].firstObject;
    bridge->_connectionClass=classes[3];bridge->_listener=[[classes[2] alloc]init];
    if(!bridge->_listener)return nil;
    bridge->_listener.delegate=bridge;
    @try {[bridge->_device setSocketListener:bridge->_listener forPort:VM27_CLIPBOARD_PORT];bridge->_registered=YES;}
    @catch(NSException *exception){if(error)*error=[NSError errorWithDomain:@"VirtualMac.Clipboard" code:EIO userInfo:nil];[bridge close];return nil;}
    [NSNotificationCenter.defaultCenter addObserver:bridge selector:@selector(privacyChanged:) name:UIApplicationWillResignActiveNotification object:nil];
    [NSNotificationCenter.defaultCenter addObserver:bridge selector:@selector(privacyChanged:) name:VZSettingsDidChangeNotification object:nil];
    __weak VM27ClipboardBridge *weak=bridge;
    bridge->_timer=[NSTimer scheduledTimerWithTimeInterval:0.25 repeats:YES block:^(NSTimer *timer){(void)timer;[weak tick];}];
    return bridge;
}
- (void)close {
    NSAssert(NSThread.isMainThread,@"Clipboard close requires actual VM.queue");
    if(_closed)return;[self finishTest:NO];_closed=YES;
    [NSNotificationCenter.defaultCenter removeObserver:self];
    [_timer invalidate];_timer=nil;
    [_channel close];_channel=nil;
    if(_registered){[_device removeSocketListenerForPort:VM27_CLIPBOARD_PORT];_registered=NO;}
    _listener.delegate=nil;_listener=nil;_connection=nil;_device=nil;_vm=nil;
}
@end
