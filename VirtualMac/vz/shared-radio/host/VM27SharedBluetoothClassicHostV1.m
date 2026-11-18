// One owned classic discovery client, reachable only through the guest's fixed
// NAT-to-Unix mapping. Never changes host power, discoverability or pairing.
#import "VM27SharedBluetoothClassicHostV1.h"
#include <objc/message.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "../common/vm27_shared_radio_paths_v1.h"
static const char *Path=VM27_SHARED_RADIO_CLASSIC_SOCKET_V1;
static BOOL verified(Class cls,const char *selector,const char *types) {
    Method method=class_getInstanceMethod(cls,sel_registerName(selector));
    return method&&!strcmp(method_getTypeEncoding(method),types);
}
static BOOL flag(id value,const char *selector) {
    return ((BOOL(*)(id,SEL))objc_msgSend)(value,sel_registerName(selector));
}
static NSData *addressBytes(NSString *text) {
    if(![text isKindOfClass:NSString.class]||text.length>17)return nil;
    NSArray *parts=[text componentsSeparatedByString:@":"];if(parts.count!=6)return nil;
    uint8_t bytes[6];unsigned nonzero=0;
    for(unsigned i=0;i<6;++i) {
        NSString *part=parts[i];unsigned value=0;NSScanner *scan=[NSScanner scannerWithString:part];
        if(!part.length||part.length>2||![scan scanHexInt:&value]||!scan.isAtEnd||value>255)return nil;
        bytes[i]=(uint8_t)value;nonzero|=value;
    }
    return nonzero?[NSData dataWithBytes:bytes length:6]:nil;
}
@interface VM27SharedBluetoothClassicHostV1 () {
    int _listener,_client;ino_t _inode;
    dispatch_source_t _accept,_read,_write;
    NSMutableData *_input,*_output;
    NSMutableDictionary<NSData *,NSDictionary *> *_devices;
    id _manager,_observer;Class _deviceClass;
    uint64_t _generation;
    BOOL _scanning,_invalidated,_finishing;
}
- (void)closeClient;
- (void)flush;
- (void)finish:(int)status;
@end
@implementation VM27SharedBluetoothClassicHostV1
- (instancetype)init {if((self=[super init])){_listener=-1;_client=-1;}return self;}
- (BOOL)start {
    NSAssert(NSThread.isMainThread,@"classic bridge uses its owner's queue");
    if(_invalidated)return NO;if(_listener>=0)return YES;
    if(!dlopen("/System/Library/PrivateFrameworks/BluetoothManager.framework/BluetoothManager",RTLD_NOW|RTLD_LOCAL))return NO;
    Class cls=NSClassFromString(@"BluetoothManager");_deviceClass=NSClassFromString(@"BluetoothDevice");
    if(!verified(object_getClass(cls),"sharedInstance","@16@0:8")||
       !verified(object_getClass(cls),"setSharedInstanceQueue:","v24@0:8@16")||
       !verified(cls,"available","B16@0:8")||!verified(cls,"powered","B16@0:8")||
       !verified(cls,"deviceScanningEnabled","B16@0:8")||
       !verified(cls,"resetDeviceScanning","v16@0:8")||
       !verified(cls,"setDeviceScanningEnabled:","v20@0:8B16")||
       !verified(_deviceClass,"address","@16@0:8")||!verified(_deviceClass,"name","@16@0:8")||
       !verified(_deviceClass,"majorClass","I16@0:8")||!verified(_deviceClass,"minorClass","I16@0:8"))return NO;
    // The singleton outlives each VM/radio session. Configuring its queue a
    // second time asserts inside BluetoothManager after a guest restart.
    static dispatch_once_t managerOnce;static id sharedManager;
    dispatch_once(&managerOnce,^{
        ((void(*)(id,SEL,id))objc_msgSend)(cls,sel_registerName("setSharedInstanceQueue:"),dispatch_get_main_queue());
        sharedManager=((id(*)(id,SEL))objc_msgSend)(cls,sel_registerName("sharedInstance"));
    });
    _manager=sharedManager;if(!_manager)return NO;
    struct stat old;
    if(!VM27SharedRadioPrepareHostDirectoryV1())return NO;
    if(!lstat(Path,&old)) {
        if(!S_ISSOCK(old.st_mode)||old.st_uid!=geteuid()||old.st_nlink!=1||(old.st_mode&0777)!=0600||unlink(Path))return NO;
    } else if(errno!=ENOENT)return NO;
    int fd=socket(AF_UNIX,SOCK_STREAM,0),one=1;if(fd<0)return NO;
    struct sockaddr_un address={0};address.sun_family=AF_UNIX;address.sun_len=sizeof(address);
    strlcpy(address.sun_path,Path,sizeof(address.sun_path));
    if(fcntl(fd,F_SETFL,O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)||setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))||
       bind(fd,(void *)&address,sizeof(address))||chmod(Path,0600)||listen(fd,2)||lstat(Path,&old)) {close(fd);return NO;}
    _listener=fd;_inode=old.st_ino;__weak typeof(self) weak=self;
    _accept=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,dispatch_get_main_queue());
    dispatch_source_set_event_handler(_accept,^{
        typeof(self) strong=weak;if(!strong||strong->_listener<0)return;
        int client=accept(strong->_listener,NULL,NULL);if(client<0)return;uid_t uid;gid_t gid;int option=1;
        if(strong->_client>=0||getpeereid(client,&uid,&gid)||uid!=geteuid()||
           fcntl(client,F_SETFL,O_NONBLOCK)||fcntl(client,F_SETFD,FD_CLOEXEC)||
           setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&option,sizeof(option))) {close(client);return;}
        strong->_client=client;strong->_input=[NSMutableData data];strong->_output=[NSMutableData data];
        strong->_devices=[NSMutableDictionary dictionary];strong->_finishing=NO;uint64_t generation=++strong->_generation;
        strong->_read=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)client,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(strong->_read,^{
            typeof(self) owner=weak;if(!owner||owner->_generation!=generation)return;
            uint8_t bytes[64];ssize_t count=recv(client,bytes,sizeof(bytes),MSG_DONTWAIT);
            if(count<0&&(errno==EAGAIN||errno==EINTR))return;
            if(count<=0||owner->_input.length+(NSUInteger)count>32){[owner closeClient];return;}
            [owner->_input appendBytes:bytes length:(NSUInteger)count];
            NSData *request=[@"VM27CLASSIC1 INQUIRE\n" dataUsingEncoding:NSASCIIStringEncoding];
            if(owner->_input.length<request.length)return;
            if(![owner->_input isEqual:request]||owner->_scanning||owner->_finishing){[owner closeClient];return;}
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{
                typeof(self) current=weak;if(!current||current->_generation!=generation)return;
                if(!flag(current->_manager,"available")||!flag(current->_manager,"powered")){[current finish:ENODEV];return;}
                if(flag(current->_manager,"deviceScanningEnabled")){[current finish:EBUSY];return;}
                // BluetoothManager reports each device once per discovery
                // agent. Stop completed scans and replace only our agent so
                // later native inquiries receive fresh discovery callbacks.
                ((void(*)(id,SEL))objc_msgSend)(current->_manager,sel_registerName("resetDeviceScanning"));
                current->_scanning=YES;
                ((void(*)(id,SEL,BOOL))objc_msgSend)(current->_manager,sel_registerName("setDeviceScanningEnabled:"),YES);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),dispatch_get_main_queue(),^{
                    typeof(self) done=weak;if(done&&done->_generation==generation)[done finish:0];
                });
            });
        });dispatch_resume(strong->_read);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,15*NSEC_PER_SEC),dispatch_get_main_queue(),^{
            typeof(self) owner=weak;if(owner&&owner->_generation==generation)[owner closeClient];
        });
    });dispatch_resume(_accept);
    _observer=[NSNotificationCenter.defaultCenter addObserverForName:@"BluetoothDeviceDiscoveredNotification" object:nil
        queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
        typeof(self) owner=weak;id device=notification.object;
        if(!owner||!owner->_scanning||![device isKindOfClass:owner->_deviceClass]||owner->_devices.count>=128)return;
        NSData *address=addressBytes(((id(*)(id,SEL))objc_msgSend)(device,sel_registerName("address")));if(!address)return;
        NSString *name=((id(*)(id,SEL))objc_msgSend)(device,sel_registerName("name"));
        if(![name isKindOfClass:NSString.class]||[name lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>248)name=@"";
        unsigned major=((unsigned(*)(id,SEL))objc_msgSend)(device,sel_registerName("majorClass"));
        unsigned minor=((unsigned(*)(id,SEL))objc_msgSend)(device,sel_registerName("minorClass"));
        owner->_devices[address]=@{@"addressBase64":[address base64EncodedStringWithOptions:0],@"name":name,
            @"deviceClass":@((major&0x1f00)|(minor&0xfc))};
    }];
    fprintf(stderr,"[SharedBluetoothClassic] private discovery endpoint ready\n");return YES;
}
- (void)finish:(int)status {
    if(_client<0||_finishing)return;_finishing=YES;
    if(_scanning) {
        ((void(*)(id,SEL,BOOL))objc_msgSend)(_manager,sel_registerName("setDeviceScanningEnabled:"),NO);_scanning=NO;
    }
    NSDictionary *reply=@{@"schema":@1,@"status":@(status),@"source":@"iPad-native-classic-discovery",
        @"devices":status?@[]:_devices.allValues,@"pairingImplemented":@NO};
    NSData *data=[NSJSONSerialization dataWithJSONObject:reply options:0 error:NULL];
    if(!data||data.length>65536){[self closeClient];return;}
    uint32_t length=htonl((uint32_t)data.length);[_output appendBytes:&length length:4];[_output appendData:data];
    fprintf(stderr,"[SharedBluetoothClassic] own discovery complete count=%lu status=%d\n",(unsigned long)_devices.count,status);
    [self flush];
}
- (void)flush {
    while(_client>=0&&_output.length) {
        ssize_t count=send(_client,_output.bytes,_output.length,MSG_DONTWAIT);
        if(count<0&&errno==EINTR)continue;
        if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(count<=0){[self closeClient];return;}
        [_output replaceBytesInRange:NSMakeRange(0,(NSUInteger)count)withBytes:NULL length:0];
    }
    if(!_output.length){[self closeClient];return;}
    if(!_write) {
        uint64_t generation=_generation;__weak typeof(self) weak=self;
        _write=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,(uintptr_t)_client,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(_write,^{typeof(self) owner=weak;if(owner&&owner->_generation==generation)[owner flush];});
        dispatch_resume(_write);
    }
}
- (void)closeClient {
    ++_generation;
    if(_scanning){((void(*)(id,SEL,BOOL))objc_msgSend)(_manager,sel_registerName("setDeviceScanningEnabled:"),NO);_scanning=NO;}
    if(_read){dispatch_source_cancel(_read);_read=nil;}if(_write){dispatch_source_cancel(_write);_write=nil;}
    int fd=_client;_client=-1;if(fd>=0)close(fd);_input=nil;_output=nil;_devices=nil;
}
- (void)invalidate {
    if(_invalidated)return;_invalidated=YES;[self closeClient];
    if(_accept){dispatch_source_cancel(_accept);_accept=nil;}
    if(_listener>=0){close(_listener);_listener=-1;}
    struct stat info;if(_inode&&!lstat(Path,&info)&&S_ISSOCK(info.st_mode)&&info.st_uid==geteuid()&&info.st_ino==_inode)unlink(Path);
    if(_observer){[NSNotificationCenter.defaultCenter removeObserver:_observer];_observer=nil;}_manager=nil;
}
- (void)dealloc {[self invalidate];}
@end
