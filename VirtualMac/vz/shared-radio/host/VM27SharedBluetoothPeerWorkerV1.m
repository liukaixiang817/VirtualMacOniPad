#import "VM27SharedBluetoothPeerWorkerV1.h"
#include "../common/vm27_shared_radio_paths_v1.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

@interface VM27SharedBluetoothPeerWorkerV1 () {
    int _listener,_client;
    ino_t _inode;
    uint64_t _generation;
    BOOL _closed,_connected;
    dispatch_source_t _accept,_read,_write;
    NSMutableData *_input,*_output;
    void (^_fdClosed)(void);
}
- (void)closeClient;
- (void)readClient;
- (void)flush;
@end
static BOOL options(int fd) {
    int one=1,flags=fcntl(fd,F_GETFL);
    return flags>=0&&!fcntl(fd,F_SETFL,flags|O_NONBLOCK)&&!fcntl(fd,F_SETFD,FD_CLOEXEC)&&
        !setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
}
@implementation VM27SharedBluetoothPeerWorkerV1
- (instancetype)init {if((self=[super init]))_listener=_client=-1;return self;}
- (BOOL)connected {return _connected;}
- (BOOL)start {
    NSAssert(NSThread.isMainThread,@"worker owner queue");
    if(_closed)return NO;if(_listener>=0)return YES;
    if(!VM27SharedRadioPrepareHostDirectoryV1())return NO;
    struct stat old;
    if(!lstat(VM27_SHARED_RADIO_PEER_SOCKET_V1,&old)) {
        if(!S_ISSOCK(old.st_mode)||old.st_uid!=geteuid()||old.st_nlink!=1||(old.st_mode&0777)!=0600||unlink(VM27_SHARED_RADIO_PEER_SOCKET_V1))return NO;
    } else if(errno!=ENOENT)return NO;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return NO;
    struct sockaddr_un address={0};address.sun_len=sizeof(address);address.sun_family=AF_UNIX;
    strlcpy(address.sun_path,VM27_SHARED_RADIO_PEER_SOCKET_V1,sizeof(address.sun_path));
    if(!options(fd)||bind(fd,(void *)&address,sizeof(address))||chmod(VM27_SHARED_RADIO_PEER_SOCKET_V1,0600)||listen(fd,1)||lstat(VM27_SHARED_RADIO_PEER_SOCKET_V1,&old)){close(fd);return NO;}
    _listener=fd;_inode=old.st_ino;__weak typeof(self) weak=self;
    _accept=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,dispatch_get_main_queue());
    dispatch_source_set_event_handler(_accept,^{
        typeof(self) owner=weak;if(!owner||owner->_closed)return;
        int client=accept(owner->_listener,NULL,NULL);if(client<0)return;
        uid_t uid;gid_t gid;
        if(owner->_client>=0||getpeereid(client,&uid,&gid)||uid!=geteuid()||!options(client)){close(client);return;}
        [owner adoptOwnedFD:client closed:^{}];
    });dispatch_resume(_accept);return YES;
}
- (void)adoptOwnedFD:(int)fd closed:(void (^)(void))closed {
    NSAssert(NSThread.isMainThread,@"worker owner queue");
    if(_closed||_client>=0||fd<0||!options(fd)){if(fd>=0)close(fd);if(closed)closed();return;}
    _client=fd;_input=[NSMutableData data];_output=[NSMutableData data];_fdClosed=[closed copy];
    uint64_t generation=++_generation;__weak typeof(self) weak=self;
    _read=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)fd,0,dispatch_get_main_queue());
    dispatch_source_set_event_handler(_read,^{typeof(self) owner=weak;if(owner&&owner->_generation==generation)[owner readClient];});dispatch_resume(_read);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),dispatch_get_main_queue(),^{typeof(self) owner=weak;
        if(owner&&owner->_generation==generation&&!owner->_connected)[owner closeClient];});
}
- (void)closeClient {
    BOOL wasConnected=_connected;_connected=NO;++_generation;
    if(_read){dispatch_source_cancel(_read);_read=nil;}if(_write){dispatch_source_cancel(_write);_write=nil;}
    int fd=_client;_client=-1;if(fd>=0)close(fd);_input=_output=nil;
    if(wasConnected&&self.disconnectionHandler)self.disconnectionHandler();
    void (^closed)(void)=_fdClosed;_fdClosed=nil;if(closed)closed();
}
- (void)readClient {
    for(unsigned batch=0;batch<16;++batch) {
        uint8_t bytes[8192];ssize_t count=recv(_client,bytes,sizeof(bytes),MSG_DONTWAIT);
        if(count<0&&errno==EINTR)continue;if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(count<=0||_input.length+(NSUInteger)count>262144){[self closeClient];return;}
        [_input appendBytes:bytes length:(NSUInteger)count];
    }
    for(unsigned batch=0;batch<64&&_input.length>=4;++batch) {
        uint32_t size;memcpy(&size,_input.bytes,4);size=ntohl(size);
        if(!size||size>65536){[self closeClient];return;}if(_input.length<size+4)return;
        NSData *payload=[_input subdataWithRange:NSMakeRange(4,size)];
        [_input replaceBytesInRange:NSMakeRange(0,size+4)withBytes:NULL length:0];
        id message=[NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:NULL];
        if(![message isKindOfClass:NSDictionary.class]){[self closeClient];return;}
        if(!_connected) {
            if(![message[@"kind"]isEqual:@"hello"]||![message[@"schema"]isEqual:@1]){[self closeClient];return;}
            _connected=YES;[self sendMessage:@{@"kind":@"ready",@"schema":@1}];
            fprintf(stderr,"[SharedBluetooth] generic guest peer worker connected\n");
        } else if(self.messageHandler)self.messageHandler(message);
        if(_client<0)return;
    }
    if(_input.length>=4){uint64_t generation=_generation;__weak typeof(self) weak=self;dispatch_async(dispatch_get_main_queue(),^{
        typeof(self) owner=weak;if(owner&&owner->_generation==generation)[owner readClient];});}
}
- (BOOL)sendMessage:(NSDictionary *)message {
    if(!_connected||_client<0)return NO;
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:message format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if(!data.length||data.length>65536||_output.length+data.length+4>1048576){[self closeClient];return NO;}
    uint32_t size=htonl((uint32_t)data.length);[_output appendBytes:&size length:4];[_output appendData:data];[self flush];return _client>=0;
}
- (void)flush {
    while(_client>=0&&_output.length) {
        ssize_t count=send(_client,_output.bytes,_output.length,MSG_DONTWAIT);
        if(count<0&&errno==EINTR)continue;if(count<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(count<=0){[self closeClient];return;}
        [_output replaceBytesInRange:NSMakeRange(0,(NSUInteger)count)withBytes:NULL length:0];
    }
    if(!_output.length&&_write){dispatch_source_cancel(_write);_write=nil;}
    else if(_output.length&&!_write) {
        __weak typeof(self) weak=self;uint64_t generation=_generation;
        _write=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,(uintptr_t)_client,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(_write,^{typeof(self) owner=weak;if(owner&&owner->_generation==generation)[owner flush];});dispatch_resume(_write);
    }
}
- (void)invalidate {
    if(_closed)return;_closed=YES;[self closeClient];
    if(_accept){dispatch_source_cancel(_accept);_accept=nil;}int fd=_listener;_listener=-1;if(fd>=0)close(fd);
    struct stat info;if(_inode&&!lstat(VM27_SHARED_RADIO_PEER_SOCKET_V1,&info)&&info.st_ino==_inode&&S_ISSOCK(info.st_mode)&&info.st_uid==geteuid())unlink(VM27_SHARED_RADIO_PEER_SOCKET_V1);
    self.messageHandler=nil;self.disconnectionHandler=nil;
}
- (void)dealloc {[self invalidate];}
@end
