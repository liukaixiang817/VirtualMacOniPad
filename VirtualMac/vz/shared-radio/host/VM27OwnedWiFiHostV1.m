#import "VM27OwnedWiFiHostV1.h"
#include "../independent/VM27OwnedWiFiAdmissionV1.h"
#include <sys/stat.h>
#define VM27_SHARED_RADIO_CLIENT_LIBRARY 1
#define VM27_SHARED_RADIO_CLIENT_NO_VSOCK 1
#include "../guest/VM27SharedRadioGuestLinkV1.m"

static const char *OwnedWiFiSocket="/var/run/VirtualMacRadioOwned-v1/independent-wifi.sock";
static NSDictionary *OwnedWiFiFailure(int code){return @{@"ok":@NO,@"error":@{@"code":@(code),@"message":@"Independent Wi-Fi controller unavailable"}};}
@implementation VM27OwnedWiFiHostV1 {
 dispatch_queue_t _queue;
 NSLock *_lock;
 VM27GuestRadioClientV1 *_client;
 int _fd;
 BOOL _invalidated;
}
+ (BOOL)endpointPresent {struct stat info;return !lstat(OwnedWiFiSocket,&info)||errno!=ENOENT;}
- (instancetype)init {
 if((self=[super init])){_fd=-1;_lock=[NSLock new];_queue=dispatch_queue_create("com.virtualmac.owned-wifi.session",DISPATCH_QUEUE_SERIAL);}
 return self;
}
- (void)dropClient {
 [_lock lock];_fd=-1;[_lock unlock];_client=nil;
}
- (int)connectController {
 struct stat directory,endpoint;
 if(lstat("/var/run/VirtualMacRadioOwned-v1",&directory)||!S_ISDIR(directory.st_mode)||directory.st_uid||(directory.st_mode&0027)||
    lstat(OwnedWiFiSocket,&endpoint)||!S_ISSOCK(endpoint.st_mode)||endpoint.st_uid||(endpoint.st_mode&0007))return EPERM;
 int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return errno;
 [_lock lock];BOOL cancelled=_invalidated;if(!cancelled)_fd=fd;[_lock unlock];if(cancelled){close(fd);return ECANCELED;}
 int one=1,error=0,flags=fcntl(fd,F_GETFL);
 struct sockaddr_un address={.sun_len=sizeof(address),.sun_family=AF_UNIX};strlcpy(address.sun_path,OwnedWiFiSocket,sizeof(address.sun_path));
 if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)||setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)))error=errno;
 if(!error&&connect(fd,(void *)&address,sizeof(address))){
  if(errno!=EINPROGRESS)error=errno;
  else{struct pollfd p={fd,POLLOUT,0};socklen_t size=sizeof(error);if(poll(&p,1,3000)<=0)error=ETIMEDOUT;else if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size))error=errno;}
 }
 if(!error&&!VM27OwnedWiFiPeerAllowedV1(fd,0,"/var/jb/usr/local/libexec/virtualmac-owned-wifi-v1"))error=EPERM;
 [_lock lock];if(_invalidated)error=ECANCELED;[_lock unlock];
 if(error){[_lock lock];_fd=-1;[_lock unlock];close(fd);return error;}
 _client=[[VM27GuestRadioClientV1 alloc]initWithOwnedFD:fd];
 NSDictionary *hello=[_client call:@{@"protocol":@1}hello:YES error:&error];
 if(error||![hello[@"ok"]boolValue]){[self dropClient];return error?:EPROTO;}
 return 0;
}
- (void)request:(NSDictionary *)request completion:(void (^)(NSDictionary *))completion {
 dispatch_async(_queue,^{@autoreleasepool{
  [self->_lock lock];BOOL cancelled=self->_invalidated;[self->_lock unlock];
  int error=cancelled?ECANCELED:0;
  if(!error&&!self->_client)error=[self connectController];
  NSDictionary *reply=error?nil:[self->_client call:request hello:NO error:&error];
  if(error||!reply){[self dropClient];reply=OwnedWiFiFailure(error?:EPROTO);}
  dispatch_async(dispatch_get_main_queue(),^{completion(reply);});
 }});
}
- (void)invalidate {
 [_lock lock];_invalidated=YES;if(_fd>=0)shutdown(_fd,SHUT_RDWR);[_lock unlock];
 dispatch_async(_queue,^{[self dropClient];});
}
@end
