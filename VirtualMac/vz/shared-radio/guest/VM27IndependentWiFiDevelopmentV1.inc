// Optional bounded development transport. Absence keeps the installed shared
// route; an invalid/present configuration fails closed, never uses host NAT.
#include <sys/stat.h>
#include <arpa/inet.h>
static VM27GuestRadioClientV1 *IndependentWiFiClient;
static int initializeIndependentWiFi(void){
 const char *path="/private/var/root/VirtualMacWiFiDevelopment-v1/broker.json";struct stat info;
 if(lstat(path,&info))return errno==ENOENT?0:errno;
 if(!S_ISREG(info.st_mode)||info.st_uid||info.st_nlink!=1||(info.st_mode&0777)!=0600||info.st_size<2||info.st_size>4096)return EPERM;
 NSDictionary *configuration=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(path)]options:0 error:NULL];
 NSString *token=[configuration isKindOfClass:NSDictionary.class]?configuration[@"tokenBase64"]:nil;
 if(![configuration[@"transport"]isEqual:@"ssh-loopback-development"]||![token isKindOfClass:NSString.class]||[[[NSData alloc]initWithBase64EncodedString:token options:0]length]!=32)return EINVAL;
 int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return errno;
 struct sockaddr_in address={.sin_len=sizeof(address),.sin_family=AF_INET,.sin_port=htons(39034)};inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
 int flags=fcntl(fd,F_GETFL),one=1;if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)||setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))){int error=errno;close(fd);return error;}
 if(connect(fd,(void *)&address,sizeof(address))&&errno!=EINPROGRESS){int error=errno;close(fd);return error;}
 struct pollfd item={fd,POLLOUT,0};int ready=poll(&item,1,5000),error=0;socklen_t size=sizeof(error);
 if(ready<=0||getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error){close(fd);return error?:ETIMEDOUT;}
 VM27GuestRadioClientV1 *client=[[VM27GuestRadioClientV1 alloc]initWithOwnedFD:fd];NSDictionary *hello=[client call:@{@"protocol":@1,@"tokenBase64":token}hello:YES error:&error];
 if(error||![hello[@"ok"]boolValue])return error?:EPERM;
 IndependentWiFiClient=client;fputs("Independent auxiliary Wi-Fi development transport authenticated\n",stderr);return 0;
}
static NSDictionary *wifiCall(VM27GuestRadioClientV1 *shared,NSDictionary *request,int *error){
 return [(IndependentWiFiClient?:shared) call:request hello:NO error:error];
}
