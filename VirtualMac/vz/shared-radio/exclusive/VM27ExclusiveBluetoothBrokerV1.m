// Root-owned lease broker. Exactly one authorized app session may own Bluetooth.
// The supervising parent restores the native service after any worker exit.
#import <Foundation/Foundation.h>
#include "VM27ExclusiveBluetoothSkywalkV1.h"
#include "VM27ExclusiveBluetoothControllerInitV1.h"
#ifndef VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
#define VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1 0
#endif
#if VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
#include "VM27ExclusiveBluetoothHostReadyV1.h"
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#define PROC_PIDPATHINFO_MAXSIZE 4096
extern int proc_pidpath(int,void *,uint32_t);
#include <spawn.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <CommonCrypto/CommonDigest.h>
extern char **environ;
static const char *Directory="/var/run/VirtualMacRadioOwned-v1";
static const char *Socket="/var/run/VirtualMacRadioOwned-v1/exclusive-bluetooth.sock";
static volatile sig_atomic_t Stop;
static void stopSignal(int signal){(void)signal;Stop=1;}
static int ctl(const char *operation,const char *target,const char *path){
 const char *args[]={"/var/jb/bin/launchctl",operation,target,path,NULL};pid_t pid;int status=0;
 int e=posix_spawn(&pid,args[0],NULL,NULL,(char *const *)args,environ);if(e)return e;
 while(waitpid(pid,&status,0)<0)if(errno!=EINTR)return errno;
 return WIFEXITED(status)?WEXITSTATUS(status):EIO;
}
static void restore(void){
 // Native plist retains the original UserName/Mach services. No persistent
 // launchd override, preference, pairing database or system image is changed.
 ctl("bootstrap","system","/System/Library/LaunchDaemons/com.apple.bluetoothd.plist");
 ctl("kickstart","user/501/com.apple.bluetoothd",NULL);
 unlink("/var/run/VirtualMacRadioOwned-v1/lease");
 fprintf(stderr,"[ExclusiveBluetooth] native service restored\n");
}
static BOOL admitted(int fd){
 uid_t uid=UINT32_MAX;gid_t gid;pid_t pid=0;socklen_t size=sizeof(pid);char path[PROC_PIDPATHINFO_MAXSIZE],expected[PATH_MAX],actual[PATH_MAX];
 int identity=getpeereid(fd,&uid,&gid),peer=getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&size);
 BOOL pathRead=pid>1&&proc_pidpath(pid,path,sizeof(path))>0;
 BOOL match=pathRead&&realpath(path,actual)&&realpath("/var/jb/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27",expected)&&!strcmp(actual,expected);
 BOOL ok=!identity&&uid==501&&!peer&&match;
 fprintf(stderr,"[ExclusiveBluetooth] admission uid=%u peerPIDAvailable=%d pathRead=%d appPathMatch=%d accepted=%d\n",uid,!peer,pathRead,match,ok);
 return ok;
}

static BOOL exact(int fd,void *buffer,size_t size){
 size_t n=0;while(n<size&&!Stop){struct pollfd p={fd,POLLIN,0};if(poll(&p,1,3000)<=0)return NO;
 ssize_t r=read(fd,(uint8_t *)buffer+n,size-n);if(r<=0)return NO;n+=(size_t)r;}return n==size;
}
static void frame(NSMutableData *output,uint8_t type,const void *data,size_t size){
 uint32_t length=htonl((uint32_t)size+1);[output appendBytes:&length length:4];[output appendBytes:&type length:1];if(size)[output appendBytes:data length:size];
}
static BOOL valid(uint8_t type,const uint8_t *b,size_t n){
 if(type==1)return n>=3&&n==(size_t)3+b[2];
 if(type==2)return n>=4&&n==(size_t)4+(b[2]|(b[3]<<8));
 if(type==3)return n>=3&&n==(size_t)3+b[2];
 if(type==5)return n>=4&&n==(size_t)4+((b[2]|(b[3]<<8))&0x3fff);
 return NO;
}
static void pairingStage(const uint8_t *acl,size_t size,BOOL sent){
 if(size<9||((acl[1]>>4)&3)==1||(acl[6]|acl[7]<<8)!=6)return;
 unsigned opcode=acl[8];if(opcode<1||opcode>14)return;
 fprintf(stderr,"[ExclusiveBluetooth] SMP direction=%s opcode=%u",sent?"TX":"RX",opcode);
 if(opcode==5&&size>=10)fprintf(stderr," reason=%u",acl[9]);
 fprintf(stderr,"\n");
}
static void controllerIdentityReceipt(const uint8_t wireAddress[6]){
 uint8_t comparison[22],digest[CC_SHA256_DIGEST_LENGTH];arc4random_buf(comparison,16);
 for(unsigned i=0;i<6;++i)comparison[16+i]=wireAddress[5-i];
 CC_SHA256(comparison,sizeof(comparison),digest);
 NSMutableString *nonce=[NSMutableString string],*hash=[NSMutableString string];
 for(unsigned i=0;i<16;++i)[nonce appendFormat:@"%02x",comparison[i]];
 for(unsigned i=0;i<sizeof(digest);++i)[hash appendFormat:@"%02x",digest[i]];
 NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"schema":@1,@"nonce":nonce,@"publicAddressDigest":hash,@"addressLogged":@NO}options:0 error:NULL];
 const char *path="/var/root/VM27ExclusiveBluetooth-v1/controller-identity-v1.json";
 if(json&&[json writeToFile:@(path) options:NSDataWritingAtomic error:NULL])chmod(path,0600);
 // Private provisioning seed for the native guest BT_DEVICE_ADDRESS input.
 // This is an identity value, never a bond/link key. Do not print its bytes.
 const char *seed="/var/root/VM27ExclusiveBluetooth-v1/controller-identity-v1.bin";
 NSData *identity=[NSData dataWithBytes:comparison+16 length:6];
 if([identity writeToFile:@(seed) options:NSDataWritingAtomic error:NULL])chmod(seed,0600);
 memset(comparison,0,sizeof(comparison));
}
static int serve(int fd,BOOL fresh){@autoreleasepool{
 VM27BTRawChannel *channels[6]={0};const char *names[]={NULL,NULL,"acl","sco","hci","iso"};int result=0;
 NSMutableData *input=[NSMutableData data],*output=[NSMutableData data];
 uint8_t guestState[7]={0};if(fresh&&!exact(fd,guestState,sizeof(guestState)))return EPROTO;
 for(unsigned t=2;t<=5;++t){int error=0;channels[t]=VM27BTRawOpen(names[t],&error);
  if(!channels[t]){fprintf(stderr,"[ExclusiveBluetooth] open type=%u errno=%d\n",t,error);if(t!=5){result=error;goto done;}}}
 if(fresh){result=VM27BTPrepareController(channels[4],guestState);if(result){fprintf(stderr,"[ExclusiveBluetooth] controller preparation failed errno=%d\n",result);goto done;}
  uint8_t address[6];result=VM27BTPrepareCommandResult(channels[4],0x1009,NULL,0,address,sizeof(address));
  if(result)goto done;controllerIdentityReceipt(address);memset(address,0,sizeof(address));
 }
 fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
 frame(output,0x7d,NULL,0);
 double lastHeartbeat=NSProcessInfo.processInfo.systemUptime;unsigned long long commands=0,events=0,acl=0;
 while(!Stop){
  if(NSProcessInfo.processInfo.systemUptime-lastHeartbeat>10){result=ETIMEDOUT;break;}
  struct pollfd p[5]={{fd,POLLIN|(output.length?POLLOUT:0),0}};
  for(unsigned t=2;t<=5;++t)p[t-1]=(struct pollfd){VM27BTRawFD(channels[t]),POLLIN,0};
  int ready=poll(p,5,200);if(ready<0){if(errno==EINTR)continue;result=errno;break;}
  if(p[0].revents&(POLLERR|POLLHUP|POLLNVAL)){result=ECONNRESET;break;}
  if(p[0].revents&POLLOUT){ssize_t n=write(fd,output.bytes,output.length);if(n>0)[output replaceBytesInRange:NSMakeRange(0,n)withBytes:NULL length:0];else if(n<0&&errno!=EAGAIN&&errno!=EINTR){result=errno;break;}}
  if(p[0].revents&POLLIN){uint8_t chunk[8192];ssize_t n=read(fd,chunk,sizeof(chunk));if(n<=0){result=ECONNRESET;break;}[input appendBytes:chunk length:n];}
  if(input.length>131072||output.length>1048576){result=ENOBUFS;break;}
  while(input.length>=5){const uint8_t *b=input.bytes;uint32_t n;memcpy(&n,b,4);n=ntohl(n);
   if(!n||n>65536){result=EPROTO;goto done;}if(input.length<n+4)break;
   uint8_t type=b[4];
   if(type==0x7e&&n==1){lastHeartbeat=NSProcessInfo.processInfo.systemUptime;frame(output,0x7f,NULL,0);}
   else{
    if(!valid(type,b+5,n-1)){result=EPROTO;goto done;}
    if(type==1){const uint8_t *command=b+5;unsigned opcode=command[0]|command[1]<<8;
     if(opcode==0x2043&&n>=15)fprintf(stderr,"[ExclusiveBluetooth] LE create ownAddressType=%u peerAddressType=%u\n",command[4],command[5]);
    }else if(type==2)pairingStage(b+5,n-1,YES);
    unsigned channel=type==1?4:type;
    if(!channels[channel]){result=ENOTSUP;goto done;}
    if(VM27BTRawWrite(channels[channel],b+5,n-1)){if(errno==EAGAIN)break;result=errno;goto done;}
    if(type==1){++commands;if(commands<=64||((b[5]|(b[6]<<8))!=0x2041&&(b[5]|(b[6]<<8))!=0x2042))fprintf(stderr,"[ExclusiveBluetooth] HCI command opcode=%04x bytes=%u\n",b[5]|(b[6]<<8),n-1);}else if(type==2){++acl;if(acl<=64)fprintf(stderr,"[ExclusiveBluetooth] ACL TX bytes=%u\n",n-1);}
   }[input replaceBytesInRange:NSMakeRange(0,n+4)withBytes:NULL length:0];
  }
  for(unsigned t=2;t<=5;++t)if(channels[t]&&(p[t-1].revents&POLLIN)){
   uint8_t packet[65536];int n;while((n=VM27BTRawRead(channels[t],packet,sizeof(packet)))>0){frame(output,t,packet,(size_t)n);if(t==4&&n>=6&&packet[0]==0x0e&&(packet[5]!=0||(packet[3]|(packet[4]<<8))==0x0c03))fprintf(stderr,"[ExclusiveBluetooth] command result opcode=%04x status=%u\n",packet[3]|(packet[4]<<8),packet[5]);
    if(t==4&&n>=4&&packet[0]==0x3e&&(packet[2]==1||packet[2]==10))fprintf(stderr,"[ExclusiveBluetooth] LE connection status=%u\n",packet[3]);
    if(t==4&&n>=6&&packet[0]==8)fprintf(stderr,"[ExclusiveBluetooth] encryption status=%u enabled=%u\n",packet[2],packet[5]);
    if(t==2){pairingStage(packet,n,NO);if(events<10000)fprintf(stderr,"[ExclusiveBluetooth] ACL RX bytes=%d\n",n);}
    if(t==4){++events;if(events<=64)fprintf(stderr,"[ExclusiveBluetooth] HCI event code=%02x bytes=%d\n",packet[0],n);}if(output.length>1048576){result=ENOBUFS;goto done;}}
   if(n<0){result=errno;goto done;}
  }
 }
 fprintf(stderr,"[ExclusiveBluetooth] lease finished errno=%d commands=%llu events=%llu ACL=%llu\n",result,commands,events,acl);
 done:for(unsigned t=2;t<=5;++t)VM27BTRawClose(channels[t]);return result;
}}
int main(int argc,char **argv){@autoreleasepool{
 if(geteuid()!=0)return EPERM;
 char build[32]={0};size_t buildSize=sizeof(build);if(sysctlbyname("kern.osversion",build,&buildSize,NULL,0)||strcmp(build,"20B101"))return EPROTONOSUPPORT;
 if((argc==3||argc==4)&&!strcmp(argv[1],"--worker-fd")){int fd=atoi(argv[2]);BOOL fresh=argc==4&&!strcmp(argv[3],"--fresh-controller");return fd>=3&&(argc==3||fresh)?serve(fd,fresh):EINVAL;}
 if(argc!=1)return EINVAL;signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
 struct stat st;if(lstat(Directory,&st)&&errno==ENOENT){if(mkdir(Directory,0750)||chown(Directory,0,501))return errno;}
 if(lstat(Directory,&st)||!S_ISDIR(st.st_mode)||st.st_uid||st.st_mode&0022)return EPERM;
 if(!access("/var/run/VirtualMacRadioOwned-v1/lease",F_OK))restore();
 int server=socket(AF_UNIX,SOCK_STREAM,0);if(server<0)return errno;fcntl(server,F_SETFD,FD_CLOEXEC);
 if(!lstat(Socket,&st)){if(!S_ISSOCK(st.st_mode)||st.st_uid)return EPERM;unlink(Socket);}
 struct sockaddr_un address={0};address.sun_len=sizeof(address);address.sun_family=AF_UNIX;strlcpy(address.sun_path,Socket,sizeof(address.sun_path));
 mode_t old=umask(0077);int bound=bind(server,(void *)&address,sizeof(address));umask(old);
 if(bound||chown(Socket,0,501)||chmod(Socket,0660)||listen(server,1))return errno;
 while(!Stop){struct pollfd p={server,POLLIN,0};if(poll(&p,1,500)<=0)continue;int fd=accept(server,NULL,NULL);if(fd<0)continue;
  char greeting[11];if(!admitted(fd)){close(fd);continue;}
#if VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
  int ready=VM27ExclusiveHostReadyTransferV1(fd,1);
  if(ready){fprintf(stderr,"[ExclusiveBluetooth] host ready handshake errno=%d\n",ready);close(fd);continue;}
  fprintf(stderr,"[ExclusiveBluetooth] host stream readiness sent\n");
#endif
  if(!exact(fd,greeting,sizeof(greeting))||(memcmp(greeting,"VM27BTRAW1\n",11)&&memcmp(greeting,"VM27BTRAW2\n",11))){fprintf(stderr,"[ExclusiveBluetooth] invalid or incomplete greeting\n");close(fd);continue;}
  BOOL fresh=!memcmp(greeting,"VM27BTRAW2\n",11);
  int lease=open("/var/run/VirtualMacRadioOwned-v1/lease",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(lease<0){close(fd);continue;}close(lease);
  if(ctl("bootout","user/501/com.apple.bluetoothd",NULL)){restore();close(fd);continue;}
  pid_t child=-1;char descriptor[24];snprintf(descriptor,sizeof(descriptor),"%d",fd);
  char *args[]={argv[0],"--worker-fd",descriptor,fresh?"--fresh-controller":NULL,NULL};
  int spawned=posix_spawn(&child,argv[0],NULL,NULL,args,environ);if(spawned)child=-1;
  close(fd);
  if(child>0){int status;while(waitpid(child,&status,0)<0&&errno==EINTR)if(Stop)kill(child,SIGTERM);}
  restore();
 }
 close(server);unlink(Socket);return 0;
}}
