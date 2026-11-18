// Native guest VSOCK -> loopback relay. Never listens on a LAN interface.
#include <sys/socket.h>
#include <sys/vsock.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#ifndef VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
#define VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1 0
#endif
#if VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
#include "VM27ExclusiveBluetoothHostReadyV1.h"
#endif
static volatile sig_atomic_t stop;
static void finish(int s){(void)s;stop=1;}
static void relay(int vm,int native){
 int fds[]={vm,native};uint8_t b[2][65536];size_t used[2]={0,0};
 for(unsigned i=0;i<2;++i){int one=1;fcntl(fds[i],F_SETFL,O_NONBLOCK);fcntl(fds[i],F_SETFD,FD_CLOEXEC);setsockopt(fds[i],SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));}
 while(!stop){struct pollfd p[2];for(unsigned i=0;i<2;++i)p[i]=(struct pollfd){fds[i],(used[i]<sizeof(b[i])?POLLIN:0)|(used[1-i]?POLLOUT:0),0};
  int n=poll(p,2,500);if(n<0){if(errno==EINTR)continue;break;}
  for(unsigned i=0;i<2;++i){unsigned other=1-i;if(p[i].revents&(POLLERR|POLLHUP|POLLNVAL))return;
   if(p[i].revents&POLLIN){ssize_t r=read(fds[i],b[i]+used[i],sizeof(b[i])-used[i]);if(r>0)used[i]+=r;else if(r==0||(errno!=EAGAIN&&errno!=EINTR))return;}
   if(p[i].revents&POLLOUT){ssize_t r=write(fds[i],b[other],used[other]);if(r>0){used[other]-=r;memmove(b[other],b[other]+r,used[other]);}else if(r<0&&errno!=EAGAIN&&errno!=EINTR)return;}
  }
 }
}
int main(void){
 uint8_t token[32];int key=open("/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1/exclusive-transport-token-v1",O_RDONLY|O_NOFOLLOW);struct stat st;
 if(key<0||fstat(key,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_mode&0077||st.st_size!=32||read(key,token,32)!=32)return EPERM;close(key);
 signal(SIGTERM,finish);signal(SIGINT,finish);signal(SIGPIPE,SIG_IGN);
 int server=socket(AF_VSOCK,SOCK_STREAM,0);if(server<0)return errno;
 struct sockaddr_vm a={0};a.svm_len=sizeof(a);a.svm_family=AF_VSOCK;a.svm_cid=VMADDR_CID_ANY;a.svm_port=39031;
 if(bind(server,(void *)&a,sizeof(a))||listen(server,1))return errno;
 while(!stop){struct pollfd p={server,POLLIN,0};if(poll(&p,1,500)<=0)continue;
  socklen_t length=sizeof(a);int vm=accept(server,(void *)&a,&length);if(vm<0)continue;
  fprintf(stderr,"[ExclusiveBluetoothRelay] accepted family=%u CID=%u size=%u\n",a.svm_family,a.svm_cid,(unsigned)length);
  if(a.svm_cid!=VMADDR_CID_HOST){close(vm);continue;}
#if VM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1
  int ready=VM27ExclusiveHostReadyTransferV1(vm,0);
  if(ready){fprintf(stderr,"[ExclusiveBluetoothRelay] host ready handshake errno=%d\n",ready);close(vm);continue;}
  fprintf(stderr,"[ExclusiveBluetoothRelay] host stream readiness confirmed\n");
#endif
  int native=socket(AF_INET,SOCK_STREAM,0);if(native<0){close(vm);continue;}
  struct sockaddr_in local={0};local.sin_len=sizeof(local);local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);local.sin_port=htons(39032);
  int connection=connect(native,(void *)&local,sizeof(local));if(connection)fprintf(stderr,"[ExclusiveBluetoothRelay] loopback connect errno=%d\n",errno);
  if(!connection&&write(native,token,sizeof(token))==sizeof(token)){fprintf(stderr,"[ExclusiveBluetoothRelay] native stream attached\n");relay(vm,native);fprintf(stderr,"[ExclusiveBluetoothRelay] native stream detached\n");}
  close(native);close(vm);
 }
 close(server);return 0;
}
