#pragma once
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
// Byte relay only. The root broker and guest independently validate framing.
// Cancellation and either EOF tear down ownership. No LAN endpoint is opened.
static int VM27ExclusiveBluetoothRelayV1(int guest,int cancellation) {
 int root=socket(AF_UNIX,SOCK_STREAM,0);if(root<0)return errno;
 struct sockaddr_un a={0};a.sun_len=sizeof(a);a.sun_family=AF_UNIX;
 strlcpy(a.sun_path,"/var/run/VirtualMacRadioOwned-v1/exclusive-bluetooth.sock",sizeof(a.sun_path));
 if(connect(root,(void *)&a,sizeof(a))){int e=errno;close(root);return e;}
 int fds[]={guest,root};for(unsigned i=0;i<2;++i){int one=1;fcntl(fds[i],F_SETFL,fcntl(fds[i],F_GETFL)|O_NONBLOCK);fcntl(fds[i],F_SETFD,FD_CLOEXEC);setsockopt(fds[i],SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));}
 uint8_t buffers[2][65536];size_t used[2]={0,0};int result=0;
 for(;;){struct pollfd p[3]={{guest,(used[0]<sizeof(buffers[0])?POLLIN:0)|(used[1]?POLLOUT:0),0},{root,(used[1]<sizeof(buffers[1])?POLLIN:0)|(used[0]?POLLOUT:0),0},{cancellation,POLLIN,0}};
  int n=poll(p,3,500);if(n<0){if(errno==EINTR)continue;result=errno;break;}
  if(p[2].revents){result=ECANCELED;break;}
  BOOL done=NO;
  for(unsigned i=0;i<2;++i){unsigned other=1-i;
   if(p[i].revents&(POLLERR|POLLHUP|POLLNVAL)){done=YES;break;}
   if(p[i].revents&POLLIN){ssize_t count=read(fds[i],buffers[i]+used[i],sizeof(buffers[i])-used[i]);if(count>0)used[i]+=count;else if(count==0||(errno!=EAGAIN&&errno!=EINTR)){done=YES;break;}}
   if(p[i].revents&POLLOUT){ssize_t count=write(fds[i],buffers[other],used[other]);if(count>0){used[other]-=count;memmove(buffers[other],buffers[other]+count,used[other]);}else if(count<0&&errno!=EAGAIN&&errno!=EINTR){done=YES;break;}}
  }if(done)break;
 }
 close(root);return result;
}
