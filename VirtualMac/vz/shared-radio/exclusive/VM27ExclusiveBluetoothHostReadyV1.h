#pragma once
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <time.h>

// A framed no-op already understood by all native guest modules. The legacy
// macOS 15 relay consumes it before opening the native stream, so its initial
// greeting cannot race the host's VSOCK descriptor handoff and broker admission.
// Older relays simply forward it; native incoming(0x7f, NULL, 0) ignores it.
static const uint8_t VM27ExclusiveHostReadyBytesV1[5]={0,0,0,1,0x7f};
static inline int VM27ExclusiveHostReadyTransferV1(int fd,int writing){
 uint8_t bytes[5]={0};size_t used=0;
 if(writing)memcpy(bytes,VM27ExclusiveHostReadyBytesV1,sizeof(bytes));
 struct timespec start,now;
 if(clock_gettime(CLOCK_MONOTONIC,&start))return errno;
 while(used<sizeof(bytes)){
  if(clock_gettime(CLOCK_MONOTONIC,&now))return errno;
  int64_t elapsed=(int64_t)(now.tv_sec-start.tv_sec)*1000+(now.tv_nsec-start.tv_nsec)/1000000;
  if(elapsed>=3000)return ETIMEDOUT;
  struct pollfd ready={fd,writing?POLLOUT:POLLIN,0};
  int result=poll(&ready,1,(int)(3000-elapsed));
  if(result<0){if(errno==EINTR)continue;return errno;}
  if(!result)return ETIMEDOUT;
  if(ready.revents&POLLNVAL)return EBADF;
  ssize_t count=writing?write(fd,bytes+used,sizeof(bytes)-used):read(fd,bytes+used,sizeof(bytes)-used);
  if(count>0)used+=(size_t)count;
  else if(!count)return ECONNRESET;
  else if(errno!=EINTR&&errno!=EAGAIN)return errno;
 }
 return writing||!memcmp(bytes,VM27ExclusiveHostReadyBytesV1,sizeof(bytes))?0:EPROTO;
}
