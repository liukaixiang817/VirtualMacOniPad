// Bounded local-only framing for the one-shot GUI agent. No credential file,
// command argument, environment variable or standard-output stream is used.
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { VM27OwnerUIReadyV2=1, VM27OwnerPasswordV2=2, VM27OwnerCancelledV2=3 };
typedef struct { uint8_t kind; uint16_t length; uint8_t bytes[255]; } VM27OwnerMessageV2;

static inline double VM27OwnerMonotonicV2(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (double)t.tv_sec+(double)t.tv_nsec/1e9;
}
static inline int VM27OwnerTransferV2(int fd,void *bytes,size_t count,BOOL sending,double deadline) {
    size_t offset=0;
    while(offset<count) {
        double remaining=deadline-VM27OwnerMonotonicV2();
        if(remaining<=0)return ETIMEDOUT;
        struct pollfd p={fd,sending?POLLOUT:POLLIN,0};
        int rc=poll(&p,1,(int)(remaining*1000)+1);
        if(rc<0&&errno==EINTR)continue;
        if(rc<0)return errno;
        if(!rc)return ETIMEDOUT;
        ssize_t n=sending?send(fd,(uint8_t *)bytes+offset,count-offset,0):
                          recv(fd,(uint8_t *)bytes+offset,count-offset,0);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(n<0)return errno;
        if(!n)return EPIPE;
        offset+=(size_t)n;
    }
    return 0;
}
static inline BOOL VM27OwnerShapeV2(uint8_t kind,uint16_t length) {
    return (kind==VM27OwnerPasswordV2 && length>0 && length<=255) ||
        ((kind==VM27OwnerUIReadyV2 || kind==VM27OwnerCancelledV2) && !length);
}
static inline BOOL VM27OwnerSecretValidV2(const uint8_t *bytes,size_t size) {
    return size>0 && size<=255 && !memchr(bytes,0,size) &&
        !memchr(bytes,'\n',size) && !memchr(bytes,'\r',size);
}
static inline int VM27OwnerSendV2(int fd,uint8_t kind,const void *bytes,uint16_t length) {
    if(!VM27OwnerShapeV2(kind,length) ||
       (kind==VM27OwnerPasswordV2 && (!bytes||!VM27OwnerSecretValidV2(bytes,length))))return EINVAL;
    uint8_t header[8]={'V','R','2',0,kind,0,(uint8_t)(length>>8),(uint8_t)length};
    double now=VM27OwnerMonotonicV2();if(now<0)return EIO;
    int rc=VM27OwnerTransferV2(fd,header,sizeof(header),YES,now+5);
    if(!rc&&length)rc=VM27OwnerTransferV2(fd,(void *)bytes,length,YES,now+5);
    return rc;
}
static inline int VM27OwnerReceiveV2(int fd,VM27OwnerMessageV2 *message,double timeout) {
    if(!message || timeout<=0 || timeout>310)return EINVAL;
    memset(message,0,sizeof(*message));
    double now=VM27OwnerMonotonicV2();if(now<0)return EIO;
    uint8_t header[8]={0};int rc=VM27OwnerTransferV2(fd,header,sizeof(header),NO,now+timeout);
    if(rc)return rc;
    uint16_t length=((uint16_t)header[6]<<8)|header[7];
    if(memcmp(header,"VR2\0",4)||header[5]||!VM27OwnerShapeV2(header[4],length))return EPROTO;
    message->kind=header[4];message->length=length;
    if(length)rc=VM27OwnerTransferV2(fd,message->bytes,length,NO,now+timeout);
    if(!rc&&message->kind==VM27OwnerPasswordV2 && !VM27OwnerSecretValidV2(message->bytes,length))rc=EPROTO;
    return rc;
}
