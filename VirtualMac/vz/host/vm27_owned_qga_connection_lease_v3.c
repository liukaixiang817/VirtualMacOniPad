#include "vm27_owned_qga_connection_lease_v3.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(VM27_QGA_LEASE_FIXTURE_V3) && defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error "QGA clock/send fixture cannot enter an iOS product"
#endif
#ifdef VM27_QGA_LEASE_FIXTURE_V3
extern bool VM27QGAFixtureTimeV3(uint64_t *);
#endif
static bool now_ns(uint64_t *out) {
#ifdef VM27_QGA_LEASE_FIXTURE_V3
    return VM27QGAFixtureTimeV3(out);
#else
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t) || t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000 ||
       (uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/1000000000)return false;
    *out=(uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;return true;
#endif
}
static bool same_socket(int fd,const VM27OwnedQGALeaseV3 *o) {
    struct stat st;return fd>=0 && fstat(fd,&st)==0 && S_ISSOCK(st.st_mode) && st.st_dev==o->device && st.st_ino==o->inode;
}
VM27QGAResultV3 VM27OwnedQGALeaseCreateV3(VM27OwnedQGALeaseV3 *o,int fd,uint64_t epoch,uint64_t generation) {
    if(!o)return VM27QGAInvalidV3;
    memset(o,0,sizeof(*o));o->ownedFD=-1;o->originalFD=-1;
    if(fd<0 || !epoch)return VM27QGAInvalidV3;
    struct stat before,after;uint64_t now;
    if(fstat(fd,&before) || !S_ISSOCK(before.st_mode) || !now_ns(&now) || now>UINT64_MAX-UINT64_C(45000000000))return VM27QGANativeFailureV3;
    int held=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if(held<0)return VM27QGANativeFailureV3;
    if(fstat(held,&after) || !S_ISSOCK(after.st_mode) || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino) {
        close(held);return VM27QGANativeFailureV3;
    }
#ifdef SO_NOSIGPIPE
    int enabled=1;if(setsockopt(held,SOL_SOCKET,SO_NOSIGPIPE,&enabled,sizeof(enabled))) {close(held);return VM27QGANativeFailureV3;}
#endif
    int status=fcntl(fd,F_GETFL);
    if(status<0 || (!(status&O_NONBLOCK) && fcntl(fd,F_SETFL,status|O_NONBLOCK))) {close(held);return VM27QGANativeFailureV3;}
    o->originalStatusFlags=status;o->statusChanged=!(status&O_NONBLOCK);
    o->ownedFD=held;o->originalFD=fd;o->pid=getpid();o->device=after.st_dev;o->inode=after.st_ino;
    o->epoch=epoch;o->generation=generation;o->deadlineNS=now+UINT64_C(45000000000);o->active=true;
    return VM27OwnedQGALeaseCheckV3(o,fd,epoch,generation);
}
VM27QGAResultV3 VM27OwnedQGALeaseCheckV3(const VM27OwnedQGALeaseV3 *o,int fd,uint64_t epoch,uint64_t generation) {
    if(!o || !o->active)return VM27QGACancelledV3;
    if(o->pid!=getpid() || fd!=o->originalFD || epoch!=o->epoch || generation!=o->generation ||
       !same_socket(fd,o) || !same_socket(o->ownedFD,o))return VM27QGAStaleV3;
    uint64_t now;if(!now_ns(&now))return VM27QGANativeFailureV3;
    return now>=o->deadlineNS?VM27QGAExpiredV3:VM27QGAValidV3;
}
VM27QGAResultV3 VM27OwnedQGALeaseSendV3(VM27OwnedQGALeaseV3 *o,int fd,uint64_t epoch,uint64_t generation,const void *bytes,size_t length) {
    if(!bytes || !length || length>2097152)return VM27QGAInvalidV3;
    const unsigned char *p=bytes;size_t used=0;
    while(used<length) {
        VM27QGAResultV3 r=VM27OwnedQGALeaseCheckV3(o,fd,epoch,generation);if(r!=VM27QGAValidV3)return r;
        int flags=MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
        flags|=MSG_NOSIGNAL;
#endif
        ssize_t n=send(o->ownedFD,p+used,length-used,flags);
        if(n>0) {used+=(size_t)n;continue;}
        if(n<0 && errno==EINTR)continue;
        /* A partial request cannot safely be retried as a new JSON message. */
        return VM27QGANativeFailureV3;
    }
    return VM27OwnedQGALeaseCheckV3(o,fd,epoch,generation);
}
VM27QGAResultV3 VM27OwnedQGALeaseCloseV3(VM27OwnedQGALeaseV3 *o,bool stop) {
    if(!o || !o->active)return VM27QGACancelledV3;
    o->active=false;
    if(!same_socket(o->ownedFD,o))return VM27QGAStaleV3; /* Never close a reused unrelated FD. */
    VM27QGAResultV3 result=VM27QGAValidV3;
    /* Darwin may block a stream send even with MSG_DONTWAIT. Use actual
     * O_NONBLOCK during this serialized lease; restore only this same socket. */
    if(!stop && o->statusChanged) {
        int current=fcntl(o->originalFD,F_GETFL);
        if(!same_socket(o->originalFD,o) || current!=(o->originalStatusFlags|O_NONBLOCK) ||
           fcntl(o->originalFD,F_SETFL,o->originalStatusFlags))result=VM27QGANativeFailureV3;
    }
    if(stop && shutdown(o->ownedFD,SHUT_RDWR) && errno!=ENOTCONN)result=VM27QGANativeFailureV3;
    if(close(o->ownedFD))result=VM27QGANativeFailureV3;
    o->ownedFD=-1;return result;
}
