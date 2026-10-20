#include "vm27_guest_vsock_ssh_helper_v1.h"
#include "vm27_owned_stream_relay_v1.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vsock.h>
#include <time.h>
#include <unistd.h>
#ifdef VM27_GUEST_SSH_PEER_TEST
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#error Peer transport injection must never be compiled for iOS products
#endif
extern int VM27GuestSSHPeerConnectV1(int vsock, int cancel_fd);
#endif

static uint64_t be64_v1(const uint8_t *p) {
    uint64_t n=0; for (unsigned i=0;i<8;i++) n=(n<<8)|p[i]; return n;
}
static int time_v1(uint64_t *out) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return errno;
    *out=(uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;return 0;
}
static int nonblocking_v1(int fd) {
    int f=fcntl(fd,F_GETFL);if(f<0)return errno;
    if(fcntl(fd,F_SETFL,f|O_NONBLOCK))return errno;
    return 0;
}
static int owned_stream_v1(int fd) {
    int t=0;socklen_t n=sizeof(t);
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&t,&n))return errno;
    if(n!=sizeof(t)||t!=SOCK_STREAM)return EINVAL;
    int e=nonblocking_v1(fd);if(e)return e;
    int one=1;if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)))return errno;
    return 0;
}
static int cancelled_v1(int fd) {
    /* Keep the borrowed cancellation byte unread so setup/error writes cannot
     * lose cancellation before the outer owner observes the same boundary. */
    struct pollfd p={fd,POLLIN,0};
    int n=poll(&p,1,0);if(n<0)return errno;
    if(p.revents&POLLNVAL)return EBADF;
    if(p.revents&(POLLIN|POLLHUP))return ECANCELED;
    return p.revents&POLLERR?EIO:0;
}
static int wait_v1(int fd,short events,int cancel_fd,uint64_t deadline) {
    for(;;){
        uint64_t now;int e=time_v1(&now);if(e)return e;
        if(now>=deadline)return ETIMEDOUT;
        uint64_t remain=deadline-now;int ms=remain>INT_MAX?INT_MAX:(int)remain;
        struct pollfd p[2]={{fd,events,0},{cancel_fd,POLLIN,0}};
        int n=poll(p,2,ms);if(n<0){if(errno==EINTR)continue;return errno;}
        if(p[1].revents&POLLNVAL)return EBADF;
        if(p[1].revents&(POLLIN|POLLHUP|POLLERR)){e=cancelled_v1(cancel_fd);if(e)return e;}
        if(p[0].revents&POLLNVAL)return EBADF;
        if(p[0].revents&(events|POLLERR|POLLHUP))return 0;
    }
}
static int connect_v1(int vsock,int cancel_fd) {
    int cancellation=cancelled_v1(cancel_fd);
    if(cancellation){errno=cancellation;return -1;}
#ifdef VM27_GUEST_SSH_PEER_TEST
    int fd=VM27GuestSSHPeerConnectV1(vsock,cancel_fd);
    if(fd<0)return -1;int e=owned_stream_v1(fd);
    if(e){close(fd);errno=e;return -1;}return fd;
#else
    int fd=socket(vsock?AF_VSOCK:AF_INET,SOCK_STREAM,0);if(fd<0)return -1;
    int e=owned_stream_v1(fd);if(e)goto fail;
    struct sockaddr_vm vm={0};struct sockaddr_in tcp={0};
    vm.svm_len=sizeof(vm);vm.svm_family=AF_VSOCK;
    vm.svm_cid=VMADDR_CID_HOST;vm.svm_port=VM27_SSH_VSOCK_HOST_PORT;
    tcp.sin_len=sizeof(tcp);tcp.sin_family=AF_INET;
    tcp.sin_port=htons(22);tcp.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    const struct sockaddr *address=vsock?(const struct sockaddr *)&vm:(const struct sockaddr *)&tcp;
    socklen_t length=vsock?sizeof(vm):sizeof(tcp);
    if(connect(fd,address,length)<0){
        if(errno!=EINPROGRESS){e=errno;goto fail;}
        uint64_t now;e=time_v1(&now);if(e)goto fail;
        e=wait_v1(fd,POLLOUT,cancel_fd,now+VM27_SSH_VSOCK_CONNECT_MS);if(e)goto fail;
    }
    int socket_error=0;socklen_t n=sizeof(socket_error);
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&socket_error,&n)){e=errno;goto fail;}
    if(n!=sizeof(socket_error)){e=EIO;goto fail;}
    if(socket_error){e=socket_error;goto fail;}
    return fd;
fail:close(fd);errno=e;return -1;
#endif
}
static int send_frame_v1(int fd,const uint8_t h[32],int cancel_fd) {
    uint64_t now;int e=time_v1(&now);if(e)return e;
    uint64_t deadline=now+VM27_SSH_VSOCK_CONNECT_MS;size_t used=0;
    while(used<32){
        e=wait_v1(fd,POLLOUT,cancel_fd,deadline);if(e)return e;
        ssize_t n=send(fd,h+used,32-used,0);
        if(n>0){used+=(size_t)n;continue;}
        if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        return n==0?EPIPE:errno;
    }return 0;
}
struct owner_v1;
struct session_v1 {
    struct owner_v1 *owner;int used,done,local_fd,data_fd,cancel[2];
    pthread_t thread;uint8_t token[16];
    int result;struct vm27_stream_relay_v1_result receipt;
};
struct owner_v1 {
    pthread_mutex_t mutex;int notify[2],control,cancel_fd;uint32_t idle_ms;
    uint8_t nonce[8];uint64_t sequence;int has_nonce;
    struct session_v1 slots[VM27_SSH_VSOCK_MAX_SESSIONS];
};
static void *worker_v1(void *opaque) {
    struct session_v1 *s=opaque;
    int e=vm27_owned_stream_relay_v1_run(s->data_fd,s->local_fd,s->cancel[0],
                                        s->owner->idle_ms,&s->receipt);
    fprintf(stderr,"VM27_GUEST_SSH_SESSION_DONE seq=%llu errno=%d stop=%d toSSH=%llu fromSSH=%llu\n",
        (unsigned long long)be64_v1(s->token+8),e,(int)s->receipt.stop,
        (unsigned long long)s->receipt.bytes_left_to_right,
        (unsigned long long)s->receipt.bytes_right_to_left);
    pthread_mutex_lock(&s->owner->mutex);s->result=e;s->done=1;
    pthread_mutex_unlock(&s->owner->mutex);
    uint8_t b=1;ssize_t ignored=write(s->owner->notify[1],&b,1);(void)ignored;
    return NULL;
}
static void finish_v1(struct session_v1 *s) {
    int join_error=pthread_join(s->thread,NULL);
    if(join_error){
        fprintf(stderr,"VM27_GUEST_SSH_OWN_JOIN_FAILED errno=%d\n",join_error);
        abort(); /* never claim drain or reuse storage while an owner is live */
    }
    close(s->local_fd);close(s->data_fd);close(s->cancel[0]);
    if(s->cancel[1]>=0)close(s->cancel[1]);
    s->used=0;
}
static void reap_v1(struct owner_v1 *o) {
    for(unsigned i=0;i<VM27_SSH_VSOCK_MAX_SESSIONS;i++){
        struct session_v1 *s=&o->slots[i];if(!s->used)continue;
        pthread_mutex_lock(&o->mutex);int done=s->done;pthread_mutex_unlock(&o->mutex);
        if(done)finish_v1(s);
    }
}
static int report_error_v1(struct owner_v1 *o,const uint8_t token[16],int e) {
    fprintf(stderr,"VM27_GUEST_SSH_SESSION_SETUP_FAILED seq=%llu errno=%d\n",
        (unsigned long long)be64_v1(token+8),e);
    uint8_t h[32];vm27_ssh_vsock_header_v1(h,VM27_SSH_VSOCK_TYPE_ERROR,(uint32_t)e,token);
    return send_frame_v1(o->control,h,o->cancel_fd);
}
static int start_v1(struct owner_v1 *o,const uint8_t token[16]) {
    uint8_t nz=0;for(unsigned i=0;i<8;i++)nz|=token[i];
    uint64_t seq=be64_v1(token+8);
    if(!nz||!seq||seq<=o->sequence)return EPROTO;
    if(o->has_nonce&&memcmp(o->nonce,token,8))return EPROTO;
    if(!o->has_nonce){memcpy(o->nonce,token,8);o->has_nonce=1;}
    o->sequence=seq; /* consume even if real setup fails; never reconnect a token */
    reap_v1(o);struct session_v1 *s=NULL;
    for(unsigned i=0;i<VM27_SSH_VSOCK_MAX_SESSIONS;i++)if(!o->slots[i].used){s=&o->slots[i];break;}
    if(!s)return report_error_v1(o,token,EBUSY);
    int local=connect_v1(0,o->cancel_fd);if(local<0)return report_error_v1(o,token,errno);
    int data=connect_v1(1,o->cancel_fd);
    if(data<0){int e=errno;close(local);return report_error_v1(o,token,e);}
    int p[2];if(pipe(p)){int e=errno;close(local);close(data);return report_error_v1(o,token,e);}
    int e=nonblocking_v1(p[0]);if(!e)e=nonblocking_v1(p[1]);
    uint8_t h[32];vm27_ssh_vsock_header_v1(h,VM27_SSH_VSOCK_TYPE_DATA,0,token);
    if(!e)e=send_frame_v1(data,h,o->cancel_fd);
    if(e){close(local);close(data);close(p[0]);close(p[1]);return report_error_v1(o,token,e);}
    memset(s,0,sizeof(*s));s->owner=o;s->local_fd=local;s->data_fd=data;
    s->cancel[0]=p[0];s->cancel[1]=p[1];memcpy(s->token,token,16);
    e=pthread_create(&s->thread,NULL,worker_v1,s);
    if(e){close(local);close(data);close(p[0]);close(p[1]);return report_error_v1(o,token,e);}
    s->used=1;
    fprintf(stderr,"VM27_GUEST_SSH_SESSION_CONNECTED seq=%llu\n",(unsigned long long)seq);
    return 0;
}
int vm27_guest_vsock_ssh_helper_v1_run(int cancellation_read_fd,uint32_t idle_ms) {
    if(cancellation_read_fd<0||idle_ms<1||idle_ms>3600000)return EINVAL;
    struct stat st;int flags=fcntl(cancellation_read_fd,F_GETFL);
    if(flags<0||fstat(cancellation_read_fd,&st))return errno;
    if(!S_ISFIFO(st.st_mode)||!(flags&O_NONBLOCK)||(flags&O_ACCMODE)==O_WRONLY)return EINVAL;
    struct owner_v1 o;memset(&o,0,sizeof(o));o.control=-1;
    o.cancel_fd=cancellation_read_fd;o.idle_ms=idle_ms;
    int e=pthread_mutex_init(&o.mutex,NULL);if(e)return e;
    if(pipe(o.notify)){e=errno;pthread_mutex_destroy(&o.mutex);return e;}
    e=nonblocking_v1(o.notify[0]);if(!e)e=nonblocking_v1(o.notify[1]);
    if(e)goto cleanup;
    int probe=connect_v1(0,o.cancel_fd);
    if(probe<0){e=errno;fprintf(stderr,"VM27_GUEST_SSH_LOCAL_PREFLIGHT_FAILED errno=%d\n",e);goto cleanup;}
    close(probe);fprintf(stderr,"VM27_GUEST_SSH_LOCAL_TCP22_CONNECTED errno=0\n");
    o.control=connect_v1(1,o.cancel_fd);
    if(o.control<0){e=errno;fprintf(stderr,"VM27_GUEST_VSOCK_CONTROL_FAILED errno=%d\n",e);goto cleanup;}
    fprintf(stderr,"VM27_GUEST_VSOCK_CONTROL_CONNECTED port=22223 errno=0\n");
    uint8_t h[32];vm27_ssh_vsock_header_v1(h,VM27_SSH_VSOCK_TYPE_HELLO,0,NULL);
    e=send_frame_v1(o.control,h,o.cancel_fd);if(e)goto cleanup;
    fprintf(stderr,"VM27_GUEST_VSOCK_HELLO_SENT version=1 sessions=16\n");
    size_t used=0;
    for(;;){
        reap_v1(&o);
        struct pollfd p[3]={{o.control,POLLIN,0},{o.cancel_fd,POLLIN,0},{o.notify[0],POLLIN,0}};
        int count=poll(p,3,-1);if(count<0){if(errno==EINTR)continue;e=errno;break;}
        if(p[1].revents&POLLNVAL){e=EBADF;break;}
        if(p[1].revents&(POLLIN|POLLHUP|POLLERR)){e=cancelled_v1(o.cancel_fd);if(e)break;}
        if(p[2].revents&POLLIN){uint8_t b[64];while(read(o.notify[0],b,sizeof(b))>0){};reap_v1(&o);}
        if(p[0].revents&POLLNVAL){e=EBADF;break;}
        if(!(p[0].revents&(POLLIN|POLLHUP|POLLERR)))continue;
        ssize_t n=recv(o.control,h+used,32-used,0);
        if(n<0){if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)continue;e=errno;break;}
        if(n==0){e=EPIPE;break;}
        used+=(size_t)n;if(used!=32)continue;
        uint16_t type;uint32_t error;uint8_t token[16];
        e=vm27_ssh_vsock_parse_v1(h,&type,&error,token);if(e)break;
        if(type!=VM27_SSH_VSOCK_TYPE_START){e=EPROTO;break;}
        e=start_v1(&o,token);if(e)break;used=0;
    }
cleanup:
    if(o.control>=0)close(o.control);
    for(unsigned i=0;i<VM27_SSH_VSOCK_MAX_SESSIONS;i++)if(o.slots[i].used){
        close(o.slots[i].cancel[1]);o.slots[i].cancel[1]=-1;
    }
    for(unsigned i=0;i<VM27_SSH_VSOCK_MAX_SESSIONS;i++)if(o.slots[i].used)finish_v1(&o.slots[i]);
    close(o.notify[0]);close(o.notify[1]);pthread_mutex_destroy(&o.mutex);
    fprintf(stderr,"VM27_GUEST_VSOCK_HELPER_STOP errno=%d owned_workers_joined=1\n",e);
    return e;
}
