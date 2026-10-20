/* Real local socket tests only. No VZ, guest, device or network services. */
#include "vm27_owned_stream_relay_v1.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr,"FAILED line=%d expression=%s errno=%d\n",__LINE__,#x,errno); \
    exit(2); } } while (0)
static atomic_uint_fast64_t relay_polls;
static atomic_uint_fast64_t relay_sends;
int VM27PeerCountedPollV1(struct pollfd *fds, nfds_t count, int timeout)
{
    atomic_fetch_add(&relay_polls, 1);
    return poll(fds, count, timeout);
}
ssize_t VM27PeerCountedSendV1(int fd,const void *bytes,size_t length,int flags)
{
    atomic_fetch_add(&relay_sends,1);
    return send(fd,bytes,length,flags);
}
static uint64_t now_ms(void)
{
    struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0);
    return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;
}
static void pause_ms(unsigned value)
{
    struct timespec t={.tv_sec=value/1000u,.tv_nsec=(long)(value%1000u)*1000000};
    while(nanosleep(&t,&t)!=0) CHECK(errno==EINTR);
}
static void nonblock(int fd)
{
    int flags=fcntl(fd,F_GETFL); CHECK(flags>=0);
    CHECK(fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0);
}
struct fixture {
    int left[2],right[2],cancel[2];
    pthread_t worker; int rc; uint32_t idle; atomic_int done;
    struct vm27_stream_relay_v1_result result;
};
static void init(struct fixture *f,uint32_t idle)
{
    memset(f,0,sizeof(*f)); atomic_init(&f->done,0); f->idle=idle;
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,f->left)==0);
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,f->right)==0);
    CHECK(pipe(f->cancel)==0);
    int buffer=4096;
    for(unsigned i=0;i<2;i++) {
        nonblock(f->left[i]); nonblock(f->right[i]); nonblock(f->cancel[i]);
        CHECK(setsockopt(f->left[i],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer))==0);
        CHECK(setsockopt(f->right[i],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer))==0);
    }
    atomic_store(&relay_polls,0);
    atomic_store(&relay_sends,0);
}
static void *worker(void *v)
{
    struct fixture *f=v;
    f->rc=vm27_owned_stream_relay_v1_run(f->left[0],f->right[0],f->cancel[0],f->idle,&f->result);
    atomic_store(&f->done,1); return NULL;
}
static void start(struct fixture *f) { CHECK(pthread_create(&f->worker,NULL,worker,f)==0); }
static void joined(struct fixture *f)
{
    CHECK(pthread_join(f->worker,NULL)==0); CHECK(atomic_load(&f->done)==1);
    CHECK(fcntl(f->left[0],F_GETFD)>=0 && fcntl(f->right[0],F_GETFD)>=0);
    CHECK(fcntl(f->cancel[0],F_GETFD)>=0);
}
static void close_fixture(struct fixture *f)
{
    for(unsigned i=0;i<2;i++) {
        if(f->left[i]>=0) CHECK(close(f->left[i])==0);
        if(f->right[i]>=0) CHECK(close(f->right[i])==0);
        if(f->cancel[i]>=0) CHECK(close(f->cancel[i])==0);
    }
}
static unsigned char pattern(size_t offset,unsigned seed)
{ return (unsigned char)((offset*29u+(offset>>9u)*7u+seed*113u)&255u); }
static unsigned char *payload(size_t n,unsigned seed)
{
    unsigned char *p=malloc(n); CHECK(p!=NULL);
    for(size_t i=0;i<n;i++)p[i]=pattern(i,seed);
    return p;
}
struct exchange {
    int fd; size_t send_length,receive_length; unsigned seed,receive_seed;
    size_t written,received; unsigned blocked; int saw_eof;
};
static void *exchange(void *v)
{
    struct exchange *x=v; unsigned char *bytes=payload(x->send_length,x->seed);
    unsigned char read_buffer[8192]; int halfclosed=0; uint64_t deadline=now_ms()+6000u;
    while(!x->saw_eof || !halfclosed) {
        CHECK(now_ms()<deadline);
        if(x->written==x->send_length && !halfclosed) {
            CHECK(shutdown(x->fd,SHUT_WR)==0); halfclosed=1;
        }
        struct pollfd p={.fd=x->fd,.events=0};
        if(!x->saw_eof)p.events|=POLLIN;
        if(x->written<x->send_length)p.events|=POLLOUT;
        int rc=poll(&p,1,50); CHECK(rc>=0 || errno==EINTR);
        if(rc<0)continue;
        if(x->written<x->send_length) {
            ssize_t n=send(x->fd,bytes+x->written,x->send_length-x->written,0);
            if(n>0)x->written+=(size_t)n;
            else if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR))x->blocked++;
            else CHECK(0);
        }
        if(!x->saw_eof) {
            ssize_t n=recv(x->fd,read_buffer,sizeof(read_buffer),0);
            if(n>0) {
                CHECK(x->received+(size_t)n<=x->receive_length);
                for(ssize_t i=0;i<n;i++)CHECK(read_buffer[i]==pattern(x->received+(size_t)i,x->receive_seed));
                x->received+=(size_t)n;
            } else if(n==0) {
                x->saw_eof=1; CHECK(x->received==x->receive_length);
            } else CHECK(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR);
        }
    }
    free(bytes);return NULL;
}
static void read_all(int fd,size_t wanted,unsigned seed)
{
    size_t received=0; unsigned char b[8192]; uint64_t deadline=now_ms()+6000;
    for(;;) {
        CHECK(now_ms()<deadline);
        struct pollfd p={.fd=fd,.events=POLLIN}; int rc=poll(&p,1,50);
        CHECK(rc>=0 || errno==EINTR); if(rc<=0)continue;
        ssize_t n=recv(fd,b,sizeof(b),0);
        if(n==0)break;
        if(n<0) { CHECK(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR);continue; }
        CHECK(received+(size_t)n<=wanted);
        for(ssize_t i=0;i<n;i++)CHECK(b[i]==pattern(received+(size_t)i,seed));
        received+=(size_t)n;
    }
    CHECK(received==wanted);
}
static void write_all(int fd,size_t length,unsigned seed)
{
    unsigned char *b=payload(length,seed);size_t sent=0;uint64_t deadline=now_ms()+6000;
    while(sent<length) {
        CHECK(now_ms()<deadline);
        ssize_t n=send(fd,b+sent,length-sent,0);
        if(n>0)sent+=(size_t)n;
        else {CHECK(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR));
            struct pollfd p={.fd=fd,.events=POLLOUT}; CHECK(poll(&p,1,50)>=0 || errno==EINTR);}
    }
    free(b);
}
static void announce(const char *name,struct fixture *f)
{
    printf("{\"case\":\"%s\",\"passed\":true,\"rc\":%d,\"stop\":%d,\"leftWritten\":%llu,\"rightWritten\":%llu,\"relayPolls\":%llu}\n",
        name,f->rc,f->result.stop,(unsigned long long)f->result.bytes_left_to_right,
        (unsigned long long)f->result.bytes_right_to_left,
        (unsigned long long)atomic_load(&relay_polls));fflush(stdout);
}
static void duplex(void)
{
    struct fixture f;init(&f,5000);start(&f);pthread_t a,b;
    struct exchange x={.fd=f.left[1],.send_length=1048576,.receive_length=1179648,.seed=1,.receive_seed=2};
    struct exchange y={.fd=f.right[1],.send_length=1179648,.receive_length=1048576,.seed=2,.receive_seed=1};
    CHECK(pthread_create(&a,NULL,exchange,&x)==0 && pthread_create(&b,NULL,exchange,&y)==0);
    CHECK(pthread_join(a,NULL)==0 && pthread_join(b,NULL)==0);joined(&f);
    CHECK(f.rc==0 && f.result.stop==VM27_STREAM_RELAY_V1_COMPLETE);
    CHECK(f.result.bytes_left_to_right==x.written && f.result.bytes_right_to_left==y.written);
    announce("duplex-large-exact-bytes",&f);close_fixture(&f);
}
static void backpressure(void)
{
    struct fixture f;init(&f,5000);start(&f);pthread_t a;
    struct exchange x={.fd=f.left[1],.send_length=1048576,.receive_length=0,.seed=3,.receive_seed=4};
    CHECK(pthread_create(&a,NULL,exchange,&x)==0);
    pause_ms(150);CHECK(atomic_load(&f.done)==0);
    /* Both kernel buffers and the relay buffer must fill before draining. */
    CHECK(atomic_load(&relay_polls)<300);
    CHECK(shutdown(f.right[1],SHUT_WR)==0);read_all(f.right[1],1048576,3);
    CHECK(pthread_join(a,NULL)==0);joined(&f);
    CHECK(x.blocked>0 && f.rc==0 && f.result.bytes_left_to_right==1048576);
    CHECK(f.result.bytes_right_to_left==0);announce("real-backpressure-drain",&f);close_fixture(&f);
}
static void *requester(void *v)
{
    int fd=*(int*)v;write_all(fd,65536,5);CHECK(shutdown(fd,SHUT_WR)==0);
    read_all(fd,81920,6);return NULL;
}
static void halfclose(void)
{
    struct fixture f;init(&f,5000);start(&f);pthread_t a;
    CHECK(pthread_create(&a,NULL,requester,&f.left[1])==0);
    read_all(f.right[1],65536,5);
    /* Reply starts only after request EOF; the reverse direction must survive. */
    write_all(f.right[1],81920,6);CHECK(shutdown(f.right[1],SHUT_WR)==0);
    CHECK(pthread_join(a,NULL)==0);joined(&f);
    CHECK(f.rc==0 && f.result.bytes_left_to_right==65536 && f.result.bytes_right_to_left==81920);
    announce("halfclose-then-server-reply",&f);close_fixture(&f);
}
static void cancellation(int eof)
{
    struct fixture f;init(&f,1000);start(&f);pause_ms(25);
    if(eof){CHECK(close(f.cancel[1])==0);f.cancel[1]=-1;}
    else CHECK(write(f.cancel[1],"X",1)==1);
    joined(&f);CHECK(f.rc==ECANCELED && f.result.stop==VM27_STREAM_RELAY_V1_CANCELLED);
    CHECK(f.result.bytes_left_to_right==0 && f.result.bytes_right_to_left==0);
    announce(eof?"cancel-pipe-eof":"cancel-pipe-byte",&f);close_fixture(&f);
}
static void idle(void)
{
    struct fixture f;init(&f,70);uint64_t begin=now_ms();worker(&f);uint64_t elapsed=now_ms()-begin;
    CHECK(f.rc==ETIMEDOUT && f.result.stop==VM27_STREAM_RELAY_V1_IDLE);
    CHECK(elapsed>=60 && elapsed<500 && atomic_load(&relay_polls)<8);
    CHECK(fcntl(f.left[0],F_GETFD)>=0 && fcntl(f.right[0],F_GETFD)>=0 && fcntl(f.cancel[0],F_GETFD)>=0);
    announce("bounded-idle-borrowed-fds-open",&f);close_fixture(&f);
}
static void closed_source_full_buffer(void)
{
    struct fixture f;init(&f,2000);start(&f);
    unsigned char bytes[4096];memset(bytes,0x5a,sizeof(bytes));size_t sent=0;
    uint64_t deadline=now_ms()+300;
    while(now_ms()<deadline) {
        ssize_t n=send(f.left[1],bytes,sizeof(bytes),0);
        if(n>0)sent+=(size_t)n;
        else {CHECK(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR));pause_ms(1);}
    }
    CHECK(sent>16384);CHECK(close(f.left[1])==0);f.left[1]=-1;
    uint64_t before=atomic_load(&relay_polls);pause_ms(180);
    uint64_t after=atomic_load(&relay_polls);
    CHECK(atomic_load(&f.done)==0 && after-before<12);
    CHECK(write(f.cancel[1],"C",1)==1);joined(&f);
    CHECK(f.rc==ECANCELED && f.result.bytes_left_to_right<=sent);
    announce("closed-source-full-buffer-no-busy-poll",&f);close_fixture(&f);
}
static void no_sigpipe(void)
{
    pid_t child=fork();CHECK(child>=0);
    if(child==0) {
        signal(SIGPIPE,SIG_DFL);struct fixture f;init(&f,1000);start(&f);pause_ms(25);
        CHECK(close(f.right[1])==0);f.right[1]=-1;
        CHECK(send(f.left[1],"payload",7,0)==7);joined(&f);
        CHECK(atomic_load(&relay_sends)>0);
        CHECK(f.rc==EPIPE || f.rc==ECONNRESET || f.rc==ENOTCONN);
        CHECK(f.result.stop==VM27_STREAM_RELAY_V1_ERROR);
        CHECK(fcntl(f.left[0],F_GETFD)>=0 && fcntl(f.right[0],F_GETFD)>=0);
        announce("default-sigpipe-closed-destination",&f);close_fixture(&f);_exit(0);
    }
    int status=0;CHECK(waitpid(child,&status,0)==child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
int main(void)
{
    alarm(30);atomic_init(&relay_polls,0);
    duplex();backpressure();halfclose();cancellation(0);cancellation(1);idle();
    closed_source_full_buffer();no_sigpipe();
    printf("{\"allPassed\":true,\"cases\":8,\"deviceOperations\":0}\n");return 0;
}
