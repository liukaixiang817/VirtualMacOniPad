#include "../../host/vm27_host_vsock_ssh_owner_v1.h"
#include "../../guest/vm27_guest_vsock_ssh_helper_v1.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* Actual host TCP/socketpair event tests. These are not VZ objects, a guest or
 * an SSH server. The genuine Objective-C VZ adapter is compiled separately. */
static atomic_uint checks;
#define CHECK(x) do {atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"line%d failed: %s errno%d\n",__LINE__,#x,errno);exit(1);}}while(0)
static atomic_int released;
static void release(void *context){CHECK(context==&released);atomic_fetch_add(&released,1);}
static uint64_t ms(void){struct timespec t;CHECK(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void pause_ms(int n){(void)poll(NULL,0,n);}
static struct vm27_host_ssh_snapshot_v1 snap(struct vm27_host_ssh_owner_v1 *o){struct vm27_host_ssh_snapshot_v1 s;CHECK(!vm27_host_ssh_owner_v1_snapshot(o,&s));return s;}
static void wait_state(struct vm27_host_ssh_owner_v1 *o,int ready,unsigned pending,unsigned active,int stopped,int timeout){
    uint64_t end=ms()+(unsigned)timeout;for(;;){struct vm27_host_ssh_snapshot_v1 s=snap(o);
        if(s.ready==ready&&s.pending==pending&&s.active==active&&s.stopped==stopped)return;
        CHECK(ms()<end);pause_ms(5);}}
static void write_all(int fd,const void *p,size_t n){const unsigned char *b=p;uint64_t end=ms()+2000;
    while(n){struct pollfd f={fd,POLLOUT,0};CHECK(poll(&f,1,50)>=0);CHECK(ms()<end);
        ssize_t x=send(fd,b,n,0);if(x<0&&(errno==EINTR||errno==EAGAIN))continue;CHECK(x>0);b+=x;n-=(size_t)x;}}
static void read_all(int fd,void *p,size_t n){unsigned char *b=p;uint64_t end=ms()+2000;
    while(n){struct pollfd f={fd,POLLIN,0};CHECK(poll(&f,1,50)>=0);CHECK(ms()<end);
        ssize_t x=recv(fd,b,n,0);if(x<0&&(errno==EINTR||errno==EAGAIN))continue;CHECK(x>0);b+=x;n-=(size_t)x;}}
static void expect_eof(int fd){struct pollfd f={fd,POLLIN,0};CHECK(poll(&f,1,2000)>0);char b;CHECK(recv(fd,&b,1,0)==0);}
static int incoming(struct vm27_host_ssh_owner_v1 *o){int p[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,p));
    CHECK(!vm27_host_ssh_owner_v1_admit(o,p[0],release,&released));return p[1];}
static int tcp(struct vm27_host_ssh_owner_v1 *o){int fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);struct sockaddr_in a={0};
    a.sin_family=AF_INET;a.sin_port=htons(snap(o).tcp_port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(!connect(fd,(struct sockaddr*)&a,sizeof(a)));return fd;}
static struct vm27_host_ssh_owner_v1 *create(void){struct vm27_host_ssh_owner_v1 *o=NULL;
    CHECK(!vm27_host_ssh_owner_v1_create(0,30000,&o));CHECK(o);return o;}
static int hello(struct vm27_host_ssh_owner_v1 *o){int fd=incoming(o);uint8_t h[32];vm27_ssh_vsock_header_v1(h,1,0,NULL);
    write_all(fd,h,7);pause_ms(5);write_all(fd,h+7,25);wait_state(o,1,0,0,0,2000);return fd;}
static void start(int control,uint8_t token[16],uint64_t sequence){uint8_t h[32];read_all(control,h,32);uint16_t t;uint32_t e;
    CHECK(!vm27_ssh_vsock_parse_v1(h,&t,&e,token));CHECK(t==2&&!e);uint64_t seq=0;
    for(unsigned i=0;i<8;i++)seq=(seq<<8)|token[8+i];CHECK(seq==sequence);
    unsigned nonce=0;for(unsigned i=0;i<8;i++)nonce|=token[i];CHECK(nonce);}
static int data(struct vm27_host_ssh_owner_v1 *o,const uint8_t token[16],int partial){int fd=incoming(o);uint8_t h[32];
    vm27_ssh_vsock_header_v1(h,3,0,token);if(partial){write_all(fd,h,13);pause_ms(5);write_all(fd,h+13,19);}else write_all(fd,h,32);return fd;}
static void error_frame(int fd,const uint8_t token[16],uint32_t error){uint8_t h[32];vm27_ssh_vsock_header_v1(h,4,error,token);write_all(fd,h,32);}
static void duplex_and_token_ownership(void){struct vm27_host_ssh_owner_v1 *o=create();int c=hello(o);
    int a=tcp(o);uint8_t at[16];start(c,at,1);int b=tcp(o);uint8_t bt[16];start(c,bt,2);
    CHECK(!memcmp(at,bt,8));CHECK(memcmp(at+8,bt+8,8));
    int bd=data(o,bt,1),ad=data(o,at,0);wait_state(o,1,0,2,0,2000);
    int duplicate=data(o,at,0);expect_eof(duplicate);close(duplicate);
    uint8_t wrong[16];memcpy(wrong,at,16);wrong[0]^=1;int wd=data(o,wrong,0);expect_eof(wd);close(wd);
    memcpy(wrong,at,16);wrong[15]=99;wd=data(o,wrong,0);expect_eof(wd);close(wd);
    write_all(a,"actual-A",8);write_all(b,"actual-B",8);char out[8];read_all(ad,out,8);CHECK(!memcmp(out,"actual-A",8));
    read_all(bd,out,8);CHECK(!memcmp(out,"actual-B",8));write_all(ad,"return-A",8);write_all(bd,"return-B",8);
    read_all(a,out,8);CHECK(!memcmp(out,"return-A",8));read_all(b,out,8);CHECK(!memcmp(out,"return-B",8));
    CHECK(!shutdown(a,SHUT_WR));CHECK(!shutdown(b,SHUT_WR));expect_eof(ad);expect_eof(bd);
    CHECK(!shutdown(ad,SHUT_WR));CHECK(!shutdown(bd,SHUT_WR));expect_eof(a);expect_eof(b);
    wait_state(o,1,0,0,0,2000);struct vm27_host_ssh_snapshot_v1 s=snap(o);
    CHECK(s.streams_started==2&&s.streams_completed==2);CHECK(s.bytes_tcp_to_guest==16&&s.bytes_guest_to_tcp==16);
    CHECK(s.rejected_connections==3);close(a);close(b);close(ad);close(bd);
    vm27_host_ssh_owner_v1_destroy(o);expect_eof(c);close(c);CHECK(atomic_load(&released)==6);
    puts("duplex-reversed-DATA-partial-headers-and-exact-token-ownership passed");}
static void setup_errors_and_capacity(void){int baseline=atomic_load(&released);struct vm27_host_ssh_owner_v1 *o=create();int c=hello(o);
    int fds[16];uint8_t tokens[16][16];for(unsigned i=0;i<16;i++){fds[i]=tcp(o);start(c,tokens[i],i+1);}
    wait_state(o,1,16,0,0,2000);int busy=tcp(o);expect_eof(busy);close(busy);CHECK(snap(o).last_sequence==16);
    for(unsigned i=0;i<16;i++){error_frame(c,tokens[i],ECONNREFUSED);expect_eof(fds[i]);close(fds[i]);}
    wait_state(o,1,0,0,0,2000);CHECK(snap(o).setup_errors==16);
    int next=tcp(o);uint8_t nt[16];start(c,nt,17);error_frame(c,nt,EIO);expect_eof(next);close(next);
    vm27_host_ssh_owner_v1_destroy(o);close(c);CHECK(atomic_load(&released)==baseline+1);
    puts("real-cap16-failed-setup-consumes-sequence-and-reopens-capacity passed");}
static void control_loss_and_cancel(void){for(unsigned mode=0;mode<2;mode++){
    int baseline=atomic_load(&released);struct vm27_host_ssh_owner_v1 *o=create();int c=hello(o);
    int a=tcp(o);uint8_t at[16];start(c,at,1);int ad=data(o,at,0);wait_state(o,1,0,1,0,2000);
    int pending=tcp(o);uint8_t pt[16];start(c,pt,2);int partial=incoming(o);write_all(partial,"VM27",4);
    if(mode){vm27_host_ssh_owner_v1_cancel(o);}else{CHECK(!shutdown(c,SHUT_WR));}
    wait_state(o,0,0,0,1,2000);CHECK(snap(o).error==(mode?ECANCELED:ECONNRESET));
    expect_eof(a);expect_eof(ad);expect_eof(pending);expect_eof(partial);
    int q[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,q));CHECK(vm27_host_ssh_owner_v1_admit(o,q[0],release,&released)==ECANCELED);
    CHECK(fcntl(q[0],F_GETFD)>=0);close(q[0]);close(q[1]);
    vm27_host_ssh_owner_v1_destroy(o);close(a);close(ad);close(pending);close(partial);close(c);
    CHECK(atomic_load(&released)==baseline+3);
  }puts("control-EOF-and-explicit-cancel-drain-active-pending-partial-reject-new-admission passed");}
static void deadlines_and_protocol(void){int baseline=atomic_load(&released);struct vm27_host_ssh_owner_v1 *o=create();int c=hello(o);
    int pending=tcp(o);uint8_t token[16];start(c,token,1);int partial=incoming(o);write_all(partial,"VM27",4);
    wait_state(o,1,0,0,0,6500);expect_eof(pending);expect_eof(partial);close(pending);close(partial);
    CHECK(snap(o).setup_errors==1);CHECK(snap(o).rejected_connections==1);
    int next=tcp(o);start(c,token,2);uint8_t wrong[16];memcpy(wrong,token,16);wrong[0]^=1;
    error_frame(c,wrong,EIO);wait_state(o,0,0,0,1,2000);CHECK(snap(o).error==EPROTO);expect_eof(next);close(next);
    vm27_host_ssh_owner_v1_destroy(o);close(c);CHECK(atomic_load(&released)==baseline+2);
    puts("actual-five-second-handshake-and-pending-deadlines-invalid-control-nonce-fail-closed passed");}
static void nonzero_hello_and_bind(void){struct vm27_host_ssh_owner_v1 *o=create();int bad=incoming(o);uint8_t h[32],t[16]={1};
    vm27_ssh_vsock_header_v1(h,1,0,t);write_all(bad,h,32);expect_eof(bad);close(bad);CHECK(!snap(o).ready);
    uint16_t port=snap(o).tcp_port;struct vm27_host_ssh_owner_v1 *collision=(void*)1;
    CHECK(vm27_host_ssh_owner_v1_create(port,30000,&collision)==EADDRINUSE);CHECK(!collision);
    int no_control=tcp(o);expect_eof(no_control);close(no_control);CHECK(!snap(o).last_sequence);
    vm27_host_ssh_owner_v1_destroy(o);puts("nonzero-HELLO-rejected-no-control-no-stream-real-bind-collision passed");}
int main(void){duplex_and_token_ownership();setup_errors_and_capacity();control_loss_and_cancel();deadlines_and_protocol();nonzero_hello_and_bind();
    printf("host owner real event/socket cases5 passed; checks%u releaseCallbacks%d\n",atomic_load(&checks),atomic_load(&released));return 0;}
