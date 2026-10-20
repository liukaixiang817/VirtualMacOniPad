#include "vm27_guest_vsock_ssh_helper_v1.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define MUST(x) do{if(!(x)){fprintf(stderr,"PEER_FAIL line=%d %s errno=%d\n",__LINE__,#x,errno);abort();}}while(0)
struct transport {pthread_mutex_t mu;int control,local_calls,vsock_calls,fail_local,fail_data;
 int local_peer[32],data_peer[32],owned[80],owned_count,cancel[2],result,cancel_on_data;pthread_t helper;};
static struct transport t={.mu=PTHREAD_MUTEX_INITIALIZER};
static int pair_v1(int p[2]){int e=socketpair(AF_UNIX,SOCK_STREAM,0,p);if(e)return e;
 int one=1;for(int i=0;i<2;i++)MUST(!setsockopt(p[i],SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)));return 0;}
int VM27GuestSSHPeerConnectV1(int vsock,int cancel_fd){(void)cancel_fd;pthread_mutex_lock(&t.mu);
 int count=vsock?++t.vsock_calls:++t.local_calls;
 if((vsock&&count==t.fail_data)||(!vsock&&count==t.fail_local)){
  pthread_mutex_unlock(&t.mu);errno=ECONNREFUSED;return -1;}
 int p[2];MUST(!pair_v1(p));t.owned[t.owned_count++]=p[0];
 if(vsock){if(count==1)t.control=p[1];else t.data_peer[count-2]=p[1];}
 else t.local_peer[count-1]=p[1];
 if(vsock&&count==2&&t.cancel_on_data){uint8_t b=5;MUST(write(t.cancel[1],&b,1)==1);}
 pthread_mutex_unlock(&t.mu);return p[0];}
static void *run_v1(void *arg){(void)arg;t.result=vm27_guest_vsock_ssh_helper_v1_run(t.cancel[0],30000);return NULL;}
static void init_v1(int fl,int fd){t.control=-1;t.local_calls=t.vsock_calls=t.owned_count=0;
 t.fail_local=fl;t.fail_data=fd;t.result=-1;t.cancel_on_data=(fd==-9);
 for(unsigned i=0;i<32;i++)t.local_peer[i]=t.data_peer[i]=-1;
 MUST(!pipe(t.cancel));for(int i=0;i<2;i++)MUST(!fcntl(t.cancel[i],F_SETFL,O_NONBLOCK));
 if(fl==-9){uint8_t b=5;MUST(write(t.cancel[1],&b,1)==1);}
 MUST(!pthread_create(&t.helper,NULL,run_v1,NULL));}
static int wait_peer_v1(int which,unsigned index){for(unsigned i=0;i<1000;i++){
 pthread_mutex_lock(&t.mu);int fd=which==0?t.control:which==1?t.local_peer[index]:t.data_peer[index];pthread_mutex_unlock(&t.mu);
 if(fd>=0)return fd;usleep(1000);}MUST(0);return -1;}
static void writeall_v1(int fd,const void *opaque,size_t n){const unsigned char *p=opaque;while(n){
 ssize_t k=send(fd,p,n,0);if(k<0&&errno==EINTR)continue;MUST(k>0);p+=k;n-=(size_t)k;}}
static void readall_v1(int fd,void *opaque,size_t n){unsigned char *p=opaque;while(n){
 struct pollfd q={fd,POLLIN,0};MUST(poll(&q,1,3000)>0);ssize_t k=recv(fd,p,n,0);MUST(k>0);p+=k;n-=(size_t)k;}}
static void token_v1(uint8_t p[16],uint64_t seq){memset(p,0,16);p[0]=0xa5;for(unsigned i=0;i<8;i++)p[15-i]=(uint8_t)(seq>>(8*i));}
static void hello_v1(void){uint8_t h[32],token[16];uint16_t type;uint32_t error;
 readall_v1(wait_peer_v1(0,0),h,32);MUST(!vm27_ssh_vsock_parse_v1(h,&type,&error,token));MUST(type==1&&!error);}
static void start_v1(uint64_t seq,int nonce_delta){uint8_t token[16],h[32];token_v1(token,seq);token[0]+=(uint8_t)nonce_delta;
 vm27_ssh_vsock_header_v1(h,2,0,token);writeall_v1(t.control,h,7);writeall_v1(t.control,h+7,25);}
static void data_v1(unsigned index,uint64_t seq){uint8_t h[32],token[16],expected[16];uint16_t type;uint32_t error;
 readall_v1(wait_peer_v1(2,index),h,32);MUST(!vm27_ssh_vsock_parse_v1(h,&type,&error,token));token_v1(expected,seq);MUST(type==3&&!error&&!memcmp(token,expected,16));}
static void finish_v1(int expected,int close_control){if(close_control){close(t.control);t.control=-1;}
 MUST(!pthread_join(t.helper,NULL));MUST(t.result==expected);MUST(fcntl(t.cancel[0],F_GETFD)>=0);
 pthread_mutex_lock(&t.mu);for(int i=0;i<t.owned_count;i++){errno=0;MUST(fcntl(t.owned[i],F_GETFD)==-1&&errno==EBADF);}pthread_mutex_unlock(&t.mu);
 if(t.control>=0)close(t.control);for(unsigned i=0;i<32;i++){if(t.local_peer[i]>=0)close(t.local_peer[i]);if(t.data_peer[i]>=0)close(t.data_peer[i]);}
 close(t.cancel[0]);if(t.cancel[1]>=0)close(t.cancel[1]);}
struct exchange {int fd;size_t send_count,receive_count;uint8_t send_seed,receive_seed;};
static uint8_t pattern_v1(size_t i,uint8_t seed){return (uint8_t)(i*17u+seed);}
static void *writer_v1(void *opaque){struct exchange *x=opaque;uint8_t b[4096];size_t off=0;
 while(off<x->send_count){size_t n=x->send_count-off;if(n>sizeof(b))n=sizeof(b);for(size_t i=0;i<n;i++)b[i]=pattern_v1(off+i,x->send_seed);writeall_v1(x->fd,b,n);off+=n;}
 MUST(!shutdown(x->fd,SHUT_WR));return NULL;}
static void *exchange_v1(void *opaque){struct exchange *x=opaque;uint8_t b[4096];size_t off=0;pthread_t writer;
 MUST(!pthread_create(&writer,NULL,writer_v1,x));while(off<x->receive_count){size_t n=x->receive_count-off;if(n>sizeof(b))n=sizeof(b);readall_v1(x->fd,b,n);for(size_t i=0;i<n;i++)MUST(b[i]==pattern_v1(off+i,x->receive_seed));off+=n;}
 struct pollfd p={x->fd,POLLIN,0};MUST(poll(&p,1,3000)>0);MUST(recv(x->fd,b,1,0)==0);MUST(!pthread_join(writer,NULL));return NULL;}
static void protocol_v1(void){uint8_t h[32],token[16],out[16];uint16_t type=99;uint32_t error=99;
 token_v1(token,1);vm27_ssh_vsock_header_v1(h,2,0,token);MUST(!vm27_ssh_vsock_parse_v1(h,&type,&error,out));MUST(type==2&&!memcmp(token,out,16));
 h[0]^=1;type=99;error=99;MUST(vm27_ssh_vsock_parse_v1(h,&type,&error,out)==EPROTO&&type==99&&error==99);
 h[0]^=1;h[9]=2;MUST(vm27_ssh_vsock_parse_v1(h,&type,&error,out)==EPROTO);
 puts("PASS protocol32_reserved_version_real_boundary");}
static void bidirectional_v1(void){init_v1(0,0);hello_v1();struct exchange x[4];pthread_t threads[4];
 for(unsigned i=0;i<2;i++){start_v1(i+1,0);data_v1(i,i+1);
 x[i*2]=(struct exchange){wait_peer_v1(2,i),262144u+i*4096u,327680u+i*4096u,(uint8_t)(11+i),(uint8_t)(71+i)};
 x[i*2+1]=(struct exchange){wait_peer_v1(1,i+1),x[i*2].receive_count,x[i*2].send_count,x[i*2].receive_seed,x[i*2].send_seed};}
 for(unsigned i=0;i<4;i++)MUST(!pthread_create(&threads[i],NULL,exchange_v1,&x[i]));for(unsigned i=0;i<4;i++)MUST(!pthread_join(threads[i],NULL));
 finish_v1(EPIPE,1);puts("PASS two_independent_sessions_big_bidirectional_halfclose_framing");}
static void failed_setup_v1(int which){init_v1(which==0?2:0,which==1?2:0);hello_v1();start_v1(1,0);
 uint8_t h[32],token[16];uint16_t type;uint32_t error;readall_v1(t.control,h,32);MUST(!vm27_ssh_vsock_parse_v1(h,&type,&error,token));MUST(type==4&&error==ECONNREFUSED);
 pthread_mutex_lock(&t.mu);MUST(t.vsock_calls==(which==0?1:2));pthread_mutex_unlock(&t.mu);finish_v1(EPIPE,1);puts(which==0?"PASS failed_local_connect_exact_ERROR_no_DATA":"PASS failed_DATA_connect_exact_ERROR_owned_local_closed");}
static void cap_v1(void){init_v1(0,0);hello_v1();for(unsigned i=0;i<16;i++){start_v1(i+1,0);data_v1(i,i+1);}
 start_v1(17,0);uint8_t h[32],token[16];uint16_t type;uint32_t error;readall_v1(t.control,h,32);MUST(!vm27_ssh_vsock_parse_v1(h,&type,&error,token));MUST(type==4&&error==EBUSY);pthread_mutex_lock(&t.mu);MUST(t.vsock_calls==17&&t.local_calls==17);pthread_mutex_unlock(&t.mu);
 finish_v1(EPIPE,1);puts("PASS cap16_busy17_control_EOF_joins_all16_no_new_connection");}
static void reject_v1(int nonce){init_v1(0,0);hello_v1();start_v1(1,0);data_v1(0,1);start_v1(nonce?2:1,nonce?1:0);
 finish_v1(EPROTO,0);MUST(t.vsock_calls==2&&t.local_calls==2);puts(nonce?"PASS changed_control_nonce_rejected_no_reconnect":"PASS duplicate_token_rejected_no_reconnect");}
static void cancel_v1(int eof){init_v1(0,0);hello_v1();start_v1(1,0);data_v1(0,1);
 if(eof){close(t.cancel[1]);t.cancel[1]=-1;}else{uint8_t b=9;MUST(write(t.cancel[1],&b,1)==1);}
 MUST(!pthread_join(t.helper,NULL));MUST(t.result==ECANCELED);if(!eof){uint8_t b=0;MUST(read(t.cancel[0],&b,1)==1&&b==9);}
 /* finish helper already joined; manually prove every lent socket closed. */
 for(int i=0;i<t.owned_count;i++){errno=0;MUST(fcntl(t.owned[i],F_GETFD)==-1&&errno==EBADF);}
 MUST(fcntl(t.cancel[0],F_GETFD)>=0);close(t.control);for(unsigned i=0;i<32;i++){if(t.local_peer[i]>=0)close(t.local_peer[i]);if(t.data_peer[i]>=0)close(t.data_peer[i]);}close(t.cancel[0]);if(t.cancel[1]>=0)close(t.cancel[1]);
 puts(eof?"PASS borrow_cancel_EOF_joins_ownworkers":"PASS borrow_cancel_byte_persists_and_joins_ownworkers");}
static void cancelled_setup_v1(void){init_v1(0,-9);hello_v1();start_v1(1,0);finish_v1(ECANCELED,0);
 MUST(t.local_calls==2&&t.vsock_calls==2);puts("PASS cancel_before_DATA_write_persists_through_error_cleanup");}
static void pre_cancel_v1(void){init_v1(-9,0);finish_v1(ECANCELED,0);
 MUST(t.local_calls==0&&t.vsock_calls==0);puts("PASS already_cancelled_no_connection_or_HELLO");}
int main(void){alarm(30);protocol_v1();bidirectional_v1();failed_setup_v1(0);failed_setup_v1(1);cap_v1();reject_v1(0);reject_v1(1);cancel_v1(0);cancel_v1(1);cancelled_setup_v1();pre_cancel_v1();puts("ALL11_HOST_AFUNIX_MODELS_PASS_NO_VSOCK_OR_GUEST_EXECUTION");return 0;}
