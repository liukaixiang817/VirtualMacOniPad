#include "vm27_host_vsock_ssh_owner_v3.h"
#include <ifaddrs.h>
#include <net/if.h>
#include "vm27_owned_stream_relay_v1.h"
#include "../guest/vm27_guest_vsock_ssh_helper_v1.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HCOUNT 32
#define SCOUNT VM27_SSH_VSOCK_MAX_SESSIONS
struct lease { int fd; vm27_host_ssh_release_v1 release; void *context; };
struct handshake { struct lease lease; uint8_t bytes[32]; size_t have; uint64_t deadline; };
struct session {
    struct vm27_host_ssh_owner_v1 *owner;
    int tcp, cancel[2], state, done;
    struct lease data;
    uint8_t token[16]; uint64_t deadline;
    pthread_t thread;
    struct vm27_stream_relay_v1_result result;
};
struct vm27_host_ssh_owner_v1 {
    pthread_mutex_t mutex; pthread_t thread;
    int listeners[2], notify[2], cancel_requested;
    unsigned scope;
    uint32_t idle_ms;
    struct lease incoming[HCOUNT]; unsigned incoming_count;
    struct handshake handshake[HCOUNT];
    struct lease control; uint8_t rx[32], tx[SCOUNT * 32], nonce[8];
    size_t rx_have, tx_offset, tx_length;
    struct session sessions[SCOUNT];
    struct vm27_host_ssh_snapshot_v1 published;
};
static uint64_t now_ms(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static int nonblock(int fd) {
    int f=fcntl(fd,F_GETFL); if(f<0 || fcntl(fd,F_SETFL,f|O_NONBLOCK)<0) return errno;
    if(fcntl(fd,F_SETFD,FD_CLOEXEC)<0) return errno;
    return 0;
}
static int prepare_socket(int fd) {
    int type=0; socklen_t n=sizeof(type);
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)) return errno;
    if(n!=sizeof(type)||type!=SOCK_STREAM) return EPROTOTYPE;
    int rc=nonblock(fd); if(rc) return rc;
#ifdef SO_NOSIGPIPE
    int yes=1; if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes))) return errno;
#endif
    return 0;
}
static void notify_owner(struct vm27_host_ssh_owner_v1 *o) {
    const uint8_t b=1; ssize_t n; do {n=write(o->notify[1],&b,1);} while(n<0&&errno==EINTR);
}
static void release_lease(struct lease *l) {
    struct lease old=*l; l->fd=-1;l->release=NULL;l->context=NULL;
    if(old.fd>=0) close(old.fd);
    if(old.release) old.release(old.context);
}
static void publish(struct vm27_host_ssh_owner_v1 *o) {
    pthread_mutex_lock(&o->mutex);
    unsigned pending=0,active=0;
    for(unsigned i=0;i<SCOUNT;i++) {
        pending+=o->sessions[i].state==1; active+=o->sessions[i].state==2;
    }
    o->published.pending=pending;o->published.active=active;
    pthread_mutex_unlock(&o->mutex);
}
static void add_counter(struct vm27_host_ssh_owner_v1 *o,uint64_t *counter,uint64_t n) {
    pthread_mutex_lock(&o->mutex);*counter+=n;pthread_mutex_unlock(&o->mutex);
}
static void close_session(struct session *s) {
    if(s->state==2) {
        if(s->cancel[1]>=0) {close(s->cancel[1]);s->cancel[1]=-1;}
        pthread_join(s->thread,NULL);
        add_counter(s->owner,&s->owner->published.streams_completed,1);
        add_counter(s->owner,&s->owner->published.bytes_tcp_to_guest,s->result.bytes_left_to_right);
        add_counter(s->owner,&s->owner->published.bytes_guest_to_tcp,s->result.bytes_right_to_left);
    }
    if(s->tcp>=0) close(s->tcp);
    for(unsigned i=0;i<2;i++) if(s->cancel[i]>=0) close(s->cancel[i]);
    release_lease(&s->data);
    s->tcp=-1;s->cancel[0]=s->cancel[1]=-1;s->state=0;s->done=0;
    memset(s->token,0,sizeof(s->token));
}
static void *relay_worker(void *context) {
    struct session *s=context;
    (void)vm27_owned_stream_relay_v1_run(s->tcp,s->data.fd,s->cancel[0],
                                       s->owner->idle_ms,&s->result);
    pthread_mutex_lock(&s->owner->mutex);s->done=1;pthread_mutex_unlock(&s->owner->mutex);
    notify_owner(s->owner);return NULL;
}
static int start_session(struct session *s,struct lease *data) {
    if(pipe(s->cancel)) return errno;
    int rc=nonblock(s->cancel[0]);if(!rc)rc=nonblock(s->cancel[1]);
    if(rc){close(s->cancel[0]);close(s->cancel[1]);s->cancel[0]=s->cancel[1]=-1;return rc;}
    s->data=*data;data->fd=-1;data->release=NULL;data->context=NULL;
    rc=pthread_create(&s->thread,NULL,relay_worker,s);
    if(rc){release_lease(&s->data);close(s->cancel[0]);close(s->cancel[1]);
        s->cancel[0]=s->cancel[1]=-1;return rc;}
    s->state=2;add_counter(s->owner,&s->owner->published.streams_started,1);return 0;
}
static int token_zero(const uint8_t *p,unsigned n) {
    uint8_t x=0;for(unsigned i=0;i<n;i++)x|=p[i];return x==0;
}
static struct session *find_pending(struct vm27_host_ssh_owner_v1 *o,const uint8_t token[16]) {
    for(unsigned i=0;i<SCOUNT;i++) if(o->sessions[i].state==1 &&
        memcmp(o->sessions[i].token,token,16)==0) return &o->sessions[i];
    return NULL;
}
static void reject_handshake(struct vm27_host_ssh_owner_v1 *o,struct handshake *h) {
    release_lease(&h->lease);h->have=0;
    add_counter(o,&o->published.rejected_connections,1);
}
static void consume_handshake(struct vm27_host_ssh_owner_v1 *o,struct handshake *h) {
    uint16_t type=0;uint32_t error=0;uint8_t token[16];
    if(vm27_ssh_vsock_parse_v1(h->bytes,&type,&error,token)) {reject_handshake(o,h);return;}
    if(type==VM27_SSH_VSOCK_TYPE_HELLO && token_zero(token,16) && !error && o->control.fd<0) {
        o->control=h->lease;h->lease.fd=-1;h->lease.release=NULL;h->lease.context=NULL;
        do {arc4random_buf(o->nonce,8);}while(token_zero(o->nonce,8));
        pthread_mutex_lock(&o->mutex);o->published.ready=1;o->published.control_generation++;
        pthread_mutex_unlock(&o->mutex);return;
    }
    struct session *s=type==VM27_SSH_VSOCK_TYPE_DATA && !error &&
        o->control.fd>=0 && !memcmp(token,o->nonce,8) ? find_pending(o,token):NULL;
    if(!s){reject_handshake(o,h);return;}
    int rc=start_session(s,&h->lease);
    if(rc){close_session(s);reject_handshake(o,h);add_counter(o,&o->published.setup_errors,1);}
}
static int control_read(struct vm27_host_ssh_owner_v1 *o) {
    ssize_t n=recv(o->control.fd,o->rx+o->rx_have,32-o->rx_have,0);
    if(!n)return ECONNRESET;
    if(n<0)return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?0:errno;
    o->rx_have+=(size_t)n;if(o->rx_have<32)return 0;
    uint16_t type;uint32_t error;uint8_t token[16];o->rx_have=0;
    if(vm27_ssh_vsock_parse_v1(o->rx,&type,&error,token)||type!=VM27_SSH_VSOCK_TYPE_ERROR||
       !error||memcmp(token,o->nonce,8))return EPROTO;
    struct session *s=find_pending(o,token);if(!s)return EPROTO;
    close_session(s);add_counter(o,&o->published.setup_errors,1);return 0;
}
static int control_write(struct vm27_host_ssh_owner_v1 *o) {
    ssize_t n=send(o->control.fd,o->tx+o->tx_offset,o->tx_length,0);
    if(n<0)return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?0:errno;
    if(!n)return EIO;
    o->tx_offset+=(size_t)n;o->tx_length-=(size_t)n;
    if(!o->tx_length)o->tx_offset=0;return 0;
}
static int directly_attached_peer(const struct sockaddr *peer) {
    struct ifaddrs *rows=NULL;if(getifaddrs(&rows))return 0;int allowed=0;
    for(struct ifaddrs *r=rows;r&&!allowed;r=r->ifa_next) {
        if(!r->ifa_addr||!r->ifa_netmask||!(r->ifa_flags&IFF_UP)||
           r->ifa_addr->sa_family!=peer->sa_family)continue;
        const uint8_t *a,*b,*m;size_t count;
        if(peer->sa_family==AF_INET) {
            a=(const uint8_t*)&((const struct sockaddr_in*)peer)->sin_addr;
            b=(const uint8_t*)&((const struct sockaddr_in*)r->ifa_addr)->sin_addr;
            m=(const uint8_t*)&((const struct sockaddr_in*)r->ifa_netmask)->sin_addr;count=4;
        } else if(peer->sa_family==AF_INET6) {
            const struct sockaddr_in6 *v=(const struct sockaddr_in6*)peer;
            const struct sockaddr_in6 *local=(const struct sockaddr_in6*)r->ifa_addr;
            if(IN6_IS_ADDR_LINKLOCAL(&v->sin6_addr)&&v->sin6_scope_id!=local->sin6_scope_id)continue;
            a=v->sin6_addr.s6_addr;b=local->sin6_addr.s6_addr;
            m=((const struct sockaddr_in6*)r->ifa_netmask)->sin6_addr.s6_addr;count=16;
        } else continue;
        unsigned difference=0,nonzero_mask=0;
        for(size_t i=0;i<count;i++){difference|=(a[i]^b[i])&m[i];nonzero_mask|=m[i];}
        allowed=!difference&&nonzero_mask;
    }
    freeifaddrs(rows);return allowed;
}
static int lan_peer(const struct sockaddr *peer) {
    if(peer->sa_family==AF_INET) {
        uint32_t a=ntohl(((const struct sockaddr_in*)peer)->sin_addr.s_addr);
        if((a>>24)==127||(a>>24)==10||(a>>20)==0xac1||(a>>16)==0xc0a8||(a>>16)==0xa9fe)return 1;
    } else if(peer->sa_family==AF_INET6) {
        const struct in6_addr *a=&((const struct sockaddr_in6*)peer)->sin6_addr;
        if(IN6_IS_ADDR_LOOPBACK(a)||IN6_IS_ADDR_LINKLOCAL(a)||(a->s6_addr[0]&0xfe)==0xfc)return 1;
    }
    return directly_attached_peer(peer);
}
static int accept_tcp(struct vm27_host_ssh_owner_v1 *o,int listener) {
    struct sockaddr_storage peer;socklen_t peer_size=sizeof(peer);
    int fd=accept(listener,(struct sockaddr*)&peer,&peer_size);if(fd<0)
        return errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR?0:errno;
    if(o->scope==VM27SSHLANV3&&!lan_peer((struct sockaddr*)&peer)){close(fd);return 0;}
    int rc=prepare_socket(fd);struct session *s=NULL;
    for(unsigned i=0;i<SCOUNT;i++)if(!o->sessions[i].state){s=&o->sessions[i];break;}
    if(rc||!s||o->control.fd<0||o->tx_length>sizeof(o->tx)-32){close(fd);return 0;}
    pthread_mutex_lock(&o->mutex);
    uint64_t seq=o->published.last_sequence;
    if(seq!=UINT64_MAX)o->published.last_sequence=++seq;
    pthread_mutex_unlock(&o->mutex);
    if(seq==UINT64_MAX){close(fd);return EOVERFLOW;}
    s->tcp=fd;s->state=1;s->deadline=now_ms()+VM27_SSH_VSOCK_CONNECT_MS;
    memcpy(s->token,o->nonce,8);
    for(unsigned i=0;i<8;i++)s->token[8+i]=(uint8_t)(seq>>(56-8*i));
    if(o->tx_offset){memmove(o->tx,o->tx+o->tx_offset,o->tx_length);o->tx_offset=0;}
    vm27_ssh_vsock_header_v1(o->tx+o->tx_length,VM27_SSH_VSOCK_TYPE_START,0,s->token);
    o->tx_length+=32;return 0;
}
static void drain_incoming(struct vm27_host_ssh_owner_v1 *o) {
    struct lease q[HCOUNT];unsigned count;
    pthread_mutex_lock(&o->mutex);count=o->incoming_count;
    memcpy(q,o->incoming,count*sizeof(q[0]));o->incoming_count=0;
    pthread_mutex_unlock(&o->mutex);
    for(unsigned j=0;j<count;j++) {
        struct handshake *h=NULL;
        for(unsigned i=0;i<HCOUNT;i++)if(o->handshake[i].lease.fd<0){h=&o->handshake[i];break;}
        if(!h){release_lease(&q[j]);add_counter(o,&o->published.rejected_connections,1);continue;}
        h->lease=q[j];h->have=0;h->deadline=now_ms()+VM27_SSH_VSOCK_CONNECT_MS;
    }
}
/* A VZ socket can disconnect while iPadOS suspends the foreground App on
 * lock. Keep the owned TCP listener, discard every old-generation token and
 * require a fresh genuine guest HELLO before opening any new stream. */
static int recoverable_control_transport(int error) {
    return error==ECONNRESET || error==EPIPE || error==ENOTCONN || error==ETIMEDOUT;
}
static void reset_control_generation(struct vm27_host_ssh_owner_v1 *o) {
    release_lease(&o->control);
    for(unsigned i=0;i<SCOUNT;i++)close_session(&o->sessions[i]);
    for(unsigned i=0;i<HCOUNT;i++) {
        release_lease(&o->handshake[i].lease);o->handshake[i].have=0;
    }
    memset(o->nonce,0,sizeof(o->nonce));
    memset(o->rx,0,sizeof(o->rx));memset(o->tx,0,sizeof(o->tx));
    o->rx_have=o->tx_offset=o->tx_length=0;
    pthread_mutex_lock(&o->mutex);o->published.ready=0;pthread_mutex_unlock(&o->mutex);
    publish(o);
}
static void *owner_worker(void *context) {
    struct vm27_host_ssh_owner_v1 *o=context;int error=0;
    for(;;) {
        pthread_mutex_lock(&o->mutex);int cancelled=o->cancel_requested;pthread_mutex_unlock(&o->mutex);
        if(cancelled){error=ECANCELED;break;}
        drain_incoming(o);
        for(unsigned i=0;i<SCOUNT;i++) {
            struct session *s=&o->sessions[i];pthread_mutex_lock(&o->mutex);
            int done=s->done;pthread_mutex_unlock(&o->mutex);
            if(done)close_session(s);
            else if(s->state==1 && now_ms()>=s->deadline){close_session(s);add_counter(o,&o->published.setup_errors,1);}
        }
        for(unsigned i=0;i<HCOUNT;i++)if(o->handshake[i].lease.fd>=0 &&
            now_ms()>=o->handshake[i].deadline)reject_handshake(o,&o->handshake[i]);
        publish(o);
        struct pollfd p[4+HCOUNT];
        p[0]=(struct pollfd){o->notify[0],POLLIN,0};p[1]=(struct pollfd){o->listeners[0],POLLIN,0};
        p[2]=(struct pollfd){o->listeners[1],POLLIN,0};
        p[3]=(struct pollfd){o->control.fd,(short)(POLLIN|(o->tx_length?POLLOUT:0)),0};
        for(unsigned i=0;i<HCOUNT;i++)p[4+i]=(struct pollfd){o->handshake[i].lease.fd,POLLIN,0};
        int n=poll(p,4+HCOUNT,50);if(n<0){if(errno==EINTR)continue;error=errno;break;}
        if(p[0].revents){uint8_t b[128];while(read(o->notify[0],b,sizeof(b))>0){}continue;}
        if(p[1].revents && (error=accept_tcp(o,o->listeners[0])))break;
        if(p[2].revents && (error=accept_tcp(o,o->listeners[1])))break;
        if(p[3].revents&(POLLIN|POLLHUP|POLLERR|POLLNVAL))error=control_read(o);
        if(!error && (p[3].revents&POLLOUT))error=control_write(o);
        if(error) {
            if(!recoverable_control_transport(error))break;
            reset_control_generation(o);error=0;
            /* The poll array refers to the discarded generation. */
            continue;
        }
        for(unsigned i=0;i<HCOUNT;i++)if(p[4+i].revents) {
            struct handshake *h=&o->handshake[i];
            ssize_t r=recv(h->lease.fd,h->bytes+h->have,32-h->have,0);
            if(r>0){h->have+=(size_t)r;if(h->have==32)consume_handshake(o,h);}
            else if(!r||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))reject_handshake(o,h);
        }
    }
    pthread_mutex_lock(&o->mutex);o->cancel_requested=1;pthread_mutex_unlock(&o->mutex);
    for(unsigned i=0;i<2;i++){if(o->listeners[i]>=0)close(o->listeners[i]);o->listeners[i]=-1;}
    release_lease(&o->control);
    drain_incoming(o);
    for(unsigned i=0;i<HCOUNT;i++)release_lease(&o->handshake[i].lease);
    for(unsigned i=0;i<SCOUNT;i++)close_session(&o->sessions[i]);
    publish(o);
    pthread_mutex_lock(&o->mutex);o->published.ready=0;o->published.error=error;o->published.stopped=1;
    pthread_mutex_unlock(&o->mutex);return NULL;
}
static int create_listener(unsigned family,unsigned scope,uint16_t *port,int *output) {
    int af=family==VM27SSHIPv4V3?AF_INET:AF_INET6;
    int fd=socket(af,SOCK_STREAM,0);if(fd<0)return errno;int rc=prepare_socket(fd);
    int one=1;
    if(!rc&&setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)))rc=errno;
    if(!rc&&af==AF_INET6&&setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one)))rc=errno;
    struct sockaddr_storage storage;memset(&storage,0,sizeof(storage));socklen_t length;
    if(af==AF_INET) {
        struct sockaddr_in *v=(void*)&storage;length=sizeof(*v);v->sin_family=AF_INET;v->sin_port=htons(*port);
#ifdef __APPLE__
        v->sin_len=sizeof(*v);
#endif
        v->sin_addr.s_addr=htonl(scope==VM27SSHLocalV3?INADDR_LOOPBACK:INADDR_ANY);
    } else {
        struct sockaddr_in6 *v=(void*)&storage;length=sizeof(*v);v->sin6_family=AF_INET6;v->sin6_port=htons(*port);
#ifdef __APPLE__
        v->sin6_len=sizeof(*v);
#endif
        v->sin6_addr=scope==VM27SSHLocalV3?in6addr_loopback:in6addr_any;
    }
    if(!rc&&(bind(fd,(struct sockaddr*)&storage,length)||listen(fd,SCOUNT)))rc=errno;
    if(!rc&&getsockname(fd,(struct sockaddr*)&storage,&length))rc=errno;
    if(rc){close(fd);return rc;}
    *port=ntohs(af==AF_INET?((struct sockaddr_in*)&storage)->sin_port:((struct sockaddr_in6*)&storage)->sin6_port);
    *output=fd;return 0;
}
int vm27_host_ssh_owner_v3_create(uint16_t port,unsigned scope,unsigned families,uint32_t idle,struct vm27_host_ssh_owner_v1 **out) {
    if(!out)return EINVAL;*out=NULL;
    if(!idle||idle>3600000||scope>VM27SSHInternetV3||!families||(families&~3u))return EINVAL;
    struct vm27_host_ssh_owner_v1 *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
    o->listeners[0]=o->listeners[1]=o->notify[0]=o->notify[1]=o->control.fd=-1;o->idle_ms=idle;o->scope=scope;
    for(unsigned i=0;i<HCOUNT;i++)o->handshake[i].lease.fd=-1;
    for(unsigned i=0;i<SCOUNT;i++) {
        o->sessions[i].owner=o;o->sessions[i].tcp=o->sessions[i].data.fd=-1;
        o->sessions[i].cancel[0]=o->sessions[i].cancel[1]=-1;
    }
    int rc=pthread_mutex_init(&o->mutex,NULL);if(rc){free(o);return rc;}
    if(families&VM27SSHIPv4V3){rc=create_listener(VM27SSHIPv4V3,scope,&port,&o->listeners[0]);if(rc)goto fail;}
    if(families&VM27SSHIPv6V3){rc=create_listener(VM27SSHIPv6V3,scope,&port,&o->listeners[1]);if(rc)goto fail;}
    o->published.tcp_port=port;
    if(pipe(o->notify)){rc=errno;goto fail;}
    if((rc=nonblock(o->notify[0]))||(rc=nonblock(o->notify[1])))goto fail;
    rc=pthread_create(&o->thread,NULL,owner_worker,o);if(rc)goto fail;
    *out=o;return 0;
fail:
    for(unsigned i=0;i<2;i++){if(o->listeners[i]>=0)close(o->listeners[i]);if(o->notify[i]>=0)close(o->notify[i]);}
    pthread_mutex_destroy(&o->mutex);free(o);return rc;
}
int vm27_host_ssh_owner_v1_create(uint16_t port,uint32_t idle,struct vm27_host_ssh_owner_v1 **out) {
    return vm27_host_ssh_owner_v3_create(port,VM27SSHLocalV3,VM27SSHIPv4V3,idle,out);
}
int vm27_host_ssh_owner_v1_admit(struct vm27_host_ssh_owner_v1 *o,int fd,
                               vm27_host_ssh_release_v1 release,void *ctx) {
    if(!o||fd<0)return EINVAL;
    int rc=prepare_socket(fd);if(rc)return rc;
    pthread_mutex_lock(&o->mutex);
    if(o->cancel_requested)rc=ECANCELED;
    else if(o->incoming_count==HCOUNT)rc=EBUSY;
    else o->incoming[o->incoming_count++]=(struct lease){fd,release,ctx};
    pthread_mutex_unlock(&o->mutex);if(!rc)notify_owner(o);return rc;
}
int vm27_host_ssh_owner_v1_snapshot(struct vm27_host_ssh_owner_v1 *o,struct vm27_host_ssh_snapshot_v1 *out) {
    if(!o||!out)return EINVAL;pthread_mutex_lock(&o->mutex);*out=o->published;
    pthread_mutex_unlock(&o->mutex);return 0;
}
void vm27_host_ssh_owner_v1_cancel(struct vm27_host_ssh_owner_v1 *o) {
    if(!o)return;pthread_mutex_lock(&o->mutex);o->cancel_requested=1;
    pthread_mutex_unlock(&o->mutex);notify_owner(o);
}
void vm27_host_ssh_owner_v1_destroy(struct vm27_host_ssh_owner_v1 *o) {
    if(!o)return;vm27_host_ssh_owner_v1_cancel(o);pthread_join(o->thread,NULL);
    close(o->notify[0]);close(o->notify[1]);pthread_mutex_destroy(&o->mutex);free(o);
}
