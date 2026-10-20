#include "vm27_owned_qga_connection_lease_v3.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static uint64_t now=1000000000;
static bool time_ok=true;
static unsigned checks;
bool VM27QGAFixtureTimeV3(uint64_t *out) {*out=now;return time_ok;}
static void check(bool valid) {if(!valid){fprintf(stderr,"failed check %u\n",checks+1);abort();}++checks;}
static void pair(int f[2]) {check(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0);}
int main(void) {
    alarm(10);
    int a[2],b[2];pair(a);pair(b);VM27OwnedQGALeaseV3 lease;
    check(VM27OwnedQGALeaseCreateV3(&lease,a[0],1,4)==VM27QGAValidV3);
    check(lease.ownedFD!=a[0] && (fcntl(lease.ownedFD,F_GETFD)&FD_CLOEXEC));
    check(VM27OwnedQGALeaseCheckV3(&lease,a[0],1,4)==VM27QGAValidV3);
    check(VM27OwnedQGALeaseCheckV3(&lease,a[0],2,4)==VM27QGAStaleV3);
    check(VM27OwnedQGALeaseCheckV3(&lease,a[0],1,5)==VM27QGAStaleV3);
    check(VM27OwnedQGALeaseCheckV3(&lease,b[0],1,4)==VM27QGAStaleV3);
    const char packet[]="{\"execute\":\"guest-info\"}\n";
    check(VM27OwnedQGALeaseSendV3(&lease,a[0],1,4,packet,sizeof(packet)-1)==VM27QGAValidV3);
    char received[128];check(recv(a[1],received,sizeof(received),0)==(ssize_t)(sizeof(packet)-1));
    check(!memcmp(packet,received,sizeof(packet)-1));
    now=lease.deadlineNS;check(VM27OwnedQGALeaseCheckV3(&lease,a[0],1,4)==VM27QGAExpiredV3);
    check(VM27OwnedQGALeaseSendV3(&lease,a[0],1,4,packet,sizeof(packet)-1)==VM27QGAExpiredV3);
    check(VM27OwnedQGALeaseCloseV3(&lease,true)==VM27QGAValidV3);
    check(recv(a[1],received,sizeof(received),0)==0);
    check(send(b[0],packet,sizeof(packet)-1,0)==(ssize_t)(sizeof(packet)-1));
    check(recv(b[1],received,sizeof(received),0)==(ssize_t)(sizeof(packet)-1));
    check(VM27OwnedQGALeaseCheckV3(&lease,a[0],1,4)==VM27QGACancelledV3);
    close(a[0]);close(a[1]);
    now=1;check(VM27OwnedQGALeaseCreateV3(&lease,b[0],3,6)==VM27QGAValidV3);
    check(VM27OwnedQGALeaseCloseV3(&lease,false)==VM27QGAValidV3);
    check(send(b[0],packet,sizeof(packet)-1,0)==(ssize_t)(sizeof(packet)-1));
    check(recv(b[1],received,sizeof(received),0)==(ssize_t)(sizeof(packet)-1));
    int p[2];check(pipe(p)==0);check(VM27OwnedQGALeaseCreateV3(&lease,p[0],4,8)==VM27QGANativeFailureV3);close(p[0]);close(p[1]);
    now=UINT64_MAX;check(VM27OwnedQGALeaseCreateV3(&lease,b[0],4,8)==VM27QGANativeFailureV3);
    now=1;time_ok=false;check(VM27OwnedQGALeaseCreateV3(&lease,b[0],4,8)==VM27QGANativeFailureV3);time_ok=true;
    int buffer=4096;check(setsockopt(b[0],SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer))==0);
    check(VM27OwnedQGALeaseCreateV3(&lease,b[0],5,9)==VM27QGAValidV3);
    char *large=malloc(2097152);check(large!=NULL);memset(large,'x',2097152);
    check(VM27OwnedQGALeaseSendV3(&lease,b[0],5,9,large,2097152)==VM27QGANativeFailureV3);
    check(VM27OwnedQGALeaseCloseV3(&lease,true)==VM27QGAValidV3);free(large);
    close(b[0]);close(b[1]);
    pair(a);pair(b);now=1;
    check(VM27OwnedQGALeaseCreateV3(&lease,a[0],8,10)==VM27QGAValidV3);
    int old=a[0];check(close(old)==0);check(dup2(b[0],old)==old);
    check(VM27OwnedQGALeaseCheckV3(&lease,old,8,10)==VM27QGAStaleV3);
    check(VM27OwnedQGALeaseSendV3(&lease,old,8,10,packet,sizeof(packet)-1)==VM27QGAStaleV3);
    check(VM27OwnedQGALeaseCloseV3(&lease,true)==VM27QGAValidV3);check(recv(a[1],received,sizeof(received),0)==0);
    check(send(old,packet,sizeof(packet)-1,0)==(ssize_t)(sizeof(packet)-1));
    check(recv(b[1],received,sizeof(received),0)==(ssize_t)(sizeof(packet)-1));
    close(old);close(a[1]);close(b[0]);close(b[1]);printf("QGA lease v3: %u finite real-socket checks passed\n",checks);return 0;
}
