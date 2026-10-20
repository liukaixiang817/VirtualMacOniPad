#include "vm27_guest_vsock_ssh_helper_v1.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t cancellation_write_v1=-1;
static void cancel_v1(int signal_number) {
    (void)signal_number;int saved=errno;
    uint8_t b=1;int fd=(int)cancellation_write_v1;
    if(fd>=0){ssize_t ignored=write(fd,&b,1);(void)ignored;}
    errno=saved;
}
int main(int argc,char **argv) {
    if(argc!=2||strcmp(argv[1],"--serve-v1")){
        fprintf(stderr,"usage: vm27-guest-vsock-ssh --serve-v1\n");return 64;
    }
    int p[2];if(pipe(p)){perror("own cancellation pipe");return 70;}
    for(unsigned i=0;i<2;i++){
        int flags=fcntl(p[i],F_GETFL);
        if(flags<0||fcntl(p[i],F_SETFL,flags|O_NONBLOCK)){
            perror("own pipe nonblocking");close(p[0]);close(p[1]);return 70;
        }
    }
    cancellation_write_v1=p[1];struct sigaction action={0};
    action.sa_handler=cancel_v1;sigemptyset(&action.sa_mask);
    if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)){
        perror("own signal cancellation");cancellation_write_v1=-1;
        close(p[0]);close(p[1]);return 70;
    }
    fprintf(stderr,"VM27_GUEST_VSOCK_PROCESS pid=%ld uid=%ld euid=%ld\n",(long)getpid(),(long)getuid(),(long)geteuid());
    int e=vm27_guest_vsock_ssh_helper_v1_run(p[0],600000);
    cancellation_write_v1=-1;close(p[0]);close(p[1]);
    return e==ECANCELED?0:e==0?0:1;
}
