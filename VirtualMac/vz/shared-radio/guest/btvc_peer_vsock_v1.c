// Guest-only native VZ listener. The Python protocol worker owns no LAN socket.
// Accept only the hypervisor host CID, then pass the owned stream as stdio.
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/wait.h>
#include <spawn.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
extern char **environ;
static volatile sig_atomic_t stopping;
static void stop(int signal) {(void)signal;stopping=1;}
int main(int argc,char **argv) {
    if(argc!=4||argv[1][0]!='/'||argv[2][0]!='/'||argv[3][0]!='/')return 64;
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,SIG_IGN);
    int listener=socket(AF_VSOCK,SOCK_STREAM,0);if(listener<0)return errno;
    if(fcntl(listener,F_SETFD,FD_CLOEXEC)){close(listener);return errno;}
    struct sockaddr_vm address={0};address.svm_len=sizeof(address);address.svm_family=AF_VSOCK;
    address.svm_cid=VMADDR_CID_ANY;address.svm_port=39030;
    if(bind(listener,(void *)&address,sizeof(address))||listen(listener,1)){int error=errno;close(listener);return error;}
    fprintf(stderr,"VM27PeerVSOCK listening port=39030 hostCIDOnly=1\n");
    while(!stopping) {
        struct pollfd item={listener,POLLIN,0};int ready=poll(&item,1,1000);
        if(ready<0&&errno==EINTR)continue;if(ready<=0)continue;
        struct sockaddr_vm peer={0};socklen_t size=sizeof(peer);
        int fd=accept(listener,(void *)&peer,&size);if(fd<0)continue;
        if(size!=sizeof(peer)||peer.svm_family!=AF_VSOCK||peer.svm_cid!=VMADDR_CID_HOST){close(fd);continue;}
        int one=1,flags=fcntl(fd,F_GETFL);
        if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)||setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))){close(fd);continue;}
        posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions,fd,STDIN_FILENO);posix_spawn_file_actions_adddup2(&actions,fd,STDOUT_FILENO);
        if(fd>STDERR_FILENO)posix_spawn_file_actions_addclose(&actions,fd);
        posix_spawn_file_actions_addclose(&actions,listener);
        char *arguments[]={argv[1],argv[2],"--state",argv[3],"--stdio",NULL};pid_t child=0;
        int error=posix_spawn(&child,argv[1],&actions,NULL,arguments,environ);
        posix_spawn_file_actions_destroy(&actions);close(fd);
        if(error){fprintf(stderr,"VM27PeerVSOCK spawn failed errno=%d\n",error);continue;}
        int status=0;
        while(!stopping) {
            pid_t result=waitpid(child,&status,WNOHANG);
            if(result==child){child=0;break;}if(result<0&&errno!=EINTR){child=0;break;}
            poll(NULL,0,100);
        }
        if(child>0) {
            kill(child,SIGTERM);
            for(unsigned i=0;i<30;++i){pid_t result=waitpid(child,&status,WNOHANG);if(result==child){child=0;break;}poll(NULL,0,100);}
            if(child>0){kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}
        }
        fprintf(stderr,"VM27PeerVSOCK worker stream closed\n");
    }
    close(listener);return 0;
}
