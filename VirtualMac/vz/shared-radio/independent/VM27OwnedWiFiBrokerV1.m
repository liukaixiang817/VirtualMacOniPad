// One root physical actor serves isolated authenticated guest data sessions.
// Closing a virtual data session does not tear down its physical STA.
#include <sys/types.h>
#ifdef VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME
static int VM27OwnedWiFiSessionProxyV1(int fd,uid_t owner);
#endif
#define main VM27OwnedWiFiWorkerMainV1
#include "../../development/probes/builtin-wifi-auxiliary-station-lease-v1.m"
#undef main
#include <spawn.h>
extern char **environ;

static const char *OwnedDirectory="/var/run/VirtualMacRadioOwned-v1";
static const char *OwnedSocket="/var/run/VirtualMacRadioOwned-v1/independent-wifi.sock";
static const char *OwnedExecutable="/var/jb/usr/local/libexec/virtualmac-owned-wifi-v1";

static int ownedWorker(int fd){
 if(fd<3)return EINVAL;
 char value[16];snprintf(value,sizeof(value),"%d",fd);
 const char *args[]={OwnedExecutable,"--serve-owned-station-fd",value,NULL};
 OwnedStationSessionFD=fd;
 int result=VM27OwnedWiFiWorkerMainV1(3,args);
 if(OwnedStationSessionFD==fd){OwnedStationSessionFD=-1;close(fd);}
 return result;
}
#ifdef VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME
#include "VM27OwnedWiFiSessionProxyV1.inc"
#endif
#ifndef VM27_OWNED_SUPERVISOR_ENTRY
#define VM27_OWNED_SUPERVISOR_ENTRY main
#endif
int VM27_OWNED_SUPERVISOR_ENTRY(int argc,const char **argv){@autoreleasepool{
 if(argc>1)return VM27OwnedWiFiWorkerMainV1(argc,argv);
 if(geteuid())return 77;
 char model[32]={0},build[32]={0};size_t modelSize=sizeof(model),buildSize=sizeof(build);
 if(sysctlbyname("hw.machine",model,&modelSize,NULL,0)||strcmp(model,"iPad14,6")||
    sysctlbyname("kern.osversion",build,&buildSize,NULL,0)||strcmp(build,"20B101"))return 78;
 signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
 struct stat directory;
 if(lstat(OwnedDirectory,&directory)&&errno==ENOENT){if(mkdir(OwnedDirectory,0750)||chown(OwnedDirectory,0,501))return errno;}
 if(lstat(OwnedDirectory,&directory)||!S_ISDIR(directory.st_mode)||directory.st_uid||directory.st_gid!=501||(directory.st_mode&0027))return 77;
 int lock=open("/var/run/VirtualMacRadioOwned-v1/independent-wifi.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
 struct stat lockInfo;if(lock<0||fstat(lock,&lockInfo)||!S_ISREG(lockInfo.st_mode)||lockInfo.st_uid||lockInfo.st_nlink!=1||(lockInfo.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB))return 73;
 // A live orphan has no in-memory credential proof and cannot be adopted.
 struct stat old;if(!lstat(OwnedSocket,&old)){if(!S_ISSOCK(old.st_mode)||old.st_uid||unlink(OwnedSocket))return 77;}else if(errno!=ENOENT)return errno;
 int server=socket(AF_UNIX,SOCK_STREAM,0);if(server<0)return errno;fcntl(server,F_SETFD,FD_CLOEXEC);
 struct sockaddr_un address={.sun_len=sizeof(address),.sun_family=AF_UNIX};strlcpy(address.sun_path,OwnedSocket,sizeof(address.sun_path));
 if(bind(server,(void *)&address,sizeof(address))||chown(OwnedSocket,0,501)||chmod(OwnedSocket,0660)||listen(server,1))return errno;
 while(!Stop){
  struct pollfd p={server,POLLIN,0};int ready=poll(&p,1,500);if(ready<0&&errno!=EINTR)break;if(ready<=0)continue;
  int peer=accept(server,NULL,NULL);if(peer<0)continue;fcntl(peer,F_SETFD,FD_CLOEXEC);
  if(!VM27OwnedWiFiPeerAllowedV1(peer,501,"/var/jb/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27")){close(peer);continue;}
  int result=ownedWorker(peer);fprintf(stderr,"[OwnedWiFi] VM lease ended status=%d\n",result);
  // Closing one guest never triggers physical recovery or credential erasure.
 }
 close(server);unlink(OwnedSocket);close(lock);return 0;
}}
