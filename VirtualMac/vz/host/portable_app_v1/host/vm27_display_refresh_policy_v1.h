#ifndef VM27_DISPLAY_REFRESH_POLICY_V1_H
#define VM27_DISPLAY_REFRESH_POLICY_V1_H
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#define VM27_DISPLAY_REFRESH_KEY @"ProMotion120HzEnabled"
#define VM27_REFRESH_DIRECTORY_V1 "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/display-session-v1"
typedef struct {uint32_t magic,version,parentPID,hertz;} VM27RefreshPlanV1;
static inline unsigned VM27RefreshSelectV1(int requested,int maximum,int lowPower) {
 return requested && maximum>=120 && !lowPower?120:60;
}
static inline int VM27RefreshDirectoryV1(int create) {
 if(getuid()!=501 || geteuid()!=501)return -1;
 if(create && mkdir(VM27_REFRESH_DIRECTORY_V1,0700) && errno!=EEXIST)return -1;
 int fd=open(VM27_REFRESH_DIRECTORY_V1,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
 if(fd>=0 && (fstat(fd,&st) || st.st_uid!=501 || (st.st_mode&0777)!=0700)){close(fd);return -1;}
 return fd;
}
static inline int VM27RefreshWriteV1(unsigned hertz) {
 if(hertz!=60 && hertz!=120)return EINVAL;
 int dir=VM27RefreshDirectoryV1(1);if(dir<0)return EACCES;
 char name[64],temporary[64];snprintf(name,sizeof(name),"%u.bin",(unsigned)getpid());
 snprintf(temporary,sizeof(temporary),"%u.pending",(unsigned)getpid());
 int fd=openat(dir,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd<0){close(dir);return EIO;}
 VM27RefreshPlanV1 plan={0x564d485a,1,(uint32_t)getpid(),hertz};
 int result=write(fd,&plan,sizeof(plan))==(ssize_t)sizeof(plan)?0:EIO;
 if(close(fd) && !result)result=EIO;
 if(!result && renameat(dir,temporary,dir,name))result=EIO;
 if(result)unlinkat(dir,temporary,0);close(dir);return result;
}
static inline unsigned VM27RefreshReadParentV1(void) {
 int dir=VM27RefreshDirectoryV1(0);if(dir<0)return 60;
 pid_t parent=getppid();char name[64];snprintf(name,sizeof(name),"%u.bin",(unsigned)parent);
 int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(dir);if(fd<0)return 60;
 struct stat st;VM27RefreshPlanV1 plan={0};
 int valid=parent>1 && !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==501 &&
  (st.st_mode&0777)==0600 && st.st_nlink==1 && st.st_size==sizeof(plan) &&
  read(fd,&plan,sizeof(plan))==(ssize_t)sizeof(plan);
 if(close(fd))valid=0;
 return valid && plan.magic==0x564d485a && plan.version==1 && plan.parentPID==(uint32_t)parent &&
  (plan.hertz==60 || plan.hertz==120)?plan.hertz:60;
}
static inline void VM27RefreshRemoveV1(void) {
 int dir=VM27RefreshDirectoryV1(0);if(dir<0)return;
 char name[64];snprintf(name,sizeof(name),"%u.bin",(unsigned)getpid());
 struct stat st;if(!fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode) &&
  st.st_uid==501 && (st.st_mode&0777)==0600 && st.st_nlink==1 && st.st_size==sizeof(VM27RefreshPlanV1))unlinkat(dir,name,0);
 close(dir);
}
#endif
