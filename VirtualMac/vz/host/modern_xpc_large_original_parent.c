#include "modern_xpc_large_original_parent.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int Hex(const char *s,size_t n) {
 if(!s||strnlen(s,n+1)!=n)return 0;
 for(size_t i=0;i<n;++i)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
 return 1;
}
int VM27LargeOriginalParentCheckFile(const char *path,const char *SHA,const char *CD,VM27ApprovedCodeInfo *out) {
 if(!out)return EINVAL;memset(out,0,sizeof(*out));
 if(!path||path[0]!='/'||strnlen(path,4096)>=4096||!Hex(SHA,64)||!Hex(CD,40))return EINVAL;
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return errno;
 struct stat before={0},after={0};int status=0;unsigned char *data=NULL;
 if(fstat(fd,&before))status=errno;
 else if(!S_ISREG(before.st_mode)||before.st_uid!=geteuid()||before.st_nlink!=1||(before.st_mode&0022)||!(before.st_mode&S_IXUSR)||before.st_size<=0||before.st_size>8*1024*1024)status=EACCES;
 if(!status&&!(data=malloc((size_t)before.st_size)))status=ENOMEM;
 size_t count=0;
 while(!status&&count<(size_t)before.st_size) {
  ssize_t n=pread(fd,data+count,(size_t)before.st_size-count,(off_t)count);
  if(n<0&&errno==EINTR)continue;if(n<=0)status=n<0?errno:EIO;else count+=(size_t)n;
 }
 if(!status&&fstat(fd,&after))status=errno;
 if(!status&&(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mode!=after.st_mode||before.st_uid!=after.st_uid||before.st_nlink!=after.st_nlink||before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec||before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec||before.st_ctimespec.tv_sec!=after.st_ctimespec.tv_sec||before.st_ctimespec.tv_nsec!=after.st_ctimespec.tv_nsec))status=ESTALE;
 if(!status)status=VM27ApprovedCodeInspectBytes(data,count,out);
 if(!status&&(strcmp(out->fileSHA256,SHA)||strcmp(out->CDHash,CD)))status=EACCES;
 free(data);if(close(fd)&&!status)status=errno;if(status)memset(out,0,sizeof(*out));return status;
}
