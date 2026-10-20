/* One bounded, read-only dyld image table of the controller-identified VMM.
 * No guest memory interpretation, remote calls, suspend, signals or writes. */
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static mach_port_t target;
static unsigned calls;
static size_t bytes;
static bool read_data(uint64_t at,size_t n,void *out) {
 if(!n||n>32768||at<0x10000||at>UINT64_C(0x0000ffffffffffff)-n||calls>=2200||bytes+n>16777216)return false;
 ++calls;bytes+=n;vm_size_t got=0;
 return vm_read_overwrite(target,(vm_address_t)at,n,(vm_address_t)out,&got)==KERN_SUCCESS&&got==n;
}
int main(int argc,char **argv) {
 if(argc!=2||getuid()!=0)return 64;
 char *end=NULL;long pid=strtol(argv[1],&end,10);if(!end||*end||pid<=1||pid>0x3fffff)return 64;
 kern_return_t k=task_for_pid(mach_task_self(),(pid_t)pid,&target);if(k){fprintf(stderr,"IMAGE_TASK_FAILED kr=%d\n",k);return 2;}
 struct task_dyld_info info={0};mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
 k=task_info(target,TASK_DYLD_INFO,(task_info_t)&info,&count);
 if(k||count!=TASK_DYLD_INFO_COUNT||info.all_image_info_format!=TASK_DYLD_ALL_IMAGE_INFO_64||info.all_image_info_size<16)return 3;
 struct {uint32_t version,count;uint64_t array;} first={0},last={0};
 if(!read_data(info.all_image_info_addr,sizeof(first),&first)||first.version<1||first.version>32||!first.count||first.count>1024||!first.array)return 4;
 struct {uint64_t header,path,date;} images[1024];size_t table=first.count*sizeof(images[0]);
 if(!read_data(first.array,table,images))return 5;
 unsigned emitted=0,unread=0;uint8_t commands[32768];
 printf("VM27_DYLD_BEGIN pid=%ld version=%u images=%u readOnly=1 suspend=0 writes=0\n",pid,first.version,first.count);
 for(unsigned i=0;i<first.count;++i) {
  struct mach_header_64 h={0};
  if(!read_data(images[i].header,sizeof(h),&h)||h.magic!=MH_MAGIC_64||h.cputype!=CPU_TYPE_ARM64||h.ncmds>2048||h.sizeofcmds<8||h.sizeofcmds>sizeof(commands)||!read_data(images[i].header+sizeof(h),h.sizeofcmds,commands)){++unread;continue;}
  size_t at=0;const uint8_t *uuid=NULL;uint64_t size=0;bool valid=true;
  for(unsigned j=0;j<h.ncmds;++j){
   if(at+8>h.sizeofcmds){valid=false;break;}
   uint32_t cmd=0,z=0;memcpy(&cmd,commands+at,4);memcpy(&z,commands+at+4,4);
   if(z<8||z%8||z>h.sizeofcmds-at){valid=false;break;}
   if(cmd==LC_UUID&&z==24)uuid=commands+at+8;
   if(cmd==LC_SEGMENT_64&&z>=72&&memcmp(commands+at+8,"__TEXT\0",7)==0)memcpy(&size,commands+at+32,8);
   at+=z;
  }
  if(!valid||at!=h.sizeofcmds||!uuid||!size){++unread;continue;}
  printf("VM27_DYLD_IMAGE load=0x%llx textSize=0x%llx uuid=",(unsigned long long)images[i].header,(unsigned long long)size);for(unsigned j=0;j<16;++j)printf("%02x",uuid[j]);putchar('\n');++emitted;
 }
 bool stable=read_data(info.all_image_info_addr,sizeof(last),&last)&&memcmp(&first,&last,sizeof(first))==0;
 printf("VM27_DYLD_END emitted=%u unread=%u arrayStable=%u reads=%u bytes=%zu atomicSnapshot=0\n",emitted,unread,stable,calls,bytes);mach_port_deallocate(mach_task_self(),target);return stable&&emitted&&!unread?0:6;
}
