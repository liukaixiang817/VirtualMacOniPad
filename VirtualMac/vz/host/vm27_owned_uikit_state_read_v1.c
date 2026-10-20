/* Read only own compiled UIKit metadata/status. No key codes/text, UI calls,
 * process writes, suspend, signals or pointer authentication operations. */
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static mach_port_t task;
static uint64_t base;
static unsigned calls;
static size_t bytes;
static bool rd(uint64_t p,size_t n,void *out){if(!n||n>16384||p<0x10000||p>UINT64_C(0x0000ffffffffffff)-n||calls>=128||bytes+n>65536)return false;vm_size_t got=0;++calls;bytes+=n;return vm_read_overwrite(task,(vm_address_t)p,n,(vm_address_t)out,&got)==KERN_SUCCESS&&got==n;}
static bool offset(uint64_t rva,uint32_t *out){return rd(base+rva,4,out)&&*out>=8&&*out<16384;}
static bool ptr(uint64_t object,uint64_t rva,uint64_t *out){uint32_t off=0;return offset(rva,&off)&&rd(object+off,8,out)&&*out>=0x10000&&*out<=UINT64_C(0x0000ffffffffffff);}
static bool value(uint64_t object,uint64_t rva,size_t width,const char *name){uint32_t off=0;uint64_t v=0;if(!offset(rva,&off)||!rd(object+off,width,&v))return false;printf("VM27_UIKIT_FIELD name=%s value=%llu\n",name,(unsigned long long)v);return true;}
int main(int argc,char **argv){
 if(argc!=2||getuid()!=0)return 64;char *end=NULL;long pid=strtol(argv[1],&end,10);if(!end||*end||pid<=1||pid>0x3fffff)return 64;
 if(task_for_pid(mach_task_self(),(pid_t)pid,&task)!=KERN_SUCCESS)return 2;
 struct task_dyld_info info={0};mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
 if(task_info(task,TASK_DYLD_INFO,(task_info_t)&info,&count)||count!=TASK_DYLD_INFO_COUNT||info.all_image_info_format!=TASK_DYLD_ALL_IMAGE_INFO_64)return 3;
 struct {uint32_t version,count;uint64_t array;} images={0};
 if(!rd(info.all_image_info_addr,sizeof(images),&images)||!images.count||images.count>1024||!rd(images.array,8,&base))return 4;
 struct mach_header_64 h={0};uint8_t commands[16384];
 if(!rd(base,sizeof(h),&h)||h.magic!=MH_MAGIC_64||h.filetype!=MH_EXECUTE||h.ncmds>2048||h.sizeofcmds>sizeof(commands)||!rd(base+32,h.sizeofcmds,commands))return 5;
 size_t at=0;bool matched=false;const uint8_t expected[16]={55,34,14,148,101,115,63,98,191,81,177,33,62,15,12,145};
 for(unsigned i=0;i<h.ncmds;++i){if(at+8>h.sizeofcmds)return 5;uint32_t cmd=0,z=0;memcpy(&cmd,commands+at,4);memcpy(&z,commands+at+4,4);if(z<8||z%8||z>h.sizeofcmds-at)return 5;if(cmd==LC_UUID&&z==24&&memcmp(commands+at+8,expected,16)==0)matched=true;at+=z;}
 if(!matched||at!=h.sizeofcmds)return 5;
 printf("VM27_UIKIT_STATUS_BEGIN pid=%ld exactAppUUID=37220e9465733f62bf51b1213e0f0c91 readOnly=1 keyCodesOrTextRead=0 snapshotAtomic=0\n",pid);
 uint64_t surface=0,queue=0,session=0,adapter=0,check=0;
 if(!rd(base+0xc0b40,8,&surface)||!rd(base+0xc09d0,8,&queue)||!surface||!queue)return 6;
 if(!value(surface,0xbf220,4,"Surface._ownerPID"))return 7;
 if(!value(surface,0xbf224,4,"Surface._lastInputResult"))return 7;
 if(!value(surface,0xbf228,4,"Surface._softwareKeyboardRejectionLogs"))return 7;
 if(!value(surface,0xbf23c,8,"Surface._lastStamp"))return 7;
 if(!value(queue,0xbf330,1,"Queue._admitted"))return 7;
 if(!value(queue,0xbf334,1,"Queue._closing"))return 7;
 if(!value(queue,0xbf344,4,"Queue._lastDeliveryResult"))return 7;
 if(!ptr(surface,0xbf22c,&session)||!ptr(session,0xbf200,&adapter))return 8;
 if(!value(adapter,0xbf268,8,"Adapter._sequence"))return 7;
 if(!value(adapter,0xbf260,8,"Adapter._epoch"))return 7;
 if(!rd(base+0xc0b40,8,&check)||check!=surface||!rd(base+0xc09d0,8,&check)||check!=queue)return 9;
 printf("VM27_UIKIT_STATUS_END sameObjectsObservedBeforeAfter=1 reads=%u bytes=%zu\n",calls,bytes);mach_port_deallocate(mach_task_self(),task);return 0;
}
