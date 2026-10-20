/* Inspect the current Mac's own Apple function bytes; never invoke them.
 * No iPad, IOKit connection, surface, hypervisor or guest API is called. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    const char *path="/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/Versions/A/IOSurfaceAccelerator";
    void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!handle){fprintf(stderr,"%s\n",dlerror());return 3;}
    void *address=dlsym(handle,"IOSurfaceAcceleratorParavirtProcessGuestData");
    address=ptrauth_strip(address,ptrauth_key_function_pointer);
    Dl_info info={0};
    if(!address||!dladdr(address,&info)||strcmp(info.dli_fname,path))return 4;
    const struct mach_header_64 *header=info.dli_fbase;
    if(header->magic!=MH_MAGIC_64||header->ncmds>512||header->sizeofcmds>65536)return 5;
    const uint8_t *p=(const uint8_t *)(header+1),*end=p+header->sizeofcmds;
    const struct segment_command_64 *text=NULL;const struct uuid_command *uuid=NULL;
    for(uint32_t i=0;i<header->ncmds;i++) {
        if((size_t)(end-p)<8)return 6;
        const struct load_command *lc=(const void *)p;
        if(lc->cmdsize<8||lc->cmdsize>(size_t)(end-p))return 7;
        if(lc->cmd==LC_SEGMENT_64) {
            const struct segment_command_64 *seg=(const void *)p;
            if(!strcmp(seg->segname,"__TEXT"))text=seg;
        }
        if(lc->cmd==LC_UUID){if(lc->cmdsize!=24||uuid)return 8;uuid=(const void *)p;}
        p+=lc->cmdsize;
    }
    if(p!=end||!text||!uuid)return 9;
    uintptr_t rva=(uintptr_t)address-(uintptr_t)header;
    /* Current dyld_info reports actual function starts at RVA2f0c and 2fc0.
     * Refuse drift instead of reading an invented or unbounded extent. */
    if(rva!=0x2f0c||text->vmsize<rva+0xb4)return 10;
    int out=open(argv[1],O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC,0600);
    if(out<0)return 11;
    ssize_t written=write(out,address,0xb4);int released=close(out);
    if(written!=0xb4||released)return 12;
    printf("{\"symbol\":\"IOSurfaceAcceleratorParavirtProcessGuestData\",\"rva\":%llu,"
        "\"bytes\":180,\"UUID\":\"",(unsigned long long)rva);
    for(unsigned i=0;i<16;i++)printf("%02x",uuid->uuid[i]);
    printf("\",\"loadedImage\":\"%s\",\"functionInvocations\":0,"
        "\"IOKitOperations\":0,\"iPadOperations\":0,\"guestBoot\":false}\n",info.dli_fname);
    dlclose(handle);return 0;
}
