/* Finite real-Mach-read fixture. Only dyld inventory/symbol lookup is modeled;
 * the production source has no test callbacks or alternate authority path. */
#include <TargetConditionals.h>
#if !TARGET_OS_OSX
#error This host-only fixture must never enter an iOS product
#endif
#include "vm27_actual_executable_image_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {struct mach_header_64 h; struct uuid_command uuid, extra;} FixtureImage;
static FixtureImage mainImage, libraryImage, secondImage;
static const struct mach_header *images[3];
static const char *names[3];
static char actualPath[PATH_MAX];
static uint32_t imageCount, countCalls;
static bool countChanges, noSymbol, wrongBase, wrongDlPath, selfNoNul;
static unsigned cases;
static void Require(bool ok, const char *message) {
    if (!ok) {fprintf(stderr,"failed: %s\n",message);exit(1);}
}
static void *PeerSymbol(void *handle, const char *name) {
    Require(handle == RTLD_MAIN_ONLY && !strcmp(name,"_mh_execute_header"),"executable-only symbol lookup");
    return noSymbol ? NULL : &mainImage.h;
}
static int PeerDladdr(const void *pointer, Dl_info *info) {
    Require(pointer == &mainImage.h,"same symbol/header lookup");
    *info = (Dl_info){.dli_fname = wrongDlPath ? "/usr/bin/true" : actualPath,
        .dli_fbase = wrongBase ? (void *)&libraryImage.h : (void *)&mainImage.h};
    return 1;
}
static uint32_t PeerCount(void) {return imageCount + (countChanges && countCalls++ != 0);}
static const struct mach_header *PeerHeader(uint32_t index) {return index < imageCount ? images[index] : NULL;}
static const char *PeerName(uint32_t index) {return index < imageCount ? names[index] : NULL;}
static int PeerExecutable(char *target, uint32_t *size) {
    if (selfNoNul) {memset(target,'x',*size);return 0;}
    size_t bytes = strlen(actualPath) + 1;
    if (bytes > *size) {*size=(uint32_t)bytes;return -1;}
    memcpy(target,actualPath,bytes);return 0;
}
#define dlsym PeerSymbol
#define dladdr PeerDladdr
#define _dyld_image_count PeerCount
#define _dyld_get_image_header PeerHeader
#define _dyld_get_image_name PeerName
#define _NSGetExecutablePath PeerExecutable
#include "vm27_actual_executable_image_v1.c"
#undef dlsym
#undef dladdr
#undef _dyld_image_count
#undef _dyld_get_image_header
#undef _dyld_get_image_name
#undef _NSGetExecutablePath

static void Reset(void) {
    mainImage=(FixtureImage){.h={.magic=MH_MAGIC_64,.cputype=0x100000c,.filetype=MH_EXECUTE,
        .ncmds=1,.sizeofcmds=sizeof(struct uuid_command)},.uuid={.cmd=LC_UUID,.cmdsize=24,
        .uuid={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b}}};
    libraryImage=(FixtureImage){.h={.magic=MH_MAGIC_64,.cputype=0x100000c,.filetype=MH_DYLIB}};
    secondImage=mainImage;
    images[0]=(void *)&libraryImage.h;images[1]=(void *)&mainImage.h;images[2]=(void *)&secondImage.h;
    names[0]="/usr/lib/libSystem.B.dylib";names[1]=actualPath;names[2]=actualPath;
    imageCount=2;countCalls=0;countChanges=noSymbol=wrongBase=wrongDlPath=selfNoNul=false;
}
static void Reject(const char *label) {
    VM27ActualExecutableImageV1 out, before;
    memset(&out,0xa5,sizeof(out));before=out;
    Require(VM27ActualExecutableImageFindV1(actualPath,&out)!=0,label);
    Require(!memcmp(&out,&before,sizeof(out)),"failure must not publish output");cases++;
}
int main(int argc, char **argv) {
    Require(argc>=1 && realpath(argv[0],actualPath),"actual canonical fixture executable path");
    Reset();VM27ActualExecutableImageV1 out={0};
    Require(!VM27ActualExecutableImageFindV1(actualPath,&out) && out.header==&mainImage.h &&
        out.dyldIndex==1 && !memcmp(out.uuid,mainImage.uuid.uuid,16),"valid executable at actual index1");cases++;
    Reset();Require(!VM27ActualExecutableImageFindSelfV1(&out) && out.dyldIndex==1,"real self path API routes to index1");cases++;
    Reset();noSymbol=true;Reject("no genuine executable export");
    Reset();wrongBase=true;Reject("dladdr different base");
    Reset();wrongDlPath=true;Reject("different canonical executable");
    Reset();images[1]=(const void *)1;Reject("unreadable dyld header safely rejected");
    Reset();imageCount=3;Reject("duplicate canonical MH_EXECUTE identity");
    Reset();mainImage.h.filetype=MH_DYLIB;Reject("non-executable main symbol");
    Reset();mainImage.h.ncmds=2;mainImage.h.sizeofcmds=48;mainImage.extra=mainImage.uuid;Reject("duplicate UUID command");
    Reset();mainImage.uuid.cmdsize=25;Reject("misaligned load command");
    Reset();mainImage.h.sizeofcmds=32;Reject("trailing command bytes");
    Reset();countChanges=true;Reject("dyld snapshot changed during inspection");
    Reset();mainImage.uuid.cmd=LC_SEGMENT_64;Reject("missing UUID");
    Reset();selfNoNul=true;memset(&out,0xa5,sizeof(out));VM27ActualExecutableImageV1 before=out;
    Require(VM27ActualExecutableImageFindSelfV1(&out)!=0 && !memcmp(&out,&before,sizeof(out)),"unterminated self path rejects before realpath");cases++;
    printf("{\"passed\":true,\"cases\":%u,\"actualMachReads\":true,\"modeledDyldInventory\":true,\"processesSpawned\":0,\"nativeVMOperations\":0}\n",cases);
    return 0;
}
