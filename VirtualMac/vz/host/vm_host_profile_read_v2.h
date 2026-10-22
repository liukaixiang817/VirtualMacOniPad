#ifndef VM_HOST_PROFILE_READ_V2_H
#define VM_HOST_PROFILE_READ_V2_H
#include "vm_host_target_policy_v2.h"
#include <sys/sysctl.h>
#include <unistd.h>

typedef struct {
    char machine[64], release[64], build[64];
    long pageBytes;
} VMHostProfileV1;

static inline bool VMHostReadStringV1(const char *key, char *out, size_t size) {
    memset(out,0,size);
    size_t used=size;
    return !sysctlbyname(key,out,&used,NULL,0) && used>1 && used<=size &&
        out[used-1]==0 && strlen(out)+1==used;
}

static inline bool VMHostReadProfileV1(VMHostProfileV1 *out) {
    if (!out) return false;
    memset(out,0,sizeof(*out));
    out->pageBytes=getpagesize();
    return VMHostReadStringV1("hw.machine",out->machine,sizeof(out->machine)) &&
        VMHostReadStringV1("kern.osrelease",out->release,sizeof(out->release)) &&
        VMHostReadStringV1("kern.osversion",out->build,sizeof(out->build));
}

static inline bool VM27HostCurrentExperimentalMatchesV2(void) {
    VMHostProfileV1 actual;
    return VMHostReadProfileV1(&actual) && VM27HostExperimentalMatchesV2(
        actual.machine,actual.release,actual.build,actual.pageBytes);
}
#endif
