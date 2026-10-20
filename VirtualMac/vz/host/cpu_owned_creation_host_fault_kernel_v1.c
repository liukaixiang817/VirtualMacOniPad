// Compiler-selected host model only. Never linked into the iPad executable.
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static _Alignas(16) unsigned char memory[0x5000];
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out) {
    (void)out; abort(); // Neither the real nor host fixture enables TLBI.
}
int32_t VM27OwnedCreationNativeTrapV1(uint64_t operation,void *arguments) {
    const char *mode=getenv("VM27_CREATION_HOST_FAULT");
    if (operation==1 || operation==2) return 0;
    if (operation==6) {
        if (mode && !strcmp(mode,"native6-fails")) return -123;
        uint64_t version=mode && !strcmp(mode,"version-fails") ? 0 : VZ_KERNEL_NATIVE_CONTEXT_VERSION;
        memcpy(memory+0x4000,&version,8);((uint64_t *)arguments)[1]=(uintptr_t)memory;return 0;
    }
    if (operation==7) return mode && !strcmp(mode,"native7-fails") ? -123 : 0;
    abort();
}
