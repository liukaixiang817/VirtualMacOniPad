#include "modern_cpu_config_capability_acquisition_v1.h"
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t, void *);
static pthread_once_t Once = PTHREAD_ONCE_INIT;
static VM27CPUTLBICapabilityValueV1 Value;
static _Thread_local bool Acquiring;
static bool SysString(const char *key, char *out, size_t bytes) {
    size_t actual = bytes; memset(out, 0, bytes);
    return sysctlbyname(key, out, &actual, NULL, 0) == 0 &&
        actual && actual <= bytes && memchr(out, 0, actual);
}
static bool Profile(void) {
    char release[32], build[32], machine[32];
    return SysString("kern.osrelease", release, sizeof(release)) &&
        SysString("kern.osversion", build, sizeof(build)) &&
        SysString("hw.machine", machine, sizeof(machine)) &&
        !strcmp(release, "22.1.0") && !strcmp(build, "20B101") &&
        (!strcmp(machine, "iPad14,3") || !strcmp(machine, "iPad14,4") ||
         !strcmp(machine, "iPad14,5") || !strcmp(machine, "iPad14,6"));
}
static bool Canary(const unsigned char *bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) if (bytes[i] != 0xa5) return false;
    return true;
}
static void Acquire(void) {
    // Capacity is our allocation bound, never a claim about kernel write width.
    const size_t page = 16384, capacity = 352, tail = 32, total = 3 * page;
    uint64_t owner = 0;
    if (!Profile() || geteuid() != 0 || sysconf(_SC_PAGESIZE) != (long)page ||
        pthread_threadid_np(NULL, &owner) || !owner) return;
    unsigned char *region = mmap(NULL, total, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region == MAP_FAILED) return;
    VM27CPUTLBICapabilityInputV1 input = {0};
    input.schemaVersion = 1; input.actualOwnerThread = owner;
    input.nativeReturn = (int32_t)UINT32_C(0xfae94001); input.sysctlReturn = -1;
    VM27CPUTLBICapabilityValueV1 staged = {false, false};
    unsigned char *middle = region + page, *buffer = middle + page - capacity - tail;
    bool known = false;
    if (mprotect(middle, page, PROT_READ | PROT_WRITE) == 0) {
        memset(middle, 0xa5, page); memset(buffer, 0, capacity);
        if (!((uintptr_t)buffer % 32) && Canary(middle, (size_t)(buffer-middle)) &&
            Canary(buffer + capacity, tail)) {
            input.queryCalls = 1;
            // Sole native request in this component. No VM/CPU/HV-map/Run call.
            input.nativeReturn = VM27CPUConfigCapabilityKernelQueryV1(0, buffer);
            bool exterior = Canary(middle, (size_t)(buffer-middle)) &&
                Canary(buffer + capacity, page-(size_t)(buffer+capacity-middle));
            input.guardedContextKnown = input.nativeReturn == 0 && exterior;
            if (input.guardedContextKnown) {
                memcpy(&input.hostContextWord40, buffer + 0x40, 8);
                int vmm = -1; size_t bytes = sizeof(vmm);
                input.sysctlReturn = sysctlbyname("kern.hv_vmm_present", &vmm, &bytes, NULL, 0);
                input.sysctlOutputBytes = bytes; input.vmmPresent = vmm;
                known = VM27CPUInterpretTLBICapabilityV1(&input, &staged);
            }
        }
    }
    // Failed cleanup also keeps the support property UNKNOWN. No kernel
    // pointer or op0 buffer survives; this value cannot authorize native writes.
    if (munmap(region, total) != 0) known = false;
    if (known) Value = staged;
}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out) {
    if (!out) return;
    if (Acquiring) { *out = (VM27CPUTLBICapabilityValueV1){false,false}; return; }
    Acquiring = true; int result = pthread_once(&Once, Acquire); Acquiring = false;
    *out = result == 0 ? Value : (VM27CPUTLBICapabilityValueV1){false,false};
}
