#ifndef VM_HOST_TARGET_POLICY_V1_H
#define VM_HOST_TARGET_POLICY_V1_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Product targets are distinct from native ABI profiles. Adding a target
 * here does not admit a different kernel layout or claim device acceptance. */
typedef enum {
    VMHostFamilyUnknownV1, VMHostFamilyM1V1, VMHostFamilyM2V1,
    VMHostFamilyA16V1
} VMHostFamilyV1;

static inline VMHostFamilyV1 VMHostFamilyForMachineV1(const char *machine) {
    if (!machine) return VMHostFamilyUnknownV1;
    const char *m1[] = {"iPad13,4", "iPad13,5", "iPad13,6", "iPad13,7",
        "iPad13,8", "iPad13,9", "iPad13,10", "iPad13,11",
        "iPad13,16", "iPad13,17"};
    const char *m2[] = {"iPad14,3", "iPad14,4", "iPad14,5", "iPad14,6",
        "iPad14,8", "iPad14,9", "iPad14,10", "iPad14,11"};
    for (size_t i=0; i<sizeof(m1)/sizeof(*m1); ++i)
        if (!strcmp(machine,m1[i])) return VMHostFamilyM1V1;
    for (size_t i=0; i<sizeof(m2)/sizeof(*m2); ++i)
        if (!strcmp(machine,m2[i])) return VMHostFamilyM2V1;
    if (!strcmp(machine,"iPhone15,2") || !strcmp(machine,"iPhone15,3"))
        return VMHostFamilyA16V1;
    return VMHostFamilyUnknownV1;
}

static inline bool VMHostInRequestedDopamineRangeV1(unsigned major,
    unsigned minor, unsigned patch) {
    /* Dopamine starts at iOS 15. The user's current upper bound is 16.3.1.
     * Hardware that cannot install this OS is not made compatible by this. */
    return major==15 || (major==16 &&
        (minor<3 || (minor==3 && patch<=1)));
}

/* The current independent CPU implementation uses native context version
 * 0x206879700000000e and its checked 16 KiB shared-page layout. OS 15 and
 * other OS 16 builds require their own ABI evidence before admission.
 * CPU creation still checks the actual native version before state writes. */
static inline bool VM27HostABI20B101MatchesV1(const char *machine,
    const char *release, const char *build, long pageBytes) {
    return VMHostFamilyForMachineV1(machine)!=VMHostFamilyUnknownV1 &&
        release && build && !strcmp(release,"22.1.0") &&
        !strcmp(build,"20B101") && pageBytes==16384;
}
#endif
