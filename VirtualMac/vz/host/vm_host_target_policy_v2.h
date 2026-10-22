#ifndef VM_HOST_TARGET_POLICY_V2_H
#define VM_HOST_TARGET_POLICY_V2_H
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

/* Admission is experimental, not a claim that a kernel ABI is compatible.
 * The existing native CPU creation/read/write code still checks the actual
 * returned context version and mapping bounds before using shared state. */
static inline bool VMHostDecimalV2(const char **cursor, unsigned *out) {
    const char *p=*cursor; unsigned value=0, digits=0;
    while (*p>='0' && *p<='9') {
        if (++digits>6) return false;
        value=value*10+(unsigned)(*p++-'0');
    }
    if (!digits) return false;
    *cursor=p;*out=value;return true;
}
static inline bool VM27HostExperimentalMatchesV2(const char *machine,
    const char *release, const char *build, long pageBytes) {
    if (VMHostFamilyForMachineV1(machine)==VMHostFamilyUnknownV1 ||
        !release || !build || pageBytes!=16384) return false;
    unsigned major,minor,patch,train,number;
    const char *r=release,*b=build;
    if (!VMHostDecimalV2(&r,&major) || *r++!='.' ||
        !VMHostDecimalV2(&r,&minor) || *r++!='.' ||
        !VMHostDecimalV2(&r,&patch) || *r ||
        !VMHostDecimalV2(&b,&train)) return false;
    char letter=*b;
    if (!letter) return false;
    ++b;
    if (!VMHostDecimalV2(&b,&number) || *b || !number) return false;
    /* Public release trains only: no beta suffixes or future releases.
     * 15.7/15.8 keep Darwin 21.6 and use build train 19H. */
    if (major==21 && minor<=6 && train==19 && letter>='A' && letter<='H')
        return true;
    if (major!=22 || minor>3 || train!=20 || letter!=(char)('A'+minor)) return false;
    return minor<3 || number<=67; /* 16.3.1 is 20D67. */
}
#endif
