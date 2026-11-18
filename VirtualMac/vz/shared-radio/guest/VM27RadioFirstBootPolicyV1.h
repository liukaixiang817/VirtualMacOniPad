#ifndef VM27_RADIO_FIRST_BOOT_POLICY_V1_H
#define VM27_RADIO_FIRST_BOOT_POLICY_V1_H
#include <stdbool.h>
#include <stdint.h>

// The native owner workflow enables these guest-scoped exceptions: untrusted
// kexts, filesystem, task-for-pid/debugger and NVRAM. CSR_ALLOW_APPLE_INTERNAL
// (0x10) is not a prerequisite. On the real retail 25G83 guest the kernel
// returns 0x4f while the local-policy display reports sip0=0x5f.
#define VM27_RADIO_CSR_REQUIRED_V1 UINT32_C(0x4f)
typedef struct {
    bool policyReadable;
    bool policyReady;
    bool bootArgumentsReady;
    bool radioActivationAllowed;
    bool ownerPolicyNeeded;
} VM27RadioFirstBootPolicyV1;
static inline VM27RadioFirstBootPolicyV1 VM27RadioEvaluateFirstBootPolicyV1(
    bool readable, uint32_t config, bool argumentsReady) {
    bool ready = readable && (config & VM27_RADIO_CSR_REQUIRED_V1) == VM27_RADIO_CSR_REQUIRED_V1;
    return (VM27RadioFirstBootPolicyV1){readable, ready, argumentsReady,
                                     ready && argumentsReady, readable && !ready};
}
// A completed native operation gets one restart for this exact package.
// If the next boot did not apply it, report the failed stage instead of
// requesting another password or entering an automatic restart loop.
static inline bool VM27RadioStageMayRunV1(bool needed, bool restartRecorded) {
    return needed && !restartRecorded;
}
#endif
