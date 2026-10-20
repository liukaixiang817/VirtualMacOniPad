#ifndef VM27_NO_MAC_HAPTIC_PORT_V1_H
#define VM27_NO_MAC_HAPTIC_PORT_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* This profile has no macOS WindowServer host haptic connection. The first
 * return is an error status, never a connection ID. The second call consumes
 * only that status and preserves the original task's device/pattern/options
 * ABI. Both refuse with ENOTSUP; no host actuation or successful effect. */
uint32_t VM27NoHapticV1(void);
int VM27RejectHapticV1(uint32_t rejectedStatus, uint64_t device,
                     int64_t pattern, uint64_t options);
typedef struct {
    uint64_t statusRequests, patternRequests;
    uint32_t rejectedStatus;
    uint64_t device;
    int64_t pattern;
    uint64_t options;
} VM27HapticRejectV1;
/* Own process diagnostics only. No callback, VM dispatcher or hardware API. */
int VM27CopyHapticRejectV1(VM27HapticRejectV1 *report);
#ifdef __cplusplus
}
#endif
#endif
