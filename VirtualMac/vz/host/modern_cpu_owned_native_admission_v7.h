#ifndef VM27_OWNED_NATIVE_ADMISSION_V7_H
#define VM27_OWNED_NATIVE_ADMISSION_V7_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {uintptr_t token,context;uint64_t version;} VM27OwnedNativeAdmissionV7;
/* Private actual publishing pthread only, fresh native version, epoch guarded.
 * The output must be on its genuinely admitted writable pthread stack. */
__attribute__((visibility("hidden"))) bool VM27CPUOwnedNativeAdmissionV7(VM27OwnedNativeAdmissionV7 *);
#endif
