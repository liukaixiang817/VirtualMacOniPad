#ifndef VM27_PRODUCTION_EXIT_SNAPSHOT_V22_H
#define VM27_PRODUCTION_EXIT_SNAPSHOT_V22_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {
 uint32_t reason,syndrome;
 uint64_t virtualAddress,physicalAddress;
 bool valid;
} VM27NativeExitSnapshotV22;
/* Private, read-only native9 result. Only reasons 1/6/8 require the other
 * three fields. Refusal leaves the caller on its original sequential path. */
__attribute__((visibility("hidden"))) VM27NativeExitSnapshotV22
VM27ProductionExitSnapshotV22(uintptr_t context);
#endif
