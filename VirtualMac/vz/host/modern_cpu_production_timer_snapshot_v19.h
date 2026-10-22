#ifndef VM27_PRODUCTION_TIMER_SNAPSHOT_V19_H
#define VM27_PRODUCTION_TIMER_SNAPSHOT_V19_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {uint64_t first,second,third;bool valid;} VM27NativeTimerSnapshotV19;
/* Private finite native owner reads: 0=offset/dirty/ready,
 * 1=physical CTL/CVAL, 2=virtual CTL/CVAL/duplicate-exit mask. */
__attribute__((visibility("hidden"))) VM27NativeTimerSnapshotV19 VM27ProductionTimerSnapshotV19(uintptr_t context,unsigned kind);
#endif
