#ifndef VM27_LOCK_PAUSE_POLICY_V1_H
#define VM27_LOCK_PAUSE_POLICY_V1_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {bool locked,eligible,owned,autoResume;uintptr_t owner;uint64_t ticket;} VM27LockPausePolicyV1;
static inline bool VM27LockShouldPauseV1(const VM27LockPausePolicyV1 *p,bool running,bool pending) {
 return p->locked && p->eligible && !p->owned && running && !pending;
}
static inline bool VM27LockShouldResumeV1(const VM27LockPausePolicyV1 *p,uintptr_t owner,bool active,bool paused,bool pending) {
 return p->owned && p->owner==owner && !p->locked && p->autoResume && active && paused && !pending;
}
static inline void VM27LockManualV1(VM27LockPausePolicyV1 *p) {p->owned=false;p->owner=0;p->ticket=0;}
#endif
