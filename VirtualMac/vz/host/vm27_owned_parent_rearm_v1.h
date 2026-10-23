#ifndef VM27_OWNED_PARENT_REARM_V1_H
#define VM27_OWNED_PARENT_REARM_V1_H
#include "vm27_owned_app_child_startup_v3.h"
/* Bounded, off the actual startup queue; no signal or guessed PID absence.
 * A running child, unfinished native handler, partial startup or pending
 * callback retains the old owner. Success clears only that exact dead epoch. */
int VM27OwnedAppParentRetireAfterExitV1(VM27OwnedAppParentV1 **);
#endif
