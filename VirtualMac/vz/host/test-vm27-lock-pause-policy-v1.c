#include "vm27_lock_pause_policy_v1.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
 VM27LockPausePolicyV1 p={.locked=true,.eligible=true,.autoResume=false};
 assert(VM27LockShouldPauseV1(&p,true,false));
 assert(!VM27LockShouldPauseV1(&p,true,true));
 assert(!VM27LockShouldPauseV1(&p,false,false));
 p.eligible=false;assert(!VM27LockShouldPauseV1(&p,true,false));
 p.eligible=true;p.owned=true;p.owner=123;p.ticket=4;
 assert(!VM27LockShouldPauseV1(&p,true,false));
 p.locked=false;assert(!VM27LockShouldResumeV1(&p,123,true,true,false));
 p.autoResume=true;assert(VM27LockShouldResumeV1(&p,123,true,true,false));
 assert(!VM27LockShouldResumeV1(&p,124,true,true,false));
 assert(!VM27LockShouldResumeV1(&p,123,false,true,false));
 assert(!VM27LockShouldResumeV1(&p,123,true,false,false));
 assert(!VM27LockShouldResumeV1(&p,123,true,true,true));
 p.locked=true;assert(!VM27LockShouldResumeV1(&p,123,true,true,false));
 p.locked=false;VM27LockManualV1(&p);assert(!VM27LockShouldResumeV1(&p,123,true,true,false));
 assert(p.owner==0 && p.ticket==0);
 puts("PASS: 14 lock pause ownership and resume admission checks");
}
