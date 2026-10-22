#include "vm27_trackpad_multifinger_swipe_v2.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
 for(unsigned count=0;count<=5;++count) {
  VM27TrackpadSwipeV2 pan={0};VM27TrackpadSwipeContactV2(&pan,count,10);
  VM27TrackpadSwipeResultV1 r=VM27TrackpadSwipePanV2(&pan,1,0,-30,10.1);
  assert(r.consumed==(count==3||count==4));
  assert(r.direction==((count==3||count==4)?VM27TrackpadSwipeUp:VM27TrackpadSwipeNone));
  assert(!VM27TrackpadSwipePanV2(&pan,2,0,-90,10.2).direction);
  VM27TrackpadTransformV2 transform={0};VM27TrackpadTransformContactV2(&transform,count,10);
  assert(VM27TrackpadTransformMoveV2(&transform,-30,0,10.1)==((count==3||count==4)?VM27TrackpadSwipeLeft:VM27TrackpadSwipeNone));
 }
 for(unsigned count=3;count<=4;++count) {
  VM27TrackpadTransformV2 s={0};VM27TrackpadTransformContactV2(&s,count,20);
  assert(!VM27TrackpadTransformMoveV2(&s,5,0,20.1));
  assert(!VM27TrackpadTransformMoveV2(&s,12,0,20.3));
  assert(VM27TrackpadTransformMoveV2(&s,30,0,20.5)==VM27TrackpadSwipeRight);
  assert(!VM27TrackpadTransformMoveV2(&s,100,0,20.6));
  VM27TrackpadTransformContactV2(&s,0,21);VM27TrackpadTransformContactV2(&s,count,21.1);
  assert(VM27TrackpadTransformMoveV2(&s,0,30,21.2)==VM27TrackpadSwipeDown);
  VM27TrackpadTransformResetV2(&s);VM27TrackpadTransformContactV2(&s,count,22);
  assert(!VM27TrackpadTransformMoveV2(&s,30,0,22.5));
  VM27TrackpadTransformResetV2(&s);VM27TrackpadTransformContactV2(&s,count,23);
  assert(!VM27TrackpadTransformMoveV2(&s,1,0,23.1));
  VM27TrackpadTransformContactV2(&s,count==3?4:3,23.2);
  VM27TrackpadTransformContactV2(&s,count,23.3);
  assert(!VM27TrackpadTransformMoveV2(&s,30,0,23.3));
  VM27TrackpadSwipeV2 p={0};VM27TrackpadSwipeContactV2(&p,count,24);
  assert(VM27TrackpadSwipePanV2(&p,1,1,1,24.1).consumed);
  VM27TrackpadSwipeContactV2(&p,0,24.2);
  assert(VM27TrackpadSwipePanV2(&p,3,0,-30,24.2).direction==VM27TrackpadSwipeUp);
  VM27TrackpadSwipeResetV2(&p);VM27TrackpadSwipeContactV2(&p,count,25);
  assert(VM27TrackpadSwipePanV2(&p,1,1,1,25.1).consumed);
  assert(!VM27TrackpadSwipePanV2(&p,4,100,0,25.2).direction);
 }
 puts("PASS: two-finger exclusion, three/four-finger directions, one-shot, lift, stale hints, contact changes, long active gesture and cancellation");
}
