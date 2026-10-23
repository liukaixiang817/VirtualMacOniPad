#include "vm27_native_trackpad_swipe_v1.h"
#include <assert.h>
#include <stdio.h>
static void start(VM27NativeTrackpadContactV1 c[4]){for(unsigned i=0;i<4;++i)c[i]=(VM27NativeTrackpadContactV1){i,.2+i*.1,.7};}
int main(void){
 VM27NativeTrackpadContactV1 c[4];VM27NativeTrackpadSwipeV1 s={0};
 for(unsigned count=1;count<=4;++count){start(c);VM27NativeTrackpadResetV1(&s);assert(!VM27NativeTrackpadUpdateV1(&s,c,count,1));for(unsigned i=0;i<count;++i)c[i].y-=.15;
  assert(VM27NativeTrackpadUpdateV1(&s,c,count,1.1)==(count>=3?VM27TrackpadSwipeUp:VM27TrackpadSwipeNone));assert(!VM27NativeTrackpadUpdateV1(&s,c,count,1.2));assert(!VM27NativeTrackpadUpdateV1(&s,NULL,0,1.3));}
 start(c);VM27NativeTrackpadResetV1(&s);assert(!VM27NativeTrackpadUpdateV1(&s,c,3,2));assert(!VM27NativeTrackpadUpdateV1(&s,c,4,2.01));for(unsigned i=0;i<4;++i)c[i].x+=.1;assert(VM27NativeTrackpadUpdateV1(&s,c,4,2.1)==VM27TrackpadSwipeRight);
 start(c);VM27NativeTrackpadResetV1(&s);VM27NativeTrackpadUpdateV1(&s,c,3,3);c[2].identifier=9;assert(!VM27NativeTrackpadUpdateV1(&s,c,3,3.1));for(unsigned i=0;i<3;++i)c[i].y-=.2;assert(!VM27NativeTrackpadUpdateV1(&s,c,3,3.2));
 start(c);VM27NativeTrackpadResetV1(&s);VM27NativeTrackpadUpdateV1(&s,c,3,4);c[0].x-=.15;c[2].x+=.15;assert(!VM27NativeTrackpadUpdateV1(&s,c,3,4.1));
 start(c);VM27NativeTrackpadResetV1(&s);VM27NativeTrackpadUpdateV1(&s,c,3,5);for(unsigned i=0;i<3;++i)c[i].y+=.1;assert(!VM27NativeTrackpadUpdateV1(&s,c,3,5.6));
 start(c);VM27NativeTrackpadResetV1(&s);VM27NativeTrackpadUpdateV1(&s,c,3,6);c[1].x=NAN;assert(!VM27NativeTrackpadUpdateV1(&s,c,3,6.1));
 puts("PASS: two-finger exclusion, coherent three/four motion, one shot, promotion, lift, identity replacement, pinch, stale and invalid data");
}
