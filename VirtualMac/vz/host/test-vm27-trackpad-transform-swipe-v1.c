#include "vm27_trackpad_transform_swipe_v1.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    VM27TrackpadTransformV1 s={0};
    for(unsigned count=0;count<=5;++count) {
        VM27TrackpadTransformResetV1(&s);
        VM27TrackpadTransformContactV1(&s,count,10);
        assert(VM27TrackpadTransformMoveV1(&s,0,-40,10.1)==
            (count==3?VM27TrackpadSwipeUp:VM27TrackpadSwipeNone));
        assert(!VM27TrackpadTransformMoveV1(&s,100,0,10.2));
    }
    VM27TrackpadTransformResetV1(&s);
    VM27TrackpadTransformContactV1(&s,3,20);
    assert(!VM27TrackpadTransformMoveV1(&s,10,10,20.1));
    VM27TrackpadTransformContactV1(&s,2,20.2);
    VM27TrackpadTransformContactV1(&s,3,20.3);
    assert(!VM27TrackpadTransformMoveV1(&s,-100,0,20.3));
    VM27TrackpadTransformContactV1(&s,0,21);
    VM27TrackpadTransformContactV1(&s,3,21.1);
    assert(VM27TrackpadTransformMoveV1(&s,-40,0,21.2)==VM27TrackpadSwipeLeft);
    VM27TrackpadTransformContactV1(&s,0,22);
    VM27TrackpadTransformContactV1(&s,3,22);
    assert(!VM27TrackpadTransformMoveV1(&s,0,-40,22.5));
    VM27TrackpadTransformContactV1(&s,3,23);
    assert(!VM27TrackpadTransformMoveV1(&s,NAN,0,23));
    puts("PASS: transform contacts, one-shot, partial lift, complete lift, stale and invalid movement");
}
