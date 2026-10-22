#include "vm27_trackpad_three_finger_swipe_v1.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    VM27TrackpadSwipeV1 state = {0};
    for (unsigned fingers = 0; fingers <= 5; fingers++) {
        VM27TrackpadSwipeResetV1(&state);
        VM27TrackpadSwipeContactV1(&state, fingers, 10);
        VM27TrackpadSwipeResultV1 r = VM27TrackpadSwipePanV1(&state, 1, 0, 0, 10.1);
        assert(r.consumed == (fingers == 3) && !r.direction);
        r = VM27TrackpadSwipePanV1(&state, 2, 0, -30, 10.2);
        assert(r.consumed == (fingers == 3));
        assert(r.direction == (fingers == 3 ? VM27TrackpadSwipeUp : VM27TrackpadSwipeNone));
        assert(!VM27TrackpadSwipePanV1(&state, 2, 0, -100, 10.3).direction);
        VM27TrackpadSwipePanV1(&state, 3, 0, -100, 10.4);
        assert(!state.active);
    }
    VM27TrackpadSwipeContactV1(&state, 3, 11);
    assert(!VM27TrackpadSwipePanV1(&state, 1, 0, 0, 11.4).consumed);
    VM27TrackpadSwipeContactV1(&state, 3, 12);
    assert(VM27TrackpadSwipePanV1(&state, 1, 0, 0, 12.1).consumed);
    VM27TrackpadSwipeContactV1(&state, 2, 12.2);
    assert(!VM27TrackpadSwipePanV1(&state, 2, 100, 0, 12.3).direction);
    assert(VM27TrackpadSwipePanV1(&state, 3, 100, 0, 12.4).consumed);
    VM27TrackpadSwipeContactV1(&state, 3, 13);
    VM27TrackpadSwipePanV1(&state, 1, 0, 0, 13);
    VM27TrackpadSwipeContactV1(&state, 0, 13.1);
    assert(VM27TrackpadSwipePanV1(&state, 3, -30, 0, 13.2).direction == VM27TrackpadSwipeLeft);
    VM27TrackpadSwipeContactV1(&state, 3, 14);
    VM27TrackpadSwipePanV1(&state, 1, 0, 0, 14);
    assert(!VM27TrackpadSwipePanV1(&state, 4, 0, -100, 14.1).direction);
    VM27TrackpadSwipeContactV1(&state, 3, 15);
    VM27TrackpadSwipePanV1(&state, 1, 0, 0, 15);
    assert(!VM27TrackpadSwipePanV1(&state, 2, NAN, 10, 15.1).direction);
    assert(!VM27TrackpadSwipePanV1(&state, 3, 100, 0, 15.2).direction);
    VM27TrackpadSwipeContactV1(&state, 3, 16);
    VM27TrackpadSwipeContactV1(&state, 3, 15);
    assert(!VM27TrackpadSwipePanV1(&state, 1, 0, 0, 16).consumed);
    puts("PASS: real-contact admission, ordinary scroll, one-shot, stale hint, lift/cancel and invalid values");
}
