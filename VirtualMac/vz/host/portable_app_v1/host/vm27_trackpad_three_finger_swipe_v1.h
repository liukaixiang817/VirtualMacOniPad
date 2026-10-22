#ifndef VM27_TRACKPAD_THREE_FINGER_SWIPE_V1_H
#define VM27_TRACKPAD_THREE_FINGER_SWIPE_V1_H
#include <math.h>
#include <stdbool.h>
#include <string.h>

/* UIKit trackpad scrolling has zero UITouches. The contact hint comes from
 * the actual UIHoverEvent dispatched to our own active input window. Keep
 * only copied scalar values; no UIEvent or HID object survives dispatch. */
typedef struct {
    double contactTime;
    unsigned contacts;
    bool haveContact, active, fired, cancelled;
} VM27TrackpadSwipeV1;
typedef enum {
    VM27TrackpadSwipeNone, VM27TrackpadSwipeUp, VM27TrackpadSwipeDown,
    VM27TrackpadSwipeLeft, VM27TrackpadSwipeRight
} VM27TrackpadDirectionV1;
typedef struct { bool consumed; VM27TrackpadDirectionV1 direction; } VM27TrackpadSwipeResultV1;

static inline void VM27TrackpadSwipeResetV1(VM27TrackpadSwipeV1 *state) {
    memset(state, 0, sizeof(*state));
}
static inline void VM27TrackpadSwipeContactV1(VM27TrackpadSwipeV1 *state,
    unsigned contacts, double now) {
    if (contacts > 16 || !isfinite(now) || now < 0 ||
        (state->haveContact && now < state->contactTime)) {
        VM27TrackpadSwipeResetV1(state); return;
    }
    state->contacts = contacts; state->contactTime = now; state->haveContact = true;
    /* A normal lift may precede the terminal scroll packet. Changing to a
     * different nonzero contact count cancels the shortcut for this sequence. */
    if (state->active && contacts && contacts != 3) state->cancelled = true;
}
static inline VM27TrackpadSwipeResultV1 VM27TrackpadSwipePanV1(
    VM27TrackpadSwipeV1 *state, unsigned phase, double x, double y, double now) {
    VM27TrackpadSwipeResultV1 result = {false, VM27TrackpadSwipeNone};
    if (phase == 1) {
        state->active = state->haveContact && state->contacts == 3 &&
            isfinite(now) && now >= state->contactTime && now - state->contactTime <= 0.35;
        state->fired = false; state->cancelled = false;
    }
    result.consumed = state->active;
    if (!state->active) return result;
    if (!isfinite(x) || !isfinite(y) || fabs(x) > 1000000 || fabs(y) > 1000000)
        state->cancelled = true;
    if (!state->fired && !state->cancelled && phase >= 1 && phase <= 3) {
        if (fabs(x) >= 24 && fabs(x) > fabs(y) * 1.25)
            result.direction = x < 0 ? VM27TrackpadSwipeLeft : VM27TrackpadSwipeRight;
        else if (fabs(y) >= 24 && fabs(y) > fabs(x) * 1.25)
            result.direction = y < 0 ? VM27TrackpadSwipeUp : VM27TrackpadSwipeDown;
        if (result.direction) state->fired = true;
    }
    if (phase >= 3) { state->active = false; state->fired = false; state->cancelled = false; }
    return result;
}
#endif
