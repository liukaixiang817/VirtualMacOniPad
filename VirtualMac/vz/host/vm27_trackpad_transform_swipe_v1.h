#ifndef VM27_TRACKPAD_TRANSFORM_SWIPE_V1_H
#define VM27_TRACKPAD_TRANSFORM_SWIPE_V1_H
#include "vm27_trackpad_three_finger_swipe_v1.h"

/* A transform is separate from the zero-touch scroll pan. Three real contacts
 * arm it; a complete lift is required before another one-shot action. */
typedef struct {
    double contactTime;
    unsigned contacts;
    bool haveContact, active, fired, cancelled;
} VM27TrackpadTransformV1;
static inline void VM27TrackpadTransformResetV1(VM27TrackpadTransformV1 *s) {
    memset(s, 0, sizeof(*s));
}
static inline void VM27TrackpadTransformContactV1(VM27TrackpadTransformV1 *s,
    unsigned contacts, double now) {
    if (contacts>16 || !isfinite(now) || now<0 ||
        (s->haveContact && now<s->contactTime)) {
        VM27TrackpadTransformResetV1(s); return;
    }
    if (!contacts) VM27TrackpadTransformResetV1(s);
    else if (s->active && contacts!=3) s->cancelled=true;
    s->contacts=contacts; s->contactTime=now; s->haveContact=true;
}
static inline VM27TrackpadDirectionV1 VM27TrackpadTransformMoveV1(
    VM27TrackpadTransformV1 *s, double x, double y, double now) {
    if (!s->haveContact || s->contacts!=3 || !isfinite(now) ||
        now<s->contactTime || now-s->contactTime>0.35 ||
        !isfinite(x) || !isfinite(y) || fabs(x)>1000000 || fabs(y)>1000000) {
        if (s->active) s->cancelled=true;
        return VM27TrackpadSwipeNone;
    }
    s->active=true;
    if (s->fired || s->cancelled) return VM27TrackpadSwipeNone;
    VM27TrackpadDirectionV1 direction=VM27TrackpadSwipeNone;
    if (fabs(x)>=24 && fabs(x)>fabs(y)*1.25)
        direction=x<0?VM27TrackpadSwipeLeft:VM27TrackpadSwipeRight;
    else if (fabs(y)>=24 && fabs(y)>fabs(x)*1.25)
        direction=y<0?VM27TrackpadSwipeUp:VM27TrackpadSwipeDown;
    if (direction) s->fired=true;
    return direction;
}
#endif
