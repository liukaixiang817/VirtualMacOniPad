#ifndef VM27_TRACKPAD_MULTIFINGER_SWIPE_V2_H
#define VM27_TRACKPAD_MULTIFINGER_SWIPE_V2_H
#include "vm27_trackpad_three_finger_swipe_v1.h"
typedef struct {
    double contactTime;
    unsigned contacts, gestureContacts;
    bool haveContact, active, fired, cancelled;
} VM27TrackpadSwipeV2;
static inline bool VM27TrackpadMultiContactV2(unsigned count) { return count==3 || count==4; }
static inline void VM27TrackpadSwipeResetV2(VM27TrackpadSwipeV2 *s) { memset(s,0,sizeof(*s)); }
static inline void VM27TrackpadSwipeContactV2(VM27TrackpadSwipeV2 *s,unsigned count,double now) {
    if(count>16 || !isfinite(now) || now<0 || (s->haveContact && now<s->contactTime)) {
        VM27TrackpadSwipeResetV2(s);return;
    }
    s->contacts=count;s->contactTime=now;s->haveContact=true;
    if(s->active && count && count!=s->gestureContacts)s->cancelled=true;
}
static inline VM27TrackpadDirectionV1 VM27TrackpadDominantDirectionV2(double x,double y) {
    if(fabs(x)>=24 && fabs(x)>fabs(y)*1.25)return x<0?VM27TrackpadSwipeLeft:VM27TrackpadSwipeRight;
    if(fabs(y)>=24 && fabs(y)>fabs(x)*1.25)return y<0?VM27TrackpadSwipeUp:VM27TrackpadSwipeDown;
    return VM27TrackpadSwipeNone;
}
static inline VM27TrackpadSwipeResultV1 VM27TrackpadSwipePanV2(VM27TrackpadSwipeV2 *s,
    unsigned phase,double x,double y,double now) {
    VM27TrackpadSwipeResultV1 result={false,VM27TrackpadSwipeNone};
    if(phase==1) {
        s->active=s->haveContact && VM27TrackpadMultiContactV2(s->contacts) &&
            isfinite(now) && now>=s->contactTime && now-s->contactTime<=.35;
        s->gestureContacts=s->contacts;s->fired=false;s->cancelled=false;
    }
    result.consumed=s->active;
    if(!s->active)return result;
    if(!isfinite(x)||!isfinite(y)||fabs(x)>1000000||fabs(y)>1000000)s->cancelled=true;
    if(!s->fired && !s->cancelled && phase>=1 && phase<=3) {
        result.direction=VM27TrackpadDominantDirectionV2(x,y);
        if(result.direction)s->fired=true;
    }
    if(phase>=3) {s->active=false;s->fired=false;s->cancelled=false;}
    return result;
}
typedef struct {
    double contactTime,lastMoveTime;
    unsigned contacts,gestureContacts;
    bool haveContact,active,fired,cancelled;
} VM27TrackpadTransformV2;
static inline void VM27TrackpadTransformResetV2(VM27TrackpadTransformV2 *s) {memset(s,0,sizeof(*s));}
static inline void VM27TrackpadTransformContactV2(VM27TrackpadTransformV2 *s,unsigned count,double now) {
    if(count>16||!isfinite(now)||now<0||(s->haveContact&&now<s->contactTime)) {
        VM27TrackpadTransformResetV2(s);return;
    }
    if(!count)VM27TrackpadTransformResetV2(s);
    else if(s->active&&count!=s->gestureContacts)s->cancelled=true;
    s->contacts=count;s->contactTime=now;s->haveContact=true;
}
static inline VM27TrackpadDirectionV1 VM27TrackpadTransformMoveV2(VM27TrackpadTransformV2 *s,
    double x,double y,double now) {
    double reference=s->active?s->lastMoveTime:s->contactTime;
    if(!s->haveContact||!VM27TrackpadMultiContactV2(s->contacts)||!isfinite(now)||
       now<reference||now-reference>.35||!isfinite(x)||!isfinite(y)||fabs(x)>1000000||fabs(y)>1000000) {
        if(s->active)s->cancelled=true;
        return VM27TrackpadSwipeNone;
    }
    if(!s->active)s->gestureContacts=s->contacts;
    s->active=true;s->lastMoveTime=now;
    if(s->fired||s->cancelled)return VM27TrackpadSwipeNone;
    VM27TrackpadDirectionV1 direction=VM27TrackpadDominantDirectionV2(x,y);
    if(direction)s->fired=true;
    return direction;
}
#endif
