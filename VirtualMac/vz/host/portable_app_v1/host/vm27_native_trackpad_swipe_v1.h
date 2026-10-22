#ifndef VM27_NATIVE_TRACKPAD_SWIPE_V1_H
#define VM27_NATIVE_TRACKPAD_SWIPE_V1_H
#include "vm27_trackpad_three_finger_swipe_v1.h"
#include <stdint.h>
typedef struct { uint32_t identifier;double x,y; } VM27NativeTrackpadContactV1;
typedef struct {
 VM27NativeTrackpadContactV1 origin[4];
 unsigned count;double began,last;
 bool active,fired,cancelled;
} VM27NativeTrackpadSwipeV1;
static inline void VM27NativeTrackpadResetV1(VM27NativeTrackpadSwipeV1 *s){memset(s,0,sizeof(*s));}
static inline VM27TrackpadDirectionV1 VM27NativeTrackpadUpdateV1(VM27NativeTrackpadSwipeV1 *s,
 const VM27NativeTrackpadContactV1 *input,unsigned count,double now) {
 if(!count){VM27NativeTrackpadResetV1(s);return VM27TrackpadSwipeNone;}
 if(!input || count>10 || !isfinite(now)||now<0 || (s->active && (now<s->last || now-s->last>.5))) {
  s->cancelled=true;return VM27TrackpadSwipeNone;
 }
 VM27NativeTrackpadContactV1 contacts[10];
 for(unsigned i=0;i<count;++i){
  if(!isfinite(input[i].x)||!isfinite(input[i].y)||input[i].x<0||input[i].x>1||input[i].y<0||input[i].y>1){s->cancelled=true;return VM27TrackpadSwipeNone;}
  contacts[i]=input[i];
  for(unsigned j=0;j<i;++j)if(contacts[j].identifier==contacts[i].identifier){s->cancelled=true;return VM27TrackpadSwipeNone;}
 }
 for(unsigned i=1;i<count;++i)for(unsigned j=i;j>0 && contacts[j].identifier<contacts[j-1].identifier;--j){VM27NativeTrackpadContactV1 t=contacts[j];contacts[j]=contacts[j-1];contacts[j-1]=t;}
 if(s->cancelled)return VM27TrackpadSwipeNone;
 if(!s->active && count<3)return VM27TrackpadSwipeNone;
 if(count>4){s->cancelled=true;return VM27TrackpadSwipeNone;}
 if(!s->active || (!s->fired && s->count==3 && count==4)) {
  memcpy(s->origin,contacts,count*sizeof(*contacts));s->count=count;s->began=s->last=now;s->active=true;
  return VM27TrackpadSwipeNone;
 }
 s->last=now;
 if(count!=s->count){s->cancelled=true;return VM27TrackpadSwipeNone;}
 double dx[4],dy[4],x=0,y=0;
 for(unsigned i=0;i<count;++i){
  if(contacts[i].identifier!=s->origin[i].identifier){s->cancelled=true;return VM27TrackpadSwipeNone;}
  dx[i]=contacts[i].x-s->origin[i].x;dy[i]=contacts[i].y-s->origin[i].y;x+=dx[i];y+=dy[i];
 }
 x/=count;y/=count;
 if(s->fired || now-s->began<.04)return VM27TrackpadSwipeNone;
 bool horizontal=fabs(x)>.065 && fabs(x)>fabs(y)*1.35;
 bool vertical=fabs(y)>.065 && fabs(y)>fabs(x)*1.35;
 if(!horizontal && !vertical)return VM27TrackpadSwipeNone;
 double dominant=horizontal?x:y;
 for(unsigned i=0;i<count;++i){
  double d=horizontal?dx[i]:dy[i],other=horizontal?dy[i]:dx[i];
  if(d*dominant<=0 || fabs(d)<.012 || fabs(other)>fabs(d)*1.8+.02)return VM27TrackpadSwipeNone;
 }
 s->fired=true;
 return horizontal?(x<0?VM27TrackpadSwipeLeft:VM27TrackpadSwipeRight):(y<0?VM27TrackpadSwipeUp:VM27TrackpadSwipeDown);
}
#endif
