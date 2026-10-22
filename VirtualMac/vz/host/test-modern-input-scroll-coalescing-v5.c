#define main latest_motion_main
#include "test-modern-input-latest-motion-v4.c"
#undef main
#include <math.h>
extern VM27InputResult vm27_input_queue_pan_diagnostic_policy_v1(VM27InputQueue *,uint64_t,uint64_t,bool);
static VM27InputPacket pan(unsigned seq,VM27InputPhase phase,double x,double y) {
 VM27InputPacket p=hover(seq,phase);p.source=VM27InputPan;p.present|=VM27InputHasProcessedScroll;
 p.processed_scroll_x_points=x;p.processed_scroll_y_points=y;return p;
}
static void take_pan(VM27InputQueue *q,unsigned seq,VM27InputPhase phase,double x,double y) {
 VM27InputLease *l=NULL;CHECK(vm27_input_queue_acquire(q,&l)==VM27InputOK);
 const VM27InputPacket *p=vm27_input_lease_packet(l);
 CHECK(p->source==VM27InputPan && p->event_sequence==seq && p->phase==phase);
 CHECK(p->processed_scroll_x_points==x && p->processed_scroll_y_points==y);
 CHECK(p->monotonic_timestamp_seconds==seq && p->view_x_points==seq);
 vm27_input_lease_release(&l);
}
static void finish(VM27InputQueue **q) {
 CHECK(vm27_input_queue_close(*q,7)==VM27InputOK);CHECK(vm27_input_queue_destroy(q)==VM27InputOK);
}
int main(void) {
 CHECK(latest_motion_main()==0);
 VM27InputQueue *q=NULL;CHECK(vm27_input_queue_create(7,9,16,&q)==VM27InputOK);
 publish(q,pan(1,VM27InputBegan,0,0));
 publish(q,pan(2,VM27InputChanged,1.25,2.5));publish(q,pan(3,VM27InputChanged,-0.5,3.25));
 publish(q,key(4,VM27InputBegan));publish(q,pan(5,VM27InputChanged,4,-7));
 publish(q,pan(6,VM27InputEnded,0,0));publish(q,pan(7,VM27InputCancelled,0,0));
 take_pan(q,1,VM27InputBegan,0,0);take_pan(q,3,VM27InputChanged,0.75,5.75);
 take(q,4);take_pan(q,5,VM27InputChanged,4,-7);
 take_pan(q,6,VM27InputEnded,0,0);take_pan(q,7,VM27InputCancelled,0,0);finish(&q);
 CHECK(vm27_input_queue_create(7,9,4,&q)==VM27InputOK);
 publish(q,pan(1,VM27InputChanged,0,32767));publish(q,pan(2,VM27InputChanged,0,1));
 take_pan(q,1,VM27InputChanged,0,32767);take_pan(q,2,VM27InputChanged,0,1);
 publish(q,pan(3,VM27InputChanged,0,2));VM27InputLease *lease=NULL;
 CHECK(vm27_input_queue_acquire(q,&lease)==VM27InputOK);publish(q,pan(4,VM27InputChanged,0,3));
 CHECK(vm27_input_lease_packet(lease)->processed_scroll_y_points==2);
 CHECK(vm27_input_queue_pan_diagnostic_policy_v1(q,7,9,false)==VM27InputBusy);
 vm27_input_lease_release(&lease);take_pan(q,4,VM27InputChanged,0,3);
 CHECK(vm27_input_queue_pan_diagnostic_policy_v1(q,7,9,false)==VM27InputOK);
 publish(q,pan(5,VM27InputChanged,0,1));publish(q,pan(6,VM27InputChanged,0,2));
 take_pan(q,5,VM27InputChanged,0,1);take_pan(q,6,VM27InputChanged,0,2);
 CHECK(vm27_input_queue_pan_diagnostic_policy_v1(q,7,9,true)==VM27InputOK);
 publish(q,pan(7,VM27InputChanged,0,1));publish(q,pan(8,VM27InputChanged,0,2));
 take_pan(q,8,VM27InputChanged,0,3);
 VM27InputPacket invalid=pan(9,VM27InputChanged,0,1);invalid.coordinate_generation=10;
 CHECK(vm27_input_queue_publish(q,&invalid)==VM27InputWrongCoordinates);finish(&q);
 CHECK(vm27_input_queue_create(7,9,4,&q)==VM27InputOK);
 for(unsigned i=1;i<=120;++i)publish(q,pan(i,VM27InputChanged,0,0.25));
 take_pan(q,120,VM27InputChanged,0,30);finish(&q);
 printf("Scroll conservation, lifecycle and ordering checks=%u failures=0\n",checks);
 return 0;
}
