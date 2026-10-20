#include "modern_input_packet_v3_buttons.h"
#include <stdio.h>
#include <stdlib.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static VM27InputPacket hover(unsigned seq, VM27InputPhase phase) {
 return (VM27InputPacket){.version=1,.source=VM27InputHover,.owner_epoch=7,.coordinate_generation=9,.event_sequence=seq,.monotonic_timestamp_seconds=seq,.present=VM27InputHasPhase|VM27InputHasPosition,.phase=phase,.view_x_points=seq};
}
static VM27InputPacket button(unsigned seq, VM27InputPhase phase,unsigned mask) {
 VM27InputPacket p=hover(seq,phase);p.source=VM27InputPointerButtons;p.present|=VM27InputHasPointerButtons;p.pointer_buttons=mask;return p;
}
static VM27InputPacket key(unsigned seq,VM27InputPhase phase) {
 VM27InputPacket p=hover(seq,phase);p.source=VM27InputKey;p.present=VM27InputHasPhase|VM27InputHasHIDUsage|VM27InputHasModifiers;p.hid_usage_page=7;p.hid_usage=4;p.pressed=phase==VM27InputBegan;return p;
}
static void publish(VM27InputQueue *q,VM27InputPacket p) { CHECK(vm27_input_queue_publish(q,&p)==VM27InputOK); }
static void take(VM27InputQueue *q,unsigned seq) {
 VM27InputLease *l=NULL;CHECK(vm27_input_queue_acquire(q,&l)==VM27InputOK);CHECK(vm27_input_lease_packet(l)->event_sequence==seq);vm27_input_lease_release(&l);CHECK(!l);
}
int main(void) {
 VM27InputQueue *q=NULL;CHECK(vm27_input_queue_create(7,9,16,&q)==VM27InputOK);
 publish(q,hover(1,VM27InputBegan));publish(q,hover(2,VM27InputChanged));publish(q,hover(3,VM27InputStationary));
 publish(q,button(4,VM27InputBegan,2));publish(q,button(5,VM27InputChanged,2));publish(q,button(6,VM27InputChanged,2));publish(q,button(7,VM27InputChanged,3));publish(q,button(8,VM27InputEnded,0));publish(q,key(9,VM27InputBegan));publish(q,key(10,VM27InputEnded));
 unsigned expected[]={1,3,4,6,7,8,9,10};for(unsigned i=0;i<8;i++)take(q,expected[i]);
 VM27InputContact c={.owner_epoch=7,.contact_generation=101,.phase=VM27InputBegan,.view_x_points=4,.view_y_points=5};
 VM27InputPacket p=hover(11,VM27InputContactSnapshot);p.source=VM27InputTouch;p.present=VM27InputHasPhase|VM27InputHasContacts;p.contact_count=1;p.contacts=&c;publish(q,p);
 p.event_sequence=12;p.monotonic_timestamp_seconds=12;c.phase=VM27InputChanged;c.view_x_points=12;publish(q,p);
 p.event_sequence=13;p.monotonic_timestamp_seconds=13;c.view_x_points=13;publish(q,p);
 p.event_sequence=14;p.monotonic_timestamp_seconds=14;c.contact_generation=102;publish(q,p);
 p.event_sequence=15;p.monotonic_timestamp_seconds=15;c.phase=VM27InputEnded;publish(q,p);c.view_x_points=999;
 take(q,11);VM27InputLease *l=NULL;CHECK(vm27_input_queue_acquire(q,&l)==VM27InputOK);CHECK(vm27_input_lease_packet(l)->event_sequence==13);CHECK(vm27_input_lease_packet(l)->contacts[0].view_x_points==13);vm27_input_lease_release(&l);take(q,14);take(q,15);
 CHECK(vm27_input_queue_close(q,7)==VM27InputOK);CHECK(vm27_input_queue_destroy(&q)==VM27InputOK);
 CHECK(vm27_input_queue_create(7,9,1,&q)==VM27InputOK);publish(q,hover(1,VM27InputChanged));publish(q,hover(2,VM27InputChanged));p=key(3,VM27InputBegan);CHECK(vm27_input_queue_publish(q,&p)==VM27InputQueueFull);CHECK(vm27_input_queue_acquire(q,&l)==VM27InputOK);CHECK(vm27_input_lease_packet(l)->event_sequence==2);publish(q,p);CHECK(vm27_input_lease_packet(l)->event_sequence==2);CHECK(vm27_input_queue_close(q,7)==VM27InputBusy);CHECK(!vm27_input_lease_is_current(l));CHECK(vm27_input_lease_packet(l)->event_sequence==2);vm27_input_lease_release(&l);CHECK(vm27_input_queue_destroy(&q)==VM27InputOK);
 printf("Latest motion queue checks=%u failures=0\n",checks);return 0;
}
