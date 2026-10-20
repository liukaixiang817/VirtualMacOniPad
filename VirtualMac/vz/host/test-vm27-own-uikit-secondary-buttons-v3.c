#include "vm27_own_uikit_ingress_values_v2_buttons.h"
#define main original_pointer_regression_main
#include "test-vm27-own-uikit-pointer-drag-v2.c"
#undef main
int main(void) {
 if(original_pointer_regression_main())return 1;
 VM27InputQueue *queue=NULL;check(vm27_input_queue_create(7,9,8,&queue)==VM27InputOK);
 VM27OwnPointerStateV1 state={0},next={0};VM27OwnPointerArgumentsV1 out;
 VM27InputViewportV1 viewport={0,0,100,100};
 unsigned buttons[]={2,2,3,1,0};
 for(unsigned i=0;i<5;++i){
  VM27InputPacket packet={.version=1,.source=VM27InputPointerButtons,.owner_epoch=7,
   .coordinate_generation=9,.event_sequence=i+1,.monotonic_timestamp_seconds=i+1,
   .present=VM27InputHasPhase|VM27InputHasPosition|VM27InputHasPointerButtons,
   .phase=i==0?VM27InputBegan:i==4?VM27InputEnded:VM27InputChanged,
   .view_x_points=10+10*i,.view_y_points=20+10*i,.pointer_buttons=buttons[i]};
  check(vm27_input_queue_publish(queue,&packet)==VM27InputOK);packet.pointer_buttons=7;
  VM27InputLease *lease=NULL;check(vm27_input_queue_acquire(queue,&lease)==VM27InputOK);
  const VM27InputPacket *copied=vm27_input_lease_packet(lease);check(copied&&copied->pointer_buttons==buttons[i]);
  check(vm27_own_pointer_arguments_v1(copied,viewport,&state,&out,&next)==VM27InputOK);
  check(out.buttons==buttons[i]);state=next;vm27_input_lease_release(&lease);
  if(i==0){VM27InputPacket hover={.version=1,.source=VM27InputHover,.present=VM27InputHasPosition,.view_x_points=95,.view_y_points=95};
   check(vm27_own_pointer_arguments_v1(&hover,viewport,&state,&out,&next)==VM27InputOK);
   check(out.buttons==2&&next.pressed&&next.primaryContact==0);state=next;}
 }
 check(!state.pressed&&!state.buttons);
 VM27InputPacket bad={.version=1,.source=VM27InputPointerButtons,.owner_epoch=7,.coordinate_generation=9,.event_sequence=6,
  .monotonic_timestamp_seconds=6,.present=VM27InputHasPhase|VM27InputHasPosition|VM27InputHasPointerButtons,
  .phase=VM27InputBegan,.pointer_buttons=8};
 check(vm27_input_queue_publish(queue,&bad)==VM27InputUnsupported);
 bad.pointer_buttons=2;check(vm27_input_queue_publish(queue,&bad)==VM27InputOK);
 check(vm27_input_queue_close(queue,7)==VM27InputOK);check(vm27_input_queue_destroy(&queue)==VM27InputOK);
 printf("Pointer secondary button copied-queue/held-hover regression checks=%u failures=%u\n",checks,failures);
 return failures?1:0;
}
