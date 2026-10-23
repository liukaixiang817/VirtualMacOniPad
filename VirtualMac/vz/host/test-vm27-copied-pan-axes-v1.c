#include "vm27_copied_pan_axes_v1.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    VM27VZProcessedScrollArgumentsV1 a;
    assert(vm27_copied_pan_arguments_v1(0,40,.25,2,&a)==VM27InputOK);
    assert(a.scrolling_x==-40 && a.scrolling_y==0 && a.normalized_x==-10);
    assert(a.scroll_phase==4 && a.momentum_phase==0);
    assert(vm27_copied_pan_arguments_v1(40,0,.25,2,&a)==VM27InputOK);
    assert(a.scrolling_x==0 && a.scrolling_y==40 && a.normalized_y==10);
    assert(vm27_copied_pan_arguments_v1(-40,-80,.1,2,&a)==VM27InputOK);
    assert(a.scrolling_x==80 && a.scrolling_y==-40 && a.normalized_x==8 && a.normalized_y==-4);
    /* Reversing both screen deltas reverses both resulting wheel axes. */
    assert(vm27_copied_pan_arguments_v1(40,80,.1,2,&a)==VM27InputOK);
    assert(a.scrolling_x==-80 && a.scrolling_y==40);
    const unsigned in[]={1,2,4,8},out[]={1,4,8,16};
    for(unsigned i=0;i<4;++i) {
        assert(vm27_copied_pan_arguments_v1(0,0,1,in[i],&a)==VM27InputOK);
        assert(a.scroll_phase==out[i] && a.momentum_phase==0);
    }
    VM27VZProcessedScrollArgumentsV1 before=a;
    assert(vm27_copied_pan_arguments_v1(0,1,NAN,2,&a)==VM27InputInvalid);
    assert(!memcmp(&a,&before,sizeof(a)));
    assert(vm27_copied_pan_arguments_v1(0,32768,.1,2,&a)==VM27InputInvalid);
    assert(!memcmp(&a,&before,sizeof(a)));
    assert(vm27_copied_pan_arguments_v1(0,1,.1,3,&a)==VM27InputUnsupported);
    assert(!memcmp(&a,&before,sizeof(a)));
    /* Native HID input must retain its established order and scaling. */
    assert(vm27_vz_processed_scroll_arguments_v1(40,0,0,2,&a)==VM27InputOK);
    assert(a.scrolling_x==40 && a.scrolling_y==0 && a.normalized_x==4);
    puts("Copied pan axes, direction, phases and native HID separation passed.");
}
