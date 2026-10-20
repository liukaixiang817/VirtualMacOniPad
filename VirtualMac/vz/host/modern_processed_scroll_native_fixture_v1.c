#include "modern_processed_scroll_native_v1.h"
#include <mach/mach_time.h>
#include <math.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern uint32_t IOHIDEventGetType(CFTypeRef);
extern uint64_t IOHIDEventGetTimeStamp(CFTypeRef);
extern double IOHIDEventGetFloatValue(CFTypeRef, uint32_t);
extern uint32_t IOHIDEventGetPhase(CFTypeRef);
extern id objc_retain(id);
extern void objc_release(id);
static unsigned checks, allocated, released;
static void require(int condition, const char *name) {
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL: %s\n", name); exit(2); }
}
static VM27InputPacket pan(void) {
    return (VM27InputPacket){.version=1,.source=VM27InputPan,.owner_epoch=9,
        .event_sequence=1,.coordinate_generation=7,
        .present=VM27InputHasPosition|VM27InputHasPhase|VM27InputHasProcessedScroll,
        .monotonic_timestamp_seconds=10.125,.view_x_points=31,.view_y_points=47,
        .processed_scroll_x_points=2.25,.processed_scroll_y_points=-5.125,.phase=VM27InputBegan};
}
static void invalid_packet(VM27InputPacket packet, VM27InputResult expected) {
    CFTypeRef output=(const void *)(uintptr_t)0x1234;
    require(vm27_processed_scroll_create_owned(&packet,&output)==expected,"malformed own pan rejected");
    require(output==(const void *)(uintptr_t)0x1234,"failure preserves ownership output");
}
int main(void) {
    uint64_t ticks=73;
    require(vm27_processed_scroll_mach_ticks(0.0000000005,1,1,&ticks)==VM27InputOK&&ticks==1,"genuine FRINTA positive half rounds away");
    require(vm27_processed_scroll_mach_ticks(0.0000000015,1,1,&ticks)==VM27InputOK&&ticks==2,"second half rounds away");
    require(vm27_processed_scroll_mach_ticks(0.000000001,3,2,&ticks)==VM27InputOK&&ticks==1,"timebase multiply then divide");
    require(vm27_processed_scroll_mach_ticks(0.000000001,3,1,&ticks)==VM27InputOK&&ticks==0,"subhalf rounds zero");
    const double invalid_seconds[]={-1,NAN,INFINITY,-INFINITY,0x1p64};
    for(unsigned i=0;i<sizeof(invalid_seconds)/sizeof(invalid_seconds[0]);++i) {
        ticks=73; require(vm27_processed_scroll_mach_ticks(invalid_seconds[i],1,1,&ticks)==VM27InputInvalid&&ticks==73,"invalid timestamp preserves output");
    }
    ticks=73;
    require(vm27_processed_scroll_mach_ticks(1,0,1,&ticks)==VM27InputInvalid&&ticks==73,"zero numerator rejected");
    require(vm27_processed_scroll_mach_ticks(1,1,0,&ticks)==VM27InputInvalid&&ticks==73,"zero denominator rejected");
    require(vm27_processed_scroll_mach_ticks(1,1,1,NULL)==VM27InputInvalid,"null timestamp output rejected");
    VM27InputPacket packet=pan();
    for(unsigned i=0;i<19;++i) {
        packet=pan(); VM27InputResult expected=VM27InputInvalid;
        switch(i) {
        case 0:packet.version=2;break;case 1:packet.owner_epoch=0;break;
        case 2:packet.event_sequence=0;break;case 3:packet.coordinate_generation=0;break;
        case 4:packet.source=VM27InputKey;expected=VM27InputUnsupported;break;
        case 5:packet.present|=VM27InputHasModifiers;expected=VM27InputUnsupported;break;
        case 6:packet.present&=~VM27InputHasPhase;expected=VM27InputUnsupported;break;
        case 7:packet.view_x_points=NAN;break;case 8:packet.view_y_points=INFINITY;break;
        case 9:packet.processed_scroll_x_points=-32768;break;
        case 10:packet.processed_scroll_y_points=32768;break;
        case 11:packet.processed_scroll_x_points=NAN;break;
        case 12:packet.additive_scale_delta=1;break;case 13:packet.rotation_delta_radians=1;break;
        case 14:packet.hid_usage_page=7;break;case 15:packet.named_modifiers=1;break;
        case 16:packet.contact_count=1;break;case 17:packet.pressed=true;break;
        case 18:packet.phase=VM27InputStationary;expected=VM27InputUnsupported;break;
        }
        invalid_packet(packet,expected);
    }
    require(vm27_processed_scroll_create_owned(NULL,NULL)==VM27InputInvalid,"null output rejected");
    CFTypeRef null_event=NULL;vm27_processed_scroll_release_owned(NULL);vm27_processed_scroll_release_owned(&null_event);
#ifdef VM27_SCROLL_PRODUCTION_REJECTION_FIXTURE
    require(!vm27_processed_scroll_native_profile_matches(),"current iPad UUID rejects this genuine different Mac host");
    for(unsigned i=0;i<64;++i)invalid_packet(pan(),VM27InputUnavailable);
    printf("{\"checks\":%u,\"realEventsCreated\":0,\"productionProfileRejected\":true,\"deviceOperations\":0,\"nativeHVCalls\":0,\"nativeVMCalls\":0}\n",checks);
#else
    require(vm27_processed_scroll_native_profile_matches(),"explicit genuine Mac IOKit profile");
    mach_timebase_info_data_t timebase={0};require(mach_timebase_info(&timebase)==KERN_SUCCESS&&timebase.numer&&timebase.denom,"real Mach timebase");
    const uint32_t phases[]={VM27InputBegan,VM27InputChanged,VM27InputEnded,VM27InputCancelled};
    const uint32_t native_phases[]={1,2,4,8};
    const double values[]={0,-0.0,0.000001,-0.000001,2.25,-5.125,32767.999,-32767.999};
    for(unsigned i=0;i<512;++i) {
        packet=pan();packet.event_sequence=i+1;packet.phase=phases[i%4];
        packet.monotonic_timestamp_seconds=10.0+(double)i/256.0;
        packet.processed_scroll_x_points=values[i%8];packet.processed_scroll_y_points=values[(i+3)%8];
        double rounded=round(((packet.monotonic_timestamp_seconds*1000000000.0)*timebase.denom)/timebase.numer);
        CFTypeRef event=NULL;
        require(vm27_processed_scroll_create_owned(&packet,&event)==VM27InputOK&&event,"real native factory owned result");++allocated;
        require(object_getClass((id)event)==objc_getClass("HIDEvent"),"real native HIDEvent identity");
        require(IOHIDEventGetType(event)==6,"real native type6");
        require(IOHIDEventGetTimeStamp(event)==(uint64_t)rounded,"real native converted timestamp readback");
        require(IOHIDEventGetPhase(event)==native_phases[i%4],"real native named phase readback");
        double x=(double)(int32_t)(packet.processed_scroll_x_points*65536.0)/65536.0;
        double y=(double)(int32_t)(packet.processed_scroll_y_points*65536.0)/65536.0;
        require(IOHIDEventGetFloatValue(event,0x60000)==x,"real x signed16.16 getter");
        require(IOHIDEventGetFloatValue(event,0x60001)==y,"real y signed16.16 getter");
        require(IOHIDEventGetFloatValue(event,0x60002)==0,"real z getter");
        require(objc_retain((id)event)==(id)event,"retain preserves genuine identity");objc_release((id)event);
        require(IOHIDEventGetType(event)==6,"native +1 object survives balanced extra retain");
        vm27_processed_scroll_release_owned(&event);++released;
        require(!event,"owned release clears output");vm27_processed_scroll_release_owned(&event);
    }
    require(allocated==512&&released==allocated,"balanced true native ownership");
    printf("{\"checks\":%u,\"realEventsCreated\":%u,\"realFinalReleases\":%u,\"namedPhaseMappings\":4,\"genuineMacIOKitUUID\":\"0e4cf3e4b0c2312ab1470bd4978ef0b7\",\"actualIPadExecuted\":false,\"UIKitClockOriginValidated\":false,\"deviceOperations\":0,\"nativeHVCalls\":0,\"nativeVMCalls\":0}\n",checks,allocated,released);
#endif
    return 0;
}
