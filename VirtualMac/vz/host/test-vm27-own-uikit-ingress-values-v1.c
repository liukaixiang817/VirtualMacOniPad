#include "vm27_own_uikit_ingress_values_v1.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
static unsigned checks, failures, mapped, unsupported;
static void check(int value) { ++checks; if (!value) ++failures; }
static VM27InputPacket key(uint32_t usage, bool pressed) {
    return (VM27InputPacket){.version=1,.source=VM27InputKey,
        .present=VM27InputHasHIDUsage|VM27InputHasPhase,.hid_usage_page=7,.hid_usage=usage,
        .phase=pressed?VM27InputBegan:VM27InputEnded,.pressed=pressed};
}
int main(void) {
    for (uint32_t usage = 0; usage < 512; ++usage) {
        VM27InputPacket packet = key(usage, true); int64_t type=99; uint16_t code=999;
        VM27InputResult result = vm27_own_key_arguments_v1(&packet,&type,&code);
        if (result == VM27InputOK) {
            ++mapped; check(type==0 && code<128);
            uint16_t down=code; packet=key(usage,false);
            check(vm27_own_key_arguments_v1(&packet,&type,&code)==VM27InputOK);
            check(type==1 && code==down);
        } else {
            ++unsupported; check(result==VM27InputUnsupported); check(type==99 && code==999);
        }
    }
    const uint32_t usages[] = {4,0x29,0x50,0xe0,0xe1,0xe3,0xe7};
    const uint16_t codes[] = {0,53,123,59,56,55,54};
    for (unsigned i=0;i<7;++i) {
        VM27InputPacket packet=key(usages[i],true);int64_t type;uint16_t code;
        check(vm27_own_key_arguments_v1(&packet,&type,&code)==VM27InputOK);check(code==codes[i]);
    }
    VM27InputPacket bad=key(4,true);int64_t type=77;uint16_t code=888;
    bad.phase=VM27InputChanged;
    check(vm27_own_key_arguments_v1(&bad,&type,&code)==VM27InputInvalid);check(type==77&&code==888);
    bad=key(4,true);bad.hid_usage_page=12;
    check(vm27_own_key_arguments_v1(&bad,&type,&code)==VM27InputUnsupported);check(type==77&&code==888);
    VM27InputViewportV1 viewport={10,20,100,200};
    for (unsigned round=0;round<128;++round) {
        VM27OwnPointerStateV1 state={0}, next={0};VM27OwnPointerArgumentsV1 args={0};
        VM27InputContact contact={.owner_epoch=7,.contact_generation=round+1,.view_x_points=60,.view_y_points=120,.phase=VM27InputBegan};
        VM27InputPacket packet={.version=1,.source=VM27InputTouch,.owner_epoch=7,.present=VM27InputHasContacts,.contact_count=1,.contacts=&contact};
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);
        check(args.x==.5&&args.y==.5&&args.buttons==1);check(next.primaryContact==round+1&&next.pressed);state=next;
        contact.phase=VM27InputChanged;contact.view_x_points=210;contact.view_y_points=-40;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);
        check(args.x==1&&args.y==0&&args.buttons==1);state=next;
        VM27OwnPointerArgumentsV1 oldargs=args;VM27OwnPointerStateV1 oldnext=next;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputEmpty);
        check(!memcmp(&args,&oldargs,sizeof(args))&&!memcmp(&next,&oldnext,sizeof(next)));
        VM27InputContact two[]={contact,{.owner_epoch=7,.contact_generation=round+257,.view_x_points=35,.view_y_points=45,.phase=VM27InputBegan}};
        packet.contacts=two;packet.contact_count=2;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);
        check(args.x==1&&args.y==0&&args.buttons==0);check(!next.pressed&&!next.primaryContact);state=next;
        oldargs=args;oldnext=next;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputEmpty);
        check(!memcmp(&args,&oldargs,sizeof(args))&&!memcmp(&next,&oldnext,sizeof(next)));
        packet.contacts=&contact;packet.contact_count=1;contact.phase=VM27InputBegan;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);state=next;
        contact.phase=VM27InputCancelled;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);
        check(args.buttons==0&&!next.pressed);state=next;
        packet.source=VM27InputHover;packet.present=VM27InputHasPosition;packet.view_x_points=60;packet.view_y_points=120;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputOK);check(args.x==.5&&args.y==.5&&args.buttons==0);
        oldargs=args;oldnext=next;
        packet.view_x_points=NAN;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputInvalid);
        check(!memcmp(&args,&oldargs,sizeof(args))&&!memcmp(&next,&oldnext,sizeof(next)));
        packet.source=VM27InputTouch;packet.present=VM27InputHasContacts;packet.contacts=two;packet.contact_count=2;two[1].contact_generation=two[0].contact_generation;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputInvalid);
        check(!memcmp(&args,&oldargs,sizeof(args))&&!memcmp(&next,&oldnext,sizeof(next)));
        two[1].contact_generation=round+257;two[1].owner_epoch=8;
        check(vm27_own_pointer_arguments_v1(&packet,viewport,&state,&args,&next)==VM27InputInvalid);
        check(!memcmp(&args,&oldargs,sizeof(args))&&!memcmp(&next,&oldnext,sizeof(next)));
    }
    check(mapped>60&&mapped<128);check(mapped+unsupported==512);
    printf("{\"checks\":%u,\"failures\":%u,\"mappedHIDUsages\":%u,\"unsupportedHIDUsages\":%u,\"pointerLifecycles\":128,\"VZCalls\":0}\n",checks,failures,mapped,unsupported);
    return failures?1:0;
}
