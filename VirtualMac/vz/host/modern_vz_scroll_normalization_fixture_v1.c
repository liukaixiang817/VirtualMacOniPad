#include "modern_vz_scroll_normalization_v1.h"
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr,"check failed at line %d: %s\n",__LINE__,#expression); exit(1); } } while(0)

int main(void) {
    const uint32_t native[4]={1,2,4,8};
    const uint64_t original[4]={1,4,8,16};
    unsigned valid=0, rejected=0;
    for (unsigned i=0;i<2048;++i) {
        double x = ((int)i-1024)/16.0, y = ((int)((i*37)%2048)-1024)/32.0;
        for (unsigned phase=0;phase<4;++phase) {
            VM27VZProcessedScrollArgumentsV1 args={0};
            CHECK(vm27_vz_processed_scroll_arguments_v1(x,y,0,native[phase],&args)==VM27InputOK);
            CHECK(args.scrolling_x==x && args.scrolling_y==y);
            CHECK(args.normalized_x==x/10.0 && args.normalized_y==y/10.0);
            CHECK(args.scroll_phase==original[phase] && args.momentum_phase==0);
            ++valid;
        }
    }
    const double limits[]={-32767.9999847412109375,32767.9999847412109375,-0.0,0.0,1.0/65536.0,-1.0/65536.0};
    for (unsigned i=0;i<sizeof(limits)/sizeof(limits[0]);++i) {
        VM27VZProcessedScrollArgumentsV1 args={0};
        CHECK(vm27_vz_processed_scroll_arguments_v1(limits[i],-limits[i],-0.0,2,&args)==VM27InputOK);
        CHECK(args.scrolling_x==limits[i] && !!signbit(args.scrolling_x)==!!signbit(limits[i]));
        CHECK(args.normalized_x==limits[i]/10.0 && !!signbit(args.normalized_x)==!!signbit(limits[i]));
        ++valid;
    }
    const double bad[]={-32768.0,32768.0,INFINITY,-INFINITY,NAN};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        for (unsigned axis=0;axis<2;++axis) {
            VM27VZProcessedScrollArgumentsV1 args, before;
            memset(&args,0xa5,sizeof(args)); before=args;
            CHECK(vm27_vz_processed_scroll_arguments_v1(axis?0:bad[i],axis?bad[i]:0,0,1,&args)==VM27InputInvalid);
            CHECK(!memcmp(&args,&before,sizeof(args))); ++rejected;
        }
    }
    for (unsigned phase=0;phase<256;++phase) {
        if (phase==1||phase==2||phase==4||phase==8) continue;
        VM27VZProcessedScrollArgumentsV1 args,before;
        memset(&args,0x5a,sizeof(args)); before=args;
        CHECK(vm27_vz_processed_scroll_arguments_v1(1,2,0,phase,&args)==VM27InputUnsupported);
        CHECK(!memcmp(&args,&before,sizeof(args))); ++rejected;
    }
    VM27VZProcessedScrollArgumentsV1 args,before;
    memset(&args,0x5a,sizeof(args)); before=args;
    CHECK(vm27_vz_processed_scroll_arguments_v1(1,2,1,1,&args)==VM27InputInvalid);
    CHECK(!memcmp(&args,&before,sizeof(args))); ++rejected;
    CHECK(vm27_vz_processed_scroll_arguments_v1(1,2,0,1,NULL)==VM27InputInvalid); ++rejected;
    printf("{\"checks\":%u,\"acceptedPreciseFallbackCases\":%u,\"rejectedCases\":%u,\"originalVZCalls\":0,\"nativeHVCalls\":0,\"nativeVMCalls\":0,\"deviceOperations\":0}\n",checks,valid,rejected);
    return 0;
}
