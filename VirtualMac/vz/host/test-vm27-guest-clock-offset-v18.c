#include "vm27_guest_clock_offset_v18.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    const int64_t now=1792542365LL, skew=9*24*60*60;
    unsigned cases=0;
    /* Healthy guest readings can occur at either end of a delayed exec.
     * None may trigger the old queued-timestamp backward adjustment. */
    for(unsigned rtt=0;rtt<=150;++rtt) {
        double delay=(double)rtt/10.0;
        for(unsigned position=0;position<=10;++position) {
            int64_t guest=(int64_t)((double)now+delay*position/10.0);
            VM27ClockEstimateV18 result=VM27ClockEstimateSampleV18(guest,
                now,now+delay,100,100+delay);
            assert(result.decision==VM27ClockNoChangeV18);++cases;
        }
    }
    for(int sign=-1;sign<=1;sign+=2) {
        VM27ClockEstimateV18 result=VM27ClockEstimateSampleV18(now-sign*skew,
            now-0.1,now+0.1,100,100.2);
        assert(result.decision==VM27ClockAdjustV18 && result.deltaSeconds==sign*skew);
        /* Relative correction remains current even after arbitrary queued
         * delivery delays; an absolute timestamp would discard this delay. */
        for(int delivery=0;delivery<=120;++delivery) {
            int64_t atExecution=now-sign*skew+delivery;
            assert(atExecution+result.deltaSeconds==now+delivery);++cases;
        }
    }
    assert(VM27ClockEstimateSampleV18(now,now,now+20,100,120).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(now,now,now+10,100,101).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(now,now,now-10,100,101).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(now,now,now+1,100,99).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(now,NAN,now+1,100,101).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(now,now,INFINITY,100,101).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(-1,now,now+1,100,101).decision==VM27ClockInvalidV18);
    assert(VM27ClockEstimateSampleV18(INT64_MAX,now,now+1,100,101).decision==VM27ClockInvalidV18);
    printf("Clock18 delayed delivery and uncertainty checks passed: %u cases\n",cases+8);
    return 0;
}
