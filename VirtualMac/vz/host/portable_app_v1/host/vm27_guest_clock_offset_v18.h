#ifndef VM27_GUEST_CLOCK_OFFSET_V18_H
#define VM27_GUEST_CLOCK_OFFSET_V18_H
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
typedef enum {
    VM27ClockInvalidV18=0, VM27ClockNoChangeV18=1, VM27ClockAdjustV18=2
} VM27ClockDecisionV18;
typedef struct {
    VM27ClockDecisionV18 decision;
    int64_t deltaSeconds;
    double offsetSeconds, uncertaintySeconds, roundTripSeconds;
} VM27ClockEstimateV18;
/* The guest reading happened somewhere inside the measured round trip.
 * Never mistake command delivery time for guest clock drift. Wall-clock
 * changes during that interval invalidate the estimate. */
static inline VM27ClockEstimateV18 VM27ClockEstimateSampleV18(int64_t guest,
    double wallStart,double wallEnd,double monoStart,double monoEnd) {
    VM27ClockEstimateV18 r={0};
    if(guest<946684800LL || guest>=4102444800LL ||
       !isfinite(wallStart) || !isfinite(wallEnd) ||
       !isfinite(monoStart) || !isfinite(monoEnd) ||
       wallStart<1704067200.0 || wallStart>=4102444800.0 ||
       wallEnd<1704067200.0 || wallEnd>=4102444800.0 ||
       monoStart<0 || monoEnd<monoStart)return r;
    double elapsed=monoEnd-monoStart;
    if(elapsed>15 || fabs((wallEnd-wallStart)-elapsed)>0.5)return r;
    r.roundTripSeconds=elapsed;
    r.offsetSeconds=(wallStart+wallEnd)*0.5-(double)guest;
    r.uncertaintySeconds=elapsed*0.5+1.0;
    r.decision=VM27ClockNoChangeV18;
    if(fabs(r.offsetSeconds)>5.0+r.uncertaintySeconds) {
        r.deltaSeconds=(int64_t)llround(r.offsetSeconds);
        r.decision=VM27ClockAdjustV18;
    }
    return r;
}
#endif
