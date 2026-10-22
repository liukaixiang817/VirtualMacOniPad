#include "vm27_guest_clock_offset_v18.h"
#include <time.h>
static double VM27ClockMonotonicV18(void) {
    struct timespec value;
    if(clock_gettime(CLOCK_MONOTONIC,&value))return -1;
    return (double)value.tv_sec+(double)value.tv_nsec/1000000000.0;
}
typedef void (^VM27ClockReadCompletionV18)(BOOL,VM27ClockEstimateV18);
static void VM27ClockReadActualV18(VM27OwnedQGAOperationV5 *owner,
                                 VM27ClockReadCompletionV18 completion) {
    double wallStart=NSDate.date.timeIntervalSince1970;
    double monoStart=VM27ClockMonotonicV18();
    OwnedQGARunV3(owner,@"/bin/date",@[@"-u",@"+%s"],^(BOOL success,NSData *output){
        double monoEnd=VM27ClockMonotonicV18();
        double wallEnd=NSDate.date.timeIntervalSince1970;
        NSString *text=[[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]autorelease];
        NSScanner *scanner=[NSScanner scannerWithString:text?:@""];
        long long epoch=0;
        BOOL parsed=[scanner scanLongLong:&epoch] &&
            [[text substringFromIndex:scanner.scanLocation]
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].length==0;
        VM27ClockEstimateV18 estimate=VM27ClockEstimateSampleV18(epoch,wallStart,wallEnd,monoStart,monoEnd);
        completion(success && parsed && estimate.decision!=VM27ClockInvalidV18,estimate);
    });
}
/* One real socket/epoch/generation lease covers sample, optional correction,
 * and verification. Only a measured offset is sent: the guest adds it to its
 * execution-time current clock. No queued absolute timestamp can move a
 * healthy clock backwards merely because command delivery was slow. */
static void VM27GuestSyncHostClockV18(id info,uint64_t generation,void (^continuation)(void)) {
    __block BOOL finished=NO;
    void (^finish)(void)=^{
        if(finished)return;finished=YES;
        if(generation==__atomic_load_n(&gGuestProvisioningGeneration,__ATOMIC_ACQUIRE) && continuation)continuation();
    };
    if(generation!=__atomic_load_n(&gGuestProvisioningGeneration,__ATOMIC_ACQUIRE)){finish();return;}
    if(!VM27GuestCommandEnabledV16(info,@"guest-exec") ||
       !VM27GuestCommandEnabledV16(info,@"guest-exec-status")) {
        VZGuestToolsLog(@"clock18 native exec unavailable; no clock change submitted");finish();return;
    }
    VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){
        (void)output;
        VZGuestToolsLog(@"clock18 operation finished success=%u originalQGA45sLeaseWhole=1",success);
        finish();
    });
    if(!owner)return;
    VM27ClockReadActualV18(owner,^(BOOL valid,VM27ClockEstimateV18 sample){
        if(![owner isLive])return;
        if(!valid) {
            VZGuestToolsLog(@"clock18 uncertain sample; no clock change submitted");
            [owner finish:NO output:[NSData data]];return;
        }
        BOOL adjust=sample.decision==VM27ClockAdjustV18;
        VZGuestToolsLog(@"clock18 actual sample offsetEstimate=%.3f uncertainty=%.3f rtt=%.3f correctionRequired=%u delta=%lld",
            sample.offsetSeconds,sample.uncertaintySeconds,sample.roundTripSeconds,adjust,(long long)sample.deltaSeconds);
        if(!adjust){[owner finish:YES output:[NSData data]];return;}
        const long long delta=sample.deltaSeconds;
        NSString *script=[NSString stringWithFormat:
            @"set -eu\n[ \"$(/usr/bin/id -u)\" = 0 ] && [ \"$(/usr/bin/id -ru)\" = 0 ]\n"
             "before=$(/bin/date -u +%%s)\ncase \"$before\" in ''|*[!0-9]*) exit 65;;esac\n"
             "[ \"$before\" -ge 946684800 ] && [ \"$before\" -lt 4102444800 ]\n"
             "delta=%lld\ntarget=$((before+delta))\n[ \"$target\" -ge 1704067200 ] && [ \"$target\" -lt 4102444800 ]\n"
             "stamp=$(/bin/date -u -r \"$target\" '+%%m%%d%%H%%M%%Y.%%S')\n/bin/date -u \"$stamp\" >/dev/null\n"
             "after=$(/bin/date -u +%%s)\nprintf 'VM27_CLOCK18 before=%%s after=%%s delta=%%s target=%%s\\n' \"$before\" \"$after\" \"$delta\" \"$target\"\n",delta];
        OwnedQGARunV3(owner,@"/bin/sh",@[@"-c",script],^(BOOL success,NSData *output){
            if(![owner isLive])return;
            NSString *text=[[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]autorelease];
            unsigned matches=0;long long before=0,after=0,reportedDelta=0,target=0;
            for(NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
                if(![line hasPrefix:@"VM27_CLOCK18 "])continue;
                long long b=0,a=0,d=0,t=0;char extra=0;
                if(sscanf(line.UTF8String,"VM27_CLOCK18 before=%lld after=%lld delta=%lld target=%lld %c",&b,&a,&d,&t,&extra)==4)
                    {++matches;before=b;after=a;reportedDelta=d;target=t;}
            }
            BOOL applied=success && matches==1 && before>=946684800LL && before<4102444800LL &&
                reportedDelta==delta && target==before+delta && target>=1704067200LL && target<4102444800LL &&
                after>=target && after-target<=5;
            VZGuestToolsLog(@"clock18 actual relative correction applied=%u delta=%lld before=%lld after=%lld queuedAbsoluteTarget=0",
                applied,delta,before,after);
            if(!applied){[owner finish:NO output:[NSData data]];return;}
            VM27ClockReadActualV18(owner,^(BOOL read,VM27ClockEstimateV18 verified){
                if(![owner isLive])return;
                BOOL close=read && verified.decision==VM27ClockNoChangeV18;
                VZGuestToolsLog(@"clock18 actual epoch verified=%u offsetEstimate=%.3f uncertainty=%.3f rtt=%.3f noSecondClockWrite=1",
                    close,verified.offsetSeconds,verified.uncertaintySeconds,verified.roundTripSeconds);
                [owner finish:close output:[NSData data]];
            });
        });
    });
}
