#import "modern_independent_input_coordinator_v2.h"
#import "VZBackendSelection.h"
#include <pthread.h>
#include <unistd.h>
#if !__has_feature(objc_arc)
#error Independent input coordinator requires ARC as a separate compile unit.
#endif
NSString *VM27IndependentInputPlatformAvailabilityReasonV2(void) {
    /* Current class exports alone do not prove real UIKit dispatch association,
     * UIEvent clock origin or original UHK/VZ native event consumer callability. */
    return @"Independent27 UIKit dispatch, clock origin and native input consumer validation remain incomplete.";
}
static NSError *input_error(NSString *reason) {
    return [NSError errorWithDomain:@"VirtualMac.Independent27Input" code:1
        userInfo:@{NSLocalizedDescriptionKey:reason}];
}
@implementation VM27IndependentInputCoordinatorV2 {
    __weak VM27UIKitInputWindowV2 *_window;
    VM27UIKitInputSurfaceV2 *_surface;
    VM27UIKitInputSessionV2 *_session;
    id<VM27IndependentInputEndpointV2> _endpoint;
    pid_t _ownerPID;
}
- (instancetype)initWithWindow:(VM27UIKitInputWindowV2 *)window
    surface:(VM27UIKitInputSurfaceV2 *)surface {
    if (!window || !surface || !pthread_main_np() || surface.window != window) return nil;
    self = [super init];
    if (self) { _window=window;_surface=surface;_ownerPID=getpid(); }
    return self;
}
- (BOOL)attachValidatedEndpoint:(id<VM27IndependentInputEndpointV2>)endpoint
    epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates error:(NSError **)error {
    NSString *reason=nil;
    if (_ownerPID!=getpid() || !pthread_main_np()) reason=@"Independent input requires its owning UIKit thread.";
    else if (!endpoint || !epoch || !coordinates || _session) reason=@"An independent input endpoint, fresh epoch and coordinates are required.";
    else if (![VZBackendSelectedVersion() isEqualToString:@"27"] ||
             ![VZBackendLoadedVersion() isEqualToString:@"27"] || !VZBackendIsRunActive())
        reason=@"Independent27 must be exclusively selected, loaded and running before input admission.";
    else if ((reason=VZBackendAvailabilityReason(@"27"))) {}
    else if ((reason=VM27IndependentInputPlatformAvailabilityReasonV2())) {}
    else if ((reason=[endpoint independent27InputAvailabilityReason])) {}
    else if (!_window || _surface.window!=_window || !vm27_processed_scroll_native_profile_matches())
        reason=@"The receiving window or genuine native IOKit profile changed.";
    if (reason) { if(error)*error=input_error(reason);return NO; }
    VM27UIKitInputSessionV2 *session=[_surface activateWithSink:endpoint epoch:epoch coordinateGeneration:coordinates capacity:128];
    if (!session) { if(error)*error=input_error(@"Independent input session could not be created.");return NO; }
    _session=session;_endpoint=endpoint;
    BOOL started=NO;
    @try { started=[endpoint startIndependent27CopiedInputConsumer:session]; }
    @catch (NSException *exception) { (void)exception; }
    if (!started) {
        [self close];if(error)*error=input_error(@"Independent input consumer did not start.");return NO;
    }
    return YES;
}
- (VM27InputResult)close {
    if (_ownerPID!=getpid()) return VM27InputStaleEpoch;
    if (!pthread_main_np()) return VM27InputWrongThread;
    /* Admission closes under the same mutex as the native sink. Only after its
     * admitted call finishes may the independent consumer stop and release. */
    VM27InputResult result=[_surface close];
    id<VM27IndependentInputEndpointV2> endpoint=_endpoint;
    VM27InputResult stopped=VM27InputOK;
    @try { if (endpoint) stopped=[endpoint stopAndJoinIndependent27CopiedInputConsumer]; }
    @catch (NSException *exception) { (void)exception;stopped=VM27InputUnavailable; }
    if (stopped!=VM27InputOK) return stopped;
    _endpoint=nil;_session=nil;
    return result;
}
@end
