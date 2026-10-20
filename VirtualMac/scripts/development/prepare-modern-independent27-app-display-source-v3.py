#!/usr/bin/env python3
"""Build a copied App source with genuine VZ queue and source UIKit display.

The production backend admission and loader remain authoritative. No signing,
device operation, legacy App edit, or synthetic VM/display is performed.
"""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 old=N/'independent27-app-input-source-candidate-v2/VirtualMacApp.independent27.source-candidate.m'
 oldpin=pin(old);assert oldpin['sha256']=='ebe2a8bd6352d18350aee1b25c5444463d981ac5aa7df0fd98178adfa4517251'
 prior=old.read_text();source=prior
 def replace(before,after):
  nonlocal source
  assert source.count(before)==1,(before[:100],source.count(before));source=source.replace(before,after,1)
 replace('#import "modern_independent_input_app_entry_v2.h"',
         '#import "vm27_input_queue_v3.h"\n#import "vm27_uikit_guest_display_v1.h"\n#import "vm27_independent_app_runtime_v1.h"')
 replace('static VM27IndependentInputCoordinatorV2 *gIndependent27InputCoordinator;',
 '''static VM27InputQueueV3 *gIndependent27InputQueueV3;
static VM27UIKitGuestDisplayV1 *gIndependent27GuestDisplay;
static BOOL gIndependent27OwnerClosePending;
static NSError *gIndependent27DisplayFailure;
static uint64_t gIndependent27SessionEpoch;
static uint64_t gIndependent27CoordinateGeneration;
static BOOL gIndependent27InputClosePending;
static void finishVMThreadSafe(id delegate, NSError *error);
static void VZIndependent27FailActualDisplay(NSError *error);
static BOOL VZIndependent27ResumeActualInput(void);
static void VZIndependent27PauseActualInput(void);''')
 start=source.index('// Future independent27 loader\'s explicit input attachment entry.')
 end=source.index('static UIView *gDisplayContainer;',start)
 source=source[:start]+'''VM27InputResult VZIndependent27CloseInput(void) {
    return gIndependent27InputQueueV3?[gIndependent27InputQueueV3 close]:VM27InputClosed;
}
'''+source[end:]
 replace('''- (void)finishVMAndShowLibraryWithError:(NSError *)error
{
    VM27InputResult stopped=VZIndependent27CloseInput();''',
 '''- (void)finishVMAndShowLibraryWithError:(NSError *)error
{
    if (!pthread_main_np()) {
        finishVMThreadSafe(self,error);
        return;
    }
    if (gIndependent27OwnerClosePending) return;
    if (gIndependent27InputQueueV3 || gIndependent27GuestDisplay) {
        gIndependent27OwnerClosePending=YES;
        id retainedOwner=[self retain];
        NSError *retainedError=[(error ?: gIndependent27DisplayFailure) retain];
        void (^finishDisplay)(VM27InputResult)=^(VM27InputResult inputResult) {
            if (inputResult!=VM27InputOK && inputResult!=VM27InputClosed) {
                gIndependent27OwnerClosePending=NO;
                VZPresentFailureReport(retainedOwner,VZL(@"Virtual Mac Stopped"),
                    @"The actual input owner could not drain. The VM remains retained.",
                    nil,VZFailureSupportOptionSuggestDebugLogging);
                [retainedError release];[retainedOwner release];
                return;
            }
            [gIndependent27InputQueueV3 release];gIndependent27InputQueueV3=nil;
            void (^finish)(NSError *)=^(NSError *displayError) {
                gIndependent27OwnerClosePending=NO;
                if (displayError) {
                    VZPresentFailureReport(retainedOwner,VZL(@"Virtual Mac Stopped"),
                        displayError.localizedDescription,displayError.debugDescription,
                        VZFailureSupportOptionSuggestDebugLogging);
                } else {
                    [gIndependent27GuestDisplay release];gIndependent27GuestDisplay=nil;
                    [retainedOwner finishVMAndShowLibraryWithError:retainedError];
                }
                [retainedError release];[retainedOwner release];
            };
            if (gIndependent27GuestDisplay)
                [gIndependent27GuestDisplay closeWithCompletion:finish];
            else finish(nil);
        };
        if (gIndependent27InputQueueV3)
            [gIndependent27InputQueueV3 closeWithCompletion:finishDisplay];
        else finishDisplay(VM27InputClosed);
        return;
    }
    VM27InputResult stopped=VZIndependent27CloseInput();''')
 replace('''    [gVirtualMachine release];
    gVirtualMachine = nil;''','''    [gVirtualMachine release];
    gVirtualMachine = nil;
    [gIndependent27DisplayFailure release];gIndependent27DisplayFailure=nil;''')
 replace('''    if (!installFramebufferTrace())
        return NO;''','''    if (VZIndependent27SourceRouteSelected()) {
        __block BOOL profile=NO;
        void (^check)(void)=^{ profile=VM27GenuineDisplayClassProfileAvailableV1(NULL); };
        if (pthread_main_np()) check();else dispatch_sync(dispatch_get_main_queue(),check);
        if (!profile) return NO;
    } else if (!installFramebufferTrace()) return NO;''')
 replace('''static BOOL loadExtractedFrameworks(void) {
    VZBackendMarkLoadAttempt();''','''static BOOL loadExtractedFrameworks(void) {
    VZBackendMarkLoadAttempt();
    if (VZIndependent27SourceRouteSelected()) {
        NSError *runtimeError=nil;
        if (!VM27IndependentAppRuntimeLoadV1(VZRuntimeRoot(),&runtimeError)) {
            fprintf(stderr,"[Independent27] actual runtime load failed: %s\\n",
                runtimeError.description.UTF8String ?: "unknown failure");
            return NO;
        }
        __block BOOL profile=NO;
        void (^check)(void)=^{ profile=VM27GenuineDisplayClassProfileAvailableV1(NULL); };
        if (pthread_main_np()) check();else dispatch_sync(dispatch_get_main_queue(),check);
        if (!profile) return NO;
        VZBackendMarkLoaded();
        return YES;
    }''')
 replace('''static BOOL prepareFramebuffer(UIView *container) {
    NSArray *graphicsDevices''','''static BOOL prepareFramebuffer(UIView *container) {
    if (VZIndependent27SourceRouteSelected()) {
        NSError *displayError=nil;
        gIndependent27GuestDisplay=[[VM27UIKitGuestDisplayV1 alloc]
            initWithVirtualMachine:gVirtualMachine container:container
            failureHandler:^(NSError *failure) { VZIndependent27FailActualDisplay(failure); }
            error:&displayError];
        if (!gIndependent27GuestDisplay) {
            setStatus(displayError.localizedDescription ?: @"The genuine VZ27 display is unavailable.");
            return NO;
        }
        gDisplayContainer=container;
        gFramebufferView=[gIndependent27GuestDisplay.view retain];
        gFramebuffer=nil;gDisplayLayer=nil;
        gFramebufferView.hidden=NO;
        return YES;
    }
    NSArray *graphicsDevices''')
 replace('''static void activateFramebuffer(void) {
    id view''','''static void activateFramebuffer(void) {
    if (VZIndependent27SourceRouteSelected()) {
        if (gIndependent27GuestDisplay) {
            gIndependent27GuestDisplay.view.hidden=NO;
            [gIndependent27InputSurface becomeFirstResponder];
            setStatus(@"Virtual Mac running — waiting for an actual guest display frame");
        }
        return;
    }
    id view''')
 replace('''static void activateFramebuffer(void) {''','''static void VZIndependent27FailActualDisplay(NSError *error) {
    NSCAssert(pthread_main_np(),@"The actual VM control queue is main.");
    if (!error) error=[NSError errorWithDomain:@"VirtualMac.Independent27" code:6
        userInfo:@{NSLocalizedDescriptionKey:@"An actual independent VM component failed without an error description."}];
    if (!gIndependent27DisplayFailure) gIndependent27DisplayFailure=[error retain];
    setStatus(error.localizedDescription);
    if (!gVirtualMachine || ((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"))==0)
        finishVMThreadSafe(gVirtualMachineDelegate,error);
    else forceStopVirtualMachine();
}

static void activateFramebuffer(void) {''')
 replace('''static BOOL gForceStopPending;''','''static BOOL VZIndependent27ResumeActualInput(void) {
    if (!pthread_main_np() || gIndependent27OwnerClosePending || gIndependent27InputClosePending)
        return NO;
    if (!gVirtualMachine || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive)
        return YES;
    if (((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"))!=1) return YES;
    if (gIndependent27InputQueueV3) return YES;
    NSError *inputError=nil;
    if (gIndependent27SessionEpoch==UINT64_MAX || gIndependent27CoordinateGeneration==UINT64_MAX) {
        inputError=[NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3" code:2
            userInfo:@{NSLocalizedDescriptionKey:@"Input session generations are exhausted."}];
    } else {
        ++gIndependent27SessionEpoch;++gIndependent27CoordinateGeneration;
        gIndependent27InputQueueV3=[VM27ConnectGenuineInputQueueV3(gVirtualMachine,
            gPointingDevice,gKeyboard,gIndependent27InputSurface,
            gIndependent27SessionEpoch,gIndependent27CoordinateGeneration,&inputError) retain];
        if (gIndependent27InputQueueV3 && [gIndependent27InputQueueV3 startAdmission:&inputError])
            return YES;
    }
    VZIndependent27FailActualDisplay(inputError ?: [NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3"
        code:3 userInfo:@{NSLocalizedDescriptionKey:@"The actual VM input queue could not resume."}]);
    return NO;
}

static void VZIndependent27PauseActualInput(void) {
    if (!pthread_main_np() || !gIndependent27InputQueueV3 || gIndependent27InputClosePending) return;
    gIndependent27InputClosePending=YES;
    VM27InputQueueV3 *actualQueue=[gIndependent27InputQueueV3 retain];
    [actualQueue closeWithCompletion:^(VM27InputResult result) {
        gIndependent27InputClosePending=NO;
        if (result==VM27InputOK || result==VM27InputClosed) {
            if (gIndependent27InputQueueV3==actualQueue) {
                [gIndependent27InputQueueV3 release];gIndependent27InputQueueV3=nil;
            }
            if (!gIndependent27OwnerClosePending) VZIndependent27ResumeActualInput();
        } else {
            VZIndependent27FailActualDisplay([NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3"
                code:4 userInfo:@{NSLocalizedDescriptionKey:@"The actual VM input queue could not drain."}]);
        }
        [actualQueue release];
    }];
}

static BOOL gForceStopPending;''')
 replace('''    dispatch_source_set_event_handler(gControlTimer, ^{
        if (unlink''','''    dispatch_source_set_event_handler(gControlTimer, ^{
        if (gIndependent27InputQueueV3 && !gIndependent27OwnerClosePending && !gIndependent27InputClosePending) {
            VM27InputResult result=gIndependent27InputQueueV3.lastDeliveryResult;
            if (result==VM27InputClosed) VZIndependent27PauseActualInput();
            else if (result!=VM27InputOK && result!=VM27InputEmpty && result!=VM27InputUnsupported) {
                VZIndependent27FailActualDisplay([NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3"
                    code:5 userInfo:@{NSLocalizedDescriptionKey:@"Original VM input delivery failed; its owner remains retained."}]);
            }
        }
        if (unlink''')
 replace('''    gVirtualMachine = ((id(*)(id, SEL, id))objc_msgSend)(
        m0(CLS("VZVirtualMachine"), "alloc"),
        S("initWithConfiguration:"), configuration);''','''    if (VZIndependent27SourceRouteSelected()) {
        NSError *creationError=nil;
        gVirtualMachine=VM27UIKitCreateActualVirtualMachineV1(configuration,&creationError);
        if (!gVirtualMachine) { finishVMThreadSafe(delegate,creationError);return; }
    } else {
        gVirtualMachine = ((id(*)(id, SEL, id))objc_msgSend)(
            m0(CLS("VZVirtualMachine"), "alloc"),
            S("initWithConfiguration:"), configuration);
    }''')
 replace('''    gPointingDevice = [pointingDevices firstObject];
    dumpRPCHandlers''','''    gPointingDevice = [pointingDevices firstObject];
    if (VZIndependent27SourceRouteSelected()) {
        if (gIndependent27SessionEpoch==UINT64_MAX || gIndependent27CoordinateGeneration==UINT64_MAX) {
            NSError *exhausted=[NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3" code:2
                userInfo:@{NSLocalizedDescriptionKey:@"Input session generations are exhausted."}];
            finishVMThreadSafe(delegate,exhausted);return;
        }
        ++gIndependent27SessionEpoch;++gIndependent27CoordinateGeneration;
        NSError *inputError=nil;
        gIndependent27InputQueueV3=[VM27ConnectGenuineInputQueueV3(gVirtualMachine,
            gPointingDevice,gKeyboard,gIndependent27InputSurface,
            gIndependent27SessionEpoch,gIndependent27CoordinateGeneration,&inputError) retain];
        if (!gIndependent27InputQueueV3) {
            finishVMThreadSafe(delegate,inputError ?: [NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3"
                code:3 userInfo:@{NSLocalizedDescriptionKey:@"The actual VM input queue could not be constructed."}]);return;
        }
    }
    dumpRPCHandlers''')
 replace('''        printf("[VirtualMac] VM STARTED state=%ld\\n",''','''        if (VZIndependent27SourceRouteSelected() &&
            UIApplication.sharedApplication.applicationState==UIApplicationStateActive &&
            !gIndependent27InputClosePending) {
            NSError *admissionError=nil;
            if (!gIndependent27InputQueueV3) {
                if (!VZIndependent27ResumeActualInput()) return;
            } else if (![gIndependent27InputQueueV3 startAdmission:&admissionError]) {
                VZIndependent27FailActualDisplay(admissionError);return;
            }
        }
        printf("[VirtualMac] VM STARTED state=%ld\\n",''')
 replace('''        gHostVMStarted();''','''        if (VZIndependent27SourceRouteSelected()) {
            NSError *startedError=nil;
            if (!VM27IndependentAppRuntimeGuestStartedV1(&startedError)) {
                VZIndependent27FailActualDisplay(startedError);return;
            }
        } else if (gHostVMStarted) gHostVMStarted();''')
 begin=source.index('    printf("[VirtualMac] constructing VM runtime\\n");')
 end=source.index('    [startOptions release];\n}',begin)+len('    [startOptions release];')
 body=source[begin:end]
 source=source[:begin]+'''    void (^actualRuntimeControl)(void)=^{
'''+body+'''
    };
    // VZ's original initWithConfiguration:queue: uses this actual serial queue.
    // The native CPU's ExecutionThread remains owned by the original VMM.
    if (VZIndependent27SourceRouteSelected() && !pthread_main_np())
        dispatch_sync(dispatch_get_main_queue(),actualRuntimeControl);
    else actualRuntimeControl();'''+source[end:]
 replace('''    if (VZIndependent27SourceRouteSelected()) {
        NSString *reason = VZBackendAvailabilityReason(@"27") ?:
            VM27IndependentInputPlatformAvailabilityReasonV2();
        NSError *inputError = [NSError errorWithDomain:@"VirtualMac.Backend" code:1
            userInfo:@{NSLocalizedDescriptionKey:reason}];
        finishVMThreadSafe(delegate, inputError);
        return;
    }''','''    if (VZIndependent27SourceRouteSelected()) {
        NSString *reason=VZBackendAvailabilityReason(@"27");
        if (reason) {
            NSError *inputError=[NSError errorWithDomain:@"VirtualMac.Backend" code:1
                userInfo:@{NSLocalizedDescriptionKey:reason}];
            finishVMThreadSafe(delegate,inputError);return;
        }
    }''')
 replace('''    if (gIndependent27InputRoute) {
        gIndependent27InputCoordinator = [[VM27IndependentInputCoordinatorV2 alloc]
            initWithWindow:(VM27UIKitInputWindowV2 *)self.window surface:gIndependent27InputSurface];
    }
''','')
 replace('''    [gIndependent27InputCoordinator close];''','''    if (VZIndependent27SourceRouteSelected()) VZIndependent27PauseActualInput();''')
 replace('''- (void)applicationDidBecomeActive:(UIApplication *)application
{
    (void)application;''','''- (void)applicationDidBecomeActive:(UIApplication *)application
{
    (void)application;
    if (VZIndependent27SourceRouteSelected()) VZIndependent27ResumeActualInput();''')
 replace('''    if (stopped==VM27InputOK || stopped==VM27InputClosed) {
        [gIndependent27InputCoordinator release];
        gIndependent27InputCoordinator = nil;
    }''','''    if (stopped==VM27InputOK || stopped==VM27InputClosed) {
        [gIndependent27InputQueueV3 release];gIndependent27InputQueueV3=nil;
    }''')
 assert 'VM27IndependentInputCoordinatorV2' not in source
 file=o/'VirtualMacApp.independent27.display-source-v3.m';file.write_text(source)
 diff=o/'source-v2-to-v3.diff';diff.write_text(''.join(difflib.unified_diff(prior.splitlines(True),source.splitlines(True),fromfile=str(old),tofile=str(file))))
 commands=[]
 # The copy shares established selection/serialization, but modern admission
 # is an actual runtime graph preflight. Never edit production's old backend.
 backendOld=S/'VZBackendSelection.m';backendBefore=backendOld.read_text();backend=backendBefore
 backend=backend.replace('#import "VZAppSettings.h"','#import "VZAppSettings.h"\n#import "vm27_independent_app_runtime_v1.h"',1)
 gate='''    // This frontend has only the audited Ventura VZ binding/framebuffer profile.
    // GPU27 is already supported separately; it must not be advertised as CPU27.
    if ([version isEqualToString:@"27"])
        return VZBL(@"macOS 27 CPU, VMM and Virtualization compatibility is still being implemented. This backend cannot start a guest yet. Choose macOS 13.2.1 to use the working backend.");'''
 assert backend.count(gate)==1
 backend=backend.replace(gate,'''    if ([version isEqualToString:@"27"]) {
        NSError *actualError=nil;
        if (!VM27IndependentAppRuntimePreflightV1(rootForVersion(version),&actualError))
            return actualError.localizedDescription ?: @"The independent runtime graph did not pass admission.";
    }''',1)
 backendFile=o/'VZBackendSelection.independent27.v3.m';backendFile.write_text(backend)
 backendDiff=o/'backend-selection-v3.diff';backendDiff.write_text(''.join(difflib.unified_diff(backendBefore.splitlines(True),backend.splitlines(True),fromfile=str(backendOld),tofile=str(backendFile))))
 def run(label,argv):
  cp=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
  (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(label=label,argv=list(map(str,argv)),exit=cp.returncode));save(o/'commands.json',commands)
  assert cp.returncode==0,(label,cp.stderr.decode(errors='replace'));return cp
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-fblocks','-O2','-I',S]
 run('app-compile',flags+['-c',file,'-o',o/'App3.o'])
 run('app-ir',flags+['-S','-emit-llvm',file,'-o',o/'App3.ll'])
 run('backend-compile',flags+['-c',backendFile,'-o',o/'Backend3.o'])
 assert pin(old)==oldpin
 save(o/'candidate.json',dict(schema='Copied own UIKit App3 genuine VZ control queue and display source',source=pin(file),prior=oldpin,sourceDiff=pin(diff),builder=pin(pathlib.Path(__file__)),object=pin(o/'App3.o'),backendSource=pin(backendFile),backendObject=pin(o/'Backend3.o'),backendSourceDiff=pin(backendDiff),sourceInterfaces=[pin(S/f)for f in('vm27_input_queue_v3.h','vm27_uikit_guest_display_v1.h','vm27_independent_app_runtime_v1.h')],
  actualMainVZInitWithConfigurationQueue=True,actualStartCompletionAdmission=True,
  displayAndInputDrainBeforeVMRelease=True,failedDrainRetainsActualVM=True,
  oldFixedExecutorRemoved=True,sourceDisplayObserverJoined=True,
  productionSourcesModified=False,backendAdmissionRequiresActualGraphPreflight=True,
  modernLoaderHasNoLegacyHostHookDependency=True,
  applicationBinaryLinked=False,applicationPackaged=False,actualUIKitRuntimeValidated=False,
  actualGuestDisplayObserved=False,originalVMMWorkerStarted=False,full27Backend=False,
  remainingBlockers=['Runtime provider must implement the three strong product admission/loading/started interfaces','QueueV3 implementation must compile/link with App3; header is currently in progress','Independent27 full backend dependency package and actual native ops process binding remain parent work'],
  codeSigned=False,deviceOperations=0,nativeHVCalls=0))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),source=pin(file),object=pin(o/'App3.o'))))
if __name__=='__main__':main()
