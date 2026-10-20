#!/usr/bin/env python3
"""Compile a reviewable independent27 input branch without changing the app.

The original backend gate and production files are pinned and preserved. This
source candidate prevents the independent27 branch entering the old VM worker.
It is not an application package and is never signed or deployed.
"""
import difflib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('app_input_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=p.NODE/'independent27-app-input-source-candidate-v1';assert not out.exists()
    app=HOST/'VirtualMacApp.m';backend=HOST/'VZBackendSelection.m';buildscript=p.ROOT/'VirtualMac/scripts/build-ipad-app.sh'
    production=[p.pin(path)for path in (app,backend,buildscript)]
    original=app.read_text();source=original
    def replace_once(before,after):
        nonlocal source
        assert source.count(before)==1,(before,source.count(before));source=source.replace(before,after)
    replace_once('#import "VZBackendSelection.h"','#import "VZBackendSelection.h"\n#import "modern_independent_input_coordinator_v1.h"')
    replace_once('static UIView *gInputView;', '''static UIView *gInputView;
static BOOL gIndependent27InputRoute;
static VM27UIKitInputSurfaceV2 *gIndependent27InputSurface;
static VM27IndependentInputCoordinatorV1 *gIndependent27InputCoordinator;
static BOOL VZIndependent27SourceRouteSelected(void) {
    return gIndependent27InputRoute || [VZBackendSelectedVersion() isEqualToString:@"27"];
}
// Future independent27 loader's explicit input attachment entry. The current
// coordinator and backend availability gates reject admission before creation.
BOOL VZIndependent27ConnectInput(id<VM27IndependentInputEndpointV1> endpoint,
    uint64_t epoch, uint64_t coordinates, NSError **error) {
    if (!gIndependent27InputCoordinator) return NO;
    return [gIndependent27InputCoordinator attachValidatedEndpoint:endpoint
        epoch:epoch coordinates:coordinates error:error];
}''')
    guarded=[]
    for name,returned in [('sendPointer',''),('sendIndirectPointerLocation',''),('sendMagnification',''),
                          ('sendRotation',''),('sendSmartMagnification',''),('sendMouseDelta',''),
                          ('sendMouseButton',''),('sendScrollWheelEvent',''),('queueScrollWheel',''),
                          ('installGCMouse',''),('scheduleInputSelfTest',''),('sendKey',''),
                          ('sendPresses','NO'),('sendSoftwareKey',''),('sendSoftwareChord','')]:
        pattern=r'^static (?:void|BOOL) '+re.escape(name)+r'\([^;{}]*\)\s*\{'
        matches=list(re.finditer(pattern,source,re.M));assert len(matches)==1,name
        at=matches[0].end();source=source[:at]+'\n    if (VZIndependent27SourceRouteSelected()) return'+(' '+returned if returned else '')+';'+source[at:]
        guarded.append(name)
    replace_once('- (void)sendEvent:(UIEvent *)event\n{','- (void)sendEvent:(UIEvent *)event\n{\n    if (VZIndependent27SourceRouteSelected()) { [super sendEvent:event]; return; }')
    before='''    installKeyboardRenderingFix();
    installShellShortcutRelay();
    installVideoMemoryWarningRelay();
    VZTrackpadScrollBridgeConfigure(emitTrackpadScroll, NULL);
    VZSurfaceMouseScrollBridgeConfigure(emitSurfaceMouseScroll, NULL);
    VZTouchScrollBridgeConfigure(emitTouchScroll, NULL);'''
    after='''    gIndependent27InputRoute = [VZBackendSelectedVersion() isEqualToString:@"27"];
    if (!gIndependent27InputRoute) {
        installKeyboardRenderingFix();
        installShellShortcutRelay();
        VZTrackpadScrollBridgeConfigure(emitTrackpadScroll, NULL);
        VZSurfaceMouseScrollBridgeConfigure(emitSurfaceMouseScroll, NULL);
        VZTouchScrollBridgeConfigure(emitTouchScroll, NULL);
    }
    installVideoMemoryWarningRelay();'''
    replace_once(before,after)
    replace_once('''    self.window = [[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds]
        autorelease];''','''    Class inputWindowClass = gIndependent27InputRoute ? VM27UIKitInputWindowV2.class : UIWindow.class;
    self.window = [[[inputWindowClass alloc] initWithFrame:UIScreen.mainScreen.bounds] autorelease];''')
    start=source.index('    VZInputView *inputView =\n');end=source.index('    [controller.view addSubview:inputView];',start)+len('    [controller.view addSubview:inputView];')
    old_block=source[start:end].replace('    VZInputView *inputView =','    inputView =',1)
    new_block='''    UIView *inputView = nil;
    if (gIndependent27InputRoute) {
        VM27UIKitInputSurfaceV2 *surface = [[[VM27UIKitInputSurfaceV2 alloc]
            initWithFrame:controller.view.bounds] autorelease];
        inputView = surface;
        gInputView = surface;
        gIndependent27InputSurface = surface;
        surface.backgroundColor = UIColor.clearColor;
        surface.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [controller.view addSubview:surface];
    } else {
'''+old_block+'''\n    }'''
    source=source[:start]+new_block+source[end:]
    replace_once('''    [self.window makeKeyAndVisible];
    VZContinueAfterRootHideInformation''','''    [self.window makeKeyAndVisible];
    if (gIndependent27InputRoute) {
        gIndependent27InputCoordinator = [[VM27IndependentInputCoordinatorV1 alloc]
            initWithWindow:(VM27UIKitInputWindowV2 *)self.window surface:gIndependent27InputSurface];
    }
    VZContinueAfterRootHideInformation''')
    replace_once('''- (void)finishVMAndShowLibraryWithError:(NSError *)error
{
    VZBackendEndRun();''','''- (void)finishVMAndShowLibraryWithError:(NSError *)error
{
    [gIndependent27InputCoordinator close];
    VZBackendEndRun();''')
    replace_once('''- (void)applicationWillResignActive:(UIApplication *)application
{
    (void)application;
    resetPointerSession(YES);''','''- (void)applicationWillResignActive:(UIApplication *)application
{
    (void)application;
    [gIndependent27InputCoordinator close];
    resetPointerSession(YES);''')
    replace_once('''- (void)dealloc
{
    [_window release];''','''- (void)dealloc
{
    [gIndependent27InputCoordinator close];
    [gIndependent27InputCoordinator release];
    gIndependent27InputCoordinator = nil;
    gIndependent27InputSurface = nil;
    [_window release];''')
    # Even if a later change removes the backend availability gate, this source
    # candidate must never start27 through Ventura's worker/config/framebuffer.
    replace_once('''    NSDictionary *runtimeOptions = runtimeDisplayOptions(options, container);''','''    if (VZIndependent27SourceRouteSelected()) {
        NSString *reason = VZBackendAvailabilityReason(@"27") ?:
            VM27IndependentInputPlatformAvailabilityReasonV1();
        NSError *inputError = [NSError errorWithDomain:@"VirtualMac.Backend" code:1
            userInfo:@{NSLocalizedDescriptionKey:reason}];
        finishVMThreadSafe(delegate, inputError);
        return;
    }
    NSDictionary *runtimeOptions = runtimeDisplayOptions(options, container);''')
    assert source!=original and backend.read_text().count('This backend cannot start a guest yet.')==1
    out.mkdir();candidate=out/'VirtualMacApp.independent27.source-candidate.m';candidate.write_text(source)
    (out/'app-input-source.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True),source.splitlines(True),fromfile=str(app),tofile=str(candidate))))
    commands=[]
    def run(label,args):
        result=subprocess.run(list(map(str,args)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,args)),exit=result.returncode));p.save(out/'commands.json',commands)
        assert result.returncode==0,(label,result.stderr.decode())
        return result
    inputs=[Path(__file__),HOST/'modern_independent_input_coordinator_v1.h',HOST/'modern_independent_input_coordinator_v1.m']
    inputs += [HOST/name for name in ('modern_uikit_input_surface_v2.h','modern_processed_scroll_sink_v1.h','modern_processed_scroll_native_v1.h')]
    try:
        sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-fblocks','-O2','-I',HOST]
        run('compile-original-app',flags+['-c',app,'-o',out/'original-app.o'])
        run('compile-candidate-app',flags+['-c',candidate,'-o',out/'candidate-app.o'])
        run('compile-coordinator',flags+['-Wall','-Wextra','-Werror','-fobjc-arc','-c',HOST/'modern_independent_input_coordinator_v1.m','-o',out/'coordinator.o'])
        run('compile-coordinator-ir',flags+['-Wall','-Wextra','-Werror','-fobjc-arc','-S','-emit-llvm',HOST/'modern_independent_input_coordinator_v1.m','-o',out/'coordinator.ll'])
        assert production==[p.pin(path)for path in (app,backend,buildscript)]
        p.save(out/'candidate.json',dict(schema='Independent27 app receiving input source candidate v1',
            productionInputPins=production,sourceFiles=[p.pin(path)for path in inputs],
            candidateAppSource=p.pin(candidate),reviewableDiff=p.pin(out/'app-input-source.diff'),
            independentUIKitSource=p.pin(p.NODE/'uikit-own-input-surface-data-build-v6/candidate.json'),
            finiteNativeScrollSource=p.pin(p.NODE/'processed-scroll-native-data-build-v2/candidate.json'),
            guardedLegacyInputFunctions=guarded,ownWindowAndSurfaceExclusive27BranchImplemented=True,
            stopAndInactiveCloseBeforeBackendReleaseImplemented=True,atomicCopiedConsumerSessionEntryImplemented=True,
            originalBackendAvailabilityGatePreserved=True,sourcePlatformAdmissionGateClosed=True,
            independent27NeverCallsLegacyStartWorker=True,productionAppSourceModified=False,
            applicationBinaryLinked=False,applicationPackaged=False,actualUIKitRuntimeValidated=False,
            originalUHKGenericConsumerImplemented=False,independent27VMWorkerImplemented=False,
            backendNativeInputEndpointImplemented=False,codeSigned=False,readyWritten=False,
            deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
        pins=production+[p.pin(path)for path in inputs]+[p.pin(path)for path in out.iterdir()if path.is_file()]
        p.save(out/'freeze.json',dict(files=list({r['path']:r for r in pins}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),source=p.pin(candidate))))
    except Exception as error:
        failed=out/'failed-source';failed.mkdir(exist_ok=True)
        for path in inputs:(failed/path.name).write_bytes(path.read_bytes())
        p.save(out/'failure.json',dict(reason=repr(error),productionPinsUnchanged=production==[p.pin(path)for path in (app,backend,buildscript)],deviceOperations=0))
        raise
if __name__=='__main__':main()
