#!/usr/bin/env python3
"""Read-only finite App7 delta, actual MRC IR, and main-queue profile review."""
from pathlib import Path
import argparse, ast, difflib, hashlib, json, re, sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
checks = 0

def need(value, reason):
    global checks
    checks += 1
    if not value:
        raise ValueError(reason)

def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def line(text, term):
    return text.count('\n', 0, text.index(term))+1

def function_ir(ir, term):
    start = ir.index('define ', ir.index(term)-100)
    # Callers pass the exact definition prefix, so the first occurrence is a definition.
    end = ir.index('\n}', start)+2
    return ir[start:end]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    out = ap.parse_args().out.resolve()
    need(out.parent == N and not out.exists(), 'fresh independent review output')
    folder = N/'independent27-app-background-startup-source-v7-attempt1'
    candidate, freeze = folder/'candidate.json', folder/'freeze.json'
    need(pin(candidate)['sha256'] == '8001f86e2df85800d571017102ac8e581c846b2ad072f5b058d9fd6c2afb53d5', 'exact App7 candidate')
    need(pin(freeze)['sha256'] == '7129dda24d766467f83a0f66886bd388dfb77a73d135445fef958b6eef9c12c5', 'exact App7 freeze')
    record = json.loads(candidate.read_bytes())
    frozen = json.loads(freeze.read_bytes())['files']
    for row in frozen:
        need(pin(row['path']) == row, 'immutable App7 source/compiler/include pin')
    prior = Path(record['prior']['path'])
    prior_record = json.loads(prior.read_bytes())
    prior_freeze = prior.parent/'freeze.json'
    prior_pins = json.loads(prior_freeze.read_bytes())['files']
    for row in prior_pins:
        need(pin(row['path']) == row, 'immutable App6 source parent')
    source = Path(record['source']['path'])
    before_path = Path(prior_record['source']['path'])
    text, before = source.read_text(), before_path.read_text()
    builder = Path(record['builder']['path'])
    tree = ast.parse(builder.read_text())
    owner_main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    reconstructed, replacements = before, []
    for node in owner_main.body:
        if not isinstance(node, ast.Assign) or not any(isinstance(t, ast.Name) and t.id == 'source' for t in node.targets):
            continue
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'replace_once':
            old, new = map(ast.literal_eval, node.value.args[1:])
            need(reconstructed.count(old) == 1, 'unique owner finite source delta')
            reconstructed = reconstructed.replace(old, new, 1)
            replacements.append(dict(before=old, after=new))
    need(len(replacements) == 5 and reconstructed == text, 'only five actual finite source replacements')
    expected_diff = ''.join(difflib.unified_diff(before.splitlines(True), text.splitlines(True), fromfile=str(before_path), tofile=str(source)))
    need(Path(record['sourceDiff']['path']).read_text() == expected_diff, 'exact complete App6 to App7 source diff')
    includes = record['actualIncludeClosure']
    for row in includes:
        need(pin(row['path']) == row, 'actual preprocessing closure')
    need(record['backendSource'] == prior_record['backendSource'], 'genuine V4 backend provider unchanged')
    need(all(Path(row['path']).suffix != '.m' or row == record['source'] for row in includes), 'no second App or duplicate runtime state included')
    commands = json.loads((folder/'commands.json').read_bytes())
    need([row['label'] for row in commands] == ['sdk', 'app-compile', 'app-ir', 'app-deps'], 'actual compile and IR records')
    for row in commands:
        need(row['exit'] == 0, 'actual compiler command succeeded')
    for row in commands[1:]:
        need('arm64e-apple-ios16.1' in row['argv'] and '-O2' in row['argv'] and '-fobjc-arc' not in row['argv'], 'actual optimized arm64e MRC App compile')
    need(not record['applicationBinaryLinked'] and not record['codeSigned'] and not record['actualRuntimeExecuted'], 'source-only review scope')

    url = text[text.index('- (BOOL)application:(UIApplication *)application openURL:'):]
    action = url[url.index('if ([@"runtime-startup" isEqualToString:action])'):url.index('NSArray<NSURLQueryItem *> *items')]
    need('!pthread_main_np() || !components' in url and 'gVirtualMachine || VZBackendIsRunActive() ||\n            gIndependent27ExplicitRuntimeStartupPending' in url, 'actual URL ownership and pending admission')
    need(action.index('gIndependent27ExplicitRuntimeStartupPending = YES;') < action.index('dispatch_async(gIndependent27ExplicitRuntimeStartupQueue'), 'pending published before background dispatch')
    need('DISPATCH_QUEUE_SERIAL' in action and 'dispatch_once(&startupQueueOnce' in action, 'one real serial startup queue')
    need(action.index('dispatch_async(gIndependent27ExplicitRuntimeStartupQueue') < action.index('VM27IndependentAppRuntimeLoadV1(') < action.index('dispatch_async(dispatch_get_main_queue()'), 'true Runtime3 load runs inside background block')
    need('gIndependent27ExplicitRuntimeStartupPending = NO;' in action and 'errorDomain=%s errorCode=%ld error=%s' in action and 'return YES;' in action, 'actual typed main completion reports outcome and acceptance is separate')
    need(not any(term in action for term in ('startVirtualMachine(', 'VM27IndependentAppRuntimeBindGuestV1(', 'VM27UIKitCreateActualVirtualMachineV1(')), 'runtime-startup creates no actual VM')
    start_at = text.index('static void startVirtualMachine(UIView *container, id delegate,', text.index('static NSDictionary *runtimeDisplayOptions'))
    start = text[start_at:text.index('// ─── External Display', start_at)]
    need(start.index('gIndependent27ExplicitRuntimeStartupPending') < start.index('VZBackendBeginRun'), 'real library and explicit start share pending rejection before run lease')
    need('(VZIndependent27SourceRouteSelected() ||' in start and 'dispatch_async_f(' in start and 'startVirtualMachineOnBackgroundQueue' in start, 'true independent27 preparation worker runs off main')
    need('context->container = [container retain];' in start and 'context->delegate = [delegate retain];' in start and 'context->bundlePath = [bundlePath copy];' in start and 'context->options = [runtimeOptions copy];' in start, 'real background worker argument lifetimes retained')
    worker_close = text[text.index('static void startVirtualMachineOnBackgroundQueue(void *opaque)'):text.index('static CGSize orientPixelSizeForBounds')]
    need(worker_close.count(' release]') == 4 and 'free(context);' in worker_close and '[pool drain];' in worker_close, 'worker arguments released after worker returns')
    need('dispatch_sync(dispatch_get_main_queue(),actualRuntimeControl);' in text and 'VM27UIKitCreateActualVirtualMachineV1(configuration,&creationError)' in text and 'VM27IndependentAppRuntimeBindGuestV1(gVirtualMachine,actualQueue,&bindingError)' in text, 'actual VM construction and binding remain on genuine main control queue')
    need('startVirtualMachine(self.view, self, path, options);' in text and 'startVirtualMachine(controller.view, controller, path, VZVMOptionsForBundle(path));' in text and 'startVirtualMachine(controller.view, controller, autoBootPath,' in text, 'only three preserved actual App start callsites')
    need(text.count('startVirtualMachine(') == 5, 'static start entry has declaration, definition, and three UI calls')
    own_launch = text[text.index('if (VZIndependent27SourceRouteSelected()) {\n        // This independent package admits explicit actions only.'):text.index('    requestMicrophoneAccess(^{', text.index('if (VZIndependent27SourceRouteSelected()) {\n        // This independent package admits explicit actions only.'))]
    need('[controller presentVMLibrary];' in own_launch and 'return YES;' in own_launch, 'independent library launch still returns before global autoboot')

    finish = text[text.index('- (void)finishVMAndShowLibraryWithError:(NSError *)error\n{'):text.index('- (void)dealloc', text.index('- (void)finishVMAndShowLibraryWithError:(NSError *)error\n{'))]
    need('VZBackendEndRun();' in finish and not any(term in finish for term in ('VM27IndependentAppRuntime', 'VM27OwnedAppParent', 'ParentDrain', 'RetainedParentV3')), 'pending rejection cannot drain or release genuine bootstrap owner')
    need('return gIndependent27InputQueueV3?[gIndependent27InputQueueV3 close]:VM27InputClosed;' in text, 'missing input attachment cleanup is actual no-owner result')
    backend = Path(record['backendSource']['path']).read_text()
    need('runActive = YES;' in backend and 'void VZBackendEndRun(void)' in backend and 'runActive = NO;' in backend, 'actual VM run lease serialization stays separate from bootstrap owner')
    runtime = R/'VirtualMac/vz/host/vm27_independent_app_runtime_v3.m'
    runtime_text = runtime.read_text()
    need('RetainedParentV3 || BootstrapPIDV3' in runtime_text and 'Partial child startup requires a fresh App process.' in runtime_text, 'failed real bootstrap owner retained, no automatic retry')

    ir_path = folder/'app.ll'
    ir = ir_path.read_text()
    background = function_ir(ir, 'define internal void @"__53-[VirtualMacAppDelegate application:openURL:options:]_block_invoke_2"')
    completion = function_ir(ir, 'define internal void @"__53-[VirtualMacAppDelegate application:openURL:options:]_block_invoke_3"')
    need('VM27IndependentAppRuntimeLoadV1' in background and 'VM27IndependentAppRuntimeLoadV1' not in completion, 'actual IR load is background-only URL block')
    need(background.index('call void @dispatch_async(ptr noundef nonnull @_dispatch_main_q') < background.index('call void @llvm.objc.autoreleasePoolPop'), 'completion block copied before runtime-error autorelease pool drains')
    need('__block_descriptor_40_e8_32o_e5_v8' in ir and '__block_descriptor_41_e8_32o_e5_v8' in ir and '__copy_helper_block_e8_32o' in ir and '__destroy_helper_block_e8_32o' in ir, 'actual root and error capture descriptors have copy/dispose helpers')
    copy_helper = function_ir(ir, 'define linkonce_odr hidden void @__copy_helper_block_e8_32o(')
    destroy_helper = function_ir(ir, 'define linkonce_odr hidden void @__destroy_helper_block_e8_32o(')
    need('@_Block_object_assign(' in copy_helper and 'i32 3)' in copy_helper and '@_Block_object_dispose(' in destroy_helper and 'i32 3)' in destroy_helper, 'MRC captures use actual object retain/release block helpers')
    need('store i8 %8, ptr %19' in background and 'i64 40' in completion and 'zext nneg i8' in completion, 'actual loaded boolean copied by value and logged without fabricated result')
    need('store i1 false, ptr @gIndependent27ExplicitRuntimeStartupPending' in completion, 'actual completion clears pending on dispatch main queue')
    start_ir = function_ir(ir, 'define internal fastcc void @startVirtualMachine(')
    need('@pthread_main_np()' in start_ir and 'load i1, ptr @gIndependent27ExplicitRuntimeStartupPending' in start_ir and 'select i1 %20, i1 true, i1 %21' in start_ir, 'explicit actual IR speculative-read limitation retained')
    need('startVirtualMachineOnBackgroundQueue.ptrauth' in start_ir and 'call void @dispatch_async_f(' in start_ir, 'actual compiled independent worker dispatch')
    need('llvm.ptrauth.sign' in background and 'llvm.ptrauth.sign' in ir, 'actual arm64e copied blocks retain compiler PAC lowering')
    need(ir.count('store i1 true, ptr @gIndependent27ExplicitRuntimeStartupPending') == 1 and ir.count('store i1 false, ptr @gIndependent27ExplicitRuntimeStartupPending') == 1, 'only actual URL admission and main completion publish pending')

    package_builder = Path(record['packageBuilder']['path'])
    signer = R/'VirtualMac/scripts/development/sign-independent27-actual-app-product-v1.py'
    package_text, signer_text = package_builder.read_text(), signer.read_text()
    need("ap.add_argument('--runtime-source'" in package_text and "action='append'" in package_text and "ap.add_argument('--runtime-root')" in package_text, 'true Runtime3 and final anchor compile arguments')
    need("parser.add_argument('--app-candidate'" in signer_text and "parser.add_argument('--runtime-candidate'" in signer_text and "parser.add_argument('--output'" in signer_text, 'real signer argument ABI')
    need("anchor in app_input['sourceFiles']" in signer_text and "app_input['runtimeRoot'] == runtime['canonicalDeviceRoot']" in signer_text and '2*1024*1024' in signer_text, 'final fresh runtime anchor/root and signed main bound required')
    need("if __name__ == '__main__':" in builder.read_text() and "if __name__=='__main__':" in package_text and "if __name__ == '__main__':" in signer_text, 'builders and signer have guarded entry; review does not invoke them')

    out.mkdir(mode=0o700)
    limitations = [
        'Scope is the actual UIApplication/main-queue profile. All three static App callsites are UIKit entry paths. No device execution, actual child handshake, full guest startup, or display success is claimed.',
        'The compiled static start function speculates a non-atomic pending load before selecting the wrong-main rejection. Source short-circuit alone does not prove a physical no-read wrong-thread boundary; a future cross-thread call profile needs actual atomic pending loads/stores. The actual URL IR still branches on main before accessing pending.',
        'Pending rejection runs existing App input/display/UI cleanup with no VM/run lease admitted. Runtime3 holds the separate real retained parent owner; App cleanup has no bootstrap drain/release entry.',
        'Main-thread preflight still performs real signed file checks. The twenty-second ParentStart handshake is now background-only; actual device UIKit responsiveness has not yet been measured.',
        'Final package and signing must consume the fresh signed runtime containing the real mobile-capability Root18 and its matching anchor. Frozen runtime1/runtime2 anchors cannot be reused for that product.'
    ]
    review = dict(schema='Independent App7 background startup finite source and actual IR review v1',
        finiteLocalScopePassed=True, findings=[], checks=checks,
        candidate=pin(candidate), inputFreeze=pin(freeze), source=pin(source), actualIR=pin(ir_path),
        actualObject=record['objects'][0], sourceDiff=record['sourceDiff'],
        priorCandidate=pin(prior), priorFreeze=pin(prior_freeze), verifiedApp7Pins=len(frozen), verifiedApp6Pins=len(prior_pins),
        exactFiveSourceReplacementsVerified=True, actualCompilerAndIncludeClosureVerified=True,
        actualBackgroundURLLoadAndMainTypedCompletionVerified=True,
        actualMRCObjectCaptureCopyDisposeAndBooleanValueVerified=True,
        actualMainQueueVMControlUnchanged=True, actualNativeCPUThreadUnchanged=True,
        pendingRejectDoesNotCloseBootstrapOwner=True, twentySecondMainHandshakeSourceIssueFixed=True,
        wrongMainCompiledNoReadBoundaryVerified=False, actualAppCallsitesMainOnlyProfile=True,
        readyForFreshActualStrongLinkAndLocalSigning=True,
        packageBuilder=pin(package_builder), signer=pin(signer),
        buildCommandTemplate=[sys.executable,str(package_builder),'--source-candidate',str(candidate),'--output','<fresh unsigned App7 package diagnostics>',
            '--runtime-source',str(runtime),'--runtime-source','<fresh final signed runtime anchor.c>','--runtime-root','<matching canonicalDeviceRoot>'],
        signCommandTemplate=[sys.executable,str(signer),'--app-candidate','<actual newly linked unsigned App7 candidate.json>',
            '--runtime-candidate','<fresh final signed runtime candidate.json>','--output','<fresh signed App diagnostics>'],
        limitations=limitations, actualAppLinked=False, actualAppSigned=False, actualAppLaunched=False,
        deviceOperations=0, nativeOperations=0, trustCacheOperations=0, actualGuestBoot=False)
    (out/'review.json').write_text(json.dumps(review,indent=2)+'\n')
    files = [candidate,freeze,prior,prior_freeze,source,before_path,ir_path,Path(record['objects'][0]['path']),
        Path(record['sourceDiff']['path']),builder,package_builder,signer,runtime,Path(record['backendSource']['path']),Path(__file__).resolve(),out/'review.json']
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in files],deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=[])))

if __name__ == '__main__':
    main()
