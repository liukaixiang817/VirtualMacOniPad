#!/usr/bin/env python3
"""Move independent27 startup waiting off UIKit's event queue in a new copy."""
import argparse
import difflib
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def replace_once(source, before, after):
    need(source.count(before) == 1, 'unique finite source replacement')
    return source.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    output = parser.parse_args().output.resolve()
    need(output.parent == N and not output.exists(), 'fresh output')
    prior = N/'independent27-app-explicit-start-source-v6-attempt2/candidate.json'
    need(pin(prior)['sha256'] == 'f495bc9ce4f17ccbd113b28102c466a0e6a4fb1cb682e5a9c5eba4f44516a894', 'frozen explicit App6 source')
    previous = json.loads(prior.read_bytes())
    for row in json.loads((prior.parent/'freeze.json').read_bytes())['files']:
        need(pin(row['path']) == row, 'actual frozen App6 input')
    original_path = pathlib.Path(previous['source']['path'])
    original = original_path.read_text()
    source = replace_once(original, 'static BOOL gIndependent27InputRoute;',
                          '''static BOOL gIndependent27InputRoute;
// This pending state is read and published only on the actual main queue.
static BOOL gIndependent27ExplicitRuntimeStartupPending;
static dispatch_queue_t gIndependent27ExplicitRuntimeStartupQueue;''')
    source = replace_once(source,
                         '            components.path.length || gVirtualMachine || VZBackendIsRunActive()) {',
                         '''            components.path.length || gVirtualMachine || VZBackendIsRunActive() ||
            gIndependent27ExplicitRuntimeStartupPending) {''')
    source = replace_once(source, '''            NSError *runtimeError = nil;
            printf("[Independent27] runtime-startup begin root=%s\\n", VZRuntimeRoot().UTF8String);
            fflush(stdout);
            // Genuine Runtime3 bootstrap only. No VM configuration, VM object,
            // BindGuest, or startVirtualMachine is called by this action.
            BOOL loaded = VM27IndependentAppRuntimeLoadV1(VZRuntimeRoot(), &runtimeError);
            printf("[Independent27] runtime-startup result=%d errorDomain=%s errorCode=%ld error=%s\\n",
                loaded, runtimeError.domain.UTF8String ?: "", (long)runtimeError.code,
                runtimeError.description.UTF8String ?: "");
            fflush(stdout);
            return loaded;''', '''            static dispatch_once_t startupQueueOnce;
            dispatch_once(&startupQueueOnce, ^{
                gIndependent27ExplicitRuntimeStartupQueue = dispatch_queue_create(
                    "VirtualMac.independent27.explicit.runtime.startup", DISPATCH_QUEUE_SERIAL);
            });
            if (!gIndependent27ExplicitRuntimeStartupQueue) return NO;
            NSString *startupRoot = [[VZRuntimeRoot() copy] autorelease];
            gIndependent27ExplicitRuntimeStartupPending = YES;
            printf("[Independent27] runtime-startup accepted root=%s; awaiting actual background result\\n",
                startupRoot.UTF8String);
            fflush(stdout);
            dispatch_async(gIndependent27ExplicitRuntimeStartupQueue, ^{
                @autoreleasepool {
                    NSError *runtimeError = nil;
                    // Genuine Runtime3 bootstrap, with its actual ownership,
                    // loader and private check-in. This action creates no VM.
                    BOOL loaded = VM27IndependentAppRuntimeLoadV1(startupRoot, &runtimeError);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        gIndependent27ExplicitRuntimeStartupPending = NO;
                        printf("[Independent27] runtime-startup result=%d errorDomain=%s errorCode=%ld error=%s\\n",
                            loaded, runtimeError.domain.UTF8String ?: "", (long)runtimeError.code,
                            runtimeError.description.UTF8String ?: "");
                        fflush(stdout);
                    });
                }
            });
            // URL acceptance is not successful backend startup or guest boot.
            return YES;''')
    source = replace_once(source, '''                                NSDictionary *options) {
    NSError *backendError = nil;
    if (!VZBackendBeginRun(&backendError)) {''', '''                                NSDictionary *options) {
    if (VZIndependent27SourceRouteSelected() &&
        (!pthread_main_np() || gIndependent27ExplicitRuntimeStartupPending)) {
        NSError *pending = [NSError errorWithDomain:@"VirtualMac.Independent27" code:7
            userInfo:@{NSLocalizedDescriptionKey:@"Wait for the independent backend startup to finish."}];
        finishVMThreadSafe(delegate, pending);
        return;
    }
    NSError *backendError = nil;
    if (!VZBackendBeginRun(&backendError)) {''')
    source = replace_once(source, '''    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 14 &&
        pthread_main_np()) {''', '''    if ((VZIndependent27SourceRouteSelected() ||
         NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 14) &&
        pthread_main_np()) {''')
    output.mkdir(mode=0o700)
    app_source = output/'VirtualMacApp.independent27.background-startup-source-v7.m'
    app_source.write_text(source)
    difference = output/'app-v6-to-v7.diff'
    difference.write_text(''.join(difflib.unified_diff(original.splitlines(True), source.splitlines(True),
                                                     fromfile=str(original_path), tofile=str(app_source))))
    builder6 = R/'VirtualMac/scripts/development/build-independent27-copied-app-v6.py'
    builder7 = builder6.with_name('build-independent27-copied-app-v7.py')
    need(not builder7.exists(), 'new App7 builder')
    builder = builder6.read_text().replace('App6', 'App7')
    marker = " assert manifest['explicitIndependent27Launch'] and manifest['globalAutoBootNotConsumed']"
    builder = replace_once(builder, marker,
                           " assert manifest['runtimeStartupUsesActualBackgroundSerialQueue'] and manifest['runtimePendingPublishedBeforeDispatch']\n"+marker)
    builder7.write_text(builder)
    commands = []

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=90)
        (output/(label+'.stdout')).write_bytes(result.stdout)
        (output/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        (output/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        need(result.returncode == 0, label+': '+result.stderr.decode(errors='replace'))
        return result.stdout

    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    flags = ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-O2', '-fblocks', '-I', S]
    run('app-compile', flags+['-c', app_source, '-o', output/'app.o'])
    run('app-ir', flags+['-S', '-emit-llvm', app_source, '-o', output/'app.ll'])
    dependencies = run('app-deps', flags+['-MM', app_source]).decode().replace('\\\n', ' ').split(':', 1)[1]
    includes = [pin(pathlib.Path(item).resolve()) for item in shlex.split(dependencies) if pathlib.Path(item).is_file()]
    need(pin(original_path) == previous['source'], 'frozen parent unchanged')
    record = dict(previous)
    record.update(schema='Copied App7 actual background startup and explicit main queue admission',
                  source=pin(app_source), sourceDiff=pin(difference), prior=pin(prior), builder=pin(__file__),
                  packageBuilder=pin(builder7), objects=[pin(output/'app.o')], actualIncludeClosure=includes,
                  runtimeStartupUsesActualBackgroundSerialQueue=True, runtimePendingPublishedBeforeDispatch=True,
                  runtimePendingReadAndPublishedOnlyOnMainQueue=True, runtimePendingRejectsDuplicateStartupAndGuestStart=True,
                  guestPreparationWorkerDispatchedToBackgroundForIndependent27=True,
                  actualVMCreateBindAndStartKeepOriginalMainQueue=True, URLAcceptanceIsStartupSuccess=False,
                  actualRuntimeExecuted=False, deviceOperations=0, guestBoot=False)
    (output/'candidate.json').write_text(json.dumps(record, indent=2)+'\n')
    frozen = [pin(path) for path in sorted(output.rglob('*')) if path.is_file()]
    frozen.extend([pin(__file__), pin(builder6), pin(builder7), pin(prior), *includes])
    (output/'freeze.json').write_text(json.dumps({'files': list({row['path']: row for row in frozen}.values()),
                                                 'deviceOperations': 0, 'frozenApp6Unchanged': True}, indent=2)+'\n')
    print(json.dumps({'candidate': pin(output/'candidate.json'), 'freeze': pin(output/'freeze.json'),
                      'actualIOSSourceCompiled': True, 'actualRuntimeExecuted': False}))


if __name__ == '__main__':
    main()
