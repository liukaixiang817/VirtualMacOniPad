#!/usr/bin/env python3
"""Make a fresh App copy with its own log and atomic startup admission."""
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
    need(source.count(before) == 1, 'unique finite replacement: '+before[:60])
    return source.replace(before, after, 1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    output = parser.parse_args().output.resolve()
    need(output.parent == N and not output.exists(), 'fresh diagnostics output')
    prior = N/'independent27-app-background-startup-source-v7-attempt1/candidate.json'
    need(pin(prior)['sha256'] == '8001f86e2df85800d571017102ac8e581c846b2ad072f5b058d9fd6c2afb53d5', 'frozen App7')
    previous = json.loads(prior.read_bytes())
    for row in json.loads((prior.parent/'freeze.json').read_bytes())['files']:
        need(pin(row['path']) == row, 'actual frozen App7 input')
    original_path = pathlib.Path(previous['source']['path'])
    original = original_path.read_text()
    source = replace_once(original,
        '// This pending state is read and published only on the actual main queue.\n',
        '// Main publishes admission; atomic access also permits a wrong-queue refusal.\n')
    source = replace_once(source,
        '(!pthread_main_np() || gIndependent27ExplicitRuntimeStartupPending)) {',
        '(!pthread_main_np() || __atomic_load_n(&gIndependent27ExplicitRuntimeStartupPending, __ATOMIC_RELAXED))) {')
    source = replace_once(source,
        '            gIndependent27ExplicitRuntimeStartupPending) {',
        '            __atomic_load_n(&gIndependent27ExplicitRuntimeStartupPending, __ATOMIC_RELAXED)) {')
    source = replace_once(source,
        '            gIndependent27ExplicitRuntimeStartupPending = YES;',
        '            __atomic_store_n(&gIndependent27ExplicitRuntimeStartupPending, YES, __ATOMIC_RELAXED);')
    source = replace_once(source,
        '                        gIndependent27ExplicitRuntimeStartupPending = NO;',
        '                        __atomic_store_n(&gIndependent27ExplicitRuntimeStartupPending, NO, __ATOMIC_RELAXED);')
    source = replace_once(source, '''    freopen("/tmp/VirtualMac.log", "a", stdout);
    freopen("/tmp/VirtualMac.log", "a", stderr);''', '''    const char *applicationLog = VZIndependent27SourceRouteSelected()
        ? "/tmp/VirtualMacIndependent27.log" : "/tmp/VirtualMac.log";
    freopen(applicationLog, "a", stdout);
    freopen(applicationLog, "a", stderr);''')
    source = replace_once(source, '''    unlink("/tmp/vzxpchook.log");
    unlink("/tmp/vmmhook.log");
    unlink("/tmp/vmm.stderr.log");''', '''    if (!VZIndependent27SourceRouteSelected()) {
        unlink("/tmp/vzxpchook.log");
        unlink("/tmp/vmmhook.log");
        unlink("/tmp/vmm.stderr.log");
    }''')
    output.mkdir(mode=0o700)
    app_source = output/'VirtualMacApp.independent27.isolated-log-source-v8.m'
    app_source.write_text(source)
    difference = output/'app-v7-to-v8.diff'
    difference.write_text(''.join(difflib.unified_diff(original.splitlines(True), source.splitlines(True),
        fromfile=str(original_path), tofile=str(app_source))))
    builder7 = R/'VirtualMac/scripts/development/build-independent27-copied-app-v7.py'
    builder8 = builder7.with_name('build-independent27-copied-app-v8.py')
    need(not builder8.exists(), 'fresh App8 builder')
    builder = builder7.read_text().replace('App7', 'App8')
    marker = " assert manifest['runtimeStartupUsesActualBackgroundSerialQueue'] and manifest['runtimePendingPublishedBeforeDispatch']"
    builder = replace_once(builder, marker,
        " assert manifest['runtimePendingAllAccessesAtomic'] and manifest['independentApplicationLogIsolated']\n"+marker)
    builder8.write_text(builder)
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
    need(pin(original_path) == previous['source'], 'App7 unchanged')
    record = dict(previous)
    record.update(schema='Copied App8 isolated real startup log and atomic admission',
        source=pin(app_source), sourceDiff=pin(difference), prior=pin(prior), builder=pin(__file__),
        packageBuilder=pin(builder8), objects=[pin(output/'app.o')], actualIncludeClosure=includes,
        runtimePendingReadAndPublishedOnlyOnMainQueue=False, runtimePendingAllAccessesAtomic=True,
        runtimePendingPublicationStaysMainQueue=True, independentApplicationLogIsolated=True,
        independentApplicationLog='/tmp/VirtualMacIndependent27.log',
        independentGuestStartDoesNotUnlinkLegacyLogs=True,
        actualRuntimeExecuted=False, deviceOperations=0, guestBoot=False)
    (output/'candidate.json').write_text(json.dumps(record, indent=2)+'\n')
    frozen = [pin(path) for path in sorted(output.rglob('*')) if path.is_file()]
    frozen.extend([pin(__file__), pin(builder7), pin(builder8), pin(prior), *includes])
    (output/'freeze.json').write_text(json.dumps({'files': list({row['path']: row for row in frozen}.values()),
        'deviceOperations': 0, 'frozenApp7Unchanged': True}, indent=2)+'\n')
    print(json.dumps({'candidate': pin(output/'candidate.json'), 'freeze': pin(output/'freeze.json'),
        'actualIOSSourceCompiled': True, 'actualRuntimeExecuted': False}))

if __name__ == '__main__':
    main()
