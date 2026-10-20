#!/usr/bin/env python3
"""Unsigned ordinary V2 objects and explicit local identity-wiring doubles only."""
from pathlib import Path
import hashlib, json, os, shutil, subprocess, sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'vz/host'
TEST = ROOT / 'scripts/tests/test-modern-xpc-large-strict-identity-v2.c'
SHA = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main(output):
    out = Path(output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    names = ['modern_xpc_large_private_consumer_v2.c', 'modern_xpc_large_private_consumer_v2.h',
             'modern_xpc_large_strict_identity_v2.c', 'modern_xpc_large_strict_identity_v2.h',
             'modern_xpc_large_private_consumer.c', 'modern_xpc_large_private_consumer.h',
             'modern_xpc_large_bundle_registry.h', 'modern_xpc_approved_code.h',
             'modern_xpc_lwcr_policy.h', 'modern_xpc_private_endpoint.h']
    inputs = [HOST / name for name in names] + [TEST, Path(__file__)]
    rows = []
    for p in inputs:
        shutil.copyfile(p, source / p.name)
        rows.append({'path': str(p), 'SHA256': SHA(p), 'bytes': p.stat().st_size})
    processes = []
    def run(label, arguments):
        env = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            child.kill(); stdout, stderr = child.communicate()
            (out / (label + '.stdout')).write_bytes(stdout)
            (out / (label + '.stderr')).write_bytes(stderr)
            raise
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        (out / (label + '.argv.json')).write_text(json.dumps(arguments, indent=2) + '\n')
        processes.append({'label': label, 'PID': child.pid, 'observedWaitExit': child.returncode, 'reaped': True})
        if child.returncode:
            raise RuntimeError((label, child.returncode, stdout[-4000:], stderr[-4000:]))
        return stdout
    for role, sdk, target in [('macos', 'macosx', 'arm64e-apple-macos13'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).decode().strip()
        base = ['xcrun', 'clang', '-target', target, '-isysroot', sdkpath,
                '-fptrauth-abi-version=0', '-std=c11', '-fblocks', '-O2',
                '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-I', str(source)]
        for stem in ['modern_xpc_large_private_consumer_v2', 'modern_xpc_large_strict_identity_v2']:
            run(role + '-' + stem, base + ['-c', str(source / (stem + '.c')), '-o', str(out / (role + '-' + stem + '.o'))])
    sdkpath = run('local-sdk', ['xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    base = ['xcrun', 'clang', '-target', 'arm64-apple-macos13', '-isysroot', sdkpath,
            '-std=c11', '-fblocks', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
            '-Wno-deprecated-declarations', '-I', str(source), str(source / TEST.name),
            str(source / 'modern_xpc_large_strict_identity_v2.c')]
    summaries = []
    for label, flags in [('ordinary', []), ('sanitizers', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        binary = out / ('local-doubles-' + label)
        run(label + '-compile', base + flags + ['-o', str(binary)])
        stdout = run(label + '-run', [str(binary)])
        records = [json.loads(line) for line in stdout.splitlines()]
        summary = next(row for row in records if row.get('record') == 'summary')
        assert summary['checks'] > 60 and summary['failures'] == 0 and summary['explicitLocalDoubles']
        summaries.append({'label': label, **summary})
    for row in rows:
        assert SHA(Path(row['path'])) == row['SHA256']
    result = {'formatVersion': 1, 'scope': 'NEW ordinary app-private V2 strict identity-result completion',
              'inputs': rows, 'processes': processes, 'localDoubleSummaries': summaries,
              'unsignedCandidateObjectsOnly': True, 'explicitCodeSigningOperations': 0,
              'hostTestLinkerImplicitAdHocOnly': True, 'newEntitlementPayloads': [],
              'ASanLeakDetectionSupported': False, 'ASanLeakDetectionEnabled': False,
              'trustcacheChanges': 0, 'deviceOperations': False,
              'originalFrameworkExecutions': 0, 'realNativePolicyChecks': 0,
              'realCsopsQueries': 0, 'CPUFixed': False, 'independent27GuestBoot': False}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    frozen = []
    for p in sorted(out.rglob('*')):
        if p.is_file():
            frozen.append({'path': str(p), 'SHA256': SHA(p), 'bytes': p.stat().st_size})
    (out / 'frozen-files.json').write_text(json.dumps({'files': frozen}, indent=2) + '\n')
    print(json.dumps({'output': str(out), 'resultSHA256': SHA(out / 'result.json'),
                      'freezeSHA256': SHA(out / 'frozen-files.json'), 'localDoubleSummaries': summaries}, indent=2))

if __name__ == '__main__':
    assert len(sys.argv) == 2
    main(sys.argv[1])
