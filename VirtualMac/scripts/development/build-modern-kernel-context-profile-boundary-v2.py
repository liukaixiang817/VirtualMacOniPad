"""Rebuild the repaired private V2 CPU provider without loading or executing it.

Uses the existing four-source product build and preserves its exported API,
dependency set, entitlement set and caller-supplied native trap boundary.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import plistlib
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H = R / 'VirtualMac/vz/host'
BASE = N / 'kernel-context-profiles-product-v2/provider-build-v2'
BASE_MANIFEST_SHA = 'd70453de98411033501accc2b18ef4e4013e159896ddab2fae13b36c8273914f'


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def check_old_pin(row):
    p = R / row['path']
    actual = pin(p)
    assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
    return p


def main():
    assert sys.flags.optimize == 0
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verification-receipt', type=Path, required=True)
    args = parser.parse_args()
    baseline_path = BASE / 'candidate.json'
    assert pin(baseline_path)['sha256'] == BASE_MANIFEST_SHA
    baseline = json.loads(baseline_path.read_text())
    old_candidate = check_old_pin(baseline['candidate'])
    for row in baseline['source']:
        check_old_pin(row)
    model = check_old_pin(baseline['modelReceipt'])
    source_paths = [H / Path(row['path']).name for row in baseline['source']]
    changed = [p.name for p, old in zip(source_paths, baseline['source'])
               if pin(p)['sha256'] != old['sha256']]
    assert changed == ['modern_cpu_kernel_lifecycle_v2.c'], changed
    verification_test = R / 'VirtualMac/scripts/tests/test-modern-cpu-initialization-boundary-v2.c'
    callback_test = R / 'VirtualMac/scripts/tests/test-modern-cpu-callback-lifetime-v3.c'
    verification = args.verification_receipt.resolve()
    assert verification.is_relative_to(N)
    verified = json.loads(verification.read_text())
    assert verified['schema'] == 'public-callback-lifetime-model-v3'
    assert verified['afterScenarios'] == 48 and verified['afterOrdinaryAndASanPassed']
    assert verified['existingBoundaryOrdinaryAndASanPassed']
    assert len(verified['existingTypedProfileResults']) == 12
    assert verified['nativeOperations'] == verified['deviceOperations'] == 0
    for p in source_paths + [verification_test, callback_test]:
        assert pin(p) in verified['sourceInputs'], p
    verification_freeze = verification.with_name('freeze.json')
    for row in json.loads(verification_freeze.read_text())['files']:
        assert pin(Path(row['path'])) == row
    inputs = [pin(p) for p in source_paths + [verification_test, callback_test,
              Path(__file__), verification, verification_freeze]]
    out = args.output.resolve()
    assert out.is_relative_to(N)
    out.mkdir(mode=0o700, exist_ok=False)
    source = out / 'source'
    source.mkdir(mode=0o700)
    for p in source_paths + [verification_test, callback_test]:
        (source / p.name).write_bytes(p.read_bytes())
    (out / 'model-verification.json').write_bytes(verification.read_bytes())
    (out / 'model-verification-freeze.json').write_bytes(verification_freeze.read_bytes())
    (out / 'builder-snapshot.py').write_bytes(Path(__file__).read_bytes())
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        env = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        process = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        commands.append(dict(label=label, argv=argv, directChildPID=process.pid,
                             exit=process.returncode, reaped=True))
        assert process.returncode == 0, (label, stderr.decode(errors='replace'))
        return stdout, stderr

    candidate = out / 'VM27KernelContextProfilesV2.dylib'
    implementation = [source / name for name in (
        'modern_cpu_kernel_lifecycle_v2.c', 'modern_cpu_native_fields.c',
        'modern_cpu_kernel_initialization_v2.c', 'modern_cpu_kernel_system_v2.c')]
    run('ios-link', ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64e',
                    '-miphoneos-version-min=16.1', '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-pthread', '-I', source, '-dynamiclib',
                    *implementation, '-Wl,-undefined,error',
                    '-Wl,-install_name,@rpath/VM27KernelContextProfilesV2.dylib',
                    '-Wl,-current_version,2.0', '-Wl,-compatibility_version,2.0',
                    '-o', candidate])
    run('adhoc-sign', ['codesign', '--force', '--sign', '-', candidate])
    run('strict-signature', ['codesign', '--verify', '--strict', candidate])
    identity = run('signature-identity', ['codesign', '-d', '--verbose=4', candidate])[1].decode()
    entitlements = run('entitlements', ['codesign', '-d', '--entitlements', ':-', candidate])[0]
    assert not entitlements or plistlib.loads(entitlements) == {}
    run('metadata', ['xcrun', 'dyld_info', '-validate_only', candidate])

    def symbols(data):
        return sorted(line.split()[-1] for line in data.decode().splitlines()
                      if line.split())

    exports = symbols(run('exports', ['xcrun', 'nm', '-gU', candidate])[0])
    old_exports = symbols(run('old-exports', ['xcrun', 'nm', '-gU', old_candidate])[0])
    undefined = symbols(run('undefined', ['xcrun', 'nm', '-u', candidate])[0])
    old_undefined = symbols(run('old-undefined', ['xcrun', 'nm', '-u', old_candidate])[0])
    assert exports == old_exports and undefined == old_undefined
    assert '_VZCPU27KernelTrapRaw' not in exports + undefined

    def dependencies(data):
        return sorted(line.strip() for line in data.decode().splitlines()[1:])

    deps = dependencies(run('dependencies', ['otool', '-L', candidate])[0])
    old_deps = dependencies(run('old-dependencies', ['otool', '-L', old_candidate])[0])
    assert deps == old_deps and len(deps) == 2
    assert not any(value in '\n'.join(deps) for value in (
        'Hypervisor.framework', 'Virtualization.framework', 'VirtualMac2', '13.2.1'))
    for row in inputs:
        assert pin(Path(row['path'])) == row
    check_old_pin(baseline['candidate'])
    result = dict(
        schema='application-private-kernel-context-profile-v2-repaired-provider',
        candidate=pin(candidate), sourceInputs=inputs,
        sourceSnapshots=[pin(p) for p in sorted(source.iterdir())],
        baselineManifest=pin(baseline_path), baselineCandidate=pin(old_candidate),
        historicalModelReceipt=pin(model), signingIdentity=identity, entitlements={},
        changedCompiledSources=changed, exports=exports, dependencies=deps,
        undefinedImports=undefined, exportSetUnchanged=True,
        dependencySetUnchanged=True, undefinedImportSetUnchanged=True,
        initializationFinalOwnershipRechecked=True, nativeSnapshotLifetimeProtected=True,
        publicCallbackLifetimeProtected=True, createPublishedAfterVersionCallback=True,
        nativeDestroyCallbackMutexFree=True, currentModelVerificationReceipt=pin(verification),
        currentModelVerificationFreeze=pin(verification_freeze),
        modelVerificationPerformedBeforeBuild=True, modelVerificationRerunByBuilder=False,
        nativeISA=[1, 2], knownKernelProfile='iPadOS16.1.1-version0e',
        requiresActualOwnerAndGeneration=True, typedContextSlicesOnly=True,
        validatedTrapSuppliedByCaller=True, nativeTrapEntryLinked=False,
        supportsISA3=False, completeArchitecturalReset=False,
        guestRunImplemented=False, originalVMMExecuted=False,
        originalVZLoaded=False, providerLoaded=False, deviceOperations=0,
        nativeOperations=0, full27Backend=False, commands=commands)
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    (out / 'freeze.json').write_text(json.dumps(dict(
        files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(candidate), manifest=pin(out / 'candidate.json'),
                          freeze=pin(out / 'freeze.json'), exports=len(exports),
                          exportSetUnchanged=True, dependencySetUnchanged=True,
                          providerLoaded=False, deviceOperations=0)))


if __name__ == '__main__':
    main()
