#!/usr/bin/env python3
"""HOST-only compilation/models for the independent owned-bundle decision."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import shlex
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def need(value, message):
    if not value:
        raise ValueError(message)

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh local diagnostic directory only')
    runtime_path = args.runtime_candidate.resolve()
    runtime = json.loads(runtime_path.read_bytes())
    out.mkdir(mode=0o700)
    commands = []
    def run(label, argv, timeout=60):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        save(out / 'commands.json', commands)
        need(result.returncode == 0, label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout
    sdk = run('ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    common = ['xcrun', 'clang', '-std=c11', '-O2', '-fblocks', '-Wall', '-Wextra', '-Werror',
              '-Wno-deprecated-declarations', '-I', S]
    ios = common + ['-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-fptrauth-abi-version=0']
    source = S / 'vm27_owned_bundle_approved_policy_v1.c'
    obj = out / 'vm27_owned_bundle_approved_policy_v1.ios.o'
    run('ios-production-compile', ios + ['-c', source, '-o', obj])
    closure = {}
    for index, name in enumerate(['vm27_owned_bundle_approved_policy_v1.c',
        'vm27_bundle_child_inspection_v1.c', 'modern_xpc_large_bundle_registry.c',
        'modern_xpc_lwcr_policy.c', 'test_vm27_owned_bundle_approved_policy_v1.c']):
        dependencies = run('closure-' + str(index), ios + ['-MM', S / name]).decode().replace('\\\n', ' ')
        for item in shlex.split(dependencies.split(':', 1)[1]):
            row = pin(item); closure[row['path']] = row
    # The same signed child now installed on the device is only inspected here;
    # neither its original executable nor any product DSO is executed by this model.
    relative = 'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc'
    copies = ['child-flat/VMM.bundle/Contents/Info.plist', relative + '/Contents/Info.plist',
              relative + '/Contents/_CodeSignature/CodeResources',
              relative + '/Contents/MacOS/com.apple.Virtualization.VirtualMachine']
    manifest_pin = runtime['manifest']
    need(pin(manifest_pin['path']) == manifest_pin, 'actual pinned binary product manifest')
    manifest = plistlib.loads(pathlib.Path(manifest_pin['path']).read_bytes())
    inventory = {row['path']: row for row in manifest['files']}
    inputs = []
    root = out / 'genuine-registry'; root.mkdir(mode=0o700)
    runtime_root = pathlib.Path(runtime['runtimeRoot'])
    for rel in copies:
        row = inventory[rel]; actual = pin(runtime_root / rel)
        need(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], 'genuine signed input ' + rel)
        inputs.append(actual)
        target = root / rel.removeprefix('child-flat/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(actual['path'], target)
        target.chmod(0o700 if '/MacOS/' in rel else 0o600)
    for path in root.rglob('*'):
        if path.is_dir(): path.chmod(0o700)
    code_rel = copies[-1]
    cd = inventory[code_rel]['cdhash']
    sha = inventory[code_rel]['sha256']
    bundle = root / 'VMM.bundle'
    arguments = [root, bundle, sha, cd, 'com.apple.Virtualization.VirtualMachine']
    test_sources = [S / 'test_vm27_owned_bundle_approved_policy_v1.c',
                    S / 'vm27_bundle_child_inspection_v1.c', S / 'modern_xpc_large_bundle_registry.c',
                    S / 'modern_xpc_lwcr_policy.c']
    results = []
    for label, extra in [('normal', []), ('asan-ubsan', ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        executable = out / ('host-model-' + label)
        run('compile-' + label, common + extra + test_sources + ['-framework', 'CoreFoundation', '-framework', 'Security', '-o', executable])
        result = json.loads(run('run-' + label, [executable] + arguments))
        need(result['passed'] and result['receivedAuditSecTaskKernelQueriesMocked'] and result['deviceOperations'] == 0,
             'bounded genuine-files model ' + label)
        results.append(dict(model=label, **result))
    # Header/typed C++ caller compilation verifies the explicit C ABI.
    typed = out / 'typed-caller.cpp'
    typed.write_text('#include "vm27_owned_bundle_approved_policy_v1.h"\n'
        'auto createOwned = &VM27OwnedBundleApprovedPolicyCreateV1;\n'
        'auto checkOwned = &VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1;\n'
        'auto releaseOwned = &VM27OwnedBundleApprovedPolicyReleaseV1;\n')
    run('ios-cpp-caller', ['xcrun', 'clang++', '-std=c++17', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
        '-Wall', '-Wextra', '-Werror', '-I', S, '-c', typed, '-o', out / 'typed-caller.ios.o'])
    symbols = run('ios-cpp-undefined', ['xcrun', 'nm', '-u', out / 'typed-caller.ios.o']).decode()
    for name in ['Create', 'CheckReceivedMessage', 'Release']:
        need('_VM27OwnedBundleApprovedPolicy' + name + 'V1' in symbols, 'unmangled actual API ' + name)
    for row in closure.values():
        need(pin(row['path']) == row, 'source/include closure unchanged after models')
    # Original frozen reader/source ABI must stay byte-identical.
    old_freeze = N / 'owned-child-external-slots-ports-source-local-v2-attempt1/freeze.json'
    old_rows = {row['path']: row for row in json.loads(old_freeze.read_bytes())['files']}
    reader_pins = []
    for name in ['vm27_bundle_parent_inspection_v1.c', 'vm27_bundle_parent_inspection_v1.h',
                 'vm27_bundle_child_inspection_v1.c', 'vm27_bundle_child_inspection_v1.h']:
        actual = pin(S / name); old = old_rows[actual['path']]
        need(all(actual[key] == old[key] for key in ['path', 'bytes', 'sha256']), 'original frozen reader unchanged ' + name)
        reader_pins.append(actual)
    official = [N / 'xpc-lwcr-compat-v1/official-source-v1/SecTask.c',
                N / 'xpc-lwcr-compat-v1/official-source-v1/SecTaskPriv.h',
                N / 'xpc-approved-code-v1/official-source-v1/cs_blobs.h',
                N / 'xpc-approved-code-v1/native-five-verification.json']
    record = dict(schema='Owned bundle approved-code policy source v1', builder=pin(__file__),
        sources=[pin(source), pin(S / 'vm27_owned_bundle_approved_policy_v1.h'), pin(test_sources[0])],
        actualIncludeClosure=list(closure.values()), actualIOSObject=pin(obj), hostResults=results,
        genuineSignedChildInputs=inputs, inheritedRuntime=pin(runtime_path),
        originalFrozenReadersUnchanged=reader_pins, originalReaderFreeze=pin(old_freeze),
        officialSources=[pin(path) for path in official],
        primaryLinks=['https://raw.githubusercontent.com/apple-oss-distributions/Security/main/sectask/SecTask.c',
                      'https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/cs_blobs.h'],
        semantics=dict(borrowedPlanMustOutliveAllChecks=True, consumerActualSpawnAndPIDVersionGuardRequired=True,
            explicitOwnedDecisionOnly=True, originalNativeResultAndValidatedFalsePreserved=True,
            originalStrictNativeRawAndDefaultUnmodified=True, oneNativeLWCRPerEligibleMessage=True,
            sameMessageAuditTokenForTwoReadOnlyKernelQueries=True,
            realSignedExternalSlots1And3Required=True, realSignedPluginBooleanRequired=True,
            beforeAndAfterNativeFilePlanVerification=True, noFailureFallback=True,
            nativeTrustFlagWrites=0, kernelWrites=0, deviceOperations=0,
            originalChildExecuted=False, actualChildHandshake=False, guestBoot=False),
        finiteHostSourceScopePassed=True, readyForIndependentSourceReview=True, findings=[])
    save(out / 'candidate.json', record)
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += list(closure.values()) + inputs + reader_pins + [pin(path) for path in official]
    files += [pin(__file__), pin(runtime_path), pin(runtime_path.parent / 'freeze.json'), pin(old_freeze), manifest_pin]
    save(out / 'freeze.json', dict(files=list({row['path']: row for row in files}.values()),
                                 deviceOperations=0, actualNativeQueriesInHostModels=False))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'), hostResults=results)))

if __name__ == '__main__':
    main()
