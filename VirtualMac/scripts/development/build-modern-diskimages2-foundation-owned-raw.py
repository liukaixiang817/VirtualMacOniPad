#!/usr/bin/env python3
"""Build the Foundation-closed, bounded original DI2 owned-RAW caller. No API execution."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'diskimages2-foundation-loadonly-build-v2'
SHA = lambda data: hashlib.sha256(data).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/diskimages227-foundation-owned-raw-v1')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir()
    ios = out / 'ios'; ios.mkdir(); source = out / 'source'; source.mkdir()
    original = BASE / 'candidate.json'
    assert SHA(original.read_bytes()) == '57bb57ac60d4777092e6637ad4ca62707f3d15f79a3e2434c4fe55218de24fe4'
    plan = json.loads(original.read_bytes())
    load_receipt = N / 'diskimages2-foundation-loadonly-native-v1/result.json'
    assert SHA(load_receipt.read_bytes()) == 'ef607b3f223058b5f15fe9e814686eeeee21dda9e7348dafe6ec5e79874cbb25'
    loaded = json.loads(load_receipt.read_bytes())
    assert loaded['passed'] is True and loaded['genuineDI2Loaded'] is True
    assert loaded['childPID'] == 42417 and loaded['observedWaitExit'] == 0 and loaded['childAbsent'] is True
    assert loaded['genuineDI2APICalls'] == 0 and loaded['RAWReadWriteVerified'] is False
    runtime = args.native_directory.rstrip('/')
    pins = []
    for item in plan['files'][:-1]:
        data = Path(item['path']).read_bytes()
        assert SHA(data) == item['sha256'] and len(data) == item['bytes']
        destination = ios / item['name']; destination.write_bytes(data)
        pins.append(dict(item, path=str(destination), unchangedFromFrozenProvider=True))
    assert len(pins) == 13 and pins[6]['name'] == 'VM27DI2SecurityUnavailable.dylib'
    header = (BASE / 'ios/diskimages227-pins.h').read_text()
    header = header.replace(plan['nativeDirectory'], runtime)
    header += 'static const unsigned SecurityIndex=6;\nstatic const char OwnedDirectory[]=' + json.dumps(runtime) + ';\n'
    (ios / 'diskimages227-owned-raw-pins.h').write_text(header)
    probe_source = ROOT / 'VirtualMac/vz/host/modern_diskimages2_owned_raw_probe.m'
    assert SHA(probe_source.read_bytes()) == 'ace5963f71f4be1032f86231972487aa38b6b639d906bbc391e4d9718516496f'
    (source / probe_source.name).write_bytes(probe_source.read_bytes())
    processes = []

    def run(label, argv):
        child = subprocess.Popen([str(item) for item in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout); (out / (label + '.stderr')).write_bytes(stderr)
        processes.append(dict(label=label, argv=[str(item) for item in argv], PID=child.pid, wait=child.returncode, reaped=True))
        (out / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-6000:]
        return stdout, stderr

    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'])[0].decode().strip()
    executable = ios / 'diskimages227-owned-raw-probe'
    run('probe-build', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-std=c11', '-O2',
        '-fno-objc-arc', '-fobjc-exceptions', '-fptrauth-abi-version=0', '-fno-typed-memory-operations-experimental',
        '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-I', ios, source / probe_source.name,
        '-framework', 'Foundation', '-lobjc', '-Wl,-no_adhoc_codesign', '-o', executable])
    entitlement = out / 'Probe.entitlements'; entitlement.write_bytes(plistlib.dumps(RIGHTS))
    run('probe-sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--entitlements', entitlement, executable])
    for item in pins + [dict(name=executable.name, path=str(executable))]:
        path = item['path']
        run(item['name'] + '-strict', ['codesign', '--verify', '--strict', path])
        run(item['name'] + '-dyld', ['xcrun', 'dyld_info', '-validate_only', path])
    _, signature = run('probe-signature', ['codesign', '-d', '--verbose=4', executable])
    rights, _ = run('probe-rights', ['codesign', '-d', '--entitlements', ':-', executable])
    assert plistlib.loads(rights) == RIGHTS
    data = executable.read_bytes()
    sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
    from compiler_image import commands
    probe = dict(name=executable.name, path=str(executable), bytes=len(data), sha256=SHA(data),
        UUID=next(data[at + 8:at + 24].hex() for command, at, _ in commands(data) if command == 0x1b),
        CDHash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(), entitlements=RIGHTS)
    for path in (Path(__file__), N / 'di2-raw-open-contract-v4/report.md', N / 'di2-raw-open-contract-v4/contract.json', load_receipt):
        (source / path.name).write_bytes(path.read_bytes())
    result = dict(nativeDirectory=runtime, files=pins + [probe], executable=executable.name, arguments=['--owned-raw'],
        originalLoadCandidateSHA256=SHA(original.read_bytes()), original13LibraryBytesUnchanged=True, genuineLoadReceiptSHA256=SHA(load_receipt.read_bytes()), genuineLoadPID=42417, genuineLoadWait=0, genuineLoadVerified=True,
        ownedRAWBytesLimit=131072, dataIOBytesPerCall=4096, onlyOneBoundedDataWrite=True, persistenceCall='fsync (public iOS declaration)',
        CPUSecondsSoft=3, CPUSecondsHard=4, wallSecondsLimit=10, requiresExternalWaitAndAbsence=True,
        abnormalExitRequiresExternalOwnFileCleanup=True, methodsContract='original 29-function audit; exact8method identity before calls',
        strictRWPublicMode=2, strictRWInternalMode=1, guessedCppAggregates=False, borrowedFDCloseCallsByProbe=0,
        requireZeroDesktopSecurityCounters=True, attachCalls=0, guestDiskCalls=0, VMGPUCalls=0,
        DI2APIExecutionPending=True, ownedRAWVerified=False, full27Backend=False, deviceOperations=False)
    result['scope'] = 'private-genuine27-DI2-owned-RAW-Foundation'
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(candidate=str(out / 'candidate.json'), probe=probe, nativeExecutionPending=True), indent=2))


if __name__ == '__main__': main()
