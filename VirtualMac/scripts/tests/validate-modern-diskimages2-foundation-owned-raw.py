#!/usr/bin/env python3
"""Freeze the genuine DI2 owned-file caller without loading or calling it."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'diskimages2-foundation-loadonly-build-v2'
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
SHA = lambda data: hashlib.sha256(data).hexdigest()
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate-json', type=Path, required=True); p.add_argument('--expected-candidate-sha256', required=True)
    p.add_argument('--output', type=Path, required=True); args = p.parse_args()
    raw = args.candidate_json.read_bytes(); assert SHA(raw) == args.expected_candidate_sha256
    candidate = json.loads(raw); folder = args.candidate_json.parent
    original = json.loads((BASE / 'candidate.json').read_bytes())
    assert candidate['originalLoadCandidateSHA256'] == '57bb57ac60d4777092e6637ad4ca62707f3d15f79a3e2434c4fe55218de24fe4'
    assert candidate['scope'] == 'private-genuine27-DI2-owned-RAW-Foundation'
    assert candidate['nativeDirectory'] == '/var/root/VirtualMac2/testing/diskimages227-foundation-owned-raw-v1'
    assert candidate['executable'] == 'diskimages227-owned-raw-probe' and candidate['arguments'] == ['--owned-raw']
    assert candidate['original13LibraryBytesUnchanged'] is True and candidate['genuineLoadVerified'] is True
    assert candidate['ownedRAWBytesLimit'] == 131072 and candidate['dataIOBytesPerCall'] == 4096
    assert candidate['onlyOneBoundedDataWrite'] is True and candidate['CPUSecondsSoft'] == 3 and candidate['CPUSecondsHard'] == 4
    assert candidate['wallSecondsLimit'] == 10 and candidate['requiresExternalWaitAndAbsence'] is True
    assert candidate['abnormalExitRequiresExternalOwnFileCleanup'] is True
    assert candidate['persistenceCall'] == 'fsync (public iOS declaration)'
    assert candidate['strictRWPublicMode'] == 2 and candidate['strictRWInternalMode'] == 1
    assert candidate['guessedCppAggregates'] is False and candidate['borrowedFDCloseCallsByProbe'] == 0
    assert candidate['requireZeroDesktopSecurityCounters'] is True
    assert candidate['attachCalls'] == candidate['guestDiskCalls'] == candidate['VMGPUCalls'] == 0
    assert candidate['DI2APIExecutionPending'] is True and candidate['ownedRAWVerified'] is False and candidate['full27Backend'] is False
    assert candidate['deviceOperations'] is False
    load_path = N / 'diskimages2-foundation-loadonly-native-v1/result.json'
    assert SHA(load_path.read_bytes()) == candidate['genuineLoadReceiptSHA256'] == 'ef607b3f223058b5f15fe9e814686eeeee21dda9e7348dafe6ec5e79874cbb25'
    load = json.loads(load_path.read_bytes())
    assert load['passed'] is True and load['genuineDI2Loaded'] is True and load['childAbsent'] is True
    assert load['childPID'] == candidate['genuineLoadPID'] == 42417 and load['observedWaitExit'] == candidate['genuineLoadWait'] == 0
    assert load['genuineDI2APICalls'] == 0 and load['RAWReadWriteVerified'] is False
    assert len(candidate['files']) == 14 and len(original['files']) == 14
    for item, before in zip(candidate['files'][:-1], original['files'][:-1]):
        assert item['name'] == before['name'] and item['sha256'] == before['sha256']
        assert item['bytes'] == before['bytes'] and item['UUID'] == before['UUID'] and item['CDHash'] == before['CDHash']
        assert Path(item['path']).read_bytes() == Path(before['path']).read_bytes()
    header = (folder / 'ios/diskimages227-owned-raw-pins.h').read_text()
    expected = (BASE / 'ios/diskimages227-pins.h').read_text().replace(original['nativeDirectory'], candidate['nativeDirectory'])
    expected += 'static const unsigned SecurityIndex=6;\nstatic const char OwnedDirectory[]=' + json.dumps(candidate['nativeDirectory']) + ';\n'
    assert header == expected
    assert 'ImageCount=13, CompatIndex=11, DI2Index=12;' in header and 'ProviderSymbolCount=60;' in header
    source = folder / 'source/modern_diskimages2_owned_raw_probe.m'
    assert SHA(source.read_bytes()) == 'ace5963f71f4be1032f86231972487aa38b6b639d906bbc391e4d9718516496f'
    text = source.read_text()
    for operation in ['mkstemp(path)', 'fchmod(initial, 0600)', 'ftruncate(initial, 131072)',
                      'descriptorStat.st_dev == originalStat->st_dev', 'descriptorStat.st_ino == originalStat->st_ino',
                      '(flags & O_ACCMODE) == O_RDWR', 'fsync(borrowed)', '[handle release]; [params release];',
                      'unlink(path)', 'struct rlimit cpu = {3, 4}', 'alarm(10)', '@finally']:
        assert operation in text
    assert 'close(borrowed)' not in text and text.count('pwrite(borrowed') == 1
    assert 'NSURL *url' in text and 'openWithError:' in text
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    consumer = []; processes = []
    for item in candidate['files']:
        path = Path(item['path']); data = path.read_bytes()
        assert len(data) == item['bytes'] and SHA(data) == item['sha256']
        assert [data[a + 8:a + 24].hex() for c, a, _ in commands(data) if c == 0x1b] == [item['UUID']]
        actual = {}; cd = None
        for label, argv in [('strict', ['codesign', '--verify', '--strict', path]),
                            ('dyld', ['xcrun', 'dyld_info', '-validate_only', path]),
                            ('signature', ['codesign', '-d', '--verbose=4', path]),
                            ('rights', ['codesign', '-d', '--entitlements', ':-', path])]:
            child = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = child.communicate(timeout=40)
            assert child.returncode == 0, stderr.decode(errors='replace')
            processes.append(dict(label=label, file=path.name, PID=child.pid, wait=child.returncode, reaped=True))
            if label == 'rights': actual = plistlib.loads(stdout) if stdout else {}
            if label == 'signature': cd = re.search(rb'CDHash=([0-9a-f]{40})', stderr)[1].decode()
        assert actual == (RIGHTS if item['name'] == candidate['executable'] else {})
        assert cd == item['CDHash']
        consumer.append(dict(path=str(path), name=item['name'], bytes=len(data), sha256=SHA(data),
                             UUID=item['UUID'], cdhash=cd, entitlements=actual, code=True))
    plan = dict(scope=candidate['scope'], deviceDirectory=candidate['nativeDirectory'], files=consumer,
                executable=candidate['executable'], arguments=candidate['arguments'], candidateManifestSHA256=SHA(raw),
                ownedRAWBytesLimit=131072, onlyOneBoundedDataWrite=True, originalLibraryBytesUnchanged=13,
                genuineLoadReceiptSHA256=candidate['genuineLoadReceiptSHA256'],
                originalAPICallsExpected=11, originalAPICallsMaximum=12,
                wallSecondsLimit=10, actualWaitAndPIDAbsenceRequired=True,
                abnormalExitRequiresOwnFileCleanup=True, externalOwnFileAbsenceRequired=True,
                VMGPUCalls=0, attachCalls=0, guestDiskCalls=0, full27Backend=False)
    (out / 'consumer-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    paths = [args.candidate_json, BASE / 'candidate.json', BASE / 'ios/diskimages227-pins.h',
             load_path, N / 'diskimages2-foundation-native-independent-review-v1/verification.json',
             N / 'diskimages2-foundation-native-independent-review-v1/freeze.json',
             folder / 'ios/diskimages227-owned-raw-pins.h', Path(__file__),
             Path(__file__).with_name('validate-modern-diskimages2-foundation-owned-raw-native.py')]
    paths += [Path(item['path']) for item in candidate['files']] + list((folder / 'source').glob('*'))
    pins = [dict(path=str(path.resolve()), bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in sorted(set(paths))]
    (out / 'freeze.json').write_text(json.dumps(dict(files=pins, candidateSHA256=SHA(raw)), indent=2) + '\n')
    result = dict(passed=True, actualSignaturesRightsAndDyldVerified=14, previousSuccessfulLibrariesUnchanged=13,
                  sourceProbeBytesUnchanged=True, exactPrivateProviders=60, exactMethods=8,
                  previousLoadPID=42417, previousLoadWait=0, ownedRAWBytesLimit=131072,
                  onlyOne4096ByteWrite=True, realRAWAPIExecutionPending=True, full27Backend=False, processes=processes)
    (out / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'processes'}, indent=2))


if __name__ == '__main__': main()
