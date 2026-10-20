#!/usr/bin/env python3
"""Independently freeze the one Foundation method alias and SDK caller.

Only parses files and saved receipts; does not invoke Foundation conversion.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, cstring, export_trie, imports
SHA = lambda data: hashlib.sha256(data).hexdigest()
ORIGINAL = '_$sSS10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF'
NATURAL = '_$sSS14VM27FoundationE8vm27Data5using20allowLossyConversion0B00D0VSgSSAEE8EncodingV_SbtF'
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}


def exports(data):
    at = next(a for c, a, _ in commands(data) if c == 0x80000033)
    offset, length = struct.unpack_from('<II', data, at + 8)
    return {row['symbol']: row for row in export_trie(data[offset:offset + length])}


def dylibs(data):
    return [cstring(data, at + struct.unpack_from('<I', data, at + 8)[0])
            for c, at, _ in commands(data) if c in (12, 0x80000018, 0x8000001f, 0x80000023)]


def verify_files(plan, folder):
    assert plan['scope'] == 'private-foundation-String-data-original-SDK'
    assert plan['aliases'] == [dict(originalSymbol=ORIGINAL, naturalSymbol=NATURAL)]
    assert plan['originalSDKDeclarations'] is True and plan['nativeStringEncodingDataTypes'] is True
    assert plan['realNSStringConversion'] is True and plan['privateAliases'] == 1
    assert plan['originalFoundationBinaryClaimed'] is False and plan['instructionsRewritten'] is False
    assert plan['iOSExecuted'] is False and plan['genuine27DI2Loaded'] is False and plan['full27Backend'] is False
    assert plan['expectedChecks'] == 6824 and plan['expectedSDKCalls'] == 3368 and plan['diskVMGPUCalls'] == 0
    assert plan['executable'] == 'foundation-stringdata-sdk-probe' and plan['arguments'] == []
    assert len(plan['files']) == len(plan['MacFiles']) == 2
    fixture = (folder / 'source/modern_foundation_stringdata_sdk_probe.swift').read_text()
    provider = (folder / 'source/modern_foundation_stringdata_compat.swift').read_text()
    assert re.search(r'^import Foundation$', fixture, re.M) and not re.search(r'^import VM27', fixture, re.M)
    assert 'string.data(using: encoding, allowLossyConversion: lossy)' in fixture
    assert '(self as NSString).data(using: encoding.rawValue, allowLossyConversion: allowLossyConversion)' in provider
    assert 'self.data(' not in provider and '@_silgen_name' not in provider
    for item in plan['files'] + plan['MacFiles']:
        path = Path(item['path']); data = path.read_bytes()
        assert len(data) == item['bytes'] and SHA(data) == item['sha256']
        assert [data[a + 8:a + 24].hex() for c, a, _ in commands(data) if c == 0x1b] == [item['UUID']]
        subprocess.run(['codesign', '--verify', '--strict', path], capture_output=True, check=True)
        subprocess.run(['xcrun', 'dyld_info', '-validate_only', path], capture_output=True, check=True)
        rights = subprocess.run(['codesign', '-d', '--entitlements', ':-', path], capture_output=True, check=True).stdout
        expected = RIGHTS if item['role'] == 'ios' and item['name'] == plan['executable'] else {}
        assert (plistlib.loads(rights) if rights else {}) == item['entitlements'] == expected
        signature = subprocess.run(['codesign', '-d', '--verbose=4', path], capture_output=True, check=True).stderr
        assert re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode() == item['CDHash']
        if item['name'] == 'VM27FoundationCompat.dylib':
            table = exports(data)
            assert table[ORIGINAL] == dict(table[NATURAL], symbol=ORIGINAL)
            strong = imports(data)['imports']; linked = dylibs(data)
            assert len(strong) == (7 if item['role'] == 'ios' else 6) and all(not row['weak'] and row['ordinal'] > 0 for row in strong)
            expected_imports = {'_$s10Foundation4DataV36_unconditionallyBridgeFromObjectiveCyACSo6NSDataCSgFZ',
                '_$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF', '_$sSS10FoundationE8EncodingV8rawValueSuvg'}
            assert {row['name'] for row in strong if 'Foundation' in row['name']} == expected_imports
            assert all(linked[row['ordinal'] - 1] == '/System/Library/Frameworks/Foundation.framework/Foundation' if item['role'] == 'ios'
                       else linked[row['ordinal'] - 1] == '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
                       for row in strong if row['name'] in expected_imports)
        else:
            used = [row for row in imports(data)['imports'] if row['name'] == ORIGINAL]
            assert len(used) == 1 and not used[0]['weak'] and dylibs(data)[used[0]['ordinal'] - 1] == '@rpath/VM27FoundationCompat.dylib'
            directory = folder / item['role']
            before = (directory / 'original-sdk.ll').read_text(); after = (directory / 'original-sdk-strong.ll').read_text()
            abi = json.loads((directory / 'abi-contract.json').read_bytes())
            assert SHA(before.encode()) == abi['originalIRSHA256'] and SHA(after.encode()) == abi['strongIRSHA256']
            matched = [line for line in before.splitlines(keepends=True) if line.startswith('declare extern_weak swiftcc') and '"' + ORIGINAL[1:] + '"' in line]
            assert len(matched) == 1 and after == before.replace(matched[0], matched[0].replace('extern_weak', 'external'))
            assert abi['upgradedNames'] == [ORIGINAL] and abi['instructionsChanged'] is False
            declaration = matched[0].rstrip('\n')
            definition = next(line for line in (directory / 'provider.ll').read_text().splitlines() if line.startswith('define swiftcc') and '"' + NATURAL[1:] + '"' in line)
            assert abi['originalDeclaration'] == declaration and abi['naturalDefinition'] == definition
            assert re.search(r'swiftcc (.*?) @', declaration)[1] == re.search(r'swiftcc (.*?) @', definition)[1] == '{ i64, i64 }'
            assert re.search(r'\"\((.*?)\)', declaration)[1] == re.sub(r' %[0-9]+', '', re.search(r'\"\((.*?)\)', definition)[1]) == 'ptr noalias, i1, i64, ptr'
    return dict(files=4, privateAliases=1, originalSDKStrongMethodImports=1, providerStrongImports=7, sameSwiftCC=True)


def validate_rows(rows, plan, folder, pid, wait, role='ios'):
    assert role in ('ios', 'mac') and type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    assert len(rows) == 8 and rows[0] == dict(record='start', PID=pid, conversionCallsSoFar=0)
    pin = next(row for row in (plan['files'] if role == 'ios' else plan['MacFiles']) if row['name'] == 'VM27FoundationCompat.dylib')
    table = exports(Path(pin['path']).read_bytes())
    expected_path = '/private' + plan['nativeDirectory'] + '/' + pin['name'] if role == 'ios' else pin['path']
    assert rows[1] == dict(record='identity', name=ORIGINAL, UUID=pin['UUID'], path=expected_path,
                          RVA=hex(table[ORIGINAL]['address']), naturalAliasSameAddress=True)
    for row, (name, size, stride, align) in zip(rows[2:7], [('String', 16, 16, 8), ('String.Encoding', 8, 8, 8),
            ('Data', 16, 16, 8), ('Optional<Data>', 16, 16, 8), ('Bool', 1, 1, 1)]):
        assert row == dict(record='layout', type=name, size=size, stride=stride, alignment=align)
    summary = dict(record='summary', PID=pid, checks=6824, originalSDKCalls=3368, iterations=8, strings=12, encodings=17,
                   lossyCalls=1632, copyOnWriteChecks=192, originalSDKDeclarations=True, privateAliasIdentities=1,
                   NSStringAndLegacyGenericCompared=True, diskVMGPUCalls=0, passed=True)
    last = dict(rows[-1]); nil_results = last.pop('nilResults')
    assert type(nil_results) is int and 0 < nil_results <= 3264 and nil_results % 8 == 0
    assert last == summary
    if role == 'mac': assert nil_results == 440
    return dict(passed=True, PID=pid, observedWaitExit=wait, checks=6824, originalSDKCalls=3368,
                nilResults=nil_results, copyOnWriteChecks=192, originalSDKDeclarations=True,
                actualPrivateAliasIdentity=True, realNSStringAndLegacyGenericCompared=True,
                genuine27DI2Loaded=False, full27Backend=False)


def native_transcript(path, pid, wait, role='ios', candidate=None):
    candidate = Path(candidate) if candidate else ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/foundation-stringdata-sdk-build-v1/consumer-plan.json'
    plan = json.loads(candidate.read_bytes())
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    return validate_rows(rows, plan, candidate.parent, pid, wait, role)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-json', type=Path, required=True); parser.add_argument('--expected-candidate-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    raw = args.candidate_json.read_bytes(); assert SHA(raw) == args.expected_candidate_sha256
    plan = json.loads(raw); folder = args.candidate_json.parent
    static = verify_files(plan, folder)
    actual = next(row for row in plan['processes'] if row['label'] == 'mac-actual')
    assert actual['reaped'] is True and actual['wait'] == 0
    mac = native_transcript(folder / 'mac-actual.stdout', actual['PID'], actual['wait'], 'mac', args.candidate_json)
    rows = [json.loads(line) for line in (folder / 'mac-actual.stdout').read_bytes().splitlines()]
    controls = []
    bad = []
    for label, index, key, value in [('wrong-PID', 0, 'PID', actual['PID'] + 1), ('wrong-provider-UUID', 1, 'UUID', '0' * 32),
        ('wrong-provider-RVA', 1, 'RVA', '0x1'), ('forged-system-owner', 1, 'path', '/System/Library/Frameworks/Foundation.framework/Foundation'),
        ('wrong-Optional-layout', 5, 'size', 24), ('no-nil-branch', 7, 'nilResults', 0),
        ('too-few-calls', 7, 'originalSDKCalls', 3367), ('manufactured-check-count', 7, 'checks', 1),
        ('DI2-call-in-scope', 7, 'diskVMGPUCalls', 1)]:
        altered = copy.deepcopy(rows); altered[index][key] = value; bad.append((label, altered, 0))
    bad += [('truncated-summary', rows[:-1], 0), ('duplicate-summary', rows + [rows[-1]], 0), ('nonzero-actual-wait', rows, 67)]
    for label, altered, wait in bad:
        try: validate_rows(altered, plan, folder, actual['PID'], wait, 'mac')
        except (AssertionError, KeyError): controls.append(label)
        else: raise AssertionError('negative accepted: ' + label)
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    paths = [args.candidate_json, Path(__file__)] + [Path(row['path']) for row in plan['files'] + plan['MacFiles']]
    paths += list((folder / 'source').glob('*'))
    for role in ('ios', 'mac'):
        paths += [folder / role / name for name in ['provider.ll', 'original-sdk.ll', 'original-sdk-strong.ll',
                  'abi-contract.json', 'foundation-sdk-pins.h', 'original-caller-import.json']]
    paths += [folder / name for name in ['mac-actual.stdout', 'mac-actual.stderr', 'processes.json']]
    pins = [dict(path=str(path.resolve()), bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in sorted(set(paths))]
    (out / 'freeze.json').write_text(json.dumps(dict(files=pins, candidateSHA256=SHA(raw)), indent=2) + '\n')
    result = dict(passed=True, static=static, actualMac=mac, negativeReceiptsRejected=controls,
                  frozenFiles=len(pins), iOSExecuted=False, genuine27DI2Loaded=False, full27Backend=False)
    (out / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
