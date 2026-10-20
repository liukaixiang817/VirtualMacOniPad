#!/usr/bin/env python3
"""Validate the scoped HPKE aliases and saved original Apple SDK caller receipt.

This does not invoke CryptoKit or declare original DI2/VM functionality. The
private HPKE module has a new nominal context; native P256 types remain native.
"""
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
BUILD = N / 'hpke-original-sdk-fixture-build-v5'
SOURCE = N / 'hpke-compat-build-v6'
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, cstring, export_trie, imports
import struct

RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
SHA = lambda data: hashlib.sha256(data).hexdigest()


def exports(data):
    positions = [at for command, at, _ in commands(data) if command == 0x80000033]
    assert len(positions) == 1
    offset, size = struct.unpack_from('<II', data, positions[0] + 8)
    return {row['symbol']: row for row in export_trie(data[offset:offset + size])}


def dylibs(data):
    return [cstring(data, at + struct.unpack_from('<I', data, at + 8)[0])
            for command, at, _ in commands(data)
            if command in (12, 0x80000018, 0x8000001f, 0x80000023)]


def verify_files(plan):
    assert plan['originalSDKDeclarations'] is True
    assert plan['newPrivateNaturalMetadata'] is True and plan['originalCryptoKitBinaryClaimed'] is False
    assert plan['privateAliasCount'] == 16 and plan['originalDI2AliasCount'] == 14
    assert plan['SDKConformanceDescriptorAliases'] == 2 and plan['genuineNativeP256EntryCount'] == 7
    assert plan['diskVMGPUCalls'] == 0 and plan['nativeExecutionPending'] is True
    assert plan['nativeDirectory'] == '/var/root/VirtualMac2/testing/hpke-original-sdk-v1'
    assert plan['executable'] == 'hpke-original-sdk-fixture' and plan['arguments'] == []
    aliases = json.loads((SOURCE / 'aliases.json').read_bytes())['aliases']
    names = {row['originalSymbol'] for row in aliases}
    called = {name for name in names if not name.endswith(('N', 'Mn', 'WP', 'Mc'))}
    called |= {name for name in names if name.endswith('Mc')}
    assert len(aliases) == len(names) == 16 and len(called) == 12
    sdk_caller = (BUILD / 'fixture.swift').read_text()
    assert re.search(r'^import CryptoKit$', sdk_caller, re.M)
    assert not re.search(r'^\s*import VM27HPKE\b', sdk_caller, re.M)
    for item in plan['files'] + plan['MacFiles']:
        data = Path(item['path']).read_bytes()
        assert len(data) == item['bytes'] and SHA(data) == item['sha256']
        uuids = [data[at + 8:at + 24].hex() for command, at, _ in commands(data) if command == 0x1b]
        assert uuids == [item['UUID']]
        subprocess.run(['codesign', '--verify', '--strict', item['path']], capture_output=True, check=True)
        subprocess.run(['xcrun', 'dyld_info', '-validate_only', item['path']], capture_output=True, check=True)
        rights = subprocess.run(['codesign', '-d', '--entitlements', ':-', item['path']], capture_output=True, check=True).stdout
        actual_rights = plistlib.loads(rights) if rights else {}
        expected_rights = RIGHTS if item['role'] == 'ios' and item['name'] == plan['executable'] else {}
        assert actual_rights == item['entitlements'] == expected_rights
        signature = subprocess.run(['codesign', '-d', '--verbose=4', item['path']], capture_output=True, check=True).stderr
        assert re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode() == item['CDHash']
        imp = imports(data)['imports']
        if item['name'] == plan['executable']:
            linked = dylibs(data)
            used = [row for row in imp if row['name'] in names]
            assert {row['name'] for row in used} == called and len(used) == 12
            assert all(row['weak'] is False and linked[row['ordinal'] - 1] == '@rpath/VM27HPKECompat.dylib' for row in used)
            # Restore only the precise private availability declarations. All
            # instructions, Swift calling conventions and ptrauth are identical.
            directory = BUILD / item['role']
            before = (directory / 'original-sdk.ll').read_text()
            after = (directory / 'original-sdk-strong.ll').read_text()
            upgrade = json.loads((directory / 'strong-import-upgrades.json').read_bytes())
            assert SHA(before.encode()) == upgrade['originalIRSHA256']
            assert SHA(after.encode()) == upgrade['strongIRSHA256']
            expected_after, upgraded = before, []
            for line in before.splitlines(keepends=True):
                if 'extern_weak' not in line:
                    continue
                match = [name for name in names if ('"' + name[1:] + '"') in line]
                if match:
                    assert len(match) == 1
                    upgraded.append(match[0])
                    expected_after = expected_after.replace(line, line.replace('extern_weak', 'external'))
            assert after == expected_after and upgrade['upgradedNames'] == upgraded
            assert upgrade['instructionsChanged'] is False
        else:
            assert len(imp) == 187 and all(row['weak'] is False and row['ordinal'] > 0 for row in imp)
            table = exports(data)
            for row in aliases:
                assert row['newPrivateSemantics'] is True and row['originalTypeContextNameRetained'] is False
                original, natural = table[row['originalSymbol']], table[row['naturalSymbol']]
                assert original == dict(natural, symbol=row['originalSymbol'])
    # The second alias build adds exports but no new system import contracts.
    prior_data = (N / 'hpke-compat-build-v4/ios/VM27HPKECompat.dylib').read_bytes()
    now_data = (BUILD / 'ios/VM27HPKECompat.dylib').read_bytes()
    prior, now = imports(prior_data)['imports'], imports(now_data)['imports']
    prior_owner, now_owner = dylibs(prior_data), dylibs(now_data)
    assert {(r['name'], prior_owner[r['ordinal'] - 1], r['weak']) for r in prior} == {
        (r['name'], now_owner[r['ordinal'] - 1], r['weak']) for r in now}
    inventory = json.loads((N / 'hpke-system-inventory-native-v1/result.json').read_bytes())
    assert inventory['childPID'] == 38867 and inventory['observedWaitExit'] == 0 and inventory['childAbsent'] is True
    assert inventory['targetAPICalls'] == 0 and inventory['providerImportMissing'] == 0
    assert inventory['DI2OriginalMissing'] == 14 and inventory['functionalCryptoVerified'] is False
    return {'files': 4, 'privateAliases': 16, 'originalDI2Aliases': 14,
            'originalSDKStrongCallsAndConformanceDescriptors': 12,
            'providerStrongImports': 187, 'nativeImportPresenceOnly': True}


def native_transcript(path, pid, wait, role='ios'):
    assert role in ('ios', 'mac') and pid > 1 and wait == 0
    plan = json.loads((BUILD / 'consumer-plan.json').read_bytes())
    item = next(row for row in (plan['files'] if role == 'ios' else plan['MacFiles']) if row['name'] == 'VM27HPKECompat.dylib')
    directory = BUILD / role
    header = (directory / 'hpke-sdk-pins.h').read_text()
    required = re.findall(r'\{"([^"]+)",(0|1),(0|1),(\d+)\}', header)
    assert len(required) == 23
    expected_native_uuid = '63c2cd6b57b93d7a92cca3fda099451e' if role == 'ios' else '8020b038f79637fc93be7c31dec2bd3f'
    expected_native_path = '/System/Library/Frameworks/CryptoKit.framework/' + ('' if role == 'ios' else 'Versions/A/') + 'CryptoKit'
    private_path = '/private' + plan['nativeDirectory'] + '/VM27HPKECompat.dylib' if role == 'ios' else item['path']
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 38
    assert rows[0] == {'record': 'start', 'PID': pid, 'cryptoAPICallsSoFar': 0}
    for row, (name, data, native, rva) in zip(rows[1:24], required):
        assert set(row) == {'record', 'name', 'data', 'nativeP256', 'UUID', 'path', 'RVA'}
        assert row['record'] == 'identity' and row['name'] == name
        assert row['data'] is bool(int(data)) and row['nativeP256'] is bool(int(native))
        assert row['UUID'] == (expected_native_uuid if int(native) else item['UUID'])
        assert row['path'] == (expected_native_path if int(native) else private_path)
        assert re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        if not int(native):
            assert int(row['RVA'], 16) == int(rva)
    assert rows[24] == {'record': 'identityGate', 'symbols': 23, 'privateNaturalAliases': 16,
                        'nativeP256Entries': 7, 'cryptoAPICallsSoFar': 0, 'passed': True}
    layouts = [('HPKE', 0, 1, 1), ('HPKE.Ciphersuite', 3, 3, 1), ('HPKE.Sender', 80, 80, 8),
               ('HPKE.Recipient', 64, 64, 8), ('P256.KeyAgreement.PublicKey', 8, 8, 8),
               ('P256.KeyAgreement.PrivateKey', 8, 8, 8)]
    for i, (name, size, stride, alignment) in enumerate(layouts):
        identity, layout = rows[25 + i * 2:27 + i * 2]
        native = i >= 4
        assert set(identity) == {'record', 'name', 'data', 'nativeP256', 'UUID', 'path', 'RVA'}
        assert identity['record'] == 'identity' and identity['name'] == name and identity['data'] is True
        assert identity['nativeP256'] is native and identity['UUID'] == (expected_native_uuid if native else item['UUID'])
        assert identity['path'] == (expected_native_path if native else private_path)
        assert re.fullmatch(r'0x[0-9a-f]+', identity['RVA']) and int(identity['RVA'], 16) > 0
        assert layout == {'record': 'layout', 'type': name, 'size': size, 'stride': stride, 'alignment': alignment}
    assert rows[-1] == {'record': 'summary', 'PID': pid, 'checks': 512, 'iterations': 32,
                        'originalSDKTypes': True, 'aliasEntryIdentities': 16, 'originalDI2Aliases': 14,
                        'SDKConformanceDescriptorAliases': 2, 'nativeP256EntryIdentities': 7,
                        'metadataIdentities': 6, 'P256ObjectsUsed': True, 'trueThrowNegatives': 64,
                        'genuine27CryptoKitBinaryClaimed': False, 'diskVMGPUCalls': 0, 'passed': True}
    return {'passed': True, 'PID': pid, 'observedWaitExit': wait, 'checks': 512,
            'trueThrowNegatives': 64, 'originalSDKTypes': True, 'nativeP256Types': True,
            'newPrivateNominalHPKEContext': True, 'originalDI2Executed': False, 'full27Backend': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-json', type=Path, required=True)
    parser.add_argument('--expected-candidate-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert SHA(args.candidate_json.read_bytes()) == args.expected_candidate_sha256
    plan = json.loads(args.candidate_json.read_bytes())
    static = verify_files(plan)
    process = next(row for row in json.loads((BUILD / 'processes.json').read_bytes()) if row['label'] == 'mac-actual')
    assert process['wait'] == 0 and process['reaped'] is True
    mac = native_transcript(BUILD / 'mac-actual.stdout', process['PID'], process['wait'], 'mac')
    assert not (BUILD / 'mac-actual.stderr').read_bytes()
    args.output.mkdir()
    (args.output / 'verification.json').write_text(json.dumps({'passed': True, 'static': static, 'MacActual': mac,
        'iPadFunctionalExecutionPending': True, 'originalDI2Executed': False, 'full27Backend': False}, indent=2) + '\n')
    print(json.dumps({'passed': True, 'MacActualChecks': 512, 'nativePending': True}))


if __name__ == '__main__':
    main()
