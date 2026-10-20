#!/usr/bin/env python3
"""Offline checks for the typed private Security-unavailable fixture.

No Security APIs, probes, or device operations are executed by this validator.
The fixture's denied/unimplemented results do not prove genuine DI2 functionality.
"""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-security-unavailable-build-v1'
NAMES = ['AuthorizationCreate', 'AuthorizationFree', 'AuthorizationMakeExternalForm',
         'SessionGetInfo', 'SecAccessCreate', 'SecKeychainCopyDefault', 'SecKeychainGetPath',
         'SecKeychainOpen', 'SecKeychainItemCopyKeychain', 'SecTrustedApplicationCreateFromPath']
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commands(data):
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    n, size = struct.unpack_from('<II', data, 16)
    assert n < 128 and 32 + size <= len(data)
    at = 32
    for _ in range(n):
        cmd, count = struct.unpack_from('<II', data, at)
        assert count >= 8 and count % 8 == 0 and at + count <= 32 + size
        yield cmd, at, count
        at += count
    assert at == 32 + size


def preflight(review):
    freeze = json.loads((review / 'freeze.json').read_bytes())
    for row in freeze['files']:
        path = ROOT / row['path']
        assert path.is_relative_to(ROOT) and not path.is_symlink() and path.is_file()
        assert path.stat().st_size == row['bytes'] and digest(path) == row['sha256']
    candidate = json.loads((BUILD / 'candidate.json').read_bytes())
    for original, sha in candidate['sourceSHA256'].items():
        path = Path(original)
        assert digest(path) == digest(BUILD / 'source' / path.name) == sha
    assert candidate['SDKPrototypesVerified'] == 10
    assert not candidate['SecuritySuccessReturned'] and not candidate['DI2Loaded']
    bindings = 0
    for item in candidate['candidates']:
        role = item['role']
        for part in ('provider', 'probe'):
            row = item[part]
            path = Path(row['path'])
            assert path.is_relative_to(BUILD) and not path.is_symlink()
            data = path.read_bytes()
            assert len(data) == row['bytes'] and digest(path) == row['sha256']
            uuid = [data[at+8:at+24].hex() for cmd, at, _ in commands(data) if cmd == 0x1b]
            assert uuid == [row['UUID']]
            subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True, capture_output=True)
            info = subprocess.run(['codesign', '-d', '--verbose=4', str(path)], check=True, capture_output=True).stderr
            assert ('CDHash=' + row['CDHash']).encode() in info.splitlines()
            xml = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(path)], check=True, capture_output=True).stdout
            assert (plistlib.loads(xml) if xml else {}) == row['entitlements']
            assert row['entitlements'] == (RIGHTS if role == 'ios' and part == 'probe' else {})
            subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], check=True, capture_output=True)
        imports = subprocess.run(['xcrun', 'dyld_info', '-imports', item['probe']['path']], check=True, capture_output=True).stdout.decode()
        for name in NAMES + ['VM27DI2SecurityCallCount']:
            rows = [line for line in imports.splitlines() if re.search(r'_' + name + r'\b', line)]
            assert len(rows) == 1 and '(from VM27DI2SecurityUnavailable)' in rows[0] and 'weak' not in rows[0].lower()
            bindings += 1
    return {'passed': True, 'frozenPayloadFiles': len(freeze['files']), 'strongBindings': bindings,
            'SecurityAPIsImplemented': False, 'DI2Loaded': False, 'deviceOperations': False}


def native_transcript(path, pid, wait, role='ios'):
    assert role in ('ios', 'macos') and pid > 1 and wait == 0
    candidate = json.loads((BUILD / 'candidate.json').read_bytes())
    item = next(x for x in candidate['candidates'] if x['role'] == role)
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 22
    assert [x['record'] for x in rows] == ['start'] + ['identity'] * 10 + ['counter'] * 10 + ['summary']
    assert rows[0] == {'record': 'start', 'PID': pid}
    runtime = item['nativeRuntimePath']
    if role == 'ios':
        runtime = '/private' + runtime
    for name, row in zip(NAMES, rows[1:11]):
        assert row == {'record': 'identity', 'entry': name, 'UUID': item['provider']['UUID'],
                       'path': runtime, 'callsBefore': 0}
    for name, row in zip(NAMES, rows[11:21]):
        assert row == {'record': 'counter', 'entry': name, 'calls': 258 if name == 'SecKeychainGetPath' else 257}
    summary = {'record': 'summary', 'PID': pid, 'checks': 5402, 'failures': 0,
               'providerCalls': 2571, 'systemSecurityAPICalls': 0, 'frameworkAPICalls': 0,
               'AuthorizationRefsCreated': 0, 'keychainObjectsCreated': 0,
               'privilegedOperations': 0, 'passed': True}
    assert rows[-1] == summary
    return {'passed': True, 'directPID': pid, 'observedWaitExit': wait, 'summary': summary,
            'identities': rows[1:11], 'counters': rows[11:21],
            'SecuritySuccessReturned': False, 'genuineDI2Executed': False, 'full27Backend': False}
