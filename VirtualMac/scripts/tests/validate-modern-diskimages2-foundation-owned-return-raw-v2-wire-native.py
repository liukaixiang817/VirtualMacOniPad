#!/usr/bin/env python3
"""Strict actual v2 wire-format owned-RAW success parser. Never loads a framework or opens RAW."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-owned-raw-build-v2'


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    header = (BUILD / 'ios/diskimages227-owned-raw-pins.h').read_text()
    pins = manifest['files'][:-1]
    symbols = re.findall(r'\{"([^"]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = re.findall(r'\{"([^"]+)","([^"]+)","([^"]+)",(0x[0-9a-f]+)\}', re.search(r'Methods\[\]=\{(.*?)\};', header, re.S)[1])
    assert len(pins) == 13 and len(symbols) == 60 and len(methods) == 8
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 103
    # Reject Bool/Number confusion before comparing exact record dictionaries.
    for row in rows:
        assert type(row) is dict
        for key, value in row.items():
            if key in ('reopen','closedByFramework','removed','passed','cleanupComplete','completeDI2OrVMMClaimed'):
                assert type(value) is bool
            elif key == 'hasNSError':
                # The frozen Objective-C source boxes the C comparison as
                # NSNumber(int), not CFBoolean. Preserve that exact wire type.
                assert type(value) is int and value == 1
            elif key not in ('record','UUID','path','RVA','phase','stage','domain','genuine27UUID'):
                assert type(value) is int
            else:
                assert type(value) is str
    assert rows[0] == {'record': 'start', 'PID': pid, 'DI2APICalls': 0, 'ownedRAWBytesLimit': 131072}
    native_dir = '/private' + manifest['nativeDirectory']

    def identity(row, pin, rva=None):
        assert set(row) == {'record', 'UUID', 'path', 'RVA'}
        assert row['record'] == 'identity' and row['UUID'] == pin['UUID']
        assert row['path'] == native_dir + '/' + pin['name']
        assert re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        if rva is not None: assert int(row['RVA'], 16) == rva

    for row, (_, owner, _) in zip(rows[1:61], symbols): identity(row, pins[int(owner)])
    di2 = pins[12]; assert di2['name'] == 'DiskImages227.dylib'
    for row in rows[61:66]: identity(row, di2)
    for row, (_, _, _, rva) in zip(rows[66:74], methods): identity(row, di2, int(rva, 16))
    identity(rows[74], pins[6]); assert pins[6]['name'] == 'VM27DI2SecurityUnavailable.dylib'
    for phase, offset in [('before', 75), ('after', 91)]:
        for index, row in enumerate(rows[offset:offset + 10]):
            assert row == {'record': 'securityCounter', 'phase': phase, 'entry': index, 'calls': 0}
    owned = rows[85]
    assert set(owned) == {'record', 'path', 'bytes', 'device', 'inode', 'mode'}
    assert owned['record'] == 'ownedFile' and owned['bytes'] == 131072 and owned['mode'] == 384
    # Foundation logs the exact mkstemp string (/var), while live image
    # realpath identities resolve to /private/var. Both are separately fixed.
    assert re.fullmatch(re.escape(manifest['nativeDirectory'] + '/owned-raw-') + r'[A-Za-z0-9]{6}', owned['path'])
    assert type(owned['device']) is int and type(owned['inode']) is int and owned['inode'] > 0
    for reopen, offset in [(False, 86), (True, 88)]:
        handle, lifecycle = rows[offset:offset + 2]
        assert set(handle) == {'record', 'reopen', 'fileDescriptor', 'device', 'inode', 'bytes', 'publicRequestedMode',
                               'internalMode', 'reportedHandleMode', 'actualPOSIXAccessMode'}
        assert handle['record'] == 'originalHandle' and handle['reopen'] is reopen
        assert type(handle['fileDescriptor']) is int and 0 <= handle['fileDescriptor'] < 128
        assert handle['device'] == owned['device'] and handle['inode'] == owned['inode'] and handle['bytes'] == 131072
        assert handle['publicRequestedMode'] == 2 and handle['internalMode'] == 1 and handle['actualPOSIXAccessMode'] == 2
        assert type(handle['reportedHandleMode']) is int
        assert lifecycle == {'record': 'originalLifecycle', 'reopen': reopen, 'borrowedFD': handle['fileDescriptor'],
                              'closedByFramework': True, 'borrowedFDCloseCallsByProbe': 0}
    error = rows[90]
    assert set(error) == {'record', 'stage', 'hasNSError', 'domain', 'code', 'DI2APICalls'}
    assert error['record'] == 'originalError' and error['stage'] == 'owned nonexistent RAW path'
    assert type(error['hasNSError']) is int and error['hasNSError'] == 1 and isinstance(error['domain'], str) and error['domain']
    assert type(error['code']) is int and error['DI2APICalls'] in (11, 12)
    assert rows[101] == {'record': 'cleanup', 'path': owned['path'], 'removed': True}
    assert rows[-1] == {'record': 'summary', 'PID': pid, 'exit': 0, 'passed': True,
                        'genuine27UUID': 'a456d4a4d6ab3549965d0400f3552de3', 'DI2APICalls': error['DI2APICalls'],
                        'originalOpenCalls': error['DI2APICalls'] - 9, 'originalHandles': 2, 'checks': 41,
                        'originalFDReads': 3, 'originalFDWrites': 1, 'ownedRAWBytes': 131072,
                        'borrowedFDCloseCallsByProbe': 0, 'cleanupComplete': True,
                        'attachCalls': 0, 'guestDiskCalls': 0, 'VMGPUCalls': 0, 'completeDI2OrVMMClaimed': False}
    return {'passed': True, 'PID': pid, 'observedWaitExit': wait, 'originalDI2ObjectAndDescriptorCalls': error['DI2APICalls'],
            'ownedRAWBytes': 131072, 'readBytes': 12288, 'writeBytes': 4096,
            'originalHandleCloseAndReopenVerified': True, 'realNSErrorNegativeVerified': True,
            'desktopSecurityCalls': 0, 'cleanupComplete': True,
            'originalNSErrorWireFlagType': 'NSNumber integer 1',
            'originalTranscriptBytesPreserved': True,
            'dataIOByOriginalFrameworkReturnedFDAndDirectPOSIX': True,
            'originalDI2DataReadWriteMethodsExercised': False,
            'AppleUIORingsABIProven': False, 'ASIFProven': False, 'VMMBlockDeviceIntegrationProven': False, 'full27Backend': False}
