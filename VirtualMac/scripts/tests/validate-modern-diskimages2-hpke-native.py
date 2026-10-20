#!/usr/bin/env python3
"""Strict saved original DI2 HPKE load-only transcript parser; no DI2 calls."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-hpke-loadonly-build-v1'


def native_transcript(path, pid, wait):
    assert pid > 1 and wait == 0
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    pins = manifest['files'][:-1]
    assert len(pins) == 12
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"]+)",(\d+),(0|1)\}',
                         re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = manifest['sourceProbeMethods']
    assert len(symbols) == 59 and len(methods) == 8
    di2 = next(row for row in pins if row['name'] == 'DiskImages227.dylib')
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 87
    assert rows[0] == {'record': 'start', 'PID': pid, 'DI2APICalls': 0}

    def identity(row, pin, rva=None):
        assert set(row) == {'record', 'UUID', 'path', 'RVA'}
        assert row['record'] == 'identity' and row['UUID'] == pin['UUID']
        assert row['path'] == '/private' + manifest['nativeDirectory'] + '/' + pin['name']
        assert re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        if rva is not None:
            assert int(row['RVA'], 16) == rva

    for row, (_, image, _) in zip(rows[1:60], symbols):
        identity(row, pins[int(image)])
    names = ['DIOpenParams', 'DIImageHandle', 'DIDiskImageBridge', 'DICreateParams', 'DIAttachParams']
    for index, name in enumerate(names):
        owner, cls = rows[60 + index * 2:62 + index * 2]
        identity(owner, di2)
        assert cls == {'record': 'class', 'name': name, 'actualPrivateDI2Class': True}
    for index, pin in enumerate(methods):
        owner, method = rows[70 + index * 2:72 + index * 2]
        rva = pin['rawIMP'] - 0x23fd3e000
        identity(owner, di2, rva)
        assert method == {'record': 'method', 'class': pin['class'], 'selector': pin['selector'],
                          'actualOriginalRVA': hex(rva), 'calls': 0}
    assert rows[-1] == {'record': 'summary', 'PID': pid, 'genuine27UUID': di2['UUID'],
                        'privateProviders': 59, 'classes': 5, 'methods': 8,
                        'DI2APICalls': 0, 'diskVMGPUCalls': 0, 'passed': True}
    return {'passed': True, 'PID': pid, 'observedWaitExit': wait,
            'genuine27DI2UUID': di2['UUID'], 'privateProviderIdentities': 59,
            'originalPrivateClassIdentities': 5, 'originalMethodABIIdentities': 8,
            'DI2APICalls': 0, 'RAWReadWriteVerified': False, 'full27Backend': False}
