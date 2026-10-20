#!/usr/bin/env python3
"""Strict saved DI2 + Foundation load-only transcript; no API execution."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    # JSON's Bool and Number are distinct; Python dictionary equality alone
    # would accept 1 where the actual contract requires true.
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    pins = manifest['files'][:-1]
    assert len(pins) == 13
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}',
                         re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = manifest['sourceProbeMethods']
    assert len(symbols) == 60 and len(methods) == 8
    di2 = next(row for row in pins if row['name'] == 'DiskImages227.dylib')
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 88
    same(rows[0], {'record': 'start', 'PID': pid, 'DI2APICalls': 0})

    def identity(row, pin, rva=None):
        assert set(row) == {'record', 'UUID', 'path', 'RVA'}
        assert type(row['RVA']) is str and re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        same(row, dict(record='identity', UUID=pin['UUID'],
                       path='/private' + manifest['nativeDirectory'] + '/' + pin['name'],
                       RVA=row['RVA'] if rva is None else hex(rva)))

    for row, (_, image, _) in zip(rows[1:61], symbols):
        identity(row, pins[int(image)])
    names = ['DIOpenParams', 'DIImageHandle', 'DIDiskImageBridge', 'DICreateParams', 'DIAttachParams']
    for index, name in enumerate(names):
        owner, cls = rows[61 + index * 2:63 + index * 2]
        identity(owner, di2)
        same(cls, {'record': 'class', 'name': name, 'actualPrivateDI2Class': True})
    for index, pin in enumerate(methods):
        owner, method = rows[71 + index * 2:73 + index * 2]
        rva = pin['rawIMP'] - 0x23fd3e000
        identity(owner, di2, rva)
        same(method, {'record': 'method', 'class': pin['class'], 'selector': pin['selector'],
                      'actualOriginalRVA': hex(rva), 'calls': 0})
    same(rows[-1], {'record': 'summary', 'PID': pid, 'genuine27UUID': di2['UUID'],
                   'privateProviders': 60, 'classes': 5, 'methods': 8,
                   'DI2APICalls': 0, 'diskVMGPUCalls': 0, 'passed': True})
    return {'passed': True, 'PID': pid, 'observedWaitExit': wait,
            'genuine27DI2UUID': di2['UUID'], 'privateProviderIdentities': 60,
            'originalPrivateClassIdentities': 5, 'originalMethodABIIdentities': 8,
            'DI2APICalls': 0, 'RAWReadWriteVerified': False, 'full27Backend': False}
