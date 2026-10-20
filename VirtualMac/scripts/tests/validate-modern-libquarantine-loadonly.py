#!/usr/bin/env python3
"""Validate saved symbol inventory/load-only receipts; never invoke qtn APIs."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/libquarantine-loadonly-build-v3'


def native_transcript(path, pid, wait, mode, role='ios'):
    assert mode in ('--inventory', '--load-only') and role in ('macos', 'ios')
    assert pid > 1 and wait == 0
    item = next(row for row in json.loads((BUILD / 'candidate.json').read_bytes())['candidates'] if row['role'] == role)
    header = (BUILD / role / 'libquarantine27-pins.h').read_text()
    images = re.findall(r'"([^"]+)"', re.search(r'SystemImages\[8\]=\{(.*?)\};', header, re.S)[1])
    symbols = re.findall(r'\{"([^"]+)",(\d+),(\d+),(\d+)\}', re.search(r'RequiredSymbols\[42\]=\{(.*?)\};', header, re.S)[1])
    qtn = re.findall(r'"([^"]+)"', re.search(r'QtnNames\[9\]=\{(.*?)\};', header, re.S)[1])
    rvas = [int(x) for x in re.search(r'QtnRVAs\[9\]=\{(.*?)\};', header, re.S)[1].split(',')]
    assert len(images) == 8 and len(symbols) == 42 and len(qtn) == len(rvas) == 9
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    load = mode == '--load-only'
    assert [row['record'] for row in rows] == ['start'] + ['image'] * 8 + ['symbol'] * 42 + (['qtnExport'] * 9 if load else []) + ['summary']
    assert rows[0] == {'record': 'start', 'PID': pid, 'loadOnly': load, 'qtnAPICalls': 0}
    for row, image in zip(rows[1:9], images):
        assert row == {'record': 'image', 'path': image, 'alreadyLoaded': True}
    missing = []
    for i, (row, (name, owner, data, allocator)) in enumerate(zip(rows[9:51], symbols)):
        expected = {'record': 'symbol', 'index': i, 'name': name, 'requestedOwner': images[int(owner)]}
        assert {key: row[key] for key in expected} == expected and type(row['found']) is bool
        if row['found']:
            assert set(row) == set(expected) | {'found', 'actualOwner', 'UUID', 'RVA'}
            assert row['actualOwner'] == expected['requestedOwner']
            assert re.fullmatch('[0-9a-f]{32}', row['UUID'])
            assert re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        else:
            assert set(row) == set(expected) | {'found'}
            missing.append({'index': i, 'name': name, 'privateAllocatorRoute': bool(int(allocator))})
    if load:
        assert all(row['privateAllocatorRoute'] for row in missing) and len(missing) <= (2 if role == 'ios' else 0)
        expected_path = item['nativeDirectory'] + '/Libquarantine27.dylib'
        if role == 'ios':
            expected_path = '/private' + expected_path
        for row, name, rva in zip(rows[51:60], qtn, rvas):
            assert row == {'record': 'qtnExport', 'name': name, 'UUID': item['library']['UUID'],
                           'path': expected_path, 'RVA': hex(rva), 'calls': 0}
        summary = {'record': 'summary', 'PID': pid, 'symbols': 42, 'missingSystem': len(missing),
                   'identityFailures': 0, 'genuine27UUID': item['library']['UUID'],
                   'qtnExportIdentities': 9, 'qtnLibraryLoaded': True, 'qtnAPICalls': 0,
                   'diskVMGPUCalls': 0, 'passed': True}
    else:
        summary = {'record': 'summary', 'PID': pid, 'symbols': 42, 'missing': len(missing),
                   'identityFailures': 0, 'qtnLibraryLoaded': False, 'qtnAPICalls': 0, 'diskVMGPUCalls': 0}
    assert rows[-1] == summary
    return {'passed': True, 'directPID': pid, 'observedWaitExit': wait, 'mode': mode,
            'symbols': rows[9:51], 'missing': missing, 'summary': summary,
            'genuine27LibraryLoaded': load, 'genuineQtnAPICalls': 0,
            'originalDI2Executed': False, 'full27Backend': False}
