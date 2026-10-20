#!/usr/bin/env python3
"""Route one original VMM Foundation dependency to its proved iPad alias.

Only load-command path bytes change in a new inert data copy. No function
replacement, version weakening, signing, loading, device or OS operation occurs.
Saved symbol discovery is required for all 24 original strong requirements; it
does not prove Foundation ABI functionality or the entire original VMM closure.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE = N / 'softlinking-original-consumer-routes-v1/inert-data-v2/VMM27.scoped-softlinking.inert.macho-data'
SOURCE_SHA = 'cde54210342545872acd1bb4c1b406e899179877f1ba65f500e10cfb3a6bb251'
PROOF = R / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-strong-import-preflight-native-v2/native-provider-scan-stdout.jsonl'
PROOF_SHA = '3c0c0f0c58f28c7960da3cd7930d73ad9a55b9a204a11795951d9836c9728deb'
OLD_PATH = '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
NEW_PATH = '/System/Library/Frameworks/Foundation.framework/Foundation'
FOUNDATION_UUID = 'c431acb6fe043d28b6774de6e1c7d81f'
H = lambda data: hashlib.sha256(data).hexdigest()

def unique(items):
    result = {}
    for key, value in items:
        assert key not in result
        result[key] = value
    return result

def parser():
    path = R / 'VirtualMac/scripts/development/prepare-modern-vmm-runtime-imports.py'
    assert path.is_file() and not path.is_symlink()
    spec = importlib.util.spec_from_file_location('read_only_vmm_macho_parser', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path

def validate_discovery(imports, rows):
    selected = [r for r in imports if r['ordinal'] == 12]
    assert len(selected) == 24 and len({r['symbol'] for r in selected}) == 24
    assert all(r['weak'] is False and r['addend'] == 0 for r in selected)
    providers = [r for r in rows if r.get('kind') == 'provider' and r.get('index') == 11]
    assert len(providers) == 1
    provider = providers[0]
    assert provider['originalMacPath'] == OLD_PATH and provider['requestedIOSAlias'] == NEW_PATH
    assert provider['opened'] is True and provider['intentionallyNotLoaded'] is False and provider['errorPresent'] is False
    found = [r for r in rows if r.get('kind') == 'import' and r.get('image') == 'VirtualMachine' and r.get('originalOrdinal') == 12]
    assert len(found) == 24 and len({r['sourceIndex'] for r in found}) == 24
    by_index = {r['sourceIndex']: r for r in found}
    receipts = []
    for imported in selected:
        receipt = by_index[imported['index']]
        assert receipt['machSymbol'] == imported['symbol'] and receipt['querySymbol'] == imported['symbol'][1:]
        assert receipt['sourceKind'] == 'original-chained-format2' and receipt['providerIndex'] == 11
        assert receipt['weak'] is False and receipt['addend'] == 0 and receipt['queryable'] is True
        assert type(receipt['classification']) is int and receipt['classification'] == 1
        assert receipt['requestedFound'] is True and receipt['privateFallbackFound'] is False
        identity = receipt['requestedIdentity']
        assert identity['known'] is True and identity['path'] == NEW_PATH and identity['uuid'] == FOUNDATION_UUID
        assert type(identity['platform']) is int and identity['platform'] == 2
        assert re_hex(identity['rva'])
        receipts.append(dict(imported, savedRequestedIdentity=identity))
    return receipts

def re_hex(value):
    return type(value) is str and value.startswith('0x') and 0 < len(value) <= 18 and all(c in '0123456789abcdef' for c in value[2:]) and int(value, 16) > 0

def route(original, m):
    assert len(original) == 5195312 and H(original) == SOURCE_SHA
    assert struct.unpack_from('<3I', original, 4) == (0x100000c, 0x80000002, 2)
    before_imports = m.import_rows(original)
    before_libraries = m.libraries(original)
    assert len(before_libraries) == 53 and before_libraries[11] == OLD_PATH
    assert before_libraries[35] == '@loader_path/VM27ScopedSoftLinking.dylib'
    ordinal = 0
    chosen = None
    section_ranges = []
    for cmd, at, size in m.commands(original):
        if cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            ordinal += 1
            if ordinal == 12:
                assert cmd == 0xc and at == 4880 and size == 96
                name_offset = struct.unpack_from('<I', original, at + 8)[0]
                assert name_offset == 24
                assert m.string(original, at + name_offset, at + size) == OLD_PATH
                chosen = (at, size, name_offset)
        elif cmd == 0x19:
            count = struct.unpack_from('<I', original, at + 64)[0]
            assert size == 72 + count * 80
            for i in range(count):
                section_at = at + 72 + i * 80
                length = struct.unpack_from('<Q', original, section_at + 40)[0]
                offset = struct.unpack_from('<I', original, section_at + 48)[0]
                flags = struct.unpack_from('<I', original, section_at + 64)[0]
                if length and offset and flags & 255 not in (1, 12, 18):
                    assert offset + length <= len(original)
                    section_ranges.append((offset, length))
    assert chosen is not None
    at, size, name_offset = chosen
    start, end = at + name_offset, at + size
    encoded = NEW_PATH.encode() + b'\0'
    assert len(encoded) <= end - start
    data = bytearray(original)
    data[start:end] = encoded + bytes(end - start - len(encoded))
    changed = [i for i, (a, b) in enumerate(zip(original, data)) if a != b]
    assert changed and all(start <= i < end for i in changed)
    assert len(data) == len(original) and list(m.commands(data)) == list(m.commands(original))
    assert m.import_rows(data) == before_imports
    expected_libraries = list(before_libraries)
    expected_libraries[11] = NEW_PATH
    assert m.libraries(data) == expected_libraries
    assert original[at + 12:at + 24] == data[at + 12:at + 24]
    assert all(original[offset:offset + length] == data[offset:offset + length] for offset, length in section_ranges)
    return bytes(data), {'ordinal': 12, 'loadCommandOffset': at, 'loadCommandBytes': size,
        'changedRange': [start, end], 'changedByteCount': len(changed), 'changedOffsets': changed,
        'unchangedCurrentAndCompatibilityVersions': list(struct.unpack_from('<II', original, at + 16)),
        'importsByteIdentical': True, 'allOtherBytesIdentical': True, 'sectionsByteIdentical': True,
        'allChainWordsAndPACPreservedByExactByteDelta': True, 'priorTwentySixRoutesAndSoftLinkingRoutePreserved': True}

def main(output):
    assert SOURCE.is_file() and not SOURCE.is_symlink() and PROOF.is_file() and not PROOF.is_symlink()
    original = SOURCE.read_bytes()
    proof = PROOF.read_bytes()
    assert H(proof) == PROOF_SHA and proof.endswith(b'\n')
    rows = [json.loads(line, object_pairs_hook=unique) for line in proof.splitlines()]
    m, parser_path = parser()
    imports = m.import_rows(original)
    receipts = validate_discovery(imports, rows)
    candidate, delta = route(original, m)
    out = Path(output).resolve()
    assert out.is_relative_to(N) and not out.exists() and not out.is_symlink()
    out.mkdir(mode=0o700, parents=True)
    path = out / 'VMM27.foundation-ios-alias.inert.macho-data'
    path.write_bytes(candidate)
    path.chmod(0o600)
    assert path.stat().st_mode & 0o777 == 0o600
    validation = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, timeout=20)
    (out / 'dyld-validation.stdout').write_bytes(validation.stdout)
    (out / 'dyld-validation.stderr').write_bytes(validation.stderr)
    assert validation.returncode == 0
    report = {'scope': 'one-original-VMM-Foundation-dependency-path-only-inert-candidate',
        'source': {'path': str(SOURCE), 'bytes': len(original), 'sha256': H(original)},
        'candidate': {'path': str(path), 'bytes': len(candidate), 'sha256': H(candidate), 'mode': '0600'},
        'savedDiscovery': {'path': str(PROOF), 'bytes': len(proof), 'sha256': H(proof)},
        'parser': {'path': str(parser_path), 'sha256': H(parser_path.read_bytes())},
        'oldPath': OLD_PATH, 'newPath': NEW_PATH, 'savedFoundationUUID': FOUNDATION_UUID,
        'selectedOriginalImports': receipts, 'delta': delta, 'dyldStaticValidationPassed': True,
        'savedAll24OriginalStrongSymbolsFoundAtRequestedAlias': True,
        'minimumProviderCompatibilityVersionNotYetMeasured': True,
        'originalFoundationConsumerFunctionalityNotYetVerified': True,
        'originalVMMExecuted': False, 'nativeProbeExecutions': 0, 'deviceOperations': 0,
        'signingCalls': 0, 'iPadOSModified': False, 'full27Backend': False,
        'executionGate': 'Keep inert: platform macOS27, full75 HV/VZ/framework closure, initializer/service/guest instruction contracts still unresolved.'}
    (out / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'selectedOriginalImports'}, indent=2))

if __name__ == '__main__':
    assert len(sys.argv) == 2
    main(sys.argv[1])
