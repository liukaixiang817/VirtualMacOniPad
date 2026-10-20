"""Build a local VZ27 relative-data candidate; no dlopen, deployment or execution."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
RAW = READER / 'virtualization27-stack-audit-v1/raw/Virtualization'
BASE = N / 'virtualization27-native-closure-v2/load-only-scoped-cvw-v1/VZ27.usb-off-scoped-cvw.ios.dylib'
SYMBOLS = N / 'vz-resilient-schema-root-v1/symbols.a2s.batch.json'
SCANNER = ROOT / 'VirtualMac/scripts/development/swift_relative_metadata.py'
AUTH_ORACLE = N / 'vz-original-slot-auth-oracle-v3/contract.json'
AUTH_ORACLE_SHA = '50941169a47b71d18739e3881f11ac2dccef34b3628a1fb6d75fe5f331132ef9'
sha = lambda b: hashlib.sha256(b).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    inputs = [RAW, BASE, SYMBOLS, SCANNER, AUTH_ORACLE, READER / 'compiler_image.py', pathlib.Path(__file__).resolve()]
    records = []
    for path in inputs:
        assert path.is_file() and not path.is_symlink()
        data = path.read_bytes()
        target = out / 'inputs' / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({'path': str(path), 'bytes': len(data), 'sha256': sha(data)})
    raw, original = RAW.read_bytes(), BASE.read_bytes()
    assert sha(raw) == 'ec4bbc11af44a0c04a56269397274c90265a51568fe50e4e94123dd5eaa82f04'
    assert sha(original) == 'c0a52ba8a43a52e75458aa3894aedb400b8a143d1e53718309d7dafb2de27205'
    sys.path.insert(0, str(READER))
    from compiler_image import commands, segments, imports, chain_entries
    spec = importlib.util.spec_from_file_location('readonly_relative_scanner', SCANNER)
    scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner)
    symbols = json.loads(SYMBOLS.read_bytes())
    assert symbols['uuid'] == 'c284a291b68b3d0da1a03f866f87efdc'
    assert sha(AUTH_ORACLE.read_bytes()) == AUTH_ORACLE_SHA
    auth_evidence = json.loads(AUTH_ORACLE.read_bytes())
    assert auth_evidence['mainCacheUUID'] == symbols['uuid'] and not auth_evidence['libraryLoaded'] and not auth_evidence['cacheModified']
    auth_contracts = {row['originalSlotVA']: row for row in auth_evidence['contracts']}
    assert len(auth_contracts) == len(auth_evidence['contracts']) == 40
    audit = scanner.RelativeMetadata(raw, original)
    audit.singletons(); audit.conformances(); audit.reflection()
    assert {row['label'] for row in audit.unresolved} == {'protocol', 'resilientRequirement', 'mangledSymbolicContextIndirect'}
    targets = sorted({row['target'] for row in audit.unresolved})
    assert len(targets) == 40 and len(audit.unresolved) == 55
    assert set(auth_contracts) == set(targets)
    deps = []
    for cmd, at, length in commands(original):
        if cmd in (12, 0x80000018, 0x8000001f, 0x80000023):
            nameoff = struct.unpack_from('<I', original, at + 8)[0]
            deps.append(original[at+nameoff:at+length].split(b'\0')[0].decode())
    assert len(deps) == 52
    # Normalize only the independently identified same framework install name.
    owners = {
        '/System/Library/Frameworks/DiskImageKit.framework/Versions/A/DiskImageKit': 25,
        '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation': 16,
        '/System/Library/PrivateFrameworks/UniversalHID.framework/Versions/A/UniversalHID': 7,
        '/System/Library/PrivateFrameworks/UniversalHIDKit.framework/Versions/A/UniversalHIDKit': 3,
        '/usr/lib/swift/libswiftCore.dylib': 37,
    }
    assert all(deps[ordinal-1] == owner.replace('/Versions/A', '').replace('/Versions/C', '') for owner, ordinal in owners.items())
    b = bytearray(original)
    segs = segments(b)
    data = next(s for s in segs if s['name'] == '__DATA_CONST')
    got = next(s for s in data['sections'] if s['name'] == '__got')
    insert_va = got['address'] + got['size']
    insert_fo = got['fileoff'] + got['size']
    nbytes = len(targets) * 8
    assert insert_va % 8 == 0 and insert_va+nbytes <= data['address']+data['filesize']
    assert insert_fo+nbytes <= data['fileoff']+data['filesize'] and not any(b[insert_fo:insert_fo+nbytes])
    assert not any(s['size'] and s['address'] < insert_va+nbytes and s['address']+s['size'] > insert_va for s in data['sections'])
    before_sites = list(chain_entries(original))
    predecessor = max((row for row in before_sites if row['segment'] == '__DATA_CONST' and row['section'] == '__got'), key=lambda row: row['fileoff'])
    assert predecessor['section'] == '__got' and ((predecessor['word'] >> 51) & 0x7ff) == 0
    delta = (insert_fo-predecessor['fileoff']) // 8
    assert 0 < delta < 0x800 and insert_fo-predecessor['fileoff'] == delta*8
    assert (insert_fo-data['fileoff']) // predecessor['page_size'] == (insert_fo+nbytes-1-data['fileoff']) // predecessor['page_size'] == predecessor['page']
    info = imports(b)
    assert len(info['imports']) + len(targets) < 65536
    old_blob = bytes(b[info['data']:info['data']+info['size']])
    prefix = bytearray(old_blob[:info['header'][2]])
    assert info['header'][3] == info['header'][2] + len(info['imports'])*4
    words = bytearray(old_blob[info['header'][2]:info['header'][3]])
    pool = bytearray(old_blob[info['header'][3]:])
    routes, new_map = [], {}
    for index, target in enumerate(targets):
        name, owner = symbols['symbols'][hex(target)]
        assert name.startswith('__got._$s') and owner in owners
        name = name[6:]
        labels = sorted({row['label'] for row in audit.unresolved if row['target'] == target})
        assert all(x in ('protocol', 'resilientRequirement', 'mangledSymbolicContextIndirect') for x in labels)
        auth = scanner.verified_external_auth(target, labels, name, auth_contracts[target])
        assert owners[owner] == auth_contracts[target]['ordinal'] and owner == auth_contracts[target]['originalOwner']
        symbol_offset = len(pool)
        assert symbol_offset < 1 << 23
        pool += name.encode() + b'\0'
        words += struct.pack('<I', (symbol_offset << 9) | owners[owner])
        import_index = len(info['imports']) + index
        pointer = (1 << 62) | import_index | ((1 if index+1 < len(targets) else 0) << 51)
        pointer |= (1 << 63) | (auth['discriminator'] << 32) | (int(auth['addressDiversity']) << 48) | (auth['key'] << 49)
        struct.pack_into('<Q', b, insert_fo + index*8, pointer)
        new_map[target] = insert_va + index*8
        routes.append({'originalSlotVA': target, 'symbol': name, 'originalOwner': owner,
                       'dependency': deps[owners[owner]-1], 'ordinal': owners[owner],
                       'strong': True, 'newSlotVA': new_map[target], 'labels': labels,
                       'auth': auth['auth'], 'key': 'DA', 'addressDiversity': auth['addressDiversity'],
                       'discriminator': hex(auth['discriminator']), 'pointeeKind': auth['pointeeKind'],
                       'authEvidence': auth['evidence'], 'rawOriginalCacheWord': auth_contracts[target]['rawCacheWord']})
    struct.pack_into('<Q', b, predecessor['fileoff'], predecessor['word'] | (delta << 51))
    struct.pack_into('<Q', b, got['command']+40, got['size']+nbytes)
    relocated = scanner.RelativeMetadata(raw, b)
    relocated.singletons(); relocated.conformances(new_map); relocated.reflection(new_map)
    assert not relocated.unresolved
    b = bytearray(relocated.apply())
    struct.pack_into('<I', prefix, 12, len(prefix)+len(words))
    struct.pack_into('<I', prefix, 16, len(info['imports'])+len(targets))
    new_blob = prefix + words + pool
    code_sign = next(at for cmd, at, n in commands(b) if cmd == 0x1d)
    signature_offset = struct.unpack_from('<I', b, code_sign+8)[0]
    assert signature_offset >= info['data']+info['size']
    b = b[:signature_offset]
    offset = len(b)
    b += new_blob
    old_end = 32 + struct.unpack_from('<I', b, 20)[0]
    old_commands = list(commands(b))
    for cmd, at, n in old_commands:
        if cmd == 0x80000034:
            struct.pack_into('<II', b, at+8, offset, len(new_blob))
        if cmd == 0x19 and bytes(b[at+8:at+24]).split(b'\0')[0] == b'__LINKEDIT':
            fileoff = struct.unpack_from('<Q', b, at+40)[0]
            size = len(b)-fileoff
            struct.pack_into('<Q', b, at+32, (size+0x3fff) & ~0x3fff)
            struct.pack_into('<Q', b, at+48, size)
    kept = [bytes(b[at:at+n]) for cmd, at, n in old_commands if cmd != 0x1d]
    joined = b''.join(kept)
    b[32:old_end] = joined + bytes(old_end-32-len(joined))
    struct.pack_into('<II', b, 16, len(kept), len(joined))
    target = out / 'VZ27.relative-data.ios.dylib'
    target.write_bytes(b)
    logs = []
    for label, argv in [
        ('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', str(target)]),
        ('strict', ['codesign', '--verify', '--strict', str(target)]),
        ('dyld', ['xcrun', 'dyld_info', '-validate_only', '-imports', '-linked_dylibs', str(target)]),
        ('signature', ['codesign', '-d', '--verbose=4', str(target)]),
    ]:
        result = subprocess.run(argv, capture_output=True, timeout=60)
        logs.append({'label': label, 'argv': argv, 'exit': result.returncode,
                     'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
        (out / 'commands.json').write_text(json.dumps(logs, indent=2)+'\n')
        assert result.returncode == 0, result.stderr.decode()
    final = target.read_bytes()
    after = {row['fileoff']: row for row in chain_entries(final)}
    assert len(after) == len(before_sites)+len(targets)
    for row in before_sites:
        change = (delta << 51) if row['fileoff'] == predecessor['fileoff'] else 0
        assert after[row['fileoff']]['word'] == row['word'] | change
    for before, after_import in zip(info['imports'], imports(final)['imports'][:len(info['imports'])]):
        assert {k: v for k, v in before.items() if k != 'command'} == {k: v for k, v in after_import.items() if k != 'command'}
    for row in routes:
        imported = imports(final)['imports'][len(info['imports'])+routes.index(row)]
        assert imported['name'] == row['symbol'] and imported['ordinal'] == row['ordinal'] and not imported['weak']
        got_site = after[insert_fo + routes.index(row)*8]
        assert got_site['auth'] and got_site['bind'] and ((got_site['word']>>49)&3)==2
        assert ((got_site['word']>>48)&1)==1 and ((got_site['word']>>32)&65535)==int(row['discriminator'],16)
    code = []
    for seg in segments(original):
        for section in seg['sections']:
            if section['flags'] & 0x80000000 and section['size']:
                at, size = section['fileoff'], section['size']
                assert original[at:at+size] == final[at:at+size]
                code.append({'segment': seg['name'], 'section': section['name'], 'bytes': size,
                             'sha256': sha(final[at:at+size])})
    assert all(sha(pathlib.Path(row['path']).read_bytes()) == row['sha256'] for row in records)
    result = {'candidate': str(target), 'bytes': len(final), 'sha256': sha(final),
              'cdhash': re.search(r'CDHash=([0-9a-f]{40})', logs[-1]['stderr'])[1],
              'inputs': records, 'originalExternalEdges': len(audit.unresolved),
              'newStrongDataImports': routes, 'relativePointers': relocated.rows,
              'unresolvedSelectedSchemas': relocated.unresolved,
              'instructionSectionsUnchanged': code, 'originalImportRowsAndPACPreserved': True,
              'soleExistingChainNextExtension': hex(predecessor['fileoff']),
              'sourceOtherWeakFlatSemanticsRetained': True,
              'compiledOrSignedOnly': True, 'nativeLoaded': False, 'productionChanged': False,
              'completeMetadataSchema': False, 'completeStrongVZClosure': False,
              'seventeenProtocolRequirementAuthSlotsRestoredFromOriginalCache': True,
              'actualVZRequirementOrWitnessCalls': 0,
              'completeMacOS27Backend': False}
    (out / 'candidate.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('sha256', 'originalExternalEdges', 'completeStrongVZClosure')}, indent=2))


if __name__ == '__main__':
    main()
