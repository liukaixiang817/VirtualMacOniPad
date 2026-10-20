#!/usr/bin/env python3
"""Route the two original consumers' one strong loader dependency as inert data.

The existing dependency ordinal is retained. Only its name bytes change; no
instruction, chained pointer, PAC field, weak flag or original import changes.
The outputs are mode 0600 and are never signed, loaded, deployed or executed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import stat
import struct
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0, str(R / 'VirtualMac/scripts/development'))
from vz_import_addend_image import commands, segments, imports, chain_entries, cstring, export_trie

AUDIT = N / 'softlinking-original-consumer-audit-v2/audit.json'
BUILD = N / 'softlinking-original-consumer-routes-v1/build-v2'
PRIVATE = '@loader_path/VM27ScopedSoftLinking.dylib'
DYLIB_COMMANDS = (12, 0x80000018, 0x8000001f, 0x80000023)
SOURCES = [
    dict(role='VMM', path=N / 'vmm-contiguousarray-reserve-contract-v1/inert-routes-v2/VirtualMachine27.twenty-six-strong.macos.unsigned.data',
         sha256='bb38be75b1a676d9d937f703b370da8e5530b94052d3ee6a0f041a4f2a72a136',
         bytes=5195312, ordinal=36, index=841, importOffset=5053128,
         dependencies=53, importCount=1203, strongCount=1064,
         name='/System/Library/PrivateFrameworks/SoftLinking.framework/Versions/A/SoftLinking'),
    dict(role='VZ', path=N / 'vz-scoped-display-import-data-build-v1/VZ27.scoped-display-routes.inert.macho-data',
         sha256='dbf433017bab9ee6899b832a2d29cb15f54014400d4616bf0a14bce091741849',
         bytes=4212080, ordinal=33, index=494, importOffset=4166176,
         dependencies=56, importCount=1056, strongCount=None,
         name='/System/Library/PrivateFrameworks/SoftLinking.framework/SoftLinking'),
]


def pin(path):
    assert path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def dependencies(raw):
    rows = []
    for command, at, size in commands(raw):
        if command in DYLIB_COMMANDS:
            offset = struct.unpack_from('<I', raw, at + 8)[0]
            rows.append(dict(ordinal=len(rows) + 1, command=command, at=at, size=size,
                             nameOffset=offset, path=cstring(raw, at + offset, at + size),
                             metadata=list(struct.unpack_from('<3I', raw, at + 12))))
    return rows


def derive(original, source):
    assert len(original) == source['bytes'] and hashlib.sha256(original).hexdigest() == source['sha256']
    deps = dependencies(original)
    assert len(deps) == source['dependencies']
    selected = deps[source['ordinal'] - 1]
    assert selected['path'] == source['name'] and selected['command'] == 12
    assert selected['metadata'] == [2, 4718592, 65536]
    rows = imports(original)['imports']
    assert len(rows) == source['importCount']
    owners = [row for row in rows if row['ordinal'] == source['ordinal']]
    assert owners == [rows[source['index']]]
    row = owners[0]
    assert row['name'] == '__sl_dlopen' and row['weak'] is False and row['addend'] == 0
    assert row['command'] == source['importOffset']
    if source['strongCount'] is not None:
        assert sum(not row['weak'] for row in rows) == source['strongCount']
    at, end = selected['at'] + selected['nameOffset'], selected['at'] + selected['size']
    name = PRIVATE.encode() + b'\0'
    assert len(name) <= end - at
    new = bytearray(original)
    new[at:end] = name + bytes(end - at - len(name))
    return bytes(new), dict(dependency=selected, nameBytesRange=[at, end], selectedStrongImport=row)


def verify(original, changed, source):
    expected, detail = derive(original, source)
    assert changed == expected, 'unexpected byte change beyond the dependency name'
    assert list(commands(original)) == list(commands(changed))
    before, after = dependencies(original), dependencies(changed)
    for left, right in zip(before, after):
        wanted = dict(left)
        if left['ordinal'] == source['ordinal']:
            wanted['path'] = PRIVATE
        assert right == wanted
    assert imports(original) == imports(changed)
    # This reader's enumerator supports the VZ chain format only. For VMM,
    # exact whole-file equality outside the path proves pointer preservation
    # without pretending that the different chain format was enumerated.
    chains = list(chain_entries(original)) if source['role'] == 'VZ' else None
    if chains is not None:
        assert chains == list(chain_entries(changed))
    preserved = []
    for segment in segments(original):
        for section in segment['sections']:
            at, size = section['fileoff'], section['size']
            if at and size and section['flags'] & 255 not in (1, 12, 18):
                assert original[at:at + size] == changed[at:at + size]
                preserved.append(dict(segment=segment['name'], section=section['name'], at=at,
                                      bytes=size, sha256=hashlib.sha256(original[at:at + size]).hexdigest()))
    tables = []
    for command, at, size in commands(original):
        if command == 2:
            symoff, count, stroff, strsize = struct.unpack_from('<4I', original, at + 8)
            tables.extend([('nlist', symoff, count * 16), ('strings', stroff, strsize)])
        elif command == 0x1d:
            sigoff, sigsize = struct.unpack_from('<II', original, at + 8)
            tables.append(('existing-signature-payload', sigoff, sigsize))
    for name, at, size in tables:
        assert original[at:at + size] == changed[at:at + size]
    diffs = [at for at, (left, right) in enumerate(zip(original, changed)) if left != right]
    start, end = detail['nameBytesRange']
    assert diffs and all(start <= at < end for at in diffs)
    return dict(**detail, changedByteCount=len(diffs), changedOffsets=diffs,
                totalImports=len(imports(changed)['imports']),
                enumeratedChainWords=len(chains) if chains is not None else None,
                VMMChainPreservationByExactByteDelta=source['role'] == 'VMM',
                allChainWordsPACImportsUnchanged=True, allSectionsUnchanged=True,
                allNlistStringsAndSignaturePayloadUnchanged=True, sections=preserved)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists() and not out.is_symlink()
    assert pin(AUDIT)['sha256'] == '690e58f47a9b9b5e5d9b3cfb9787fd943d7f977eb3005df67dea82644809767f'
    audit = read(AUDIT)
    assert audit['passed'] is True and audit['absoluteCallerPCResolutionGapClosedForTheseFourSitesOnly'] is True
    assert audit['originalVMMExecuted'] is False and audit['full27'] is False
    assert pin(BUILD / 'candidate.json')['sha256'] == '270b3f51f6d5439ae5bd587a14a5050cc3dd2d09c7a655731914f3cd348bd4be'
    candidate = read(BUILD / 'candidate.json')
    assert candidate['ABICompatibilityVersion'] == 65536
    provider = next(row for row in next(row for row in candidate['roles'] if row['role'] == 'ios')['files'] if row['label'] == 'provider')
    library = Path(provider['path'])
    assert pin(library) == {key: provider[key] for key in ('path', 'bytes', 'sha256')}
    raw = library.read_bytes()
    id_at, id_size = next((at, size) for cmd, at, size in commands(raw) if cmd == 13)
    assert struct.unpack_from('<II', raw, id_at + 16) == (65536, 65536)
    assert cstring(raw, id_at + struct.unpack_from('<I', raw, id_at + 8)[0], id_at + id_size) == PRIVATE
    export_range = next(struct.unpack_from('<II', raw, at + (8 if cmd == 0x80000033 else 40))
                        for cmd, at, size in commands(raw) if cmd in (0x80000033, 0x80000022))
    start, size = export_range
    exports = export_trie(raw[start:start + size])
    assert len(exports) == 1 and exports[0]['symbol'] == '__sl_dlopen' and exports[0]['flags'] == 0
    out.mkdir(parents=True, mode=0o700)
    results = []
    for source in SOURCES:
        old = source['path'].read_bytes()
        new, detail = derive(old, source)
        proof = verify(old, new, source)
        path = out / (source['role'] + '27.scoped-softlinking.inert.macho-data')
        path.write_bytes(new)
        path.chmod(0o600)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        results.append(dict(role=source['role'], source=pin(source['path']), binary=pin(path), mode='0600',
            proof=proof, originalStrongOrdinalPreserved=source['ordinal'], importCountUnchanged=True,
            providerMinimumVersionSatisfiedStatically=True, originalConsumerExecuted=False,
            originalTargetFrameworkDependenciesValidated=False))
    result = dict(schema='VM27 two original SoftLinking consumer dependency routes v1', results=results,
        audit=pin(AUDIT), providerCandidate=pin(BUILD / 'candidate.json'), requiredProvider=pin(library),
        script=pin(Path(__file__)), exactDelta='only dependency name bytes; every ordinal and pointer preserved',
        providerOnlyCoversOneAuditedExport=True, previousTwentySixVMMRoutesPreserved=True,
        previousVZLibcAndTwoDisplayRoutesPreserved=True, inputsNeverExecuted=True,
        signingCalls=0, deviceOperations=0, originalVMMExecuted=False, originalVZLoaded=False,
        guestInstructions=0, full27Backend=False, productionModified=False, iPadOSModified=False)
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), changes=[dict(role=r['role'], bytes=r['proof']['changedByteCount']) for r in results], full27=False)))


if __name__ == '__main__':
    main()
