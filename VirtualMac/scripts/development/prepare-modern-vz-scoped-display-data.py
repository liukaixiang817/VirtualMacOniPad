#!/usr/bin/env python3
"""Prepare an inert two-import display delta, with no signing/loading/execution."""
import argparse
import hashlib
import json
import pathlib
import stat
import struct
import sys

sys.dont_write_bytecode = True
from vz_import_addend_image import commands, segments, imports, chain_entries, cstring, export_trie

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE_CANDIDATE = N / 'vz-six-import-consumer-contract-v1/scoped-route-build-v1/candidate.json'
DISPLAY_CANDIDATE = N / 'vz-scoped-display-routes-build-v1/candidate.json'
CONTRACT = N / 'vz-skylight-consumer-contract-v1/build-v3/contract.json'
UPSTREAM_FREEZE = N / 'vz-six-import-consumer-contract-v1/independent-review-v1/freeze.json'
DISPLAY_FREEZE = N / 'vz-scoped-display-routes-build-v1/freeze.json'
ROUTES = {311: '_SLMainDisplayID', 313: '_SLSCopyDisplayInfoDictionary'}
PRIVATE_PATH = '@loader_path/VM27ScopedDisplayRoutes.dylib'
DYLIB_COMMANDS = (12, 0x80000018, 0x8000001f, 0x80000023)
COMPACT_ORDINALS = (1, 2, 3, 6, 7, 11, 32, 33)
SOURCE_SHA = '6611e8a3d2e37db08e9e1c0b42a3c0d3d7e3a328f808b0d4f3dc982350b6a28a'
DISPLAY_CANDIDATE_SHA = '322204399befa3ebeab277b7e2c614523dd68db3735481a76a70a2b4d9f77558'
CONTRACT_SHA = 'f1fcabba053f2e1331b8750883170b939fed06dc5c026cd9393abfe7d134d86d'


def pairs(rows):
    result = {}
    for key, value in rows:
        assert key not in result, 'duplicate JSON key'
        result[key] = value
    return result


def read(path):
    data = path.read_bytes()
    assert len(data) < 32 * 1024 * 1024
    return json.loads(data, object_pairs_hook=pairs)


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    assert not path.exists()
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def check_freeze(path):
    frozen = read(path)
    assert frozen.get('count', frozen.get('filesCount', len(frozen['files']))) == len(frozen['files'])
    for item in frozen['files']:
        assert pin(pathlib.Path(item['path'])) == item


def dependencies(data):
    result = []
    for command, at, length in commands(data):
        if command in DYLIB_COMMANDS:
            offset = struct.unpack_from('<I', data, at + 8)[0]
            result.append(dict(ordinal=len(result) + 1, kind=command,
                               path=cstring(data, at + offset, at + length),
                               metadata=list(struct.unpack_from('<3I', data, at + 12))))
    return result


def first_section(data):
    return min(section['fileoff'] for segment in segments(data) for section in segment['sections']
               if section['fileoff'] and section['size'] and section['flags'] & 255 not in (1, 12, 18))


def compacted_command(data, at, length, ordinal):
    record = bytearray(data[at:at + length])
    offset = struct.unpack_from('<I', record, 8)[0]
    path = cstring(record, offset, length)
    minimum = (offset + len(path.encode()) + 1 + 7) & ~7
    assert minimum < length and not any(record[minimum:]), 'only existing zero padding may be removed'
    struct.pack_into('<I', record, 4, minimum)
    return bytes(record[:minimum]), dict(ordinal=ordinal, path=path,
                                        beforeBytes=length, afterBytes=minimum,
                                        removedPaddingHex=data[at + minimum:at + length].hex())


def derive(source):
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA
    assert len(dependencies(source)) == 55
    old_imports = imports(source)['imports']
    assert len(old_imports) == 1056
    for index, name in ROUTES.items():
        row = old_imports[index]
        assert row['name'] == name and row['ordinal'] == 53 and row['weak'] is False and row['addend'] == 0
    new = bytearray(source)
    packed, compactions = bytearray(), []
    ordinal = 0
    for command, at, length in commands(source):
        if command in DYLIB_COMMANDS:
            ordinal += 1
            if ordinal in COMPACT_ORDINALS:
                record, detail = compacted_command(source, at, length, ordinal)
                packed += record
                compactions.append(detail)
                continue
        packed += source[at:at + length]
    name = PRIVATE_PATH.encode() + b'\0'
    needed = (24 + len(name) + 7) & ~7
    assert needed == 72 and sum(r['beforeBytes'] - r['afterBytes'] for r in compactions) == needed
    command = struct.pack('<6I', 12, needed, 24, 0, 0x10000, 0x10000) + name
    packed += command + bytes(needed - len(command))
    count, size = struct.unpack_from('<II', source, 16)
    assert len(packed) == size and 32 + size == first_section(source)
    new[32:32 + size] = packed
    struct.pack_into('<I', new, 16, count + 1)
    for index in ROUTES:
        at = old_imports[index]['command']
        before = struct.unpack_from('<I', source, at)[0]
        assert before & 255 == 53
        struct.pack_into('<I', new, at, (before & ~255) | 56)
    return bytes(new), compactions


def preserve(old, new):
    expected, compactions = derive(old)
    assert new == expected, 'bytes outside the exact two-route delta changed'
    old_cs, new_cs = list(commands(old)), list(commands(new))
    assert len(new_cs) == len(old_cs) + 1
    assert struct.unpack_from('<I', old, 20) == struct.unpack_from('<I', new, 20)
    assert len(old) == len(new) and first_section(old) == first_section(new) == 9584
    ordinal = 0
    for (oc, oa, oz), (nc, na, nz) in zip(old_cs, new_cs[:-1]):
        assert oc == nc
        if oc in DYLIB_COMMANDS:
            ordinal += 1
        if oc in DYLIB_COMMANDS and ordinal in COMPACT_ORDINALS:
            assert new[na:na + nz] == compacted_command(old, oa, oz, ordinal)[0]
        else:
            assert old[oa:oa + oz] == new[na:na + nz], 'an original non-padding load command changed'
    assert dependencies(new)[:55] == dependencies(old)
    assert dependencies(new)[55] == dict(ordinal=56, kind=12, path=PRIVATE_PATH, metadata=[0, 0x10000, 0x10000])
    before, after = imports(old), imports(new)
    assert before['data'] == after['data'] and before['size'] == after['size'] and before['header'] == after['header']
    changed = []
    for a, b in zip(before['imports'], after['imports']):
        want = dict(a)
        if a['index'] in ROUTES:
            want['ordinal'] = 56
            changed.append(a['command'])
        assert want == b, 'an unselected import or addend/weak/name/offset changed'
    assert changed == [4164712, 4164728]
    chains_before, chains_after = list(chain_entries(old)), list(chain_entries(new))
    assert len(chains_before) == 26993 and chains_before == chains_after
    assert all(sum(row['bind'] and row['import_index'] == index for row in chains_after) == 1 for index in ROUTES)
    section_pins = []
    for segment in segments(old):
        for section in segment['sections']:
            off, size = section['fileoff'], section['size']
            if off and size and section['flags'] & 255 not in (1, 12, 18):
                assert old[off:off + size] == new[off:off + size]
                section_pins.append(dict(segment=segment['name'], section=section['name'], fileoff=off, bytes=size,
                                         sha256=hashlib.sha256(old[off:off + size]).hexdigest()))
    table_pins = []
    signature_pins = []
    for command, at, length in old_cs:
        if command == 2:
            symoff, count, stroff, size = struct.unpack_from('<4I', old, at + 8)
            for name, offset, size in [('nlist', symoff, count * 16), ('strings', stroff, size)]:
                assert old[offset:offset + size] == new[offset:offset + size]
                table_pins.append(dict(name=name, fileoff=offset, bytes=size, sha256=hashlib.sha256(old[offset:offset + size]).hexdigest()))
        if command == 0x1d:
            offset, size = struct.unpack_from('<II', old, at + 8)
            assert old[offset:offset + size] == new[offset:offset + size]
            signature_pins.append(dict(fileoff=offset, bytes=size, sha256=hashlib.sha256(old[offset:offset + size]).hexdigest()))
    assert len(table_pins) == 2 and len(signature_pins) == 1
    differences = [i for i, (a, b) in enumerate(zip(old, new)) if a != b]
    assert all(i == 16 or 32 <= i < 9584 or i in changed for i in differences)
    assert [i for i in differences if i >= 9584] == changed
    pending = [row for row in after['imports'][304:318] if row['index'] not in ROUTES]
    assert len(pending) == 12 and all(row['ordinal'] == 53 and not row['weak'] and row['addend'] == 0 for row in pending)
    return dict(compactions=compactions, changedImportFileOffsets=changed, changedBytes=len(differences),
                changedHeaderBytes=sum(i < 9584 for i in differences), sectionPins=section_pins,
                symbolTablePins=table_pins, oldSignaturePayloadPreserved=signature_pins,
                chainCount=26993, bindCount=sum(row['bind'] for row in chains_after),
                rebaseCount=sum(not row['bind'] for row in chains_after),
                allChainWordsAndPACPreserved=True, allFileBackedSectionsPreserved=True,
                allNlistAndStringTableBytesPreserved=True, allAddendsWeakBitsAndNamesPreserved=True,
                allOriginalNonPaddingLoadCommandsPreserved=True, allPrevious55DependencyIdentitiesPreserved=True,
                allRemaining12SkyLightStrongImportsUnchanged=True,
                remainingSkyLightImports=[{k: row[k] for k in ('index', 'name', 'ordinal', 'weak', 'addend')} for row in pending])


def provider_exports(data):
    for command, at, length in commands(data):
        if command == 0x80000033:
            offset, size = struct.unpack_from('<II', data, at + 8)
            return export_trie(data[offset:offset + size])
        if command == 0x80000022:
            offset, size = struct.unpack_from('<II', data, at + 40)
            return export_trie(data[offset:offset + size])
    raise AssertionError('provider export trie missing')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    assert pin(DISPLAY_CANDIDATE)['sha256'] == DISPLAY_CANDIDATE_SHA
    assert pin(CONTRACT)['sha256'] == CONTRACT_SHA
    check_freeze(UPSTREAM_FREEZE)
    check_freeze(DISPLAY_FREEZE)
    source_candidate, display_candidate, contract = read(SOURCE_CANDIDATE), read(DISPLAY_CANDIDATE), read(CONTRACT)
    source = pathlib.Path(source_candidate['binary']['path'])
    assert pin(source) == source_candidate['binary'] and pin(source)['sha256'] == SOURCE_SHA
    assert source_candidate['full27'] is False and source_candidate['loaded'] is False
    provider = pathlib.Path(next(row['path'] for row in display_candidate['files'] if row['name'] == 'VM27ScopedDisplayRoutes.dylib'))
    assert pin(provider) == {k: next(row[k] for row in display_candidate['files'] if row['name'] == provider.name) for k in ('path', 'bytes', 'sha256')}
    exports = provider_exports(provider.read_bytes())
    assert sorted(row['symbol'] for row in exports) == sorted(ROUTES.values()) and all(row['flags'] == 0 for row in exports)
    assert contract['originalVZUUID'] == '418efc4809d93606918eb6f95baeffdc' and contract['originalSegments'] == 6
    genuine = {row['index']: row for row in contract['imports14']}
    assert len(genuine) == 14 and all(genuine[index]['symbol'] == name and genuine[index]['actualConsumerCalls'] for index, name in ROUTES.items())
    old = source.read_bytes()
    new, _ = derive(old)
    proof = preserve(old, new)
    out.mkdir()
    binary = out / 'VZ27.scoped-display-routes.inert.macho-data'
    binary.write_bytes(new)
    binary.chmod(0o600)
    assert stat.S_IMODE(binary.stat().st_mode) == 0o600
    inputs = [pin(path) for path in (SOURCE_CANDIDATE, source, DISPLAY_CANDIDATE, provider, CONTRACT,
                                    UPSTREAM_FREEZE, DISPLAY_FREEZE, pathlib.Path(__file__).resolve(),
                                    pathlib.Path(__file__).with_name('vz_import_addend_image.py'),
                                    R / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py')]
    save(out / 'inputs.json', inputs)
    save(out / 'static-diff.json', proof)
    retained_dependencies = dependencies(old)
    provider_dependencies = dependencies(provider.read_bytes())
    save(out / 'dependency-scope.json', dict(
        absoluteSystemDependenciesRetainedWithoutRuntimeResolution=[row for row in retained_dependencies if row['path'].startswith('/')],
        appPrivateDependenciesRetainedWithoutRuntimeResolution=[row for row in retained_dependencies if row['path'].startswith('@')],
        displayProviderDependencies=provider_dependencies,
        displayProviderRuntimeFramework='/System/Library/Frameworks/QuartzCore.framework/QuartzCore',
        displayProviderRequiresPinnedHostUUID='046338bf09cf3414bc9331296b97eb2d',
        addedRoute={'ordinal': 56, 'path': PRIVATE_PATH},
        remainingStrongSkyLightOwner=retained_dependencies[52],
        sourceContainsMacOnlyAbsoluteDependencyPaths=True, completeRuntimeClosureResolved=False,
        originalVZLoaded=False, fullSkyLight=False, full27=False))
    routes = []
    for index, name in ROUTES.items():
        row = imports(old)['imports'][index]
        routes.append(dict(index=index, symbol=name, beforeOrdinal=53, afterOrdinal=56,
                           weak=False, addend=0, importRecordOffset=row['command'],
                           typedABI='uint32_t(void)' if index == 311 else 'CFDictionaryRef(uint32_t) Copy +1',
                           genuineOriginalVZConsumerPCs=[call['originalPC'] for call in genuine[index]['actualConsumerCalls']],
                           originalConsumerExecuted=False))
    save(out / 'candidate.json', dict(
        schema='VM27 inert VZ two scoped display import delta v1', source=pin(source), binary=pin(binary),
        modeOctal='0600', sourceCandidate=pin(SOURCE_CANDIDATE), displayProviderCandidate=pin(DISPLAY_CANDIDATE),
        requiredProvider=pin(provider), onlyProviderExports=sorted(ROUTES.values()), routes=routes,
        staticDiff=pin(out / 'static-diff.json'), dependencyScope=pin(out / 'dependency-scope.json'),
        originalSkyLightConsumerContract=pin(CONTRACT),
        originalInstructionAndDataBytesPreserved=True, originalNlistPreserved=True,
        originalLCMAINAndPlatformBytesPreserved=True, originalChainedWordsAndPACPreserved=True,
        originalSignaturePayloadAndCommandPreserved=True, signatureRegenerated=False,
        signatureIsNotCurrentForModifiedData=True, executableArtifact=False, signingCalls=0,
        necessaryReexportWrapper=False, addedStrongPrivateOrdinal=56,
        remaining12SkyLightStrongImportsUnresolved=True, fullSkyLight=False,
        originalConsumerValidationPending=source_candidate['originalConsumerValidationPending'],
        originalConsumerExecuted=False, originalVZLoaded=False, originalVZCalls=0,
        originalVMMExecuted=False, guestInstructions=0, full27=False, deviceOperations=0, systemModified=False))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), data=pin(binary),
                          changedChainedImportOrdinals=2, changedChainWords=0, fullSkyLight=False,
                          full27=False, deviceOperations=0)))


if __name__ == '__main__':
    main()
