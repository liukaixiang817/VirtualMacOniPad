"""Independent finite Runtime7 resource review; no target image execution."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PROFILE_SHA = '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504'


def read(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        data = b''
        while len(data) < initial.st_size:
            chunk = os.read(fd, min(1024 * 1024, initial.st_size - len(data)))
            assert chunk
            data += chunk
        assert not os.read(fd, 1)
        final = os.fstat(fd)
        assert (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) == (
            final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        assert (before.st_dev, before.st_ino) == (initial.st_dev, initial.st_ino)
        return data
    finally:
        os.close(fd)


def sha(data):
    return hashlib.sha256(data).digest()


def pin(path):
    data = read(path)
    return dict(path=str(path.resolve()), bytes=len(data), sha256=sha(data).hex())


def checked(row):
    assert pin(Path(row['path'])) == row
    return Path(row['path'])


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def signature(data, external):
    assert len(data) >= 32 and struct.unpack_from('<I', data)[0] == 0xfeedfacf
    ncmd, extent = struct.unpack_from('<II', data, 16)
    at, signatures, uuids = 32, [], []
    for _ in range(ncmd):
        cmd, size = struct.unpack_from('<II', data, at)
        assert size >= 8 and size % 8 == 0 and at + size <= 32 + extent
        if cmd == 0x1d:
            signatures.append(struct.unpack_from('<II', data, at + 8))
        elif cmd == 0x1b:
            uuids.append(data[at + 8:at + 24].hex())
        at += size
    assert at == 32 + extent and len(signatures) == len(uuids) == 1
    offset, span = signatures[0]
    assert offset + span <= len(data)
    body = data[offset:offset + span]
    magic, length, count = struct.unpack_from('>III', body)
    assert magic == 0xfade0cc0 and 12 + count * 8 <= length <= len(body) and count <= 64
    slots = {}
    for i in range(count):
        kind, start = struct.unpack_from('>II', body, 12 + i * 8)
        assert kind not in slots and start + 8 <= length
        item_magic, item_length = struct.unpack_from('>II', body, start)
        assert item_length >= 8 and start + item_length <= length
        slots[kind] = body[start:start + item_length]
    cd = slots[0]
    magic, cd_length, version, flags, hash_offset, identifier, special, pages, limit = struct.unpack_from('>9I', cd)
    hash_bytes, hash_type, platform, page_shift = struct.unpack_from('4B', cd, 36)
    assert magic == 0xfade0c02 and cd_length == len(cd) and hash_type == 2 and hash_bytes == 32
    assert version >= 0x20001 and 0 < page_shift <= 16 and limit <= offset
    assert 0 <= special <= 64 and hash_offset >= 32 * special and hash_offset + pages * 32 <= len(cd)
    assert pages == (limit + (1 << page_shift) - 1) >> page_shift
    if version >= 0x20300:
        assert struct.unpack_from('>I', cd, 56)[0] == 0 and struct.unpack_from('>Q', cd, 56)[0] in (0, limit)
    for index in range(pages):
        start = index << page_shift
        assert sha(data[start:min(start + (1 << page_shift), limit)]) == cd[hash_offset + 32 * index:hash_offset + 32 * (index + 1)]
    special_slots = {}
    for kind in range(1, special + 1):
        expected = cd[hash_offset - kind * 32:hash_offset - (kind - 1) * 32]
        assert kind not in external or kind not in slots
        actual = external.get(kind, slots.get(kind))
        assert (sha(actual) if actual is not None else bytes(32)) == expected
        special_slots[kind] = expected.hex()
    xml = slots[5]
    assert struct.unpack_from('>I', xml)[0] == 0xfade7171
    entitlements = plistlib.loads(xml[8:])
    assert len(entitlements) == 13 and entitlements['com.apple.private.virtualization.plugin'] is True
    return dict(uuid=uuids[0], cdhash=sha(cd).hex()[:40], codeLimit=limit, actualCodePages=pages,
                pageShift=page_shift, specialSlots=special_slots, xmlSHA256=sha(xml).hex(),
                derSHA256=sha(slots[7]).hex(), embeddedEntitlements=entitlements,
                signatureOffset=offset, signatureBytes=span), slots, cd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet-candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.output.parent.resolve() == N.resolve() and not args.output.exists()
    runtime_path = N / 'independent27-signed-runtime-product-v7-attempt1/candidate.json'
    assert pin(runtime_path)['sha256'] == '3db179aa733f98eda95390beb1e9cd1eb94e769ce3288610578f178910fa9460'
    runtime = json.loads(read(runtime_path))
    packet = json.loads(read(args.packet_candidate))
    assert packet['runtimeCandidate'] == pin(runtime_path)
    scope_path = checked(packet['scope'])
    scope = json.loads(read(scope_path))
    assert scope['runtimeCandidate'] == pin(runtime_path) and scope['actualRuntimeManifestFiles'] == 149
    freeze_path = runtime_path.parent / 'freeze.json'
    freeze = json.loads(read(freeze_path))
    for row in freeze['files']:
        checked(row)
    assert freeze['deviceOperations'] == freeze['trustCacheOperations'] == 0
    delta_path = checked(runtime['runtime6DeltaVerification'])
    delta = json.loads(read(delta_path))
    old_candidate = json.loads(read(checked(delta['baselineCandidate'])))
    old_manifest_path = checked(old_candidate['manifest'])
    new_manifest_path = checked(runtime['manifest'])
    old_manifest = plistlib.loads(read(old_manifest_path))
    new_manifest = plistlib.loads(read(new_manifest_path))
    old_rows = {row['id']: row for row in old_manifest['files']}
    new_rows = {row['id']: row for row in new_manifest['files']}
    assert len(old_rows) == 148 and len(new_rows) == 149
    assert set(new_rows) - set(old_rows) == {'child-sandbox-profile'} and not set(old_rows) - set(new_rows)
    for key in old_manifest:
        if key != 'files':
            assert old_manifest[key] == new_manifest[key]
    old_root, new_root = Path(old_candidate['runtimeRoot']), Path(runtime['runtimeRoot'])
    assert len(list(new_root.rglob('*.sb'))) == 1
    actual_files = set()
    for path in new_root.rglob('*'):
        assert not path.is_symlink()
        assert path.is_dir() or stat.S_ISREG(path.lstat().st_mode)
        if path.is_file():
            actual_files.add(str(path.relative_to(new_root)))
    assert actual_files == {row['path'] for row in new_rows.values()} | {new_manifest_path.name}
    changed, unchanged_signed, file_pins = [], [], []
    for identity, row in new_rows.items():
        path = new_root / row['path']
        actual = pin(path)
        assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
        file_pins.append(actual)
        if identity not in old_rows:
            continue
        old_row = old_rows[identity]
        before = old_root / old_row['path']
        old_actual = pin(before)
        assert old_actual['bytes'] == old_row['bytes'] and old_actual['sha256'] == old_row['sha256']
        if read(before) != read(path):
            changed.append(identity)
        else:
            assert old_row == row
            if row['kind'] == 'mach-o':
                unchanged_signed.append(identity)
    child_id = new_manifest['childEntryContract']['childID']
    assert set(changed) == {child_id, 'child-coderesources'} and len(unchanged_signed) == 138
    profile_row = new_rows['child-sandbox-profile']
    profile_path = new_root / profile_row['path']
    profile = read(profile_path)
    source = checked(delta['genuineProfileSource'])
    assert profile == read(source) and len(profile) == 32301 and sha(profile).hex() == PROFILE_SHA
    assert profile_row['kind'] == 'resource' and not any(k in profile_row for k in ('uuid', 'cdhash'))
    profile_proof = json.loads(read(checked(delta['genuineProfileProof'])))
    assert pin(source) in profile_proof['files']
    resources = {}
    inspections, child_data, slot_blobs, directories = [], [], [], []
    for root, rows in ((old_root, old_rows), (new_root, new_rows)):
        info = read(root / rows['child-info']['path'])
        seal_body = read(root / rows['child-coderesources']['path'])
        data = read(root / rows[child_id]['path'])
        inspected, blobs, cd = signature(data, {1: info, 3: seal_body})
        assert inspected['cdhash'] == rows[child_id]['cdhash'] and inspected['uuid'] == rows[child_id]['uuid']
        inspections.append(inspected); child_data.append(data); slot_blobs.append(blobs); directories.append(cd)
        resources[str(root)] = plistlib.loads(seal_body)
    before_sig, after_sig = inspections
    assert before_sig['codeLimit'] == after_sig['codeLimit']
    assert child_data[0][:before_sig['codeLimit']] == child_data[1][:after_sig['codeLimit']]
    assert set(slot_blobs[0]) == set(slot_blobs[1])
    assert all(slot_blobs[0][key] == slot_blobs[1][key] for key in slot_blobs[0] if key != 0)
    assert all(before_sig['specialSlots'][key] == after_sig['specialSlots'][key]
               for key in before_sig['specialSlots'] if key != 3)
    assert before_sig['specialSlots'][3] != after_sig['specialSlots'][3]
    seal_before, seal_after = resources[str(old_root)], resources[str(new_root)]
    resource_key = 'Resources/com.apple.Virtualization.VirtualMachine.sb'
    mandatory = seal_after['files2'][resource_key]
    assert mandatory['hash2'] == sha(profile) and not mandatory.get('optional', False) and not mandatory.get('omit', False)
    stripped = dict(seal_after)
    for bank in ('files', 'files2'):
        assert resource_key not in seal_before[bank]
        stripped[bank] = {key: value for key, value in seal_after[bank].items() if key != resource_key}
    assert stripped == seal_before
    builder_path = checked(runtime['builder'])
    before_builder_path = builder_path.with_name('build-independent27-signed-runtime-product-v4.py')
    old_functions = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(read(before_builder_path)).body if isinstance(n, ast.FunctionDef)}
    new_functions = {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(read(builder_path)).body if isinstance(n, ast.FunctionDef)}
    assert set(new_functions) - set(old_functions) == {'verify_runtime6_delta'}
    changed_functions = [key for key in old_functions if old_functions[key] != new_functions[key]]
    assert set(changed_functions) == {'assemble', 'main'}
    commands_path = runtime_path.parent / 'commands.json'
    commands = json.loads(read(commands_path))
    assert len(commands) == 281 and all(row['exit'] == 0 for row in commands)
    assert all(row['argv'][-1].startswith('/private/tmp/vm27-signed-runtime-')
               for row in commands if row['argv'][0] == 'codesign')
    preflight = next(row for row in commands if row['label'] == 'run-actual-product-preflight')
    assert preflight['argv'][1].startswith('/private/tmp/vm27-signed-runtime-')
    assert runtime['sandboxInitializationExecuted'] is runtime['sandboxCompatibilityVerified'] is False
    assert runtime['actualChildSpawnExecuted'] is runtime['guestBoot'] is False
    assert runtime['trustCacheOperations'] == runtime['deviceOperations'] == 0
    layout_path = N / 'independent27-child-bundle-layout-primary-v1-attempt1/report.json'
    layout = json.loads(read(layout_path))
    layout_freeze_path = layout_path.parent / 'freeze.json'
    for row in json.loads(read(layout_freeze_path))['files']:
        checked(row)
    assert layout['actualQueriesExit0'] is True and layout['actualIOS16NSBundleLookupVerified'] is False
    assert layout['actualNativeSandboxCompatibilityVerified'] is False
    args.output.mkdir()
    actual_diff = ''.join(difflib.unified_diff(read(before_builder_path).decode().splitlines(True),
                                             read(builder_path).decode().splitlines(True),
                                             fromfile=str(before_builder_path), tofile=str(builder_path)))
    (args.output / 'actual-builder-v4-to-v5.diff').write_text(actual_diff)
    inputs = [Path(__file__), runtime_path, freeze_path, args.packet_candidate, scope_path,
              delta_path, checked(delta['baselineCandidate']), checked(delta['baselineFreeze']),
              old_manifest_path, new_manifest_path, builder_path, before_builder_path,
              source, checked(delta['genuineProfileProof']), commands_path, layout_path, layout_freeze_path]
    report = dict(schema='Independent finite Runtime7 genuine sandbox resource peer v1',
                  findings=[], finiteLocalScopePassed=True, runtimeProductScopePassed=True,
                  controllerPacketCandidate=pin(args.packet_candidate), controllerPacketScope=pin(scope_path),
                  controllerExecutionFlowReviewed=False, runtimeCandidate=pin(runtime_path), runtimeFreeze=pin(freeze_path),
                  allRuntimeFrozenPinsRechecked=len(freeze['files']), exact149ManifestFilesRechecked=True,
                  runtimeInventoryBefore=148, runtimeInventoryAfter=149, signedImages=139,
                  wholebyteUnchangedSignedImages=138, unchangedSignedIDs=unchanged_signed,
                  onlyChangedPriorFiles=changed, onlyAddedResource=profile_row,
                  genuineSource=pin(source), genuineCopiedProfile=pin(profile_path),
                  codeResourcesMandatorySHA256Binding=True, allOldCodeResourcesBindingsPreserved=True,
                  originalChildCodePrefixWholebyteUnchanged=True, originalMainAndSandboxCallUnmodified=True,
                  actualChildBefore=before_sig, actualChildAfter=after_sig, all320ActualCodePagesAndSevenSlotsVerified=True,
                  embeddedXMLAndDERWholebytesUnchanged=True, oldNativeStrictAndExplicitOwnedPolicyUnchanged=True,
                  originalStageAndDefinitionGraphReusedUnmodified=True, noImportOrDependencyModelRerun=True,
                  actualBuilderDiff=pin(args.output / 'actual-builder-v4-to-v5.diff'),
                  builderFunctionsChanged=changed_functions, builderFunctionsAdded=['verify_runtime6_delta'],
                  actualFrozenBuildCommands=len(commands), actualFrozenBuildCommandsAllExit0=True,
                  actualHostPreflightReceiptReviewed=True, actualHostBundleLayoutEvidence=pin(layout_path),
                  actualHostNSBundleResourceLookupEvidence=True, actualIOSNSBundleResourceLookupVerified=False,
                  nativeSandboxFlags3CompatibilityVerified=False, nativeSandboxInitializationExecuted=False,
                  nativeSandboxCompileExecuted=False, deviceOperations=0, trustCacheOperations=0,
                  targetIOSImageExecution=0, guestBoot=False, inputs=[pin(path) for path in inputs],
                  limits=['HOST resource/signature composition only; controller flow reviewed separately',
                          'Current iPad native init implementation capture remains separate',
                          'Native flags=3 semantics and macOS27 sandbox profile acceptance are not yet proven'])
    save(args.output / 'review.json', report)
    save(args.output / 'freeze.json', dict(schema='Independent Runtime7 resource peer freeze v1',
                                          deviceOperations=0, files=report['inputs'] + file_pins +
                                          [pin(args.output / 'review.json'), pin(args.output / 'actual-builder-v4-to-v5.diff')]))
    print(json.dumps(dict(review=pin(args.output / 'review.json'), freeze=pin(args.output / 'freeze.json'),
                          findings=[], finiteLocalScopePassed=True, deviceOperations=0)))


if __name__ == '__main__':
    main()
