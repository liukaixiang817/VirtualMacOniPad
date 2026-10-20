#!/usr/bin/env python3
"""Independently inspect the actual signed Runtime3 product without execution."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import stat
import struct

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def signed_image(path, expected, external):
    data = path.read_bytes()
    require(len(data) >= 32 and struct.unpack_from('<I', data)[0] == 0xfeedfacf, 'actual thin Mach-O')
    cpu, subtype, kind, count, size = struct.unpack_from('<5I', data, 4)
    require(cpu == 0x100000c and subtype & 0xffffff == 2 and kind in (2, 6), 'actual arm64e execute/dylib')
    require(count <= 512 and size <= len(data)-32, 'bounded load commands')
    at = 32
    uuid = None
    signature_range = None
    platforms = []
    for unused in range(count):
        require(at + 8 <= 32+size, 'complete command header')
        command, length = struct.unpack_from('<II', data, at)
        require(length >= 8 and length % 8 == 0 and at+length <= 32+size, 'complete command')
        if command == 0x1b:
            require(length == 24 and uuid is None, 'one actual UUID')
            uuid = data[at+8:at+24].hex()
        if command == 0x1d:
            require(length == 16 and signature_range is None, 'one actual signature')
            signature_range = struct.unpack_from('<II', data, at+8)
        if command == 0x32:
            require(length >= 24, 'build version command')
            platforms.append(struct.unpack_from('<III', data, at+8))
        require(command not in (0x24, 0x25, 0x2f, 0x30), 'no ambiguous legacy platform')
        at += length
    require(at == 32+size and uuid == expected['uuid'], 'actual UUID and complete command array')
    require(len(platforms) == 1 and platforms[0][0] == 2 and 0 < platforms[0][1] <= 0x100100,
            'actual compatible iOS load declaration')
    require(signature_range is not None, 'actual LC_CODE_SIGNATURE')
    start, length = signature_range
    require(length >= 12 and start+length <= len(data), 'signature extent')
    signature = data[start:start+length]
    magic, total, count = struct.unpack_from('>III', signature)
    require(magic == 0xfade0cc0 and 12 <= total <= length and count <= 64 and 12+8*count <= total,
            'bounded actual superblob')
    slots = {}
    for i in range(count):
        slot, offset = struct.unpack_from('>II', signature, 12+i*8)
        require(slot not in slots and 12+8*count <= offset <= total-8, 'unique actual signature slot')
        blob_length = struct.unpack_from('>I', signature, offset+4)[0]
        require(blob_length >= 8 and offset+blob_length <= total, 'signature slot extent')
        slots[slot] = signature[offset:offset+blob_length]
    directory = slots.get(0)
    require(directory is not None and len(directory) >= 44, 'actual primary CodeDirectory')
    magic, total, version, flags, hashes, identifier, special, pages, limit = struct.unpack_from('>9I', directory)
    hash_size, hash_type, unused, shift = directory[36:40]
    require(magic == 0xfade0c02 and total == len(directory) and version >= 0x20001 and hash_size == 32 and
            hash_type == 2 and 0 < shift <= 16 and limit <= start and special <= 64 and hashes >= special*32 and
            hashes+pages*32 <= total and pages == (limit+(1 << shift)-1) >> shift, 'true primary SHA256 shape')
    if version >= 0x20300:
        require(len(directory) >= 64 and struct.unpack_from('>Q', directory, 56)[0] in (0, limit),
                'supported actual extended code limit')
    cdhash = hashlib.sha256(directory).hexdigest()[:40]
    require(cdhash == expected['cdhash'], 'actual manifest CodeDirectory hash')
    for i in range(pages):
        page = data[i << shift:min((i+1) << shift, limit)]
        require(hashlib.sha256(page).digest() == directory[hashes+i*32:hashes+(i+1)*32], 'actual code page')
    specials = []
    for i in range(1, special+1):
        expected_hash = directory[hashes-i*32:hashes-(i-1)*32]
        value = slots.get(i)
        if i in external:
            require(value is None, 'unambiguous external special slot')
            value = external[i]
        if value is None:
            require(not any(expected_hash), 'no missing nonzero special slot')
        else:
            require(hashlib.sha256(value).digest() == expected_hash, 'actual special slot hash')
        specials.append({'slot': i, 'external': i in external, 'present': value is not None})
    entitlements = None
    if 5 in slots:
        require(struct.unpack_from('>I', slots[5])[0] == 0xfade7171, 'actual XML entitlements')
        entitlements = plistlib.loads(slots[5][8:])
    return {'file': pin(path), 'cdhash': cdhash, 'uuid': uuid, 'actualCodePages': pages,
            'actualSpecialSlots': specials, 'embeddedEntitlements': entitlements, 'actualPlatform': platforms[0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.parent == N and not output.exists(), 'new diagnostics directory')
    candidate = json.loads(args.candidate.read_bytes())
    frozen_path = args.candidate.parent / 'freeze.json'
    frozen = json.loads(frozen_path.read_bytes())
    checked = 0
    for row in frozen['files']:
        require(pin(row['path']) == row, 'immutable frozen pin: '+row['path'])
        checked += 1
    root = pathlib.Path(candidate['runtimeRoot'])
    raw = pathlib.Path(candidate['manifest']['path']).read_bytes()
    require(pin(candidate['manifest']['path']) == candidate['manifest'], 'actual manifest pin')
    anchor = pathlib.Path(candidate['anchorSource']['path']).read_text()
    match = re.search(r'SHA256V1\[32\]=\{([^}]+)\}', anchor)
    require(match is not None and bytes(int(x) for x in match[1].split(',')) == hashlib.sha256(raw).digest(),
            'real compiled product anchor digest')
    require('ManifestBytesV1='+str(len(raw))+';' in anchor, 'real compiled product anchor size')
    manifest = plistlib.loads(raw)
    files = {row['id']: row for row in manifest['files']}
    require(len(files) == len(manifest['files']) == 143, 'actual unique finite product')
    resources = {}
    for row in files.values():
        rel = pathlib.PurePosixPath(row['path'])
        require(not rel.is_absolute() and all(x not in ('', '.', '..') for x in rel.parts), 'finite relative product path')
        path = root.joinpath(*rel.parts)
        require(stat.S_ISREG(path.lstat().st_mode), 'actual regular product file')
        actual = pin(path)
        require(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], 'manifest joins actual product')
        if row['kind'] == 'resource':
            resources[row['id']] = path.read_bytes()
    actual_files = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual_files == {row['path'] for row in files.values()} | {'VM27IndependentRuntimeManifestV1.plist'},
            'no undeclared runtime product files')
    signatures = []
    for row in files.values():
        if row['kind'] == 'mach-o':
            external = {int(slot): resources[key] for slot, key in row.get('signatureSlots', {}).items()}
            signatures.append(signed_image(root / row['path'], row, external))
    require(len(signatures) == 139 and len({row['cdhash'] for row in signatures}) == 139, 'actual distinct signed Mach-O set')
    child_id = manifest['parentBootstrapContract']['childID']
    child = next(row for row in signatures if row['file']['path'] == str((root/files[child_id]['path']).resolve()))
    require(child['uuid'] == '4a6a588d1afd30f5a64d6304eb79be0b' and child['file']['bytes'] <= 8*1024*1024,
            'actual original child identity and bound')
    expected_entitlements = plistlib.loads((R/'VirtualMac/vz/host/VirtualMac.entitlements').read_bytes())
    for key in ('com.apple.private.tcc.allow', 'com.apple.virtualization.avp.videotoolbox'):
        expected_entitlements.pop(key, None)
    require(child['embeddedEntitlements'] == expected_entitlements, 'actual scoped child entitlements')
    require({row['slot'] for row in child['actualSpecialSlots'] if row['external']} == {1, 3},
            'actual child Info/CodeResources identity')
    output.mkdir(mode=0o700)
    record = {'schema': 'Independent actual signed Runtime3 source and signature inspection v1',
              'candidate': pin(args.candidate), 'inputFreeze': pin(frozen_path), 'verifiedFrozenPins': checked,
              'actualManifest': candidate['manifest'], 'actualSignedFiles': signatures,
              'actualSignedMachOs': len(signatures), 'actualVerifiedCodePages': sum(row['actualCodePages'] for row in signatures),
              'realCompiledManifestAnchorVerified': True, 'allPagesAndSpecialSlotsVerifiedIndependently': True,
              'childScopedEntitlementsVerified': True, 'findings': [], 'actualIOSImagesExecuted': False,
              'actualDeviceOperations': 0, 'trustCacheOperations': 0, 'guestBoot': False}
    (output/'review.json').write_text(json.dumps(record, indent=2)+'\n')
    (output/'freeze.json').write_text(json.dumps({'files': [pin(__file__), pin(output/'review.json'), pin(args.candidate),
                                                         pin(frozen_path)]}, indent=2)+'\n')
    print(json.dumps({'review': pin(output/'review.json'), 'freeze': pin(output/'freeze.json'),
                      'verifiedFrozenPins': checked, 'actualSignedImages': len(signatures), 'findings': []}))


if __name__ == '__main__':
    main()
