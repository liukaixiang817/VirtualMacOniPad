#!/usr/bin/env python3
"""Finite read-only reconstruction and native consumer review of firmware data."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = b'/System/Library/Frameworks/Virtualization.framework/Versions/A/Resources/'
NEW = b'/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/Firmware27/'


def pin(path):
    path = pathlib.Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def need(v, message):
    if not v:
        raise ValueError(message)


def sext(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def review(source, output):
    need(source.parent == N and output.parent == N and not output.exists(), 'actual input and fresh diagnostics output')
    c = json.loads((source / 'candidate.json').read_bytes())
    f = json.loads((source / 'freeze.json').read_bytes())
    for row in f['files']:
        need(pin(row['path']) == row, 'exact frozen bytes ' + row['path'])
    recipe = json.loads(pathlib.Path(c['patchRecipe']['path']).read_bytes())
    data = pathlib.Path(c['sourceImage']['path']).read_bytes()
    changed = pathlib.Path(c['candidate']['path']).read_bytes()
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('firmware_finite_independent_macho', reader)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    original = m.MachO(data)
    candidate = m.MachO(changed)
    need(original.uuid == candidate.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'real original27 arm64e UUID')
    need(len(OLD) == len(NEW) == 73 and b'\0' not in NEW, 'explicit counted prefix retains all 73 bytes')
    need(len(recipe['patches']) == 1, 'only one data replacement')
    p = recipe['patches'][0]
    at = p['fileOffset']
    need(p['rva'] == 0x43fe0f and original.file(original.base + p['rva']) == at, 'actual mapped CString RVA')
    section = next(s for s in original.sections if s['fileoff'] <= at and at + 74 <= s['fileoff'] + s['size'])
    need(section['name'] == '__cstring', 'bounded original data section')
    need(p['bytes'] == 74 and bytes.fromhex(p['beforeHex']) == OLD + b'\0' and
         bytes.fromhex(p['afterHex']) == NEW + b'\0' and data.count(OLD + b'\0') == 1,
         'one exact 74 byte counted string and its terminator')
    rebuilt = data[:at] + NEW + b'\0' + data[at + 74:]
    need(rebuilt == changed and len(data) == len(changed), 'whole output equals exclusive CString replacement')
    for key in ('commands', 'sections', 'segments', 'imports', 'binds', 'exports'):
        need(getattr(original, key) == getattr(candidate, key), 'all actual metadata unchanged ' + key)
    need(not recipe['importChanges'] and not recipe['newRequiredLoads'], 'no new loader or interposer dependency')

    def word(rva):
        return struct.unpack_from('<I', data, original.file(original.base + rva))[0]

    def adrp_add(first, second):
        a, b = word(first), word(second)
        need(a & 0x9f000000 == 0x90000000 and b & 0xffc00000 == 0x91000000, 'actual ADRP/ADD encoding')
        rd = a & 31
        need(b & 31 == rd and (b >> 5) & 31 == rd, 'actual ADRP/ADD register data flow')
        imm = sext(((a >> 5) & 0x7ffff) << 2 | ((a >> 29) & 3), 21)
        return ((original.base + first) & ~4095) + (imm << 12) + ((b >> 10) & 0xfff)

    def bl_target(at):
        w = word(at)
        need(w & 0xfc000000 == 0x94000000, 'actual BL instruction')
        return at + sext(w & 0x3ffffff, 26) * 4

    consumers = []
    for row in c['actualPrefixADRPADDXrefs']:
        need(adrp_add(row['adrp'], row['add']) == original.base + p['rva'], 'both genuine prefix references')
        need(word(row['countProducer']) == 0x52800923, 'real MOV W3,#73')
        need(bl_target(row['insertCall']) == 0x411f14 and bl_target(row['appendCall']) == 0x411f04 and
             bl_target(row['openCall']) == 0x4133e4, 'real counted insert, suffix append, native open calls')
        consumers.append({'functionStart': row['functionStart'], 'countedPrefixBytes': 73,
                          'prefixRVA': p['rva'], 'nativeOpenCall': row['openCall']})
    bindings = []
    for row in c['realConsumerBindings']:
        slot = adrp_add(row['stubRVA'], row['stubRVA'] + 4)
        need(slot == original.base + row['slotRVA'], 'actual stub address targets actual chained slot')
        bound = next(x for x in original.binds if x['va'] == slot)
        imported = original.imports[bound['index']]
        need(bound['auth'] == 1 and bound['addrdiv'] == 1 and bound['key'] == 0 and bound['diversity'] == 0 and
             bound['word'] == int(row['raw'], 16) and imported['name'] == row['importRecord']['name'] and
             imported['weak'] == 0 and imported['ordinal'] == row['importRecord']['ordinal'],
             'true strong authenticated import and PAC identity')
        bindings.append({'slotRVA': row['slotRVA'], 'index': bound['index'], 'name': imported['name'],
                         'ordinal': imported['ordinal'], 'authenticated': True, 'addressDiversity': True})
    need([x['index'] for x in bindings] == [166, 165, 390], 'actual native string/open imports')
    # Independently inspect the existing SSV fat image's real arm64e UUID.
    system = pathlib.Path(c['sameBuildSystemVMMReadOnly']['path']).read_bytes()
    need(pin(c['sameBuildSystemVMMReadOnly']['path']) == c['sameBuildSystemVMMReadOnly'], 'actual source system image bytes')
    magic, count = struct.unpack_from('>II', system)
    need(magic in (0xcafebabe, 0xcafebabf) and 0 < count < 16, 'actual system fat Mach-O')
    width = 32 if magic == 0xcafebabf else 20
    slices = []
    for i in range(count):
        off = 8 + width * i
        cpu, subtype = struct.unpack_from('>II', system, off)
        start, size = struct.unpack_from('>QQ' if width == 32 else '>II', system, off + 8)
        if cpu == 0x100000c and subtype & 0xffffff == 2:
            need(start + size <= len(system), 'actual bounded arm64e fat slice')
            slices.append(m.MachO(system[start:start + size]).uuid)
    need(slices == [original.uuid], 'resources source build has exactly matching arm64e VMM UUID')
    resource_pins = []
    for row in c['resources']:
        need(pin(row['sourceReadOnly']['path']) == row['sourceReadOnly'] and pin(row['local']['path']) == row['local'],
             'actual immutable source and standalone copied resource bytes')
        need(row['sourceReadOnly']['bytes'] == row['local']['bytes'] and row['sourceReadOnly']['sha256'] == row['local']['sha256'],
             'genuine exact firmware bits')
        value = struct.unpack_from('<I', pathlib.Path(row['local']['path']).read_bytes())[0]
        need(value not in (0xfeedfacf, 0xfeedface, 0xcafebabe, 0xbebafeca, 0xcffaedfe, 0xcefaedfe, 0xcafebabf, 0xbfbafeca),
             'firmware resource not a host Mach-O image')
        need(row['kind'] == 'resource' and not row['addsTrustCacheHash'] and not row['hostMachO'], 'no invented TC image')
        need(row['relativePath'] == 'Firmware27/' + pathlib.Path(row['local']['path']).name, 'actual new canonical relative resource name')
        resource_pins.append(row['local'])
    need(len(resource_pins) == 5 and sum(x['bytes'] for x in resource_pins) == 3984312, 'five exact genuine 27 resource files')
    need(not pathlib.Path(c['resources'][0]['sourceReadOnly']['path']).with_name('AVPBooter.vmapple1.bin').exists(), 'absent enum0 is not fabricated')
    for name in ('resource-consumer-1.stdout', 'resource-consumer-2.stdout', 'actual-system-version.stdout'):
        need((source / name).is_file(), 'actual LLVM/source receipts')
    one, two = [(source / ('resource-consumer-' + str(i) + '.stdout')).read_text() for i in (1, 2)]
    need('10008c230:' in one and 'brk\t#0x1' in one, 'original invalid enum remains a real refusal')
    need('100340adc:' in two and 'b\t0x100340be4' in two, 'existing FD true branch bypasses resource open')
    need(data[original.file(original.base + 0x43fccb):][:5] == b'.bin\0' and
         data[original.file(original.base + 0x43fe59):][:4] == b'.fd\0', 'real append suffixes remain intact beside prefix')
    need('26A434' in (source / 'actual-system-version.stdout').read_text(), 'actual same-build version receipt')
    output.mkdir()
    report = {'schema': 'Independent finite firmware layout data peer v1',
              'firmwareCandidate': pin(source / 'candidate.json'), 'firmwareFreeze': pin(source / 'freeze.json'),
              'patchRecipe': c['patchRecipe'], 'sourceImage': c['sourceImage'], 'candidateImage': c['candidate'],
              'frozenFilesChecked': len(f['files']), 'exclusivePatchBytes': 74, 'countedPrefixBytes': 73,
              'actualOriginalArm64eUUID': original.uuid, 'wholeOutputReconstructed': True,
              'allInstructionsMetadataAndPACUnchanged': True, 'trueConsumers': consumers, 'trueBindings': bindings,
              'resources': resource_pins, 'resourcesBytes': 3984312, 'resourcesAdditionalTrustHashes': 0,
              'finiteLocalScopePassed': True, 'findings': [],
              'readyForFreshStageAndSignedProductComposition': True,
              'boundaries': ['Unsigned CString changes require fresh product signatures, manifest hashes and the App compiled manifest anchor.',
                             'Five resource data files must be present in the actual runtime manifest and device staging before a guest start.',
                             'Enum0 AVPBooter.vmapple1.bin is actually absent; no 13 resource or substitute has been supplied.',
                             'Current selected guest hardware model enum remains unproved; VZG11 current consumer is unproved.',
                             'No resource open, firmware guest execution, device launch, trust-cache action or guest display is claimed.'],
              'source': pin(__file__), 'parser': pin(reader), 'deviceOperations': 0, 'trustCacheOperations': 0}
    (output / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(output / 'review.json'), pin(__file__), pin(reader), pin(source / 'candidate.json'), pin(source / 'freeze.json'),
            c['patchRecipe'], c['sourceImage'], c['candidate'], *resource_pins]
    (output / 'freeze.json').write_text(json.dumps({'files': rows, 'deviceOperations': 0}, indent=2) + '\n')
    print(json.dumps({'review': pin(output / 'review.json'), 'freeze': pin(output / 'freeze.json')}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate-dir', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    review(args.candidate_dir.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
