#!/usr/bin/env python3
"""An equal-width original27 firmware path port and genuine 27 resource inputs."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import runpy
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SYSTEM = pathlib.Path('/System/Library/Frameworks/Virtualization.framework/Versions/A')
OLD = b'/System/Library/Frameworks/Virtualization.framework/Versions/A/Resources/'
NEW = b'/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/Firmware27/'
RESOURCES = {
 'AVPBooter.vmapple2.bin': (334960, '6d010540a047ec71a54cb96565171f8f2e0e191dd5dbef2403f3863409afa845'),
 'AVPBooter.vresearch1.bin': (335688, '301bc973b56e86a9906bb6002d008015a57c9e07b5f191260717b97a62589072'),
 'AVPSEPBooter.vresearch1.bin': (167936, '86d008eb3d203d99fb20962b69227af9f8ecdc98f1c9bd9fed6d3581c655f5b6'),
 'VZG11.fd': (2097152, '6e6881ec7c964470f7a55d9dc170b9c1b8726aacf4f3896ac2a4c55a87d7911c'),
 'VZG21.fd': (1048576, 'df34f462c85f743cf3b2584a88a87eca082b86089e928d6f097d642286ab8b4d'),
}


def need(value, message):
 if not value:
  raise ValueError(message)


def pin(path):
 path = pathlib.Path(path).resolve()
 need(path.is_file() and not path.is_symlink(), 'actual regular source')
 data = path.read_bytes()
 return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def dump(path, value):
 path.write_text(json.dumps(value, indent=2)+'\n')


def main():
 parser = argparse.ArgumentParser()
 parser.add_argument('--stage-candidate', required=True, type=pathlib.Path)
 parser.add_argument('--output', required=True, type=pathlib.Path)
 args = parser.parse_args()
 output = args.output.resolve()
 need(output.parent == N and not output.exists(), 'fresh local diagnostics output')
 stage_path = args.stage_candidate.resolve()
 stage = json.loads(stage_path.read_bytes())
 row = next(row for row in stage['stagedImages'] if row['key'] == 'com.apple.Virtualization.VirtualMachine')
 source = pathlib.Path(row['staged']['path'])
 need(pin(source) == row['staged'], 'actual stage5 original27 child')
 audit_path = N/'vmm-public-adapter-gap-design-v1/audit.py'
 audit = runpy.run_path(str(audit_path))
 reader_path = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec = importlib.util.spec_from_file_location('firmware_original27_independent_reader', reader_path)
 reader = importlib.util.module_from_spec(spec)
 spec.loader.exec_module(reader)
 image = audit['MachO'](source.read_bytes())
 need(image.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'genuine current macOS27 child UUID')
 need(len(OLD) == len(NEW) == 73, 'actual explicit std::string insert count preserved')
 old = OLD+b'\0'
 new = NEW+b'\0'
 need(image.b.count(old) == 1, 'unique original resource directory CString')
 at = image.b.index(old)
 segment = next(s for s in image.segments if s['offset'] <= at < s['offset']+s['bytes'])
 rva = segment['va']+at-segment['offset']-image.base
 section = next(s for s in image.sections if s['offset'] <= at and at+74 <= s['offset']+s['bytes'])
 need(section['name'] == '__cstring' and rva == 0x43fe0f, 'true bounded CString section/rva')
 output.mkdir(mode=0o700)
 commands = []

 def run(label, argv):
  result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=45)
  (output/(label+'.stdout')).write_bytes(result.stdout)
  (output/(label+'.stderr')).write_bytes(result.stderr)
  commands.append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode})
  need(result.returncode == 0, 'actual local evidence command: '+label)
  return result.stdout.decode()

 version = run('actual-system-version', ['sw_vers'])
 need('27.0.1' in version and '26A434' in version, 'matching actual current macOS27 build')
 system_main = SYSTEM/'XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine'
 uuid = run('actual-system-vmm-uuid', ['xcrun', 'dyld_info', '-uuid', system_main])
 need('[arm64e]:' in uuid and '4A6A588D-1AFD-30F5-A64D-6304EB79BE0B' in uuid, 'actual same-build original arm64e main UUID')
 windows = [(0x8bfbc, 0x8c2f4), (0x340a60, 0x340c00)]
 disassembly = []
 for index, (start, end) in enumerate(windows):
  text = run('resource-consumer-'+str(index+1), ['xcrun', 'llvm-objdump', '--disassemble', '--no-show-raw-insn',
    '--start-address='+hex(image.base+start), '--stop-address='+hex(image.base+end), source])
  disassembly.append(text)
  need('mov\tw3, #0x49' in text and '0x100411f14' in text and '0x1004133e4' in text,
       'actual explicit 73-byte insert and authenticated real open callers')
 need('cmp\tw1, #0x1' in disassembly[0] and 'cmp\tw1, #0x2' in disassembly[0] and
      'cmp\tw1, #0x3' in disassembly[0], 'actual finite original AVP enum checks')
 need(image.raw(0x43fc78, 19) == b'AVPBooter.vmapple1\0' and
      image.raw(0x43fc8b, 19) == b'AVPBooter.vmapple2\0' and
      image.raw(0x43fc9e, 21) == b'AVPBooter.vresearch1\0' and
      image.raw(0x43fcb3, 24) == b'AVPSEPBooter.vresearch1\0', 'actual native filename literals')
 bindings = []
 for stub, name in [(0x411f14, '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm'),
                    (0x411f04, '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm'),
                    (0x4133e4, '_open')]:
  slot, binding = audit['authenticated_stub'](image, image.raw(stub,16), stub)
  need(binding['authenticated'] and not binding['importRecord']['weak'] and binding['importRecord']['name'] == name,
       'actual strong PAC authenticated native original consumer')
  bindings.append({'stubRVA': stub, 'slotRVA': slot, **binding})
 changed = bytearray(image.b)
 changed[at:at+74] = new
 target = output/'VirtualMachine.original27.firmware-path-v1.unsigned'
 target.write_bytes(changed)
 patched = reader.MachO(target.read_bytes())
 original = reader.MachO(image.b)
 need(len(changed) == len(image.b) and original.uuid == patched.uuid and original.commands == patched.commands and
      original.sections == patched.sections and original.imports == patched.imports and original.binds == patched.binds and
      original.exports == patched.exports, 'only fixed-width CString bytes differ; real image metadata/PAC unchanged')
 need(bytes(changed[:at]) == image.b[:at] and bytes(changed[at+74:]) == image.b[at+74:], 'exclusive 74-byte data span')
 run('actual-patched-dyld-validation', ['xcrun', 'dyld_info', '-validate_only', target])
 resource_rows = []
 firmware = output/'Firmware27'
 firmware.mkdir(mode=0o700)
 for name, (size, sha) in RESOURCES.items():
  path = SYSTEM/'Resources'/name
  actual = pin(path)
  need(actual['bytes'] == size and actual['sha256'] == sha, 'same-build actual firmware resource: '+name)
  contents = path.read_bytes()
  need(struct.unpack_from('<I', contents)[0] not in (0xfeedfacf, 0xfeedface, 0xcafebabe, 0xbebafeca,
       0xcffaedfe, 0xcefaedfe, 0xcafebabf, 0xbfbafeca), 'raw firmware resource is not a host Mach-O')
  copy = firmware/name
  copy.write_bytes(contents)
  copy.chmod(0o600)
  resource_rows.append({'id': 'firmware:'+name, 'relativePath': 'Firmware27/'+name, 'kind': 'resource', 'role': 'firmware',
   'sourceReadOnly': actual, 'local': pin(copy), 'hostMachO': False, 'addsTrustCacheHash': False,
   'originalResourceConsumerProved': name != 'VZG11.fd'})
 need(not (SYSTEM/'Resources/AVPBooter.vmapple1.bin').exists(), 'do not fabricate absent original27 legacy enum0 firmware')
 recipe = {'schema': 'Original27 actual fixed-width firmware directory data port v1',
  'sourceImage': pin(source), 'candidate': pin(target), 'inheritedStage': pin(stage_path),
  'patches': [{'rva': rva, 'fileOffset': at, 'section': section['name'], 'bytes': 74,
               'beforeHex': old.hex(), 'afterHex': new.hex(), 'explicitInsertCount': 73}],
  'resources': resource_rows, 'canonicalDeviceDirectory': NEW.decode(), 'importChanges': [],
  'newRequiredLoads': [], 'newTrustCacheHashesForResources': 0, 'originalFunctionInstructionsUnchanged': True,
  'preserveHeaderUUIDSectionsFunctionStartsUnwindPACChainedFixups': True,
  'allCodeSigningMustBeRedoneByFinalProductBuilder': True, 'runtimeManifestResourceRowsRequired': True,
  'childEnvironmentRequired': False, 'legacyVMMOpenInterposerRequired': False}
 dump(output/'patch-recipe.json', recipe)
 record = {'schema': 'Original27 firmware data path and genuine same-build resources v1',
  'builder': pin(__file__), 'sourceStage': pin(stage_path), 'sourceImage': pin(source), 'candidate': pin(target),
  'patchRecipe': pin(output/'patch-recipe.json'), 'resources': resource_rows,
  'sameBuildSystemVMMReadOnly': pin(system_main), 'sameBuildResourceVersionReadOnly': pin(SYSTEM/'Resources/version.plist'),
  'actualSystemVersion': '27.0.1', 'actualSystemBuild': '26A434', 'actualOriginalArm64eUUID': image.uuid,
  'resourcePrefixEqualWidth': 73, 'patchedCStringBytes': 74, 'realConsumerBindings': bindings,
  'actualPrefixADRPADDXrefs': [{'adrp': 0x8c0c0, 'add': 0x8c0c4, 'countProducer': 0x8c0d0, 'insertCall': 0x8c0d4,
      'appendCall': 0x8c100, 'openCall': 0x8c14c, 'functionStart': 0x8bfbc},
     {'adrp': 0x340afc, 'add': 0x340b00, 'countProducer': 0x340b0c, 'insertCall': 0x340b10,
      'appendCall': 0x340b3c, 'openCall': 0x340b88, 'functionStart': 0x340a60}],
  'AVPFilenameEnum': {'0': 'AVPBooter.vmapple1.bin', '1': 'AVPBooter.vmapple2.bin',
     '2': 'AVPBooter.vresearch1.bin', '3': 'AVPSEPBooter.vresearch1.bin'},
  'AVPEnum0SameBuildResourceAvailable': False, 'absentEnum0FabricatedOrReplacedWith13': False,
  'AVPInvalidEnumUsesOriginalBRK': True, 'currentGuestHardwareModelEnumProved': False,
  'EFIConsumerProvedFilename': 'VZG21.fd', 'EFIExistingFDCanBypassResourceOpen': True,
  'VZG11ResourceGenuineButCurrentConsumerProved': False, 'resourcesHostMachO': False,
  'actualResourceFileOpenExecuted': False, 'nativeGuestFirmwareExecuted': False,
  'deviceOperations': 0, 'trustCacheOperations': 0, 'codeSigned': False, 'guestBoot': False}
 dump(output/'candidate.json', record)
 dump(output/'commands.json', commands)
 frozen = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
 frozen.extend([pin(__file__), pin(source), pin(stage_path), pin(audit_path), pin(reader_path)])
 # The captured copies and receipts remain standalone. The read-only source
 # SSV paths are provenance records; later device operation uses only copies.
 dump(output/'freeze.json', {'files': list({row['path']: row for row in frozen}.values()), 'deviceOperations': 0})
 print(json.dumps({'candidate': pin(output/'candidate.json'), 'freeze': pin(output/'freeze.json'),
                   'patchRecipe': pin(output/'patch-recipe.json'), 'actualFirmwareResources': len(resource_rows)}))


if __name__ == '__main__':
 main()
