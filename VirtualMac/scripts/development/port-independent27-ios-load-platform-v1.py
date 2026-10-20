#!/usr/bin/env python3
"""Port three actual remaining macOS loader declarations into fresh copies.

This changes loader metadata only. It does not prove binary ABI compatibility,
load any image, sign code, or write to the iPad. All executable section bytes,
UUIDs, dependencies, exports and authenticated pointer fixups must stay exact.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.is_relative_to(N) and not out.exists(), 'Fresh diagnostic output required')
    out.mkdir()
    candidate = N / 'independent27-flat-graph-stage-v1-attempt3/candidate.json'
    need(pin(candidate)['sha256'] == '97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206',
         'Exact actual staged graph required')
    stage = json.loads(candidate.read_bytes())
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('platform_port_macho', reader)
    macho = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(macho)
    expected = {'UniversalHID27.dylib', 'UniversalHIDKit27.dylib',
                'com.apple.Virtualization.VirtualMachine'}
    reports = []
    commands = []
    for row in stage['stagedImages']:
        source = Path(row['staged']['path'])
        need(pin(source) == row['staged'], 'Exact frozen source required')
        raw = source.read_bytes()
        old = macho.MachO(raw)
        versions = [command for command in old.commands if command['cmd'] == 0x32]
        need(len(versions) == 1, 'One actual build version required')
        command = versions[0]
        platform, minimum, sdk, tools = struct.unpack_from('<4I', command['raw'], 8)
        if platform == 2:
            continue
        need(row['key'] in expected and (platform, minimum, sdk, tools) ==
             (1, 0x1b0000, 0x1b0000, 1), 'Reviewed macOS27 source metadata required')
        # Locate this genuine command from the on-file command walk.
        at = 32
        selected = None
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            cmd, size = struct.unpack_from('<II', raw, at)
            if cmd == 0x32:
                need(selected is None and raw[at:at + size] == command['raw'], 'Exact build-version extent')
                selected = at
            at += size
        need(selected is not None, 'Actual command offset required')
        data = bytearray(raw)
        struct.pack_into('<II', data, selected + 8, 2, 0x100100)
        actual = bytes(data)
        new = macho.MachO(actual)
        need(new.uuid == old.uuid and new.segments == old.segments and
             new.sections == old.sections and new.loads == old.loads and
             new.imports == old.imports and new.exports == old.exports and new.binds == old.binds,
             'Every nonselected structural and pointer field must stay exact')
        for section in old.sections:
            if section['size'] and section['fileoff'] and (section['flags'] & 255) not in [1, 12]:
                offset = section['fileoff']
                length = section['size']
                need(actual[offset:offset + length] == raw[offset:offset + length],
                     'Every file-backed section must remain byte exact')
        differences = [i for i, (before, after) in enumerate(zip(raw, actual)) if before != after]
        need(len(actual) == len(raw) and all(selected + 8 <= i < selected + 16 for i in differences),
             'Only genuine platform and minimum loader fields may change')
        path = out / row['key']
        path.write_bytes(actual)
        path.chmod(0o600)
        for label, options in [('validate', ['-validate_only']), ('platform', ['-platform'])]:
            argv = ['xcrun', 'dyld_info'] + options + [str(path)]
            result = subprocess.run(argv, capture_output=True, timeout=30)
            (out / (row['key'] + '.' + label + '.stdout')).write_bytes(result.stdout)
            (out / (row['key'] + '.' + label + '.stderr')).write_bytes(result.stderr)
            commands.append(dict(image=row['key'], label=label, argv=argv, status=result.returncode))
            need(result.returncode == 0, 'Actual dyld validation failed')
            if label == 'platform':
                need(b'iOS' in result.stdout and b'16.1' in result.stdout, 'Actual iOS16.1 declaration required')
        reports.append(dict(key=row['key'], source=row['staged'], ported=pin(path),
                            UUID=new.uuid, buildVersionOffset=selected,
                            oldPlatform=platform, newPlatform=2,
                            oldMinimumOS=minimum, newMinimumOS=0x100100,
                            historicalSDKAndToolRecordPreserved=True,
                            changedByteOffsets=differences,
                            allExecutableSectionsAndAuthenticatedFixupsByteExact=True))
    need({row['key'] for row in reports} == expected, 'All and only the three reviewed images')
    for row in stage['stagedImages']:
        need(pin(row['staged']['path']) == row['staged'], 'Frozen staged sources unchanged')
    (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    result = dict(schema='Actual independent27 iOS loader declaration source port v1',
                  stageCandidate=pin(candidate), reader=pin(reader), builder=pin(__file__),
                  actualPorts=reports, actualDyldValidationPassed=True,
                  ABICompatibilityEstablishedByThisPort=False,
                  codeSigned=False, imagesLoaded=False, deviceOperations=0,
                  guestBoot=False, readyForDeviceExecution=False)
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    pins = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
    pins += [pin(candidate), pin(reader), pin(__file__)] + [row['source'] for row in reports]
    (out / 'freeze.json').write_text(json.dumps(dict(candidate=pin(out / 'candidate.json'), pins=pins),
                                               indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          actualPortedImages=len(reports), deviceOperations=0)))


if __name__ == '__main__':
    main()
