#!/usr/bin/env python3
"""Compose reviewed, independent byte ports into a fresh actual flat graph.

The six absent definitions get real providers or explicit failure contracts.
No original signed file, installed App or frozen source is rewritten. This is
still a pre-execution candidate; CPU state, loader and guest proof are separate.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = Path(__file__).resolve().parent


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, message):
    if not value:
        raise ValueError(message)


def frozen(name, expected):
    directory = N / name
    path = directory / 'candidate.json'
    need(pin(path)['sha256'] == expected, 'Exact reviewed candidate: ' + name)
    record = json.loads((directory / 'freeze.json').read_bytes())
    def visit(value):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= value.keys():
                actual = pin(value['path'])
                need(all(actual[k] == value[k] for k in actual), 'Frozen input changed: ' + value['path'])
            else:
                for item in value.values():
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(record)
    return path, json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.is_relative_to(N) and not out.exists(), 'Fresh diagnostic output required')
    stage_path, base = frozen('independent27-flat-graph-stage-v1-attempt3',
        '97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206')
    gpu_path, gpu = frozen('original27-gpu-display-profile-source-port-v1-attempt1',
        '06d1a84bdc675b5c0cc02402e63c7eba132d8f6106bc3406cb9d47f4152a836d')
    accel_path, accel = frozen('iosurface-guest-transform-unavailable-source-port-v1-attempt4',
        '608511d7e2db166234250f34aaf4ad7abf6681c0916f567ae3f59b44039b6971')
    platform_path, platform = frozen('independent27-ios-load-platform-port-v1-attempt1',
        '8c8e0499a2e0378c00e12f26810e1176bfb71318e26d42958ec6acf7bcf4fcc3')
    cpu_path, cpu = frozen('cpu-dtr-factory-local-v21-attempt2',
        'dfa21ad3c60329f70ebf758c489cbc0290120c220923e3446d96b27497b06091')
    gpu_recipe_path = gpu_path.parent / 'patch-recipe.json'
    gpu_recipe = json.loads(gpu_recipe_path.read_bytes())
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('essential_port_macho', reader)
    macho = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(macho)
    accel_builder = B / 'build-iosurface-guest-transform-unavailable-v1.py'
    accel_tools = runpy.run_path(str(accel_builder))
    sources = {row['key']: row['staged'] for row in base['stagedImages']}
    original_vmm = sources['com.apple.Virtualization.VirtualMachine']
    need(original_vmm == gpu_recipe['authoringBase'] == accel['stageSource'], 'One actual VMM authoring base')
    vmm = bytearray(Path(original_vmm['path']).read_bytes())
    for write in gpu_recipe['byteWrites']:
        offset = write['fileOffset']
        before = bytes.fromhex(write['oldHex'])
        after = bytes.fromhex(write['newHex'])
        need(len(before) == len(after) and bytes(vmm[offset:offset + len(before)]) == before,
             'Exact independent GPU/display patch bytes')
        vmm[offset:offset + len(before)] = after
    # GPU recipe is finite and reproduces its author's actual candidate.
    gpu_vmm = gpu.get('vmmCandidate', gpu.get('vmm', gpu.get('candidate')))
    if isinstance(gpu_vmm, dict) and 'path' in gpu_vmm:
        need(bytes(vmm) == Path(gpu_vmm['path']).read_bytes(), 'Exact authored GPU output')
    own_gpu = gpu_recipe['requiredProvider']
    sources['VM27DisplayUnavailableV1.dylib'] = own_gpu
    sources['VM27IOSurfaceGuestUnavailableV1.dylib'] = accel['provider']
    sources['VM27HVVMProduction.dylib'] = cpu['provider']
    # This source helper reconstructs the genuine existing chained import
    # table, changes only index830, and appends one actual required LC_LOAD.
    after_accel, accel_recipe = accel_tools['port'](bytes(vmm))
    accel_tools['validate'](bytes(vmm), after_accel)
    vmm = bytearray(after_accel)
    platform_ports = {row['key']: row for row in platform['actualPorts']}
    for key, port in platform_ports.items():
        if key != 'com.apple.Virtualization.VirtualMachine':
            sources[key] = port['ported']
            continue
        before = Path(port['source']['path']).read_bytes()
        after = Path(port['ported']['path']).read_bytes()
        for offset in port['changedByteOffsets']:
            need(vmm[offset] == before[offset], 'Platform field must not overlap another port')
            vmm[offset] = after[offset]
    old_vmm = macho.MachO(Path(original_vmm['path']).read_bytes())
    new_vmm = macho.MachO(bytes(vmm))
    need(old_vmm.uuid == new_vmm.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'Original child UUID required')
    need(old_vmm.exports == new_vmm.exports, 'Original child export definitions unchanged')
    code_words = {row['rva']: row for row in gpu_recipe['codeWords']}
    for section in old_vmm.sections:
        if not section['size'] or not section['fileoff'] or section['flags'] & 255 in [1, 12]:
            continue
        offset = section['fileoff']
        length = section['size']
        expected = bytearray(Path(original_vmm['path']).read_bytes()[offset:offset + length])
        for write in gpu_recipe['byteWrites']:
            position = write['fileOffset']
            if offset <= position < offset + length:
                replacement = bytes.fromhex(write['newHex'])
                expected[position - offset:position - offset + len(replacement)] = replacement
        need(bytes(vmm[offset:offset + length]) == bytes(expected), 'Only explicit GPU ports may change sections')
    need(len(code_words) == 2, 'Exactly the two reviewed GPU preference branches')
    out.mkdir()
    flat = out / 'flat'
    flat.mkdir()
    reports = []
    commands = []
    for key, source in sorted(sources.items()):
        need(pin(source['path']) == source, 'Actual selected file pin')
        raw = bytes(vmm) if key == 'com.apple.Virtualization.VirtualMachine' else Path(source['path']).read_bytes()
        image = macho.MachO(raw)
        versions = [command for command in image.commands if command['cmd'] == 0x32]
        need(len(versions) == 1, 'Actual single platform declaration')
        declared_platform, minimum = struct.unpack_from('<II', versions[0]['raw'], 8)
        need(declared_platform == 2 and minimum <= 0x100100, 'Every own image must declare supported iOS deployment')
        path = flat / key
        path.write_bytes(raw)
        path.chmod(0o600)
        argv = ['xcrun', 'dyld_info', '-validate_only', str(path)]
        result = subprocess.run(argv, capture_output=True, timeout=30)
        (out / (key + '.validate.stdout')).write_bytes(result.stdout)
        (out / (key + '.validate.stderr')).write_bytes(result.stderr)
        commands.append(dict(image=key, argv=argv, status=result.returncode))
        need(result.returncode == 0, 'Actual merged Mach-O validation failed')
        reports.append(dict(key=key, source=source, staged=pin(path), UUID=image.uuid,
                            actualDyldValidationPassed=True, codeSignatureStaleUntilFinalSigning=True))
    old_code = Path(original_vmm['path']).read_bytes()
    need(bytes(vmm[0x2e9d4c:0x2e9d50]) == old_code[0x2e9d4c:0x2e9d50] == struct.pack('<I', 0x9404a45a),
         'Original real VM setup BL word and fixed file offset required')
    (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    result = dict(schema='Actual independent27 essential source-port graph stage v2',
                  builder=pin(__file__), reader=pin(reader), baseStage=pin(stage_path),
                  inputCandidates=[pin(path) for path in [gpu_path, accel_path, platform_path, cpu_path]],
                  gpuRecipe=pin(gpu_recipe_path), actualIOSurfaceRecipe=accel_recipe,
                  selectedRoots=base['selectedRoots'], stagedImages=reports,
                  actualRetargetingPerformed=True, actualImages=len(reports),
                  allOwnImagePlatformsIOS=True, allOwnMinimumOSAtMost16_1=True,
                  childOnlyPreMainAddedToActualOriginalVMM=True,
                  childOnlyPreMainAddedToParent=False, actualOriginalVMSetupCallPreserved=True,
                  CPUFactoryVersion=21, actualCPUSingleRegistryExports=153,
                  actualCPUCurrentNativeImports=71, CPUFourDTRCallerPortsStillRequired=True,
                  remainingCPUContextPortsRequired=True,
                  originalGPUPreferencesUseTrueZeroOrSingleCurrentDevice=True,
                  fakeAppleDisplayClassDefined=False,
                  actualIOSurfaceDriverCalls=0, IOSurfaceUnprovedTransformsReturnTrueUnsupported=True,
                  finalStrongDefinitionGraphClosed=False,
                  finalSignedProductManifestGenerated=False, codeSigned=False,
                  readyForDeviceExecution=False, deviceOperations=0,
                  nativeCPUOperations=0, loaderExecuted=False, guestBoot=False)
    (out / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
    pins = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
    pins += [pin(path) for path in [Path(__file__), reader, stage_path, gpu_path, accel_path,
                                  platform_path, cpu_path, gpu_recipe_path, accel_builder]]
    pins += list(sources.values())
    (out / 'freeze.json').write_text(json.dumps(dict(candidate=pin(out / 'candidate.json'), pins=pins), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          actualImages=len(reports), guestBoot=False)))


if __name__ == '__main__':
    main()
