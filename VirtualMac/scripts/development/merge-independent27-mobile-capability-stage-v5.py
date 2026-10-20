#!/usr/bin/env python3
"""Copy Stage4, replacing only its stable CPU leaf with frozen Root18."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def need(value, message):
    if not value:
        raise ValueError(message)

def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def check(value):
    if isinstance(value, dict):
        if {'path', 'bytes', 'sha256'} <= value.keys():
            actual = pin(value['path'])
            need(all(actual[key] == value[key] for key in actual), 'frozen pin: ' + value['path'])
        else:
            for child in value.values():
                check(child)
    elif isinstance(value, list):
        for child in value:
            check(child)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    need(out.parent == N and not out.exists(), 'fresh Stage5 output')
    stage_path = N / 'independent27-explicit-refusal-stage-v4-attempt1/candidate.json'
    adoption_path = N / 'vm-hv-production-root18-mobile-capability-adoption-v1/finalization.json'
    need(pin(stage_path)['sha256'] == 'e2e3d9c0222229ecfacf7e0bb2eb8b04fb531409206cf70a137623b59286dd2b', 'exact Stage4')
    need(pin(adoption_path)['sha256'] == '0807e1303f8613fcc682afdffd5b5120d3e5fa437154eb2e907da8d68506e9ed', 'exact Root18 adoption')
    check(json.loads((stage_path.parent / 'freeze.json').read_text()))
    check(json.loads((adoption_path.parent / 'freeze.json').read_text()))
    stage = json.loads(stage_path.read_text())
    adoption = json.loads(adoption_path.read_text())
    check(adoption)
    provider = adoption['provider']
    need(provider['sha256'] == '3cac1fc1561995907ff47e0cb35153bb0816f38b9f0606371b9c5633db9dca4d', 'actual Root18 whole')
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('stage5_macho', reader)
    lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
    cpu = lib.MachO(Path(provider['path']).read_bytes())
    need(len(cpu.exports) == 153 and len(cpu.imports) == 82, 'actual Root18 ABI')
    out.mkdir(mode=0o700)
    flat = out / 'flat'
    flat.mkdir(mode=0o700)
    rows, retained = [], []
    replacements = 0
    for old in stage['stagedImages']:
        check(old['staged'])
        is_cpu = old['key'] == 'VM27HVVMProduction.dylib'
        source = provider if is_cpu else old['staged']
        data = Path(source['path']).read_bytes()
        target = flat / old['key']
        target.write_bytes(data)
        target.chmod(0o600)
        image = cpu if is_cpu else lib.MachO(data)
        rows.append(dict(key=old['key'], source=source, staged=pin(target), UUID=image.uuid,
                         codeSignatureStaleUntilFinalSigning=True))
        if is_cpu:
            replacements += 1
        else:
            need(data == Path(old['staged']['path']).read_bytes(), 'unchanged other image')
            retained.append(old['key'])
    need(replacements == 1 and len(rows) == 73 and len(retained) == 72, 'one leaf change in 73')
    child = lib.MachO((flat / 'com.apple.Virtualization.VirtualMachine').read_bytes())
    need(child.uuid == '4a6a588d1afd30f5a64d6304eb79be0b' and
         struct.unpack_from('<I', child.data, child.file(child.base + 0x2e9d4c))[0] == 0x9404a45a,
         'actual child UUID and setup BL remain exact')
    stage.update(schema='Actual independent27 mobile-capability Root18 graph stage v5',
        builder=pin(__file__), reader=pin(reader), baseStage=pin(stage_path), stagedImages=rows,
        CPUFactoryVersion=22, CPUProductionRootVersion=18,
        actualCPUSingleRegistryExports=153, actualCPUCurrentNativeImports=82,
        actualCurrentCPUWholeProviderAdopted=True, actualRoot18Provider=provider,
        root18Adoption=pin(adoption_path), root18SourceFreeze=adoption['sourceFreeze'],
        actualOnlyReplacedImage='VM27HVVMProduction.dylib', actualOther72ImagesByteIdentical=True,
        actualRetainedImageKeys=retained, actualMobileNative0StillUnexecuted=True,
        finalStrongDefinitionGraphClosed=False, finalSignedProductManifestGenerated=False,
        codeSigned=False, readyForDeviceExecution=False, loaderExecuted=False,
        deviceOperations=0, nativeCPUOperations=0, guestBoot=False)
    stage['inputCandidates'] = stage.get('inputCandidates', []) + [adoption['candidate'], pin(adoption_path)]
    candidate = out / 'candidate.json'
    candidate.write_text(json.dumps(stage, indent=2) + '\n')
    receipt = out / 'composition-receipt.json'
    receipt.write_text(json.dumps(dict(schema='Actual Stage5 one-leaf composition receipt v1',
        inputStage=pin(stage_path), adoptedRoot18=pin(adoption_path), replacedImage='VM27HVVMProduction.dylib',
        replacementSource=provider, replacementStaged=next(r['staged'] for r in rows if r['key']=='VM27HVVMProduction.dylib'),
        byteIdenticalOtherImages=retained, actualImages=73, actualCPUExports=153,
        actualCPUNativeImports=82, originalVMMUUIDAndSetupBLPreserved=True,
        deviceOperations=0, nativeCPUOperations=0), indent=2) + '\n')
    frozen = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
    frozen += [pin(__file__), pin(reader), pin(stage_path), pin(stage_path.parent / 'freeze.json'),
               pin(adoption_path), pin(adoption_path.parent / 'freeze.json'), provider]
    frozen += [row['staged'] for row in json.loads(stage_path.read_text())['stagedImages']]
    freeze = out / 'freeze.json'
    freeze.write_text(json.dumps(dict(pins=frozen, deviceOperations=0, guestBoot=False), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(candidate), freeze=pin(freeze), receipt=pin(receipt),
                          actualImages=73, unchangedOtherImages=72, actualCPUExports=153, actualCPUNativeImports=82)))

if __name__ == '__main__':
    main()
