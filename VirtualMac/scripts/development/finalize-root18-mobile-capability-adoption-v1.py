#!/usr/bin/env python3
"""Bind the one Root18 unsigned composition to actual new-source schemas."""
from pathlib import Path
import argparse
import hashlib
import json
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    need(out.parent == N and not out.exists(), 'fresh adoption directory')
    base = N / 'vm-hv-production-root18-mobile-capability-local-v1-attempt1'
    inherited = N / 'cpu-dtr-factory-local-v21-attempt2'
    acq = N / 'cpu-mobile-capability-admission-source-v3-attempt3'
    cpu = json.loads((base / 'candidate.json').read_text())
    admission = json.loads((acq / 'candidate.json').read_text())
    seen = {Path(__file__).resolve()}
    for directory in [base, inherited, acq]:
        freeze = directory / 'freeze.json'
        for row in json.loads(freeze.read_text())['files']:
            need(pin(row['path']) == row, 'freeze pin: ' + row['path'])
            seen.add(Path(row['path']).resolve())
        seen.add(freeze)
    for row in admission['sourceFiles'] + admission['actualIncludeClosure']:
        need(pin(row['path']) == row, 'actual acquisition source/include pin')
    need(cpu['acquisitionObject'] == admission['productionObject'], 'exact frozen new acquisition object')
    need(cpu['actualExports'] == 153 and cpu['actualNativeImports'] == 82 and
         cpu['inheritedNativeImports'] == 71 and len(cpu['addedNativeImports']) == 11 and
         cpu['removedNativeImports'] == [], 'actual whole 153 exports and 71+11 native imports')
    factory22 = base / 'modern_cpu_native_public_factory_v22.o'
    factory21 = inherited / 'modern_cpu_native_public_factory_v21.o'
    need(factory22.read_bytes() == factory21.read_bytes(), 'F22 is byte-identical to actual frozen F21 object')
    for mode in ['normal', 'san']:
        model = admission['models'][mode]
        need(model['checks'] == 373 and model['actualNativeOperations'] == 0 and
             model['guardedNative0ModelCalls'] == 1 and model['UIDs'] == [0, 501] and
             model['sourceTestingOnIOSAllowed'] is False, 'new bounded admission model evidence')
    proof = Path(cpu['addedCurrentNativeDefinitionProof']['path'])
    need(pin(proof) == cpu['addedCurrentNativeDefinitionProof'], 'exact eleven current definitions')
    definitions = json.loads(proof.read_text())
    need(len(definitions['definitions']) == 11 and definitions['missingDefinitions'] == [], 'no added native gap')
    lower_objects = [row for row in cpu['reusedObjectPins']
                     if row['path'].endswith('/modern_cpu_kernel_lifecycle_v23.o')]
    need(len(lower_objects) == 1, 'one actual Life23 lower owner registry object')
    old_acq = cpu['replacedObjects']['acquisition'][0]
    need(not any(row['path'] == old_acq['path'] for row in cpu['reusedObjectPins']),
         'root-only acquisition is absent from actual Root18 link')
    # Root16 already resolved the unchanged 71 base names to current captures.
    # This record supplements that basis with the new eleven exact imports.
    native_base = N / 'vm-hv-production-root16-current-native-closure-v1'
    native_base_closure = native_base / 'closure.json'
    native_base_freeze = native_base / 'freeze.json'
    for row in json.loads(native_base_freeze.read_text())['files']:
        need(pin(row['path']) == row, 'inherited 71 native definition pin')
        seen.add(Path(row['path']).resolve())
    seen |= {native_base_closure, native_base_freeze}
    out.mkdir()
    record = dict(
        schema='Root18 actual unsigned one-registry mobile-capability adoption v1',
        finalizer=pin(__file__), candidate=pin(base / 'candidate.json'),
        sourceFreeze=pin(base / 'freeze.json'), provider=cpu['provider'],
        inheritedF21Candidate=pin(inherited / 'candidate.json'), inheritedF21Freeze=pin(inherited / 'freeze.json'),
        acquisitionCandidate=pin(acq / 'candidate.json'), acquisitionFreeze=pin(acq / 'freeze.json'),
        acquisitionObject=admission['productionObject'], acquisitionSourceFiles=admission['sourceFiles'],
        acquisitionActualIncludeClosure=admission['actualIncludeClosure'],
        sourcePinSchemaFallbackExplained='The immutable composition candidate references the full AcquisitionV3 candidate/freeze; this final record expands its sourceFiles and actualIncludeClosure keys.',
        acquisitionModels=admission['models'], inherited689ModelsRepeated=False,
        factory21Object=pin(factory21), factory22Object=pin(factory22), factoryObjectsByteIdentical=True,
        actualExports=153, actualNativeImports=82, inheritedNativeImports=71, addedNativeImports=11,
        inheritedCurrentNativeDefinitionClosure=pin(native_base_closure),
        inheritedCurrentNativeDefinitionFreeze=pin(native_base_freeze),
        addedCurrentNativeDefinitionProof=pin(proof), singleCPURegistry=True,
        rootOnlyAcquisitionRemoved=True, allDTRAndBoot14AndProductionOpsObjectsRetained=True,
        allowedUIDs=[0, 501], actualIdentityAndEntitlementAdmissionImplemented=True,
        actualKernelPermissionStillRequired=True, hostFiniteCompositionPassed=True, findings=[],
        codeSigned=False, deviceOperations=0, nativeOperations=0,
        mobileNativeCapabilityExecuted=False, guestBoot=False)
    finalization = out / 'finalization.json'
    finalization.write_text(json.dumps(record, indent=2) + '\n')
    seen.add(finalization)
    freeze = out / 'freeze.json'
    freeze.write_text(json.dumps(dict(schema='Root18 source/object/current-native adoption freeze v1',
        files=[pin(path) for path in sorted(seen)], deviceOperations=0, nativeOperations=0), indent=2) + '\n')
    print(json.dumps(dict(finalization=pin(finalization), freeze=pin(freeze), provider=cpu['provider'],
                         actualExports=153, actualNativeImports=82)))

if __name__ == '__main__':
    main()
