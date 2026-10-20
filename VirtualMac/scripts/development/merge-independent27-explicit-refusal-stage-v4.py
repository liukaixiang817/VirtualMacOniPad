#!/usr/bin/env python3
"""Compose finite unsupported state refusals into fresh actual stage files.

The 19 methods do not implement their architectural state. An actual call
still reaches the original assertion/crash boundary. This stage prevents
access through an incompatible native context; successful cold boot requires
device evidence that its selected profile does not request these methods.
"""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def check(value):
    if isinstance(value, dict):
        if {'path', 'bytes', 'sha256'} <= value.keys():
            actual = pin(value['path'])
            need(all(actual[key] == value[key] for key in actual), 'exact frozen input: '+value['path'])
        else:
            for child in value.values():
                check(child)
    elif isinstance(value, list):
        for child in value:
            check(child)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    output = parser.parse_args().output.resolve()
    need(output.parent == N and not output.exists(), 'fresh diagnostic output')
    source = N/'independent27-essential-dtr-stage-v3-attempt1/candidate.json'
    need(pin(source)['sha256'] == '3fa967eaff477b81774e48d72736f7bad31eccf141f921176f5db63cfa184701', 'actual frozen73 source')
    recipes = [
        (N/'original27-optional-state-fields-fail-closed-data-v1-attempt1/patch-recipe.json',
         'c828691dcd18542d2066b4f46436453a7613481cecbf5f23c34cfd701be35238', 'codePatches'),
        (N/'original27-el2-tso-explicit-refusal-data-v1-attempt1/patch-recipe.json',
         'fe17fff2782482a0a4eccf3fd114a26877478693866ea8f806c66c2de2186345', 'patches')]
    for path in [source, *[row[0] for row in recipes]]:
        check(json.loads((path.parent/'freeze.json').read_bytes()))
    patches = []
    for path, digest, key in recipes:
        need(pin(path)['sha256'] == digest, 'exact finite method recipe')
        recipe = json.loads(path.read_bytes())
        patches.extend(recipe[key])
    need(len(patches) == 19, 'exact finite 19 methods')
    graph = json.loads(source.read_bytes())
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    sp = importlib.util.spec_from_file_location('explicit_refusal_stage_reader', reader)
    macho = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(macho)
    output.mkdir(mode=0o700)
    flat = output/'flat'
    flat.mkdir(mode=0o700)
    images = []
    applied = []
    for row in graph['stagedImages']:
        need(pin(row['staged']['path']) == row['staged'], 'actual source image pin')
        data = pathlib.Path(row['staged']['path']).read_bytes()
        original = macho.MachO(data)
        result = bytearray(data)
        if row['key'] == 'com.apple.Virtualization.VirtualMachine':
            need(original.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'original child identity')
            allowed = set()
            for patch in patches:
                at = original.file(original.base+patch['startRVA'])
                before = bytes.fromhex(patch['beforeHex'])
                after = bytes.fromhex(patch['afterHex'])
                need(len(before) == len(after) == patch['endRVA']-patch['startRVA'], 'unchanged whole body extent')
                indices = set(range(at, at+len(before)))
                need(not allowed & indices and data[at:at+len(before)] == before, 'disjoint exact original method')
                allowed.update(indices)
                result[at:at+len(after)] = after
                applied.append(dict(startRVA=patch['startRVA'], endRVA=patch['endRVA'], fileOffset=at,
                                    bytes=len(after), architectureStateImplemented=False,
                                    actualCallOutcome='original assertion failed __os_crash plus BRK1'))
            composed = macho.MachO(bytes(result))
            need(original.uuid == composed.uuid and original.commands == composed.commands and
                 original.sections == composed.sections and original.imports == composed.imports and
                 original.binds == composed.binds and original.exports == composed.exports,
                 'original UUID, metadata, true imports and all authenticated chain words unchanged')
            need(all(i in allowed for i, (before, after) in enumerate(zip(data, result)) if before != after),
                 'only finite19 method bodies changed')
            need(struct.unpack_from('<I', result, original.file(original.base+0x2e9d4c))[0] == 0x9404a45a,
                 'genuine VM setup BL untouched')
        target = flat/row['key']
        target.write_bytes(result)
        target.chmod(0o600)
        images.append(dict(key=row['key'], source=row['staged'], staged=pin(target), UUID=original.uuid,
                           codeSignatureStaleUntilFinalSigning=True))
    child = flat/'com.apple.Virtualization.VirtualMachine'
    validated = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(child)], capture_output=True, timeout=30)
    (output/'vmm-validate.stdout').write_bytes(validated.stdout)
    (output/'vmm-validate.stderr').write_bytes(validated.stderr)
    need(validated.returncode == 0, 'actual composed VMM dyld structure')
    graph.update(schema='Actual independent27 explicit unsupported state refusal graph stage v4',
                 baseStage=pin(source), unsupportedStateRecipes=[pin(row[0]) for row in recipes],
                 stagedImages=images, actualFiniteUnsupportedMethodPatches=applied,
                 remainingOriginalGetContextCalls=8,
                 remainingGetContextScope='eight original full-frame calls gated by true CPU model<=3; new default constructor writes4',
                 originalVMMUnsupportedStateMethods=19, originalVMMUnsupportedContextAccesses=20,
                 optionalArchitectureStateImplemented=False, unsupportedVirtualConsumersProvedUnreachable=False,
                 unsupportedMethodActualOutcome='original assertion failed __os_crash plus BRK1; original child terminates',
                 remainingCPUContextPortsRequired=True,
                 sourceDefaultModel4FrameGatesEstablished=True, actualColdBootProfileNotYetExecuted=True,
                 builder=pin(__file__), reader=pin(reader), guestBoot=False, deviceOperations=0,
                 readyForDeviceExecution=False, finalStrongDefinitionGraphClosed=False)
    (output/'candidate.json').write_text(json.dumps(graph, indent=2)+'\n')
    frozen = [pin(path) for path in sorted(output.rglob('*')) if path.is_file()]
    frozen.extend([pin(source), pin(reader), pin(__file__), *[pin(row[0]) for row in recipes],
                   *[row['staged'] for row in json.loads(source.read_bytes())['stagedImages']]])
    (output/'freeze.json').write_text(json.dumps({'pins': frozen, 'deviceOperations': 0, 'guestBoot': False}, indent=2)+'\n')
    print(json.dumps({'candidate': pin(output/'candidate.json'), 'freeze': pin(output/'freeze.json'),
                      'actualImages': len(images), 'actualFiniteUnsupportedMethods': len(applied),
                      'unsupportedArchitectureStateImplemented': False, 'guestBoot': False}))


if __name__ == '__main__':
    main()
