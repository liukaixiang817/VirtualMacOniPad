#!/usr/bin/env python3
"""Apply four exact DTR bodies to the actual composed graph, in fresh files."""
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
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, message):
    if not value:
        raise ValueError(message)


def check(value):
    if isinstance(value, dict):
        if {'path', 'bytes', 'sha256'} <= value.keys():
            actual = pin(value['path'])
            need(all(actual[k] == value[k] for k in actual), 'Frozen input changed')
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
    need(out.is_relative_to(N) and not out.exists(), 'Fresh diagnostic output')
    source = N / 'independent27-essential-ports-stage-v2-attempt1/candidate.json'
    need(pin(source)['sha256'] == 'd245e779eecef6d0509aa922a96037596a2d5a3f8b62e6a8ceec0929de681d10', 'Actual composed graph')
    dtr = N / 'original27-dtr-methods-source-port-data-v1-attempt1/candidate.json'
    need(pin(dtr)['sha256'] == '79fb62984d92de302abca18fb6d31f6d66bc127dea55c148f3edc6937f6e243d', 'Exact DTR source port')
    for path in [source, dtr]:
        check(json.loads((path.parent / 'freeze.json').read_bytes()))
    recipe_path = dtr.parent / 'patch-recipe.json'
    recipe = json.loads(recipe_path.read_bytes())
    need(pin(recipe_path)['sha256'] == 'f07793de888e06df008ad39535af5c31aa931d0d4d4762c85b7d7b0635df2c44', 'Finite four-body recipe')
    graph = json.loads(source.read_bytes())
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('dtr_compose_macho', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = next(row for row in graph['stagedImages'] if row['key'] == 'VM27HVVMProduction.dylib')
    need(pin(root['staged']['path'])['sha256'] == recipe['replacementProvider']['sha256'], 'Actual single F21 CPU registry')
    provider = module.MachO(Path(root['staged']['path']).read_bytes())
    for name, entry in recipe['newDynamicallyResolvedSymbols'].items():
        need(provider.exports['_' + name] == entry, 'Actual DTR wrapper export')
    out.mkdir()
    flat = out / 'flat'
    flat.mkdir()
    reports = []
    patches = []
    for row in graph['stagedImages']:
        need(pin(row['staged']['path']) == row['staged'], 'Exact actual source')
        raw = Path(row['staged']['path']).read_bytes()
        before = module.MachO(raw)
        data = bytearray(raw)
        if row['key'] == 'com.apple.Virtualization.VirtualMachine':
            need(before.uuid == recipe['mainUUID'], 'Actual original main UUID')
            for patch in recipe['codePatches']:
                offset = before.file(0x100000000 + patch['startRVA'])
                old = bytes.fromhex(patch['beforeHex'])
                new = bytes.fromhex(patch['afterHex'])
                need(len(old) == len(new) == patch['endRVA'] - patch['startRVA'], 'Exact whole-body extent')
                need(raw[offset:offset + len(old)] == old, 'DTR byte range does not overlap another authored port')
                data[offset:offset + len(new)] = new
                patches.append(dict(startRVA=patch['startRVA'], fileOffset=offset, bytes=len(new)))
            after = module.MachO(bytes(data))
            need(before.uuid == after.uuid and before.commands == after.commands and
                 before.imports == after.imports and before.exports == after.exports and before.binds == after.binds,
                 'All headers, imports, exports and authenticated fixups unchanged')
            allowed = {position for patch in patches for position in range(patch['fileOffset'], patch['fileOffset'] + patch['bytes'])}
            need(all(index in allowed for index, (a, b) in enumerate(zip(raw, data)) if a != b), 'Only four body ranges may change')
            need(bytes(data[0x2e9d4c:0x2e9d50]) == struct.pack('<I', 0x9404a45a), 'Original VM setup call')
        path = flat / row['key']
        path.write_bytes(data)
        path.chmod(0o600)
        reports.append(dict(key=row['key'], source=row['staged'], staged=pin(path), UUID=before.uuid,
                            codeSignatureStaleUntilFinalSigning=True))
    need(len(patches) == 4, 'All four actual DTR methods')
    child = flat / 'com.apple.Virtualization.VirtualMachine'
    result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(child)], capture_output=True, timeout=30)
    (out / 'vmm-validate.stdout').write_bytes(result.stdout)
    (out / 'vmm-validate.stderr').write_bytes(result.stderr)
    need(result.returncode == 0, 'Actual composed VMM validation')
    graph.update(schema='Actual independent27 essential DTR graph stage v3',
                 baseStage=pin(source), dtrSourcePort=pin(dtr), dtrRecipe=pin(recipe_path),
                 stagedImages=reports, actualDTRBodyPatches=patches,
                 CPUFourDTRCallerPortsStillRequired=False,
                 remainingOriginalGetContextCalls=28, remainingEffectiveGetContextPaths=20,
                 remainingCPUContextPortsRequired=True,
                 actualCurrentCPUWholeProviderAdopted=True,
                 CPUProductionRootVersion=17, CPUFactoryVersion=21,
                 actualOriginalVMMPortsExecuted=False,
                 builder=pin(__file__), reader=pin(reader), guestBoot=False,
                 readyForDeviceExecution=False, finalStrongDefinitionGraphClosed=False)
    (out / 'candidate.json').write_text(json.dumps(graph, indent=2) + '\n')
    pins = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
    pins += [pin(path) for path in [source, dtr, recipe_path, reader, Path(__file__)]]
    pins += [row['staged'] for row in json.loads(source.read_bytes())['stagedImages']]
    (out / 'freeze.json').write_text(json.dumps(dict(candidate=pin(out / 'candidate.json'), pins=pins), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          actualImages=len(reports), actualDTRBodies=4)))


if __name__ == '__main__':
    main()
