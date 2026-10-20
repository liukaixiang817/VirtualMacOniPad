#!/usr/bin/env python3
"""HELD Stage12: repair only the genuine compiler production lookup path.

Stage11's original child metadata port and all other76 image bytes are kept.
No code signing, device calls, policy application or false init success occurs.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
ADAPTER = 'VM27SandboxInitOwnedCompilerV1.dylib'
CHILD = 'com.apple.Virtualization.VirtualMachine'
COMPILER_PATH = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/VM27GenuineSandboxCompiler27.dylib'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def frozen(directory, filename, sha, inputs):
    path = NODE / directory / filename
    need(pin(path)['sha256'] == sha, 'exact frozen candidate')
    freeze = path.parent / 'freeze.json'
    for row in json.loads(freeze.read_bytes())['files']:
        need(pin(row['path']) == row, 'actual frozen bytes: ' + row['path'])
    inputs.extend([pin(path), pin(freeze)])
    return path, json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == NODE and not out.exists(), 'fresh own Stage12 directory')
    out.mkdir(mode=0o700)
    inputs, steps = [], []
    try:
        stage_path, stage = frozen('independent27-owned-sandbox-stage-v11-attempt1', 'candidate.json',
            'bd0cb75cf50ab9e1d0fc91004303ebc2018cf2f14429481a883ca9568b25519e', inputs)
        graph_path = stage_path.parent / 'verification.json'
        need(pin(graph_path)['sha256'] == '10023c0154fe7e1441a83c2e6d0bad6e0385f3929ebade7267acddbebbba84f7', 'exact Stage11 graph')
        baseline = json.loads(graph_path.read_bytes())
        inputs.append(pin(graph_path))
        adapter_path, adapter = frozen('sandbox-init-owned-compiler-adapter-local-v3-attempt1', 'candidate.json',
            '361e1f57c14df33ae0f1024d4c209373bf96e970bab308e8df63fcbfebca0f81', inputs)
        closure_path, closure = frozen('sandbox-owned-compiler-adapter-current-definitions-v3-attempt1', 'report.json',
            '99f7b4849c85fe62aedf8b0017baa525270d0cf51e10aded44bbb26accabf46b', inputs)
        reader = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
        native_path = NODE / 'current-native-header-export-index-v3/index.json'
        inputs += [pin(__file__), pin(reader), pin(native_path)]
        spec = importlib.util.spec_from_file_location('genuine_sandbox_path_stage_reader', reader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        need(pin(reader)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b' and
             pin(native_path)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019', 'actual reader and native67')
        native = json.loads(native_path.read_bytes())['images']
        need(stage['actualImages'] == baseline['actualImages'] == 77 and baseline['actualStrongImports'] == 5673
             and baseline['unresolvedStrongImportRows'] == [] and baseline['requiredSelectedLoadGaps'] == [], 'inherited actual zero-unresolved Stage11')
        need(adapter['onlySourceDeltaActualChildCompilerMacOSPath'] and adapter['StageIntegrationHeld'], 'new exact source-only path delta')
        path_contract = json.loads(Path(adapter['actualProductionCompilerPathContract']['path']).read_bytes())
        need(path_contract['expectedFixedCompilerDlopenPath'] == COMPILER_PATH and
             path_contract['actualBinaryContainsExpectedFullPath'] and path_contract['duplicateRootCopyAdded'] is False,
             'actual producer and production child/MacOS path contract')
        flat = out / 'flat'
        flat.mkdir(mode=0o700)
        old_rows = {row['key']: row for row in stage['stagedImages']}
        new_bytes = Path(adapter['binary']['path']).read_bytes()
        need(pin(adapter['binary']['path']) == adapter['binary'], 'actual AdapterV3 unsigned bytes')
        old_adapter = module.MachO(Path(old_rows[ADAPTER]['staged']['path']).read_bytes())
        new_adapter = module.MachO(new_bytes)
        need(new_adapter.exports == old_adapter.exports == {'_VM27SandboxInitWithOwnedCompilerV1': {'flags': 0, 'address': 0x4000}}, 'real unchanged adapter public ABI')
        need(new_adapter.loads == old_adapter.loads and len(new_adapter.imports) == len(old_adapter.imports) == 33,
             'actual adapter dependency and import count unchanged')
        for old, actual in zip(old_adapter.imports, new_adapter.imports):
            need(dict(old, at=actual['at']) == actual and actual['ordinal'] == 1 and not actual['weak'], 'only actual path delta, same strong import semantics')
        need(COMPILER_PATH.encode() + b'\0' in new_bytes, 'actual final AdapterV3 full compiler path literal')
        rows, unchanged = [], []
        for key, old in sorted(old_rows.items()):
            source = adapter['binary'] if key == ADAPTER else old['staged']
            need(pin(source['path']) == source, 'exact actual selected source')
            target = flat / key
            target.write_bytes(Path(source['path']).read_bytes())
            target.chmod(0o600)
            row = copy.deepcopy(old)
            row.update(source=source, staged=pin(target))
            if key == ADAPTER:
                row.update(UUID=new_adapter.uuid, codeSignatureStaleUntilFinalSigning=False)
            else:
                need(target.read_bytes() == Path(old['staged']['path']).read_bytes(), 'actual other76 wholebyte unchanged')
                unchanged.append(key)
            rows.append(row)
        need(len(rows) == 77 and len(unchanged) == 76 and CHILD in unchanged, 'only actual AdapterV3 replacement; original VMM wholebyte unchanged')
        resources = []
        for old in stage['genuineSandboxResources']:
            source = old['local']
            need(pin(source['path']) == source and old['kind'] == 'resource', 'frozen exact genuine data resource')
            target = out / 'resources' / old['runtimeRelativePath']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(Path(source['path']).read_bytes())
            target.chmod(0o600)
            row = copy.deepcopy(old)
            row.update(local=pin(target))
            resources.append(row)
        need({row['id'] for row in resources} == {'child-sandbox-profile', 'child-sandbox-system-import', 'child-sandbox-dyld-import'}, 'actual three original resources preserved')

        # Independently join each actual AdapterV3 import to the freshly
        # captured-native closure rather than re-resolving unchanged5673 rows.
        native_routes = {row['importName']: row for row in closure['actualReexportRoutes']}
        increment = []
        for imp in new_adapter.imports:
            route = native_routes[imp['name']]['actualRoute']
            converted = []
            for position, hop in enumerate(route):
                image = native[hop['image']]
                need(image['UUID'] == hop['UUID'], 'actual current native route UUID')
                step = dict(kind='native', path=hop['image'], symbol=hop['symbol'])
                if 'definition' in hop:
                    need(image['definitions'][hop['symbol']] == hop['definition'], 'actual native export bytes')
                    step['actualExport'] = hop['definition']
                dependency = hop.get('wholeDylibReexport', hop.get('reexportDependency'))
                if dependency:
                    need(next(row for row in image['dependencies'] if row['ordinal'] == dependency['ordinal']) == dependency,
                         'actual native dependency command/ordinal')
                    need(position + 1 < len(route) and route[position + 1]['image'] == dependency['path'], 'actual recursive route')
                else:
                    step['UUID'] = hop['UUID']
                converted.append(step)
            need(converted[0]['path'] == '/usr/lib/libSystem.B.dylib' and converted[0]['symbol'] == imp['name']
                 and converted[-1]['actualExport']['flags'] == 0, 'current actual direct native final definition')
            increment.append(dict(importer=ADAPTER, actualImport=imp, resolution=dict(resolved=True, route=converted)))
        actual_child = module.MachO((flat / CHILD).read_bytes())
        selected = actual_child.imports[428]
        need(selected['name'] == '_VM27SandboxInitWithOwnedCompilerV1' and selected['ordinal'] == 57 and not selected['weak'],
             'actual original Stage11 child retained own adapter binding')
        increment.append(dict(importer=CHILD, actualImport=selected, resolution=dict(resolved=True, route=[dict(
            kind='own', path=ADAPTER, symbol=selected['name'], actualExport=new_adapter.exports[selected['name']], UUID=new_adapter.uuid)])))
        lookup = {(row['importer'], row['actualImport']['index']): row for row in increment}
        strong_rows = [lookup.get((row['importer'], row['actualImport']['index']), row) for row in baseline['actualStrongImportRows']]
        need(len(increment) == 34 and len(strong_rows) == 5660 and len(baseline['actualNativeWeakDefinitionRows']) == 13,
             'only34 actual incremental definitions; 5673 total row meanings preserved')
        need(all(row['actualImport'] == new_adapter.imports[row['actualImport']['index']] for row in strong_rows if row['importer'] == ADAPTER),
             'all33 current adapter raw import records joined')
        need(all(row['resolution']['resolved'] for row in strong_rows), 'new34 and inherited actual all strong definitions')
        argv = ['xcrun', 'dyld_info', '-validate_only', str(flat / ADAPTER)]
        result = subprocess.run(argv, capture_output=True, timeout=30)
        (out / 'new-adapter-validate.stdout').write_bytes(result.stdout)
        (out / 'new-adapter-validate.stderr').write_bytes(result.stderr)
        steps.append(dict(arguments=argv, exit=result.returncode))
        need(result.returncode == 0, 'actual new staged AdapterV3 validation')
        actual_probe = NODE / 'native-sandbox-apply-compat-device-v6-arm64-execpolicy-attempt1/actual-execute/stdout'
        need(pin(actual_probe)['sha256'] == 'e576ac0b4c690c1e5e0ccce1269762900b055c968742f7477ada1aa3185a5e37' and
             b'APPLY_RESULT count=1 return=-1 errno=45' in actual_probe.read_bytes(), 'actual previously executed native ENOTSUP evidence; not success')
        inputs.append(pin(actual_probe))
        save(out / 'incremental-34-definition-rows.json', increment)
        for obsolete in ['actualOther72ImagesByteIdentical', 'actualAddedImages', 'actualIncrementalResolvedImportRows']:
            stage.pop(obsolete, None)
        stage.update(schema='HELD Stage12 genuine compiler path corrected to actual child XPC MacOS directory',
            builder=pin(__file__), baseStage=pin(stage_path), prior=pin(stage_path), stagedImages=rows,
            actualOnlyReplacedImages=[ADAPTER], actualUnchangedOtherImages=76, actualOther76ImagesByteIdentical=True,
            actualOriginalChildWholeImageByteIdentical=True, genuineSandboxResources=resources,
            ownedSandboxAdapterCandidate=pin(adapter_path), fixedOwnedCompilerDlopenPath=COMPILER_PATH,
            actualProductionCompilerPathContract=adapter['actualProductionCompilerPathContract'],
            previousStage11WrongCompilerRootPathExplicitlySuperseded=True, oldStage11FrozenPreserved=True,
            actualIncrementalResolvedImportRows=34, definitionGraphOutputPath=str(out / 'verification.json'),
            actualNativeCompatibilityProbe=pin(actual_probe), nativeCompatibilityProbeReturn=-1, nativeCompatibilityProbeErrno=45,
            nativeCompatibilityProbeProductionOpaqueObject=False, nativeCompatibilityProbeAccepted=False,
            nativeApplyAndKernelPolicyCompatibilityVerified=False, nativeCompiledBytecodeCompatibilityVerified=False,
            finalStrongDefinitionGraphClosed=True, HELDUntilActualNativeApplyAndOracle=True,
            readiness='HELD: genuine Mac27 serialized profile actually rejected by native iPad apply ENOTSUP; no production init success',
            codeSigned=False, actualCodeSigned=False, readyForDeviceExecution=False, loaderExecuted=False,
            deviceOperations=0, trustCacheOperations=0, guestBoot=False)
        save(out / 'candidate.json', stage)
        proof = copy.deepcopy(baseline)
        proof.update(schema='Actual Stage12 graph: immutable Stage11 inheritance and34 genuine path-adapter definition joins v1',
            actualStrongImportRows=strong_rows, sources=[pin(out / 'candidate.json'), pin(native_path), pin(reader), pin(__file__), pin(graph_path)] + [row['staged'] for row in rows],
            inheritedExactPreviousVerification=pin(graph_path), inheritedActualStrongDefinitionRows=5639,
            incrementallyResolvedActualStrongRows=34, StageIntegrationHeld=True, actualSandboxApplyExecuted=False,
            deviceOperations=0, loaderExecuted=False, guestBoot=False)
        save(out / 'verification.json', proof)
        save(out / 'actual-validation-steps.json', steps)
        files = [pin(path) for path in sorted(out.rglob('*')) if path.is_file()]
        files += inputs + [row['staged'] for row in old_rows.values()] + [adapter['binary'], adapter['actualProductionCompilerPathContract']]
        save(out / 'freeze.json', dict(schema='HELD Stage12 path-correction actual source and output freeze v1',
            files=list({row['path']: row for row in files}.values()), deviceOperations=0, codeSigned=False,
            readiness='HELD with actual ENOTSUP', nativeApplyCompatibilityVerified=False))
        print(json.dumps(dict(candidate=pin(out / 'candidate.json'), verification=pin(out / 'verification.json'),
            freeze=pin(out / 'freeze.json'), images=77, other76WholeBytes=True, actualIncrement=34, readiness='HELD')))
    except Exception as error:
        save(out / 'failure.json', dict(error=repr(error), inputs=inputs, steps=steps, deviceOperations=0, codeSigned=False))
        raise


if __name__ == '__main__':
    main()
