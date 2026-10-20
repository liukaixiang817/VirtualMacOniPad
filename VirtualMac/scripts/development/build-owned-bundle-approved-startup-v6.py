#!/usr/bin/env python3
"""Compile the explicit owned consumer/startup; retain all frozen dependencies."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shlex
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'owned-app-external-signature-provider-v4-attempt1'
PREVIOUS = N / 'owned-app-postspawn-diagnostic-provider-v5-attempt4'
SOURCE = N / 'owned-bundle-consumer-startup-source-v6-attempt1'


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def core(row):
    return {key: row[key] for key in ('path', 'bytes', 'sha256')}


def need(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def section(text, begin, end=None):
    at = text.index(begin)
    return text[at:] if end is None else text[at:text.index(end, at)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'new local build directory')
    policy_candidate = args.policy_candidate.resolve()
    need(policy_candidate.parent.parent == N, 'local policy candidate')
    source_candidate = SOURCE / 'candidate.json'
    source_pin = pin(source_candidate)
    need(source_pin['bytes'] == 2605 and source_pin['sha256'] ==
         'c50aa1a7fbc4ce84d46c35f5045452e4efd1dcf0df6512cd4068530f494f257e',
         'reviewed exact root consumer/startup source candidate')
    input_pins = {}
    freezes = [SOURCE / 'freeze.json', BASE / 'freeze.json', PREVIOUS / 'freeze.json',
               policy_candidate.parent / 'freeze.json']
    for freeze in freezes:
        value = json.loads(freeze.read_bytes())
        rows = value.get('files', value.get('pins', []))
        need(isinstance(rows, list) and rows, 'nonempty real input freeze')
        for row in rows:
            expected = core(row)
            need(pin(row['path']) == expected, 'unchanged frozen input: ' + row['path'])
            input_pins[row['path']] = expected
        input_pins[str(freeze)] = pin(freeze)
    policy = json.loads(policy_candidate.read_bytes())
    need(pin(policy_candidate)['bytes'] == 10368 and pin(policy_candidate)['sha256'] ==
         'f7f66382a28639013fd051b787ddf0472fb2924c215335fb3bd77fa795d419d0',
         'exact frozen production policy candidate')
    need(policy.get('semantics', {}).get('deviceOperations') == 0 and
         policy.get('finiteHostSourceScopePassed') is True and
         policy.get('findings') == [], 'policy HOST-only source scope passed')
    need(str(S / 'vm27_owned_bundle_approved_policy_v1.c') in input_pins and
         str(S / 'vm27_owned_bundle_approved_policy_v1.h') in input_pins,
         'reviewed production policy included in its actual freeze')
    base = json.loads((BASE / 'candidate.json').read_bytes())
    previous = json.loads((PREVIOUS / 'candidate.json').read_bytes())
    v3 = (S / 'modern_xpc_large_private_consumer_v3.c').read_text()
    v4 = (S / 'modern_xpc_large_private_consumer_v4.c').read_text()
    v5 = (S / 'modern_xpc_large_private_consumer_v5.c').read_text()
    need(section(v3, 'int VM27LargePrivateServiceConsumerV2Create(',
                 'int VM27LargePrivateServiceConsumerV2Release(') ==
         section(v5, 'int VM27LargePrivateServiceConsumerV2Create(',
                 '/* This is a separate opt-in contract'), 'old Create modes 1/2 unchanged')
    need(section(v3, 'static int Authenticate(', 'int VM27LargePrivateServiceConsumerV2Create(') ==
         section(v5, 'static int Authenticate(', 'int VM27LargePrivateServiceConsumerV2Create('),
         'full original file authentication unchanged')
    need(section(v4, 'int VM27LargePrivateServiceConsumerV2Spawn(') ==
         section(v5, 'int VM27LargePrivateServiceConsumerV2Spawn(',
                 'int VM27LargePrivateServiceConsumerV2CheckMessage('), 'actual V4 spawn unchanged')
    need(section(v3, 'int VM27LargePrivateServiceConsumerV2CopyState(') ==
         section(v5, 'int VM27LargePrivateServiceConsumerV2CopyState('),
         'original state/wait/reap/statistics unchanged')
    object_rows = {pathlib.Path(row['path']).name: row for row in base['actualNewObjects']}
    reused_objects = [object_rows[name] for name in ('vm27_bundle_child_inspection_v1.o',
        'modern_xpc_large_strict_identity_v2.o', 'vm27_owned_app_parent_identity_v1.o')]
    for row in reused_objects:
        need(pin(row['path']) == core(row), 'actual frozen reused object')
    libraries = {row['name']: row for row in base['actualReusedLibraries']}
    for row in libraries.values():
        need(pin(row['path']) == core(row), 'actual frozen reused library')
    out.mkdir(mode=0o700)
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        save(out / 'commands.json', commands)
        need(result.returncode == 0, label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout

    sdk = run('ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    flags = ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
             '-O2', '-fblocks', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-Wno-deprecated-declarations', '-fptrauth-abi-version=0', '-I', S]
    objects = []
    closure = {}
    for name in ('modern_xpc_large_private_consumer_v5.c',
                 'vm27_owned_bundle_approved_policy_v1.c', 'vm27_owned_app_child_startup_v6.c'):
        source = S / name
        target = out / (source.stem + '.o')
        run('compile-' + source.stem, flags + ['-c', source, '-o', target])
        objects.append(target)
        dependencies = run('dependencies-' + source.stem, flags + ['-MM', source])
        for item in shlex.split(dependencies.decode().replace('\\\n', ' ').split(':', 1)[1]):
            row = pin(item)
            need(input_pins.get(row['path']) == row, 'actual source/include reviewed and frozen: ' + item)
            closure[row['path']] = row
    run('preprocess-startup-v6', flags + ['-E', '-P', S / 'vm27_owned_app_child_startup_v6.c'])
    consumer = out / 'VM27LargeConsumerV2.unsigned.dylib'
    consumer_names = ['VM27LargeRegistry.dylib', 'VM27ApprovedCode.dylib',
                      'VM27LWCRPolicy.dylib', 'VM27PrivateEndpoint.dylib']
    run('link-consumer-v5', flags + ['-dynamiclib'] + objects[:2] +
        [row['path'] for row in reused_objects[:2]] +
        [libraries[name]['path'] for name in consumer_names] +
        ['-framework', 'CoreFoundation', '-framework', 'Security',
         '-Wl,-install_name,@rpath/VM27LargeConsumerV2.dylib', '-Wl,-rpath,@loader_path',
         '-Wl,-current_version,1.0', '-Wl,-compatibility_version,1.0',
         '-Wl,-no_adhoc_codesign', '-o', consumer])
    adapter = out / 'VM27OwnedAppStartupV3.unsigned.dylib'
    adapter_names = ['VM27OwnedStartupV3.dylib', 'VM27LargeRegistry.dylib',
                     'VM27PrivateEndpoint.dylib', 'VM27OriginalV10Transport.dylib', 'VM27LWCRPolicy.dylib']
    run('link-startup-v6', flags + ['-dynamiclib', objects[2], reused_objects[2]['path'], consumer] +
        [libraries[name]['path'] for name in adapter_names] +
        ['-framework', 'CoreFoundation', '-framework', 'Security',
         '-Wl,-install_name,@loader_path/VM27OwnedAppStartupV3.dylib',
         '-Wl,-no_adhoc_codesign', '-o', adapter])
    for label, library in [('consumer', consumer), ('adapter', adapter)]:
        need(struct.unpack_from('<II', library.read_bytes(), 4) == (0x100000c, 0x80000002),
             'actual ARM64e Mach-O')
        for mode in ('validate_only', 'imports', 'exports', 'dependents'):
            run(label + '-' + mode, ['xcrun', 'dyld_info', '-' + mode, library])
        run(label + '-disassembly', ['xcrun', 'llvm-objdump', '--macho', '--disassemble',
                                    '--symbolize-operands', library])
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('owned_bundle_startup_macho', reader)
    macho = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(macho)
    old_consumer = macho.MachO(pathlib.Path(base['consumer']['path']).read_bytes())
    old_adapter = macho.MachO(pathlib.Path(previous['adapter']['path']).read_bytes())
    new_consumer, new_adapter = [macho.MachO(path.read_bytes()) for path in (consumer, adapter)]
    new_create = '_VM27OwnedBundlePrivateServiceConsumerCreateV5'
    need(set(new_consumer.exports) == set(old_consumer.exports) | {new_create},
         'only new explicit Create added to the exact old consumer exports')
    need(set(new_adapter.exports) == set(old_adapter.exports) == set(base['exactAdapterV3Exports']),
         'exact old eleven parent/bootstrap exports')
    need(not any('OwnedBundleApprovedPolicy' in name or 'BundleChildInspect' in name
                 for name in new_consumer.exports), 'policy and child inspector remain hidden')
    old_imports = {row['name'] for row in old_consumer.imports}
    new_imports = {row['name'] for row in new_consumer.imports}
    need(old_imports <= new_imports, 'all old consumer imports retained')
    old_adapter_imports = {row['name'] for row in old_adapter.imports}
    new_adapter_imports = {row['name'] for row in new_adapter.imports}
    old_create = '_VM27LargePrivateServiceConsumerV2Create'
    need(new_adapter_imports == (old_adapter_imports - {old_create}) | {new_create},
         'startup changes only its explicit consumer Create import')
    assembly = (out / 'adapter-disassembly.stdout').read_text()
    need('symbol stub for: ' + new_create in assembly or
         re.search(r'\bbl\s+' + re.escape(new_create) + r'\b', assembly),
         'compiled startup calls the genuine new explicit consumer Create')
    need(new_create[1:] in (out / 'preprocess-startup-v6.stdout').read_text(),
         'actual preprocessed startup explicit selection')
    for row in closure.values():
        need(pin(row['path']) == row, 'source/include closure stable after compile/link')
    for row in input_pins.values():
        need(pin(row['path']) == row, 'all frozen inputs unchanged after compile/link')
    reused_libraries = list({libraries[name]['path']: libraries[name]
        for name in consumer_names + adapter_names}.values())
    record = dict(schema='Actual explicit owned bundle consumer/startup provider v6',
        builder=pin(__file__), sourceCandidate=source_pin, sourceFreeze=pin(SOURCE / 'freeze.json'),
        policyCandidate=pin(policy_candidate), policyFreeze=pin(policy_candidate.parent / 'freeze.json'),
        inheritedProviderCandidate=pin(BASE / 'candidate.json'), inheritedProviderFreeze=pin(BASE / 'freeze.json'),
        previousStartupCandidate=pin(PREVIOUS / 'candidate.json'),
        consumer=pin(consumer), adapter=pin(adapter),
        actualNewObjects=[pin(path) for path in objects], actualReusedObjects=reused_objects,
        actualIncludeClosure=list(closure.values()), actualReusedLibraries=reused_libraries,
        exactConsumerV2Exports=sorted(new_consumer.exports), exactAdapterV3Exports=sorted(new_adapter.exports),
        addedConsumerExport=new_create, actualConsumerAddedImports=sorted(new_imports - old_imports),
        actualAdapterAddedImports=sorted(new_adapter_imports - old_adapter_imports),
        actualAdapterRemovedImports=sorted(old_adapter_imports - new_adapter_imports),
        oldStrictNativeDefaultAndRawUnchanged=True, explicitOwnedBundlePolicyNoFallback=True,
        publicV2ParentAndV3BootstrapABIUnchanged=True, privatePolicyAndInspectorHidden=True,
        actualV4SpawnFunctionUnchanged=True, spawnedPIDVersionAndReapGatesRetained=True,
        originalCoordinatorAndTransportWholeBytesUnchanged=True, nativeValidationNeverForged=True,
        originalFlatParentInspectionUnchanged=True, originalChildBootstrapV3Unchanged=True,
        nativeAuditAndKernelCodeGatesUnchanged=True, unrelatedCPUModelsRepeated=False,
        deviceOperations=0, nativeMessageValidationExecuted=False, nativeOperations=0,
        nativeVMOperations=0, codeSigned=False, guestBoot=False, readyForDeviceExecution=False)
    save(out / 'candidate.json', record)
    files = [pin(path) for path in out.iterdir() if path.is_file()]
    files += list(input_pins.values()) + list(closure.values()) + [pin(__file__), pin(reader),
        pin(BASE / 'candidate.json'), pin(PREVIOUS / 'candidate.json'), pin(policy_candidate),
        base['consumer'], previous['adapter']] + [core(row) for row in reused_objects + reused_libraries]
    save(out / 'freeze.json', dict(files=list({row['path']: core(row) for row in files}.values()),
                                   deviceOperations=0, signingCalls=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          consumer=pin(consumer), adapter=pin(adapter))))


if __name__ == '__main__':
    main()
