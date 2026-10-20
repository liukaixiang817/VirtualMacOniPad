#!/usr/bin/env python3
"""Compile the minimal external-resource reader and startup diagnostics graph."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import shlex
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def need(value, reason):
    if not value:
        raise ValueError(reason)

def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh actual build directory')
    source_candidate = args.source_candidate.resolve()
    frozen = {}
    for freeze in [source_candidate.parent/'freeze.json',
                   N/'owned-vmm-xpc-v10-provider-build-v2/freeze.json',
                   N/'owned-app-child-startup-source-v3-attempt1/freeze.json']:
        value = json.loads(freeze.read_bytes())
        rows = value.get('files', value.get('pins', []))
        need(rows, 'nonempty actual input freeze')
        for row in rows:
            need(pin(row['path']) == row, 'unchanged frozen source/input: '+row['path'])
            frozen[row['path']] = row
    source_names = ['modern_xpc_large_private_consumer_v4.c',
                    'vm27_bundle_child_inspection_v1.c',
                    'vm27_bundle_child_inspection_v1.h',
                    'vm27_owned_app_child_startup_v4.c']
    for name in source_names:
        need(frozen.get(str(S/name)) == pin(S/name), 'actual reviewed new source: '+name)
    base = N/'owned-vmm-xpc-v10-provider-build-v2'
    libraries = {row['name']: row for row in json.loads((base/'candidate.json').read_bytes())['libraries']}
    out.mkdir(mode=0o700)
    commands = []
    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        save(out/'commands.json', commands)
        need(result.returncode == 0, label+': '+result.stderr.decode(errors='replace'))
        return result.stdout
    sdk = run('ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    flags = ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
             '-O2', '-fblocks', '-std=c11', '-Wall', '-Wextra', '-Werror',
             '-Wno-deprecated-declarations', '-fptrauth-abi-version=0', '-I', S]
    object_paths = []
    closure = {}
    for index, name in enumerate(source_names[:2]+[
        'modern_xpc_large_strict_identity_v2.c', 'vm27_owned_app_child_startup_v4.c',
        'vm27_owned_app_parent_identity_v1.c']):
        source = S/name
        target = out/(source.stem+'.o')
        run('compile-'+str(index), flags+['-c', source, '-o', target])
        object_paths.append(target)
        dependencies = run('dependencies-'+str(index), flags+['-MM', source]).decode().replace('\\\n', ' ')
        for item in shlex.split(dependencies.split(':', 1)[1]):
            row = pin(item)
            closure[row['path']] = row
    consumer = out/'VM27LargeConsumerV2.unsigned.dylib'
    consumer_deps = ['VM27LargeRegistry.dylib', 'VM27ApprovedCode.dylib',
                     'VM27LWCRPolicy.dylib', 'VM27PrivateEndpoint.dylib']
    reused = [libraries[name] for name in consumer_deps]
    run('link-consumer-v3', flags+['-dynamiclib']+object_paths[:3]+
        [row['path'] for row in reused]+['-framework', 'CoreFoundation',
        '-Wl,-install_name,@rpath/VM27LargeConsumerV2.dylib', '-Wl,-rpath,@loader_path',
        '-Wl,-current_version,1.0', '-Wl,-compatibility_version,1.0',
        '-Wl,-no_adhoc_codesign', '-o', consumer])
    adapter = out/'VM27OwnedAppStartupV3.unsigned.dylib'
    adapter_deps = ['VM27OwnedStartupV3.dylib', 'VM27LargeRegistry.dylib',
                    'VM27PrivateEndpoint.dylib', 'VM27OriginalV10Transport.dylib', 'VM27LWCRPolicy.dylib']
    reused.extend(libraries[name] for name in adapter_deps)
    run('link-startup-v4', flags+['-dynamiclib']+object_paths[3:]+
        [consumer]+[libraries[name]['path'] for name in adapter_deps]+
        ['-framework', 'CoreFoundation', '-framework', 'Security',
         '-Wl,-install_name,@loader_path/VM27OwnedAppStartupV3.dylib',
         '-Wl,-no_adhoc_codesign', '-o', adapter])
    for label, library in [('consumer', consumer), ('adapter', adapter)]:
        for mode in ['validate_only', 'imports', 'exports', 'dependents']:
            run(label+'-'+mode, ['xcrun', 'dyld_info', '-'+mode, library])
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('external_startup_macho', reader)
    macho = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(macho)
    old_consumer = macho.MachO(pathlib.Path(libraries['VM27LargeConsumerV2.dylib']['path']).read_bytes())
    old_adapter_path = N/'owned-app-child-startup-source-v3-attempt1/VM27OwnedAppStartupV3.unsigned.dylib'
    old_adapter = macho.MachO(old_adapter_path.read_bytes())
    new_consumer, new_adapter = [macho.MachO(path.read_bytes()) for path in [consumer, adapter]]
    need(set(new_consumer.exports) == set(old_consumer.exports), 'exact inherited consumer V2 public exports')
    need(set(new_adapter.exports) == set(old_adapter.exports), 'exact inherited parent/child public exports')
    need('_VM27BundleChildInspectV1' not in new_consumer.exports, 'read-only child inspector hidden')
    need('_VM27OwnedAppChildBootstrapBeforeMainV3' in new_adapter.exports and
         '_VM27OwnedAppParentStartWithScopedPolicyV2' in new_adapter.exports,
         'actual original startup ABI retained')
    for row in closure.values():
        need(pin(row['path']) == row, 'new source closure stable after linking')
    record = dict(schema='Actual external-slot child startup provider v4',
        builder=pin(__file__), sourceCandidate=pin(source_candidate),
        sourceFreeze=pin(source_candidate.parent/'freeze.json'),
        consumer=pin(consumer), adapter=pin(adapter),
        actualNewObjects=[pin(path) for path in object_paths], actualIncludeClosure=list(closure.values()),
        actualReusedLibraries=list({row['path']: row for row in reused}.values()),
        exactConsumerV2Exports=sorted(new_consumer.exports),
        exactAdapterV3Exports=sorted(new_adapter.exports),
        singleNativeStrictIdentity=True, nativeAuditAndKernelCodeGatesUnchanged=True,
        originalFlatParentInspectionUnchanged=True, originalChildBootstrapV3Unchanged=True,
        oldRawInspectorStrictRejectionUnchanged=True,
        unrelatedCPUModelsRepeated=False, deviceOperations=0, nativeOperations=0,
        codeSigned=False, guestBoot=False, readyForDeviceExecution=False)
    save(out/'candidate.json', record)
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += list(closure.values())+[pin(__file__), pin(reader), pin(source_candidate),
        pin(source_candidate.parent/'freeze.json'), pin(base/'candidate.json'), pin(base/'freeze.json'),
        pin(old_adapter_path)]
    files += [{key: row[key] for key in ['path', 'bytes', 'sha256']} for row in reused]
    save(out/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), consumer=pin(consumer), adapter=pin(adapter))))

if __name__ == '__main__':
    main()
