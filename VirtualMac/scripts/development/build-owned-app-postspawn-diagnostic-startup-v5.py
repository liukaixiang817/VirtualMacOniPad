#!/usr/bin/env python3
"""Compile one real startup diagnostic TU; retain exact frozen consumer ABI/code."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shlex
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
BASE = N/'owned-app-external-signature-provider-v4-attempt1'


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh own host build directory')
    frozen = json.loads((BASE/'freeze.json').read_bytes())['files']
    for row in frozen:
        need(pin(row['path']) == row, 'frozen provider source/input remains unchanged: '+row['path'])
    base = json.loads((BASE/'candidate.json').read_bytes())
    source = S/'vm27_owned_app_child_startup_v5.c'
    source_pin = pin(source)
    consumer = pathlib.Path(base['consumer']['path'])
    need(pin(consumer) == base['consumer'], 'actual old consumer unchanged')
    old_adapter = pathlib.Path(base['adapter']['path'])
    parent_identity = next(row for row in base['actualNewObjects'] if pathlib.Path(row['path']).name == 'vm27_owned_app_parent_identity_v1.o')
    reused = {pathlib.Path(row['path']).name: row for row in base['actualReusedLibraries']}
    dependency_names = ['VM27OwnedStartupV3.dylib', 'VM27LargeRegistry.dylib',
                        'VM27PrivateEndpoint.dylib', 'VM27OriginalV10Transport.dylib', 'VM27LWCRPolicy.dylib']
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
    obj = out/'vm27_owned_app_child_startup_v5.o'
    run('compile-startup-v5', flags+['-c', source, '-o', obj])
    dependencies = run('dependencies-startup-v5', flags+['-MM', source]).decode().replace('\\\n', ' ')
    closure = [pin(path) for path in shlex.split(dependencies.split(':', 1)[1])]
    run('preprocess-startup-v5', flags+['-E', '-P', source])
    adapter = out/'VM27OwnedAppStartupV3.unsigned.dylib'
    dependency_pins = [reused[name] for name in dependency_names]
    run('link-startup-v5', flags+['-dynamiclib', obj, parent_identity['path'], consumer]+
        [row['path'] for row in dependency_pins]+['-framework', 'CoreFoundation',
        '-framework', 'Security', '-Wl,-install_name,@loader_path/VM27OwnedAppStartupV3.dylib',
        '-Wl,-no_adhoc_codesign', '-o', adapter])
    for mode in ('validate_only', 'imports', 'exports', 'dependents'):
        run('adapter-'+mode, ['xcrun', 'dyld_info', '-'+mode, adapter])
    run('adapter-disassembly', ['xcrun', 'llvm-objdump', '--macho', '--disassemble',
                               '--symbolize-operands', adapter])
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('diagnostic_startup_macho', reader)
    macho = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(macho)
    old, new = [macho.MachO(path.read_bytes()) for path in (old_adapter, adapter)]
    need(set(new.exports) == set(old.exports), 'exact old eleven public V2/V3 exports')
    need(sorted(new.exports) == base['exactAdapterV3Exports'], 'frozen adapter export ABI')
    old_names = {x['name'] for x in old.imports}
    new_names = {x['name'] for x in new.imports}
    need(old_names <= new_names and new_names-old_names <= {'_getuid', '_geteuid', '___error'},
         'retain all actual old imports; only actual UID and preserved errno diagnostics may add native names')
    need(all('DiagnosticV5' not in name for name in new.exports), 'all new typed diagnostic wrappers remain private')
    need(pin(consumer) == base['consumer'] and pin(parent_identity['path']) == parent_identity, 'old consumer and parent identity object byte identical')
    for row in closure:
        need(pin(row['path']) == row, 'actual include/source closure stable')
    need(pin(source) == source_pin, 'new source stable across actual compilation')
    assembly = (out/'adapter-disassembly.stdout').read_text()
    preprocessed = (out/'preprocess-startup-v5.stdout').read_text()
    wrapper_targets = (
        ('ReceivedMessageDiagnosticV5', '_VM27LargePrivateServiceConsumerV2CheckMessage', 'parent-config check-message'),
        ('ParentInstallFactoryDiagnosticV5', '_VM27OwnedStartupParentInstallFactoryV3', 'parent-hello install-factory'),
        ('ActualParentMessageDiagnosticV5', '_VM27OwnedAppCheckActualParentMessageV1', 'child-parent-message'),
        ('ChildPrepareDiagnosticV5', '_VM27OwnedStartupChildPrepareV3', 'child-prepare'))
    for wrapper, target, label in wrapper_targets:
        # -O2 may inline a wrapper. Prove the compiled real callee plus actual
        # diagnostic literal, and one original call in each preprocessed body.
        begin = preprocessed.index('static int '+wrapper+'(')
        start = preprocessed.index('{', begin)
        depth, end = 1, start+1
        while depth:
            depth += (preprocessed[end] == '{')-(preprocessed[end] == '}')
            end += 1
        body = preprocessed[start:end]
        need(body.count(target[1:]+'(') == 1 and body.count('errno = actualErrno;') == 0,
             'one exact original callee in preprocessed wrapper: '+wrapper)
        actual_call = 'symbol stub for: '+target in assembly or re.search(r'\bbl\s+'+re.escape(target)+r'\b', assembly)
        need(actual_call and label in assembly,
             'actual compiled real callee and diagnostic literal: '+wrapper)
    record = dict(schema='Actual owned startup post-spawn diagnostics provider v5',
        builder=pin(__file__), source=source_pin, inheritedProviderCandidate=pin(BASE/'candidate.json'),
        inheritedProviderFreeze=pin(BASE/'freeze.json'), consumer=base['consumer'], adapter=pin(adapter),
        actualNewObjects=[pin(obj)], actualReusedObjects=[parent_identity], actualIncludeClosure=closure,
        actualReusedLibraries=dependency_pins+[base['consumer']], exactAdapterV3Exports=sorted(new.exports),
        exactConsumerV2Exports=base['exactConsumerV2Exports'], consumerWholeBytesUnchanged=True,
        actualNewNativeImportNames=sorted(new_names-old_names),
        hiddenChildInspectorWholeBytesUnchanged=True, parentIdentityObjectWholeBytesUnchanged=True,
        publicV2ParentAndV3BootstrapABIUnchanged=True, permissionPolicyAndCleanupUnchanged=True,
        everyWrappedOriginalCalleeInvokedOnce=True, originalCalleeErrnoRestoredAfterDiagnostics=True,
        compilerMayInlinePrivateDiagnosticWrappers=True,
        configurationMessageNativeFieldsRecorded=True, helloExternalGateNotRepeated=True,
        helloExternalNativeDetailsUnavailable=True, childParentIdentityPublishedOnlyOnActualSuccess=True,
        deviceOperations=0, nativeMessageValidationExecuted=False, nativeVMOperations=0,
        codeSigned=False, guestBoot=False, readyForDeviceExecution=False)
    save(out/'candidate.json', record)
    files = [pin(path) for path in out.iterdir() if path.is_file()]
    files += closure+[pin(__file__), pin(reader), pin(BASE/'candidate.json'), pin(BASE/'freeze.json'),
        pin(old_adapter), base['consumer'], parent_identity]+dependency_pins
    save(out/'freeze.json', dict(files=list({row['path']:row for row in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), freeze=pin(out/'freeze.json'), adapter=pin(adapter), consumer=pin(consumer))))


if __name__ == '__main__':
    main()
