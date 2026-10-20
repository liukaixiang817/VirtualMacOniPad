#!/usr/bin/env python3
"""Build an unsigned own UIKit packet provider and ordinary Mac queue fixtures.

Only the two ordinary Mac C fixtures execute. The iOS provider is inert data;
no Apple event API, original UHK/VZ, device, signature or readiness is produced.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('input_packet_builder_common', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
from macho_chained_import_records_v1 import read as import_records


def main():
    out = p.NODE / 'uikit-own-input-packets-data-build-v2'
    assert not out.exists()
    out.mkdir()
    host = p.ROOT / 'VirtualMac/vz/host'
    core = host / 'modern_input_packet_v1.c'
    adapter = host / 'modern_uikit_input_adapter_v1.m'
    fixture = host / 'modern_input_packet_fixture_v1.c'
    sources = [Path(__file__), core, adapter, fixture,
        host / 'modern_input_packet_v1.h', host / 'modern_uikit_input_adapter_v1.h']
    peer_dir = p.NODE / 'uhk-input-semantic-bridge-design-independent-v1'
    peer = json.loads((peer_dir / 'review.json').read_bytes())
    assert not peer['findings'] and not peer['scope']['productProviderImplemented']
    for pin in json.loads((peer_dir / 'freeze.json').read_bytes())['files']:
        actual = p.pin(Path(pin['path']))
        assert set(pin) == {'path', 'bytes', 'sha256'}
        assert actual['bytes'] == pin['bytes'] and actual['sha256'] == pin['sha256']
        assert actual['path'] == str(Path(pin['path']).resolve())
    ios_sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    mac_sdk = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
    commands = []
    def run(label, arguments, timeout=60):
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        (out / (label + '-stdout')).write_bytes(result.stdout)
        (out / (label + '-stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, command=arguments, exit=result.returncode))
        p.save(out / 'commands.json', commands)
        assert result.returncode == 0, label
        return result
    common = ['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror']
    normal, sanitized = out / 'mac-normal', out / 'mac-sanitized'
    run('compile-mac-normal', common + ['-isysroot', mac_sdk, '-O2', str(core), str(fixture), '-o', str(normal)])
    run('compile-mac-sanitized', common + ['-isysroot', mac_sdk, '-O1', '-g', '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer', str(core), str(fixture), '-o', str(sanitized)])
    ios_flags = common + ['-target', 'arm64e-apple-ios16.1', '-isysroot', ios_sdk, '-O2']
    core_object, adapter_object = out / 'ios-core.o', out / 'ios-adapter.o'
    run('compile-ios-core', ios_flags + ['-c', str(core), '-o', str(core_object)])
    run('compile-ios-adapter', ios_flags + ['-fobjc-arc', '-c', str(adapter), '-o', str(adapter_object)])
    run('compile-ios-adapter-ir', ios_flags + ['-fobjc-arc', '-S', '-emit-llvm', str(adapter), '-o', str(out / 'ios-adapter.ll')])
    provider = out / 'VM27UIKitInputPackets.ios.unsigned.inert.dylib'
    run('link-ios-provider', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', ios_sdk,
        '-dynamiclib', str(core_object), str(adapter_object), '-framework', 'UIKit', '-framework', 'Foundation',
        '-Wl,-install_name,@loader_path/VM27UIKitInputPackets.dylib', '-Wl,-current_version,1.0',
        '-Wl,-compatibility_version,1.0', '-Wl,-no_adhoc_codesign', '-o', str(provider)])
    run('validate-ios-data', ['xcrun', 'dyld_info', '-validate_only', str(provider)])
    run('ios-exports', ['xcrun', 'dyld_info', '-exports', str(provider)])
    body = provider.read_bytes()
    deps = p.dependencies(body)
    assert {row['path'] for row in deps} == {
        '/System/Library/Frameworks/UIKit.framework/UIKit',
        '/System/Library/Frameworks/Foundation.framework/Foundation',
        '/usr/lib/libobjc.A.dylib', '/usr/lib/libSystem.B.dylib'}
    assert not any(command == 29 for command, _, _ in p.commands(body))
    imports = import_records(body, p.commands)
    assert not any(any(fragment in row['name'] for fragment in ('_SLEvent', '_SLS', '_CGEvent', '_NSEvent', '_NSTouch', '_hv_', '_VZ', '_VMM'))
                   for row in imports['imports'])
    material = [p.pin(source) for source in sources]
    material += [p.pin(peer_dir / name) for name in ('review.json', 'bridge-plan.json', 'vm27_input_packet_plan_v1.h', 'freeze.json')]
    material += [p.pin(path) for path in (normal, sanitized, core_object, adapter_object, provider, out / 'ios-adapter.ll')]
    p.save(out / 'pre-execution-inputs.json', dict(files=material, deviceOperations=0,
        iOSProviderExecuted=False, originalFrameworkExecuted=False))
    results = []
    for name, executable in (('normal', normal), ('sanitized', sanitized)):
        result = run('run-mac-' + name, [str(executable)], timeout=25)
        assert not result.stderr
        actual = json.loads(result.stdout)
        assert actual['copiedConcurrentSnapshots'] == 2048 and actual['consumerThreads'] == 4
        assert actual['forkedForeignOwnerRejected'] and actual['disconnectWaitedForOwnSink']
        assert actual['deviceOperations'] == actual['nativeHVCalls'] == actual['nativeVMCalls'] == 0
        assert not actual['UIKitEventsCaptured'] and not actual['originalUHKExecuted']
        results.append(dict(mode=name, executable=p.pin(executable), stdout=p.pin(out / ('run-mac-' + name + '-stdout')),
            stderr=p.pin(out / ('run-mac-' + name + '-stderr')), exit=0, result=actual))
    assert all(p.pin(Path(pin['path'])) == pin for pin in material)
    candidate = dict(schema='Own copied UIKit input packet provider inert data v2',
        provider=p.pin(provider), sourceFiles=[p.pin(source) for source in sources],
        originalSemanticSourcePlan=p.pin(peer_dir / 'bridge-plan.json'),
        independentOriginalPlanReview=p.pin(peer_dir / 'review.json'),
        preExecutionInputs=p.pin(out / 'pre-execution-inputs.json'),
        target='arm64e-apple-ios16.1', actualSDKPaths=dict(iOS=ios_sdk, macOS=mac_sdk),
        dependencies=deps, activeImportRecordSchema=imports, ordinaryMacQueueFixtures=results,
        boundedQueueAndCopiedContactsImplemented=True, consumerLeaseDrainImplemented=True,
        atomicDisconnectAndOwnSinkAdmissionImplemented=True, forkedProcessAdmissionRejected=True,
        mainThreadPublicUIKitScalarSnapshotSourceImplemented=True,
        HIDUsageNamespaceKeptSeparateFromMacKeyCode=True, UIKitRotationRemainsRadians=True,
        processedScrollOnly=True, richCGEventFieldsUnsupported=True,
        AppleAPIExportsProvided=False, AppleClassesImitated=False,
        originalUHKFourStrongDefinitionsClosed=False, originalUHKGenericFactoryIntegrated=False,
        originalVZSkyLightDefinitionsClosed=False, UIKitEventsActuallyCaptured=False,
        providerCurrentStrongDefinitionsValidated=False, originalIOKitABIExecuted=False,
        productionSourceIntegrated=False, sourceProviderIndependentReviewPassed=False,
        iOSProviderSigned=False, iOSProviderLoaded=False, readyWritten=False,
        deviceOperations=0, nativeCPUCalls=0, nativeHVCalls=0, nativeVMCalls=0,
        currentCompleteProviderDependencyGraphValidated=False, full27Backend=False)
    p.save(out / 'candidate.json', candidate)
    pins = material + [p.pin(path) for path in out.iterdir() if path.is_file()]
    unique = {pin['path']: pin for pin in pins}
    assert all(unique[pin['path']] == pin for pin in pins)
    p.save(out / 'freeze.json', dict(files=list(unique.values()), deviceOperations=0, nativeCPUCalls=0))
    print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), freeze=p.pin(out / 'freeze.json'),
        iosProvider=p.pin(provider), results=[row['result'] for row in results])))


if __name__ == '__main__':
    main()
