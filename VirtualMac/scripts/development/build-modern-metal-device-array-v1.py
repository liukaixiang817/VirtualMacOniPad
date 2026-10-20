#!/usr/bin/env python3
"""Build a finite documented iOS Metal array backport and ordinary Mac fixtures."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('finite_metal_current_stock', HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
s, p = f.s, f.p
from current_hid_system_three_capture_v1 import join as join_three
from macho_chained_import_records_v1 import read as import_records


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    host = p.ROOT/'VirtualMac/vz/host'
    source, fixture = host/'modern_metal_device_array.m', host/'modern_metal_device_array_fixture.m'
    original = p.NODE/'metal-copyall-original-contract-readonly-v1/audit.json'
    for pin in json.loads((original.parent/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
    pins = [p.pin(path) for path in [Path(__file__), source, fixture, original]]
    images = s.primary.captured_images()
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, p.NODE/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, p.NODE/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins += f.join_kernel(s, images)
    for helper in (f.join_hid_extra, f.join_swift_two, f.join_eight, join_three):
        added, _ = helper(s, images); pins += added
    assert len(images) == 32
    out.mkdir(mode=0o700)
    commands, roles = [], []
    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exitCode=result.returncode,
                             stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),
                             stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out/'commands.json', commands)
        assert result.returncode == 0, (label, result.stderr.decode())
        return result
    try:
        macsdk = run('mac-sdk', ['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        for role, macprofile, sanitized in [('normal-genuine-compare', True, False),
                ('asan-ubsan-genuine-compare', True, True), ('production-wrong-host-rejection', False, False),
                ('asan-ubsan-production-wrong-host-rejection', False, True)]:
            exe = out/(role+'-ordinary-mac-fixture')
            args = ['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0','-isysroot',macsdk,
                    '-O2','-Wall','-Wextra','-Werror','-fno-objc-arc',
                    '-DVM27_METAL_DEVICE_ARRAY_EXPORT=VM27MetalDeviceArrayFixture']
            args += ['-DVM27_METAL_MAC_ARRAY_FIXTURE'] if macprofile else ['-DVM27_METAL_PRODUCTION_REJECTION_FIXTURE']
            if sanitized: args += ['-fsanitize=address,undefined']
            run(role+'-build', args+[source, fixture, '-framework','Metal','-framework','Foundation','-o',exe])
            deps = p.dependencies(exe.read_bytes())
            assert not any(any(word in dep['path'] for word in ('Hypervisor','Virtualization','VirtualMachineMonitor','UniversalHID')) for dep in deps)
            result = run(role+'-execute', [exe])
            assert not result.stderr
            actual = json.loads(result.stdout)
            if macprofile:
                assert actual['actualLifetimeObjectsDeallocated'] == 1024 and actual['realEmptyOwnedArrays'] == 1024
                assert actual['nativeDefaultCalls'] == actual['genuineOriginalCatalogArrays'] == actual['candidateOwnedArrays'] == 512
                assert actual['realNilNativeDefaults']+actual['realNonNilNativeDefaults'] == 512
                assert actual['actualMacConsumerSelectorObjectsValidated'] == actual['realNonNilNativeDefaults']
                assert not actual['actualIPadConsumerSelectorsValidated']
            else:
                assert actual['checks'] == 128 and actual['productionProfileRejectedOnRealDifferentMac']
                assert actual['nativeDeviceCallsMade'] == 0
            roles.append(dict(role=role, executable=p.pin(exe), dependencies=deps, actualResult=actual,
                              allCandidateCodeInstrumented=sanitized, explicitDifferentMacProfile=macprofile))
        ios = run('ios-sdk', ['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        sdk_header = Path(ios)/'System/Library/Frameworks/Metal.framework/Headers/MTLDevice.h'
        text = sdk_header.read_text()
        expected = 'On iOS, tvOS and visionOS, this API returns an array containing the same device that MTLCreateSystemDefaultDevice would have returned, or an empty array if it would have failed.'
        assert expected in text and 'ios(18.0)) NS_RETURNS_RETAINED' in text
        assert 'MTLCreateSystemDefaultDevice(void) API_AVAILABLE(macos(10.11), ios(8.0)) NS_RETURNS_RETAINED' in text
        pins.append(p.pin(sdk_header))
        export_names = out/'exports.list'; export_names.write_text('_MTLCopyAllDevices\n')
        provider = out/'MD.unsigned.inert.macho-data'
        flags = ['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-isysroot',ios,
                 '-O2','-Wall','-Wextra','-Werror','-fno-objc-arc','-fvisibility=hidden']
        run('ios-build', flags+['-dynamiclib',source,'-framework','Foundation','-Wl,-reexport_framework,Metal',
                '-Wl,-install_name,@rpath/VM27MetalDeviceArray.dylib',
                '-Wl,-exported_symbols_list,'+str(export_names),'-Wl,-no_adhoc_codesign','-o',provider])
        run('ios-dyld-validate', ['xcrun','dyld_info','-validate_only',provider])
        raw = provider.read_bytes()
        assert not any(cmd == 0x1d for cmd, at, size in p.commands(raw))
        assert not any(section['name']=='__mod_init_func' and section['size'] for segment in p.segments(raw) for section in segment['sections'])
        deps = p.dependencies(raw)
        metaldeps = [dep for dep in deps if s.primary.canonical_path(dep['path'])==s.primary.canonical_path('/System/Library/Frameworks/Metal.framework/Metal')]
        assert len(metaldeps)==1 and metaldeps[0]['command']==0x8000001f
        off, size = next(struct.unpack_from('<II', raw, at+8) for cmd, at, length in p.commands(raw) if cmd==0x80000033)
        exports = s.primary.trie(raw[off:off+size])
        assert set(exports)=={'_MTLCopyAllDevices'} and exports['_MTLCopyAllDevices']['flags']==0
        schema = import_records(raw, p.commands)
        dependency_map = {dep['ordinal']: dep['path'] for dep in deps}
        proofs = []
        for record in schema['imports']:
            assert record['ordinal']>0 and not record['weak']
            owner = dependency_map[record['ordinal']]
            proof = s.primary.resolve(images, owner, record['name'])
            if proof['status'] != 'actualDirectExport':
                assert record['name']=='__Unwind_Resume' and owner=='/usr/lib/libSystem.B.dylib'
                assert proof['status']=='ownerHasNoDefinitionReexportsUnverified'
                assert '/usr/lib/system/libunwind.dylib' in proof['unverifiedReexportPaths']
            proofs.append(dict(**record, dependency=owner, actualCurrentDefinition=proof))
        assert next(row for row in proofs if row['name']=='_MTLCreateSystemDefaultDevice')['actualCurrentDefinition']['export']['offsetOrAbsoluteAddress']==144272
        ir = out/'ios-device-array.ll'
        run('ios-IR', flags+['-S','-emit-llvm',source,'-o',ir])
        llvm = ir.read_text()
        signature = next(line for line in llvm.splitlines() if line.startswith('define ') and 'MTLCopyAllDevices' in line)
        assert '@"\\01_MTLCopyAllDevices"()' in signature and 'define ptr' in signature and 'swiftcc' not in signature
        assert 'call ptr @MTLCreateSystemDefaultDevice()' in llvm and '@objc_release' in llvm
        assert 'initWithObjects:count:' in llvm
        assert pins[:4]==[p.pin(path) for path in [Path(__file__),source,fixture,original]]
        p.save(out/'candidate.json', dict(schema='Finite documented iOS Metal owned-device-array backport data v1',
            sourceInputs=pins[:4], originalMetalAndVZContract=p.pin(original), actualPlatformSDKHeader=p.pin(sdk_header),
            platformSDKIOS18ReturnValueContract=True, actualMacRoles=roles, iosProvider=p.pin(provider),
            iosIR=p.pin(ir), actualZeroArgumentCEntry=signature, exactExports=exports, actualDependencies=deps,
            trueNativeMetalReexport=metaldeps[0], actualCurrentImportRecords=schema,
            actualCurrentStrongDefinitions=proofs,
            positiveCurrentStrongDefinitions=sum(x['actualCurrentDefinition']['status']=='actualDirectExport' for x in proofs),
            remainingCurrentStrongDefinitionsUnverified=[x for x in proofs if x['actualCurrentDefinition']['status']!='actualDirectExport'],
            completeCurrentStrongDefinitionsValidated=all(x['actualCurrentDefinition']['status']=='actualDirectExport' for x in proofs),
            currentStockImages=32,
            productionMetalUUID='8f062125748839efafda57db8cd80033', explicitMacFixtureMetalUUID='b0bc74fe7080347d92ee38195058ccce',
            sameGenuineNativeDefaultObjectRetainedInOwnedArray=True, realNativeNilReturnsOwnedEmptyArray=True,
            nativeTemporaryDeviceOwnershipReleased=True, arrayReturnsPlusOne=True, nativeMetalTypesUnmodified=True,
            originalEntireMacMultiGPUCatalogEquivalent=False, actualIPadGPUObjectOrSelectorsValidated=False,
            actualIPadProviderExecuted=False, originalVZCallerExecuted=False, originalVZLoaded=False,
            nativeCPUCalls=0, deviceOperations=0, codeSigned=False, candidateReadyForNativeLoading=False,
            completeProviderGraphValidated=False, full27Backend=False))
        files = [path for path in out.rglob('*') if path.is_file()]
        p.save(out/'freeze.json', dict(files=list({pin['path']:pin for pin in pins+[p.pin(path) for path in files]}.values()), deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'), provider=p.pin(provider),
                              strongDefinitions=sum(x['actualCurrentDefinition']['status']=='actualDirectExport' for x in proofs),
                              unprovedStrongDefinitions=sum(x['actualCurrentDefinition']['status']!='actualDirectExport' for x in proofs), roles=roles)))
    except Exception as error:
        failed = out/'failed-sources'; failed.mkdir(exist_ok=True)
        for path in [Path(__file__), source, fixture]: (failed/path.name).write_bytes(path.read_bytes())
        p.save(out/'failure.json', dict(error=repr(error), deviceOperations=0, nativeIOSExecuted=False))
        raise


if __name__=='__main__':
    main()
