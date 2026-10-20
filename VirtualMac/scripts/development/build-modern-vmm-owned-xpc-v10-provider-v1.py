#!/usr/bin/env python3
"""Build the NEW typed V2 consumer / V10 / V3 provider graph locally.

Old source/provider freezes remain byte exact. iOS libraries are unsigned and
never loaded. Local execution uses only explicit coordinator and identity
test doubles, so it establishes no native authorization or original VMM run.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST = R / 'VirtualMac/vz/host'
PREVIOUS = Path(__file__).with_name('build-modern-vmm-owned-xpc-v9-provider-v1.py')
ROUTE = Path(__file__).with_name('prepare-modern-vmm-owned-xpc-v9-data-v1.py')
STRICT_CHECK = Path(__file__).with_name('check-modern-xpc-large-strict-identity-v2.py')


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    assert sys.flags.optimize == 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    out.mkdir(mode=0o700, parents=True)
    source = out / 'source'
    ios = out / 'ios'
    source.mkdir(mode=0o700)
    ios.mkdir(mode=0o700)
    previous = module(PREVIOUS, 'vm27_v9_build_inputs')
    route = module(ROUTE, 'vm27_v9_metadata_reader')
    names = [
        'modern_xpc_original_instance_transport_v10.c',
        'modern_xpc_original_instance_transport_v10.h',
        'modern_xpc_original_instance_transport_v9.c',
        'modern_xpc_original_instance_transport_v9.h',
        'vm27_owned_startup_coordinator_v3.c', 'vm27_owned_startup_coordinator_v3.h',
        'vm27_owned_startup_coordinator_v2.c', 'vm27_owned_startup_coordinator_v2.h',
        'vm27_owned_startup_aggregate_v10.c',
        'modern_xpc_large_private_consumer_v2.c', 'modern_xpc_large_private_consumer_v2.h',
        'modern_xpc_large_strict_identity_v2.c', 'modern_xpc_large_strict_identity_v2.h',
        'modern_xpc_large_private_consumer.h', 'modern_xpc_large_bundle_registry.h',
        'modern_xpc_approved_code.h', 'modern_xpc_lwcr_policy.h',
        'modern_xpc_private_endpoint.h', 'modern_xpc_original_instance_pins.h',
        'vm27_bundle_parent_inspection_v1.c', 'vm27_bundle_parent_inspection_v1.h',
        'vm27_headless_checkin_v1.c', 'vm27_headless_checkin_v1.h',
        'vm27_client_registration_v1.h', 'test-vm27-owned-startup-coordinator-v2.c',
    ]
    inputs = [HOST / name for name in names] + [Path(__file__), PREVIOUS, ROUTE, STRICT_CHECK]
    before = [pin(path) for path in inputs]
    for path in inputs:
        if path.name in previous.PINS:
            assert pin(path)['sha256'] == previous.PINS[path.name]
        target = source / path.name
        shutil.copyfile(path, target)
        target.chmod(0o600)

    # Each integration unit has only explicit token mappings and one old body
    # include. The original implementations are frozen inputs, not rewrites.
    adaptations = []
    for new, old, prefix in [
        ('modern_xpc_original_instance_transport_v10.c', 'modern_xpc_original_instance_transport_v9.c', 'VM27OriginalV9'),
        ('vm27_owned_startup_coordinator_v3.c', 'vm27_owned_startup_coordinator_v2.c', 'VM27OwnedStartup'),
    ]:
        text = (source / new).read_text()
        include = '#include "' + old + '"'
        assert text.count(include) == 1 and text.rstrip().endswith(include)
        assert not re.search(r'\b(?:if|while|return|goto|__attribute__)\b', re.sub(r'/\*.*?\*/', '', text, flags=re.S))
        mappings = dict(re.findall(r'^#define (VM27\w+) (VM27\w+)$', text, re.M))
        original = (source / old).read_text()
        selected = {token for token in re.findall(r'\bVM27\w+\b', original) if token.startswith(prefix)}
        assert selected <= mappings.keys()
        adaptations.append(dict(unit=new, unchangedBody=pin(source / old), explicitTypedMappings=mappings))
    transport_unit = (source / 'modern_xpc_original_instance_transport_v10.c').read_text()
    assert '#define VM27LargePrivateServiceConsumer VM27LargePrivateServiceConsumerV2' in transport_unit
    assert '#define VM27LargePrivateServiceConsumerCheckMessage VM27LargePrivateServiceConsumerV2CheckMessage' in transport_unit
    assert '#define VM27LargePrivateServiceConsumerCopyState VM27LargePrivateServiceConsumerV2CopyState' in transport_unit
    header = (source / 'vm27_owned_startup_coordinator_v3.h').read_text()
    assert 'VM27OwnedStartupParentInstallFactoryV3(VM27LargePrivateServiceConsumerV2 *' in header

    libraries = []
    old_pins = []
    for name, (path, expected) in previous.OLD.items():
        if name == 'VM27LargeConsumer.dylib':
            continue
        record = pin(path)
        assert record['sha256'] == expected and not path.is_symlink() and path.stat().st_nlink == 1
        target = ios / name
        shutil.copyfile(path, target)
        target.chmod(0o600)
        old_pins.append(record)
        libraries.append(dict(name=name, **pin(target), oldByteExactCopy=True, source=str(path), resigned=False))

    processes = []

    def run(label, argv, extra_env=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith('DYLD_')}
        if extra_env:
            env.update(extra_env)
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            (out / (label + '.stdout')).write_bytes(stdout)
            (out / (label + '.stderr')).write_bytes(stderr)
            raise
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        save(out / (label + '.argv.json'), argv)
        processes.append(dict(label=label, argv=argv, directChildPID=child.pid, observedWaitExit=child.returncode, reaped=True))
        save(out / 'processes.json', processes)
        assert child.returncode == 0, (label, child.returncode, stderr[-3000:])
        return stdout

    clang = run('clang-path', ['/usr/bin/xcrun', '--find', 'clang']).decode().strip()
    sdk = run('ios-sdk', ['/usr/bin/xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    base = [clang, '-std=c11', '-fblocks', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations', '-O2',
            '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-fptrauth-abi-version=0', '-I', str(source),
            '-dynamiclib', '-Wl,-no_adhoc_codesign', '-Wl,-rpath,@loader_path',
            '-Wl,-current_version,1.0', '-Wl,-compatibility_version,1.0']

    def build(label, name, bodies, dependencies, extra):
        target = ios / name
        argv = base + [str(source / body) for body in bodies] + [str(ios / dep) for dep in dependencies] + extra
        run(label + '-compile', argv + ['-Wl,-install_name,@rpath/' + name, '-o', str(target)])
        target.chmod(0o600)
        for kind, option in [('metadata', '-validate_only'), ('exports', '-exports'), ('imports', '-imports')]:
            run(label + '-' + kind, ['/usr/bin/xcrun', 'dyld_info', option, str(target)])
        libraries.append(dict(name=name, **pin(target), oldByteExactCopy=False, unsigned=True, signingCalls=0, bodies=bodies))

    build('consumer-v2', 'VM27LargeConsumerV2.dylib',
          ['modern_xpc_large_private_consumer_v2.c', 'modern_xpc_large_strict_identity_v2.c'],
          ['VM27LargeRegistry.dylib', 'VM27ApprovedCode.dylib', 'VM27LWCRPolicy.dylib', 'VM27PrivateEndpoint.dylib'], [])
    build('reader', 'VM27BundleParentV1.dylib', ['vm27_bundle_parent_inspection_v1.c'], [], ['-framework', 'CoreFoundation'])
    build('v10', 'VM27OriginalV10Transport.dylib', ['modern_xpc_original_instance_transport_v10.c'],
          ['VM27LargeConsumerV2.dylib', 'VM27ApprovedCode.dylib', 'VM27ClientRegistration.dylib', 'VM27BundleParentV1.dylib'],
          ['-framework', 'Security', '-framework', 'CoreFoundation'])
    build('v3', 'VM27OwnedStartupV3.dylib', ['vm27_owned_startup_coordinator_v3.c'],
          ['VM27OriginalV10Transport.dylib', 'VM27HeadlessCheckIn.dylib'], ['-framework', 'CoreFoundation'])
    reexports = ['VM27OriginalV10Transport.dylib', 'VM27OwnedStartupV3.dylib', 'VM27HeadlessCheckIn.dylib']
    build('aggregate', 'VM27StartupV10.dylib', ['vm27_owned_startup_aggregate_v10.c'], [],
          ['-Wl,-reexport_library,' + str(ios / name) for name in reexports])

    images = {row['name']: route.metadata((ios / row['name']).read_bytes()) for row in libraries}
    assert len(images) == 13 and 'VM27LargeConsumer.dylib' not in images
    for name, metadata in images.items():
        assert metadata['header'][1] == 0x100000c and metadata['header'][2] & 0xffffff == 2
        assert metadata['header'][3] == 6 and metadata['build'][0] == 2
        assert not any(section['bytes'] for section in metadata['sections'] if section['name'] in ('__mod_init_func', '__init_offsets', '__interpose'))
        if not next(row['oldByteExactCopy'] for row in libraries if row['name'] == name):
            assert not metadata['signatures']
        for dependency in metadata['dependencies']:
            if dependency['path'].startswith(('@rpath/', '@loader_path/')):
                child = images[Path(dependency['path']).name]
                assert child['ID']['compatibilityVersion'] >= dependency['compatibilityVersion']
    aggregate = images['VM27StartupV10.dylib']
    assert not any(section['bytes'] for section in aggregate['sections'] if section['name'] == '__text')
    assert {Path(dep['path']).name for dep in aggregate['dependencies'] if dep['command'] == 0x8000001f} == set(reexports)
    imports = route.M.imports((ios / 'VM27OriginalV10Transport.dylib').read_bytes())['imports']
    typed_imports = []
    for symbol in ['_VM27LargePrivateServiceConsumerV2CheckMessage', '_VM27LargePrivateServiceConsumerV2CopyState']:
        matches = [row for row in imports if row['name'] == symbol]
        assert len(matches) == 1 and not matches[0]['weak'] and matches[0]['ordinal'] > 0
        dependency = images['VM27OriginalV10Transport.dylib']['dependencies'][matches[0]['ordinal'] - 1]
        assert dependency['path'] == '@rpath/VM27LargeConsumerV2.dylib'
        typed_imports.append(dict(symbol=symbol, ordinal=matches[0]['ordinal'], owner=dependency['path'], strong=True))
    assert not any(row['name'] in ('_VM27LargePrivateServiceConsumerCheckMessage', '_VM27LargePrivateServiceConsumerCopyState') for row in imports)
    coordinator_imports = route.M.imports((ios / 'VM27OwnedStartupV3.dylib').read_bytes())['imports']
    coordinator_routes = []
    for symbol in ['_VM27OriginalV10TransportInstallClientFactoryMessage', '_VM27OriginalV10TransportCreateServerWithParent']:
        matches = [row for row in coordinator_imports if row['name'] == symbol]
        assert len(matches) == 1 and not matches[0]['weak'] and matches[0]['ordinal'] > 0
        dependency = images['VM27OwnedStartupV3.dylib']['dependencies'][matches[0]['ordinal'] - 1]
        assert dependency['path'] == '@rpath/VM27OriginalV10Transport.dylib'
        coordinator_routes.append(dict(symbol=symbol, ordinal=matches[0]['ordinal'], owner=dependency['path'], strong=True))
    assert not any(row['name'].startswith('_VM27OriginalV9') for row in coordinator_imports)
    consumer_imports = {row['name'] for row in route.M.imports((ios / 'VM27LargeConsumerV2.dylib').read_bytes())['imports']}
    assert {'_VM27LargeServicePlanCheckReceivedMessage', '_csops_audittoken', '_xpc_dictionary_get_audit_token'} <= consumer_imports
    exports = {row['symbol'] for row in images['VM27LargeConsumerV2.dylib']['exports']}
    assert {'_VM27LargePrivateServiceConsumerV2Create', '_VM27LargePrivateServiceConsumerV2CheckMessage', '_VM27LargeStrictIdentityV2CheckReceivedMessage'} <= exports
    save(out / 'graph-verification.json', dict(typedConsumerImports=typed_imports, typedCoordinatorImports=coordinator_routes, images=images,
         noOldConsumerImage=True, sameSharedHeadlessAndRegistrationProviders=True,
         nativeGateAndKernelQueryImportsPresent=True, zeroInstructionAggregate=True,
         providerGraphExecuted=False, originalVMMExecuted=False, completeStrongVMMClosure=False))

    # Run the established state/lifetime scenarios through the NEW typed V3
    # boundary; only the transport entry points are explicit test doubles.
    wrapper = out / 'local-v3-state.c'
    adaptation = (source / 'vm27_owned_startup_coordinator_v3.c').read_text()
    wrapper.write_text(adaptation.rsplit('#include "vm27_owned_startup_coordinator_v2.c"', 1)[0] +
                       '#include "test-vm27-owned-startup-coordinator-v2.c"\n')
    mac_sdk = run('mac-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    local_base = [clang, '-std=c11', '-fblocks', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                  '-g', '-O1', '-isysroot', mac_sdk, '-I', str(source)]
    local_summaries = []
    for flavor, flags in [('ordinary', []), ('sanitizers', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        objects = []
        for instance in ('A', 'B'):
            target = out / (flavor + '-checkin-' + instance + '.o')
            run(flavor + '-checkin-' + instance, local_base + flags + [
                '-D_LSApplicationCheckIn=VM27TestCheckIn' + instance,
                '-DVM27CopyPrivateHeadlessCheckInState=VM27TestCopyCheckIn' + instance,
                '-c', str(source / 'vm27_headless_checkin_v1.c'), '-o', str(target)])
            objects.append(str(target))
        contents = out / (flavor + 'V3State.app/Contents')
        macos = contents / 'MacOS'
        macos.mkdir(parents=True)
        target = macos / 'local-state'
        (contents / 'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier='org.virtualmac.local.V3' + flavor,
            CFBundleExecutable=target.name, CFBundleName='VM27 typed V2 consumer local state',
            CFBundlePackageType='APPL', CFBundleVersion='1')))
        run(flavor + '-state-compile', local_base + flags + [str(source / 'vm27_owned_startup_coordinator_v3.c'), str(wrapper)] + objects +
            ['-framework', 'CoreFoundation', '-o', str(target)])
        output = run(flavor + '-state-run', [str(target)], {'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1'})
        records = [json.loads(line) for line in output.splitlines()]
        assert len(records) == 9 and records[-1]['scenarios'] == 8 and records[-1]['passed']
        assert all(row['passed'] and row['checks'] > 0 and not row['genuineV9Executed'] and row['nativeCPUOperations'] == 0 for row in records[:-1])
        local_summaries.append(dict(flavor=flavor, scenarios=8, checks=sum(row['checks'] for row in records[:-1]),
            explicitTransportDoubles=True, realTwoCheckInInstances=True, passed=True))
    # Re-run the actual unchanged strict result implementation with its explicit
    # positive/refusal/query-corruption doubles. Native operations stay zero.
    strict_out = out / 'strict-result-local'
    run('strict-result-local', [sys.executable, str(STRICT_CHECK), str(strict_out)])
    strict_result = json.loads((strict_out / 'result.json').read_text())
    assert strict_result['realNativePolicyChecks'] == 0 and strict_result['realCsopsQueries'] == 0
    for record in before + old_pins:
        assert pin(Path(record['path'])) == record
    candidate = dict(schema='NEW unsigned iOS V10 V3 typed V2 consumer provider graph v1',
        inputs=before, sourceSnapshots=[pin(path) for path in sorted(source.iterdir())],
        unchangedBodyAdaptations=adaptations, libraries=libraries, oldInputsByteExactBeforeAfter=old_pins,
        typedConsumerImports=typed_imports, typedCoordinatorImports=coordinator_routes,
        processes=processes, localCoordinatorSummaries=local_summaries,
        strictResultLocal=pin(strict_out / 'result.json'), localStrictDoubleSummaries=strict_result['localDoubleSummaries'],
        consumerV2LinkedWithoutOpaqueCasts=True, nativeGatesUnchangedAndNoFallback=True,
        compiledIOSOnly=True, signingCalls=0, deviceOperations=False, providerGraphExecuted=False,
        realNativePolicyChecks=0, realCsopsQueries=0, originalVMMExecuted=False,
        trustedOriginalPreMainCallerIntegrated=False, completeStrongVMMClosure=False,
        nativeCPUOperations=0, guestInstructions=0, full27Backend=False)
    save(out / 'candidate.json', candidate)
    save(out / 'freeze.json', dict(files=[pin(path) for path in sorted(out.rglob('*')) if path.is_file()]))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
        libraries=len(libraries), newUnsignedLibraries=5, oldByteExactLibraries=8,
        typedConsumerIntegrated=True, originalExecuted=False)))


if __name__ == '__main__':
    main()
