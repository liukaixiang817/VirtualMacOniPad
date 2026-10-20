#!/usr/bin/env python3
"""Build only a finite ownership semantic component and ordinary Mac oracle."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('observed_component_build', HERE / 'build-modern-swift-hid-bitwise-take-data-v1.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
p, HOST = b.p, b.HOST


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    inputs = [Path(__file__)] + [HOST / ('modern_swift_hid_observed_cvw_v2_' + suffix) for suffix in
        ('compat.h', 'compat.cpp', 'fixture.cpp', 'fixture.swift')]
    inputs += [HOST / 'modern_swift_hid_bitwise_take_compat.cpp', HOST / 'modern_swift_hid_bitwise_take_compat.h',
        p.NODE / 'universalhid-cvw-observed-ownership-abi-readonly-v7/audit.json',
        p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-BytecodeLayouts.cpp',
        p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-RuntimeFunctions.def']
    pins = list(map(p.pin, inputs))
    commands, roles = [], []
    cache = out / 'swift-module-cache'
    cache.mkdir()

    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(), stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out / 'commands.json', commands)
        assert result.returncode == 0, (label, result.stderr.decode())
        return result

    try:
        for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos13.0'),
                                   ('mac-sanitized', 'macosx', 'arm64e-apple-macos13.0'),
                                   ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
            directory = out / role
            directory.mkdir()
            sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
            compile = ['xcrun', '--sdk', sdk, 'clang++', '-target', target, '-isysroot', sdkpath,
                '-std=c++17', '-O2', '-fno-exceptions', '-fno-rtti']
            if role == 'ios':
                obj = directory / 'semantic-component.unsigned.inert.object-data'
                run(role + '-component', compile + ['-c', HOST / 'modern_swift_hid_observed_cvw_v2_compat.cpp', '-o', obj])
                roles.append(dict(role=role, component=p.pin(obj), originalSymbolEntryProvided=False,
                    codeSigned=False, nativeIOSExecuted=False))
                continue
            sanitizers = ['-fsanitize=address,undefined'] if role == 'mac-sanitized' else []
            obj = directory / 'fixture.o'
            run(role + '-cpp', compile + sanitizers + ['-c', HOST / 'modern_swift_hid_observed_cvw_v2_fixture.cpp', '-o', obj])
            executable = directory / 'ownership-fixture'
            argv = ['xcrun', '--sdk', sdk, 'swiftc', '-target', target, '-sdk', sdkpath,
                '-module-cache-path', cache, '-O', HOST / 'modern_swift_hid_observed_cvw_v2_fixture.swift', obj,
                '-Xlinker', '-lc++', '-o', executable]
            if role == 'mac-sanitized':
                argv.append('-sanitize=address')
                resource = run('clang-resource', ['xcrun', '--sdk', sdk, 'clang', '--print-resource-dir']).stdout.decode().strip()
                argv.append(Path(resource) / 'lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib')
            run(role + '-link', argv)
            result = run(role + '-native-compare', [executable])
            actual = json.loads(result.stdout)
            assert not result.stderr and actual['nativeComparedCases'] >= 10000
            assert actual['realObjectsCreated'] == actual['realObjectsDestroyed'] == 16
            assert actual['enumTagPairs'] == 200 and all(n > 0 for n in actual['operations'])
            roles.append(dict(role=role, executable=p.pin(executable), actualOrdinaryMac=actual,
                addressAndUndefinedSanitized=role == 'mac-sanitized'))
        assert list(map(p.pin, inputs)) == pins
        report = dict(schema='Observed six-tag finite CVW ownership semantic component v2', inputs=pins, roles=roles,
            ordinaryMacGenuineCoreCompared=True, originalSymbolEntryProvided=False,
            productionProgramIdentityWhitelistImplemented=False, productionOriginalHIDEntryExecuted=False,
            originalHIDLoaded=False, originalVZLoaded=False, remainingFiveStrongBindingsRouted=False,
            processGlobalRuntimeOverrideHookIdentityPreserved=False, allSwiftBytecodeSchemasImplemented=False,
            candidateReadyForNativeLoading=False, codeSigned=False, deviceOperations=0, nativeIOSExecuted=False,
            currentCompleteProviderDependencyGraphValidated=False, full27Backend=False)
        p.save(out / 'candidate.json', report)
        files = [x for x in out.rglob('*') if x.is_file() and 'swift-module-cache' not in x.parts]
        p.save(out / 'freeze.json', dict(files=pins + list(map(p.pin, files)), deviceOperations=0, nativeIOSExecuted=False))
        print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), roles=roles)))
    except Exception as error:
        failed = out / 'failed-sources'
        failed.mkdir(exist_ok=True)
        for path in inputs:
            (failed / path.name).write_bytes(path.read_bytes())
        p.save(out / 'failure.json', dict(error=repr(error), inputPins=pins, deviceOperations=0,
            originalSymbolEntryProvided=False, nativeIOSExecuted=False))
        raise


if __name__ == '__main__':
    main()
