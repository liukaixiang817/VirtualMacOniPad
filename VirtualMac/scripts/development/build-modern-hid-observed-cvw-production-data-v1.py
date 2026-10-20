#!/usr/bin/env python3
"""Build an unsigned inert five-entry finite ownership provider, no device load."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cvw_build_finite', HERE / 'generate-modern-hid-observed-cvw-registry-v1.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
p, s, HOST = g.p, g.b.b.s, g.b.HOST
from current_kernel_capture_v1 import join as join_kernel
SYMBOLS = ['_swift_cvw_destroy', '_swift_cvw_initWithCopy', '_swift_cvw_assignWithCopy',
           '_swift_cvw_assignWithTake', '_swift_cvw_initializeBufferWithCopyOfBuffer']
WHITELIST = p.NODE / 'hid-observed-cvw-production-whitelist-readonly-v1/audit.json'
COMPONENT = p.NODE / 'hid-observed-cvw-component-build-v5/candidate.json'
PARSER = p.NODE / 'hid-observed-cvw-registry-local-review-v2/review.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    whitelist, component, parser = [json.loads(path.read_text()) for path in (WHITELIST, COMPONENT, PARSER)]
    assert len(whitelist['rows']) == 65 and not whitelist['productionRuntimeIdentityPassed']
    original_registry = json.loads((g.DIRECTORY / 'observed-registry.json').read_text())
    assert max(row['bytes'] for row in original_registry['programs']) == 584
    assert component['ordinaryMacGenuineCoreCompared'] and len(parser['roles']) == 2
    inputs = [Path(__file__), WHITELIST, COMPONENT, PARSER,
        HOST / 'modern_swift_hid_observed_cvw_entry.cpp', HOST / 'modern_swift_hid_observed_cvw_identity_fixture.cpp',
        HOST / 'modern_swift_hid_observed_cvw_v2_compat.cpp', HOST / 'modern_swift_hid_observed_cvw_v2_compat.h',
        HOST / 'modern_swift_hid_bitwise_take_compat.cpp', HOST / 'modern_swift_hid_bitwise_take_compat.h']
    for name, record in [('modern_swift_hid_observed_cvw_registry.h', whitelist['generatedRegistry']['header']),
                         ('modern_swift_hid_observed_cvw_prefix_registry.h', whitelist['prefixHeader'])]:
        assert p.pin(Path(record['path'])) == record
        path = out / name; path.write_bytes(Path(record['path']).read_bytes()); inputs.append(Path(record['path']))
    for report in (component, parser):
        for pin in report['inputs']:
            assert p.pin(Path(pin['path'])) == pin
    pins = list(map(p.pin, inputs)); roles = []; commands = []
    exports = out / 'exports.list'; exports.write_text('\n'.join(SYMBOLS) + '\n')
    images = s.primary.captured_images(); current_pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        current_pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    current_pins += join_kernel(s, images); assert len(images) == 17
    source = HOST / 'modern_swift_hid_observed_cvw_entry.cpp'

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out / 'commands.json', commands)
        assert result.returncode == 0, (label, result.stderr.decode())
        return result
    try:
        for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos13.0'),
                                  ('mac-sanitized', 'macosx', 'arm64e-apple-macos13.0'),
                                  ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
            directory = out / role; directory.mkdir()
            sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).stdout.decode().strip()
            compile = ['xcrun', '--sdk', sdk, 'clang++', '-target', target, '-isysroot', sdkpath,
                '-std=c++17', '-O2', '-fno-exceptions', '-fno-rtti', '-fvisibility=hidden', '-I', out, '-I', HOST]
            provider = directory / ('OW.unsigned.inert.macho-data' if role == 'ios' else 'VM27HIDObservedOwnership.dylib')
            args = compile + ['-dynamiclib', source, '-lswiftCore', '-lobjc',
                '-Wl,-install_name,@rpath/VM27HIDObservedOwnership.dylib', '-Wl,-exported_symbols_list,' + str(exports), '-o', provider]
            if role == 'ios': args += ['-Wl,-no_adhoc_codesign']
            run(role + '-provider-build', args)
            run(role + '-dyld-validate', ['xcrun', 'dyld_info', '-validate_only', provider])
            raw = provider.read_bytes(); definitions = {}
            for cmd, at, size in p.commands(raw):
                if cmd == 0x80000033:
                    offset, length = struct.unpack_from('<II', raw, at + 8)
                    definitions = {x['symbol']: x for x in p.export_trie(raw[offset:offset + length])}
            assert set(definitions) == set(SYMBOLS)
            record = dict(role=role, provider=p.pin(provider), exports=definitions)
            if role == 'ios':
                assert not any(cmd == 0x1d for cmd, at, size in p.commands(raw))
                deps = {x['ordinal']: x['path'] for x in p.dependencies(raw)}
                imports = []
                for row in p.imports(raw)['imports']:
                    assert row['ordinal'] > 0 and not row['weak'] and not row.get('addend', 0)
                    proof = s.primary.resolve(images, deps[row['ordinal']], row['name'])
                    assert proof['status'] == 'actualDirectExport', (row, proof)
                    imports.append(dict(row, dependency=deps[row['ordinal']], actualCurrentDefinition=proof))
                ir = directory / 'entry.ll'; run(role + '-IR', compile + ['-S', '-emit-llvm', source, '-o', ir])
                text = ir.read_text()
                for name in SYMBOLS:
                    entry = re.search(r'^define ([^\n]*)@' + name[1:] + r'\(([^\n]*)\)', text, re.M)
                    assert entry and 'swiftcc' not in entry[1]
                    count = 2 if name == '_swift_cvw_destroy' else 3
                    assert entry[2].count('ptr noundef') == count, entry.group(0)
                assert 'llvm.trap' in text and 'Identity' in text and 'ProductionMetadata' in text
                record.update(unsignedInertData=True, IR=p.pin(ir), currentExactNativeImports=imports,
                    allPositiveStrongImportsActualCurrentDefined=True, nativeIOSExecuted=False, codeSigned=False)
            else:
                exe = directory / 'identity-fixture'
                args = compile + [HOST / 'modern_swift_hid_observed_cvw_identity_fixture.cpp', '-lswiftCore', '-lobjc', '-o', exe]
                if role == 'mac-sanitized': args += ['-fsanitize=address,undefined']
                run(role + '-identity-build', args)
                original = json.loads((p.NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json').read_text())
                result = run(role + '-identity-compare', [exe] + [x['candidate']['path'] for x in original['images']])
                actual = json.loads(result.stdout)
                assert not result.stderr and actual['syntheticExactOriginalMetadataCases'] == 65
                assert actual['realProductionOwnerRejections'] == 65 and actual['counterexamplesRejected'] >= 390
                record.update(actualOrdinaryMacIdentity=actual, fixture=p.pin(exe),
                    addressAndUndefinedSanitized=role == 'mac-sanitized')
            roles.append(record)
        assert pins == list(map(p.pin, inputs))
        report = dict(schema='Genuine finite 65-static-plus-completed-POD CVW ownership provider data v1',
            inputs=pins, roles=roles, originalProgramAndMetadataBytesPreserved=True,
            originalRelativeFNProgramTagsPreserved=True, originalGetterIdentityIsExact28Bytes=True,
            ordinaryMacGenuineCoreOwnershipCompared=component['roles'][:2], ordinaryMacActualOriginalProgramsParsed=parser['roles'],
            exactStaticMetadataWhitelist=65, separatelyCompletedOriginalPODSupported=True,
            allFiveNamedEntriesImplemented=True, allPositiveStrongImportsActualCurrentDefined=True,
            productionHIDIdentityGatePassed=False, productionOriginalHIDEntryExecuted=False,
            fullSwiftBytecodeInterpreterImplemented=False, processGlobalRuntimeOverrideHookIdentityPreserved=False,
            currentCompleteProviderDependencyGraphValidated=False, originalHIDLoaded=False, originalVZLoaded=False,
            nativeIOSExecuted=False, deviceOperations=0, codeSigned=False, candidateReadyForNativeLoading=False,
            originalEnumCallbackRuntimeCallabilityProven=False, full27Backend=False)
        p.save(out / 'candidate.json', report)
        files = [x for x in out.rglob('*') if x.is_file()]
        p.save(out / 'freeze.json', dict(files=pins + current_pins + list(map(p.pin, files)), deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out / 'candidate.json'), roles=roles)))
    except Exception as error:
        failed = out / 'failed-sources'; failed.mkdir(exist_ok=True)
        for path in inputs: (failed / path.name).write_bytes(path.read_bytes())
        p.save(out / 'failure.json', dict(error=repr(error), inputs=pins, deviceOperations=0, nativeIOSExecuted=False))
        raise


if __name__ == '__main__': main()
