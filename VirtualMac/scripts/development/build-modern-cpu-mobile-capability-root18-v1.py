#!/usr/bin/env python3
"""Replace only F21 and its root-only acquisition object in one unsigned DSO.

No device, signing, trust-cache, or native hypervisor execution is performed.
The separately authored AcquisitionV3 must already have a frozen object and
successful bounded source/admission models before this composition is used.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'cpu-dtr-factory-local-v21-attempt2'


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def check_pin(row):
    need(pin(row['path']) == row, 'actual pin: ' + row['path'])


def load_json(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--acquisition-candidate', type=Path, required=True)
    parser.add_argument('--acquisition-freeze', type=Path, required=True)
    parser.add_argument('--acquisition-object', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    acquisition_candidate = args.acquisition_candidate.resolve()
    acquisition_freeze = args.acquisition_freeze.resolve()
    acquisition_object = args.acquisition_object.resolve()
    need(out.parent == N and not out.exists(), 'fresh host-only diagnostic directory')
    need(acquisition_candidate.parent.parent == N and
         acquisition_freeze.parent == acquisition_candidate.parent and
         acquisition_object.parent == acquisition_candidate.parent,
         'one actual acquisition candidate directory')
    old = load_json(BASE / 'candidate.json')
    old_freeze = load_json(BASE / 'freeze.json')
    for row in old_freeze['files']:
        check_pin(row)
    fresh = load_json(acquisition_candidate)
    fresh_freeze = load_json(acquisition_freeze)
    for row in fresh_freeze['files']:
        check_pin(row)
    pinned_paths = {Path(row['path']).resolve() for row in fresh_freeze['files']}
    need(acquisition_candidate in pinned_paths and acquisition_object in pinned_paths,
         'new acquisition candidate and actual object must be frozen')
    # Admission-model contents are copied verbatim into the candidate; a new
    # Root18 DSO cannot turn those host observations into device execution.
    need(fresh.get('deviceOperations', 0) == 0 and fresh.get('nativeOperations', 0) == 0,
         'acquisition artifact must be offline')
    old_commands = load_json(BASE / 'commands.json')
    commands = []
    out.mkdir()

    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=60)
        stdout = out / (label + '.stdout')
        stderr = out / (label + '.stderr')
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, returncode=result.returncode,
                             stdout=pin(stdout), stderr=pin(stderr)))
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        need(result.returncode == 0, label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout

    factory_source = S / 'modern_cpu_native_public_factory_v22.c'
    factory_header = S / 'modern_cpu_native_public_factory_v22.h'
    need(factory_source.read_text().count('#include "modern_cpu_native_public_factory_v21.c"') == 1,
         'F22 contains F21 exactly once')
    factory_object = out / 'modern_cpu_native_public_factory_v22.o'
    compile_argv = next(q['argv'] for q in old_commands
                        if q['label'] == 'ios-modern_cpu_native_public_factory_v21').copy()
    compile_argv[compile_argv.index('-c') + 1] = factory_source
    compile_argv[-1] = factory_object
    run('ios-factory22', compile_argv)
    provider = out / 'VM27HVVMProductionRoot18.unsigned.dylib'
    exports_file = out / 'exports.txt'
    exports_file.write_text('\n'.join(old['exactExports']) + '\n')
    link_argv = next(q['argv'] for q in old_commands if q['label'] == 'ios-link').copy()
    replaced_acquisition = []
    replaced_factory = []
    for index, value in enumerate(link_argv):
        if value.endswith('/modern_cpu_config_capability_acquisition_v2.o'):
            replaced_acquisition.append(pin(value))
            link_argv[index] = str(acquisition_object)
        elif value.endswith('/modern_cpu_native_public_factory_v21.o'):
            replaced_factory.append(pin(value))
            link_argv[index] = str(factory_object)
        elif value.startswith('-Wl,-exported_symbols_list,'):
            link_argv[index] = '-Wl,-exported_symbols_list,' + str(exports_file)
        elif value.startswith('-Wl,-install_name,'):
            link_argv[index] = '-Wl,-install_name,@rpath/' + provider.name
    need(len(replaced_acquisition) == 1 and len(replaced_factory) == 1,
         'replace exactly one actual acquisition object and one factory object')
    need(not any('acquisition_v2.o' in str(value) for value in link_argv),
         'no old root-only acquisition object')
    # The actual SecTask entitlement reader in AcquisitionV3 belongs to Security.
    # Existing CF/libSystem/objc dependencies remain in the original link order.
    link_argv[-1] = str(provider)
    link_argv[link_argv.index('-o'):link_argv.index('-o')] = ['-framework', 'Security']
    reused = {Path(value).resolve() for value in link_argv
              if str(value).endswith('.o') and Path(value).resolve().parent != out}
    need(acquisition_object in reused, 'real separately frozen acquisition object')
    run('ios-link', link_argv)
    run('ios-validate', ['xcrun', 'dyld_info', '-validate_only', provider])
    macho_parser = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('root18macho', macho_parser)
    lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
    actual = lib.MachO(provider.read_bytes())
    prior = lib.MachO(Path(old['provider']['path']).read_bytes())
    need(set(actual.exports) == set(old['exactExports']) and len(actual.exports) == 153,
         'the exact 153 inherited exports remain, including DTR')
    need('_VM27CPUFactoryAccessDTRV21' in actual.exports and
         '_VM27VMMReadDTRV1' in actual.exports and '_VM27VMMWriteDTRV1' in actual.exports,
         'all three genuine DTR exports retained')
    def import_identity(image, row):
        ordinal = row['ordinal']
        load = image.loads[ordinal - 1]['path'] if ordinal > 0 else str(ordinal)
        return (load, row['name'], row['weak'], row['addend'])
    old_imports = {import_identity(prior, row) for row in prior.imports}
    new_imports = {import_identity(actual, row) for row in actual.imports}
    need(old_imports <= new_imports, 'no original native dependency is lost')
    imports_delta = [dict(library=a, name=b, weak=c, addend=d)
                     for a, b, c, d in sorted(new_imports - old_imports)]
    need(imports_delta, 'actual entitlement admission must have real native dependencies')
    need(all(row['weak'] == 0 for row in imports_delta), 'new admission imports are strong')
    native_index = N / 'current-native-header-export-index-v3/index.json'
    native_images = load_json(native_index)['images']

    def resolve_native(path, name, visited=()):
        need((path, name) not in visited, 'native reexport cycle')
        if path not in native_images:
            return []
        image = native_images[path]
        row = image['definitions'].get(name)
        trail = visited + ((path, name),)
        if row is not None:
            if row['flags'] & 8:
                dependency = next(d for d in image['dependencies']
                                  if d['ordinal'] == row['ordinal'])
                return resolve_native(dependency['path'], row.get('importedName') or name, trail)
            return [dict(path=path, name=name, UUID=image['UUID'], base=image['base'],
                         definition=row, route=[dict(path=p, name=n) for p, n in trail],
                         actualCommandSourceRanges=image['actualCommandSourceRanges'],
                         actualCompleteExportSource=image['actualCompleteExportSource'],
                         actualCompleteCommands=image['actualCompleteCommands'])]
        found = []
        for dependency in image['dependencies']:
            if dependency['command'] == 0x8000001f:
                found.extend(resolve_native(dependency['path'], name, trail))
        return found

    native_delta = []
    for row in imports_delta:
        definitions = resolve_native(row['library'], row['name'])
        need(len(definitions) == 1, 'one true current native definition: ' + row['name'])
        native_delta.append(dict(imported=row, currentDefinition=definitions[0]))
    native_delta_file = out / 'current-native-admission-delta.json'
    native_delta_file.write_text(json.dumps(dict(
        schema='Exact added Root18 native imports joined to current captured exports v1',
        currentNativeIndex=pin(native_index), definitions=native_delta,
        missingDefinitions=[], deviceOperations=0, nativeOperations=0), indent=2) + '\n')
    typed = out / 'typed-root18.cpp'
    typed.write_text('#include "modern_cpu_native_public_factory_v22.h"\n'
                     '#include "modern_vmm_dtr_v1.h"\n'
                     'extern "C" uint64_t typed_root18(hv_vcpu_t id,VM27VMMScalarFailureV1 fail){'
                     'uint64_t v=0;VM27CPUFactoryAccessDTRV21(id,VZ_KERNEL_DTR_READ_RX_V23,0,&v);'
                     'VM27VMMWriteDTRV1(id,0x9820,v,fail);return VM27VMMReadDTRV1(id,0x9828,fail);}\n')
    run('typed-cpp-ios', ['xcrun', '--sdk', 'iphoneos', 'clang++', '-arch', 'arm64e',
                         '-miphoneos-version-min=16.1', '-std=c++17', '-Wall', '-Wextra',
                         '-Werror', '-I', S, '-dynamiclib', typed, provider,
                         '-Wl,-undefined,error', '-Wl,-no_adhoc_codesign', '-o',
                         out / 'typed-root18.unsigned.dylib'])
    lifecycle_source = S / 'modern_cpu_kernel_lifecycle_v23.c'
    life = lifecycle_source.read_text()
    need(life.count('static pthread_mutex_t RegistryMutex') == 1 and
         life.count('static VZKernelVM *RegisteredVM') == 1, 'one unchanged lower registry')
    reused_pins = [pin(path) for path in sorted(reused)]
    record = dict(
        schema='Root18 / F22 one-registry AcquisitionV3 composition v1',
        builder=pin(__file__), provider=pin(provider), inheritedCandidate=pin(BASE / 'candidate.json'),
        inheritedFreeze=pin(BASE / 'freeze.json'), acquisitionCandidate=pin(acquisition_candidate),
        acquisitionFreeze=pin(acquisition_freeze), acquisitionObject=pin(acquisition_object),
        replacedObjects=dict(acquisition=replaced_acquisition, factory=replaced_factory),
        sourcePins=old['sourcePins'] + [pin(factory_source), pin(factory_header)],
        acquisitionSourcePins=fresh.get('sourcePins', []), acquisitionModels=fresh.get('models', {}),
        reusedObjectPins=reused_pins, actualExports=len(actual.exports), exactExports=sorted(actual.exports),
        actualNativeImports=len(actual.imports), inheritedNativeImports=len(prior.imports),
        addedNativeImports=imports_delta, removedNativeImports=[], actualLoads=actual.loads,
        addedCurrentNativeDefinitionProof=pin(native_delta_file),
        singleCPURegistry=True, allF21DTRSemanticsRetained=True,
        oneAcquisitionOnceCache=True, oldRootOnlyAcquisitionObjectLinked=False,
        frozen689ModelsRepeated=False, deviceOperations=0, nativeOperations=0,
        codeSigned=False, providerLoadedOnDevice=False, mobileNativeCapabilityExecuted=False,
        guestBoot=False)
    (out / 'candidate.json').write_text(json.dumps(record, indent=2) + '\n')
    paths = set(reused) | {factory_source, factory_header, Path(__file__).resolve(),
        BASE / 'candidate.json', BASE / 'freeze.json', BASE / 'commands.json',
        Path(old['provider']['path']), acquisition_candidate, acquisition_freeze,
        macho_parser, lifecycle_source, native_index} | set(out.iterdir())
    (out / 'freeze.json').write_text(json.dumps(dict(
        schema='Root18 one-registry mobile-admission unsigned composition freeze v1',
        files=[pin(path) for path in sorted(paths) if path.is_file()],
        deviceOperations=0, nativeOperations=0), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          provider=pin(provider), actualExports=len(actual.exports),
                          actualNativeImports=len(actual.imports), addedNativeImports=imports_delta)))


if __name__ == '__main__':
    main()
