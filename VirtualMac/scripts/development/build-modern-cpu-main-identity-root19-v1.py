#!/usr/bin/env python3
"""Replace one production bootstrap object, preserving the frozen CPU owner."""
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
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True, type=pathlib.Path)
    ap.add_argument('--main-identity-candidate', required=True, type=pathlib.Path)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh Root19 host output')
    base = N/'vm-hv-production-root18-mobile-capability-local-v1-attempt1'
    prior = json.loads((base/'candidate.json').read_bytes())
    main_candidate = args.main_identity_candidate.resolve()
    for freeze in (base/'freeze.json', main_candidate.parent/'freeze.json'):
        value = json.loads(freeze.read_bytes())
        rows = value.get('files', value.get('pins', []))
        need(rows, 'actual nonempty frozen input')
        for row in rows:
            need(pin(row['path']) == row, 'unchanged frozen input: '+row['path'])
    old_source = S/'vm27_hv_public_vm_bootstrap_v14.m'
    source = S/'vm27_hv_public_vm_bootstrap_v19.m'
    replacement = '''#include "vm27_actual_executable_image_v1.h"
static const struct mach_header *ActualMainImageV19(void) {
    VM27ActualExecutableImageV1 image = {0};
    return VM27ActualExecutableImageFindSelfV1(&image) == 0
        ? (const struct mach_header *)image.header : NULL;
}
#define MAIN_IMAGE_V14 ActualMainImageV19()'''
    original = old_source.read_text()
    need(original.count('#define MAIN_IMAGE_V14 _dyld_get_image_header(0)') == 1, 'exact original production selector')
    need(source.read_text() == original.replace('#define MAIN_IMAGE_V14 _dyld_get_image_header(0)', replacement),
         'only production main-image selector changed; all caller/UUID/BL/authorization gates retained')
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

    boot_commands = json.loads((N/'vm-hv-public-bootstrap-integration-local-v14-attempt1/commands.json').read_bytes())
    compile_argv = next(row['argv'] for row in boot_commands if row['label'] == 'ios-boot').copy()
    boot = out/'vm27_hv_public_vm_bootstrap_v19.o'
    compile_argv[compile_argv.index('-c')+1] = source
    compile_argv[-1] = boot
    run('compile-bootstrap19', compile_argv)
    finder = S/'vm27_actual_executable_image_v1.c'
    finder_object = out/'vm27_actual_executable_image_v1.o'
    finder_argv = compile_argv.copy()
    finder_argv.remove('-fno-objc-arc')
    finder_argv[finder_argv.index('-c')+1] = finder
    finder_argv[-1] = finder_object
    run('compile-real-main-finder', finder_argv)
    closure = {}
    for label, argv, path in [('bootstrap', compile_argv, source), ('finder', finder_argv, finder)]:
        deps_argv = argv[:argv.index('-c')]+['-MM', path]
        text = run(label+'-actual-include-closure', deps_argv).decode().replace('\\\n', ' ')
        for item in shlex.split(text.split(':', 1)[1]):
            row = pin(item)
            closure[row['path']] = row
    old_commands = json.loads((base/'commands.json').read_bytes())
    link = next(row['argv'] for row in old_commands if row['label'] == 'ios-link').copy()
    provider = out/'VM27HVVMProductionRoot19.unsigned.dylib'
    exports = out/'exports.txt'
    exports.write_text('\n'.join(prior['exactExports'])+'\n')
    replaced = []
    for index, value in enumerate(link):
        if value.endswith('/vm27_hv_public_vm_bootstrap_v14.o'):
            replaced.append(pin(value))
            link[index] = boot
        elif value.startswith('-Wl,-exported_symbols_list,'):
            link[index] = '-Wl,-exported_symbols_list,'+str(exports)
        elif value.startswith('-Wl,-install_name,'):
            link[index] = '-Wl,-install_name,@rpath/'+provider.name
    need(len(replaced) == 1, 'one actual Root14 bootstrap object replaced')
    link.insert(link.index('-o'), finder_object)
    link[-1] = provider
    reused = [pin(value) for value in link if str(value).endswith('.o') and pathlib.Path(value).parent != out]
    run('link-whole-root19', link)
    run('validate-whole-root19', ['xcrun', 'dyld_info', '-validate_only', provider])
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('root19_macho', reader)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    actual = m.MachO(provider.read_bytes())
    need(set(actual.exports) == set(prior['exactExports']) and len(actual.exports) == 153, 'exact inherited public ABI')
    need(all(not name.startswith('_VM27ActualExecutable') for name in actual.exports), 'shared finder hidden')
    need(len([row for row in reused if row['path'].endswith('/modern_cpu_kernel_lifecycle_v23.o')]) == 1, 'one real lower registry')
    need(len([row for row in reused if row['path'].endswith('/modern_cpu_config_capability_acquisition_v3.ios.o')]) == 1,
         'one unchanged Root/mobile genuine entitlement acquisition')
    need(not any(row['path'] == replaced[0]['path'] for row in reused), 'old index-zero bootstrap object absent')
    record = dict(schema='Actual Root19 production main identity composition v1',
        builder=pin(__file__), inheritedCandidate=pin(base/'candidate.json'), inheritedFreeze=pin(base/'freeze.json'),
        mainIdentityCandidate=pin(main_candidate), provider=pin(provider),
        replacedBootstrapObjects=replaced, actualNewObjects=[pin(boot), pin(finder_object)],
        actualIncludeClosure=list(closure.values()), reusedObjectPins=reused,
        exactExports=sorted(actual.exports), actualExports=len(actual.exports), actualNativeImports=len(actual.imports),
        actualLoads=actual.loads, singleCPURegistry=True, nativeAcquisitionUnchanged=True,
        callerAddressOriginalBLAndUUIDGatesUnchanged=True, productionNativeOpsAuthorizationUnchanged=True,
        inheritedCPUModelsRepeated=False, deviceOperations=0, nativeOperations=0,
        codeSigned=False, providerLoadedOnDevice=False, guestBoot=False)
    save(out/'candidate.json', record)
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += reused+list(closure.values())+[pin(__file__), pin(reader), pin(base/'candidate.json'),
        pin(base/'freeze.json'), pin(base/'commands.json'), pin(main_candidate), pin(main_candidate.parent/'freeze.json'), pin(old_source)]
    save(out/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps({'candidate': pin(out/'candidate.json'), 'provider': pin(provider),
                      'actualExports': len(actual.exports), 'actualNativeImports': len(actual.imports)}))


if __name__ == '__main__':
    main()
