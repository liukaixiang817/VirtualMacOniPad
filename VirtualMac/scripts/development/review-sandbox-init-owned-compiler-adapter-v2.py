"""Independent finite HOST peer of the inactive flags3 adapter V2 product."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'sandbox-init-owned-compiler-adapter-independent-review-v2-attempt1'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    OUT.mkdir(exist_ok=False)
    adapter = NODE / 'sandbox-init-owned-compiler-adapter-local-v2-attempt1'
    native = NODE / 'sandbox-owned-compiler-adapter-current-definitions-v2-attempt1'
    compiler = NODE / 'genuine-sandbox-compiler-ios-unsigned-local-v1-attempt1'
    candidate = adapter / 'candidate.json'
    assert pin(candidate)['sha256'] == 'c69fd00fff9b683ad9a892e09771400a30ffe6aa7ccd275b1ce16a82f6ad134d'
    assert pin(adapter / 'freeze.json')['sha256'] == '711cf4b075853d9cb56c1b4bd715b2d47c9673231ee64e6c99ab2882bcdcba22'
    assert pin(native / 'report.json')['sha256'] == 'ca3eb330b0c5a4363a91fe8479f2377b9eef5c014c5b7ff382738c13e30c3b15'
    assert pin(compiler / 'candidate.json')['sha256'] == 'a75ebd2678202da139b8bef15bfb387b99e363e4e335c07255d5fd80fa66701c'
    inputs = [Path(__file__).resolve(), candidate, adapter / 'freeze.json', native / 'report.json', native / 'freeze.json', compiler / 'candidate.json']
    checked_freezes = []
    for directory in [adapter, native]:
        rows = json.loads((directory / 'freeze.json').read_text())['files']
        for row in rows:
            assert pin(row['path']) == row
        checked_freezes.append({'freeze': pin(directory / 'freeze.json'), 'actualRowsChecked': len(rows)})

    source = ROOT / 'VirtualMac/vz/host/vm27_sandbox_init_owned_compiler_v2.c'
    old_source = source.with_name('vm27_sandbox_init_owned_compiler_v1.c')
    assert source.read_bytes().replace(b'#define CHILD FLAT "/VMM.bundle/Contents/XPCServices/', b'#define CHILD FLAT "/XPCServices/') == old_source.read_bytes()
    inputs += [source, old_source]
    reader = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    inputs.append(reader)
    spec = importlib.util.spec_from_file_location('finite_adapter_peer_reader', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image = module.MachO((adapter / 'VM27SandboxInitOwnedCompilerV1.dylib').read_bytes())
    assert set(image.exports) == {'_VM27SandboxInitWithOwnedCompilerV1'}
    assert not any(command['cmd'] == 0x1d for command in image.commands)
    assert len(image.loads) == 1 and image.loads[0]['path'] == '/usr/lib/libSystem.B.dylib'
    assert len(image.imports) == 33
    assert all(row['ordinal'] == 1 and not row['weak'] and row['addend'] == 0 for row in image.imports)
    builds = [struct.unpack_from('<III', image.data, command['at'] + 8) for command in image.commands if command['cmd'] == 0x32]
    assert len(builds) == 1 and builds[0][0] == 2 and builds[0][1] == 0x100100
    index_path = NODE / 'current-native-header-export-index-v3/index.json'
    assert pin(index_path)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    inputs.append(index_path)
    index = json.loads(index_path.read_text())['images']
    closure = json.loads((native / 'report.json').read_text())
    assert closure['actualStrongImportCount'] == 33
    routes = closure['actualReexportRoutes']
    assert [row['name'] for row in image.imports] == [row['importName'] for row in routes]
    for row in routes:
        route = row['actualRoute']
        assert route[0]['image'] == '/usr/lib/libSystem.B.dylib' and route[0]['symbol'] == row['importName']
        for position, hop in enumerate(route):
            actual = index[hop['image']]
            assert actual['UUID'] == hop['UUID']
            if 'definition' in hop:
                assert actual['definitions'][hop['symbol']] == hop['definition']
            dependency = hop.get('wholeDylibReexport', hop.get('reexportDependency'))
            if dependency:
                actual_dependency = next(value for value in actual['dependencies'] if value['ordinal'] == dependency['ordinal'])
                assert actual_dependency == dependency and position + 1 < len(route)
                assert route[position + 1]['image'] == dependency['path']
                if 'wholeDylibReexport' in hop:
                    assert dependency['command'] == 0x8000001f and route[position + 1]['symbol'] == hop['symbol']
                else:
                    assert route[position + 1]['symbol'] == (hop['definition']['alias'] or hop['symbol'])
        assert route[-1]['definition']['flags'] == 0 and row['finalCurrentDefinition'] == route[-1]

    actual_compiler = compiler / 'flat/VM27GenuineSandboxCompiler27.dylib'
    inputs += [actual_compiler, adapter / 'VM27SandboxInitOwnedCompilerV1.dylib']
    data = actual_compiler.read_bytes()
    actual_image = module.MachO(data)
    assert actual_image.uuid == '648b6ec9b80a3673ac47f6f7806bb158'
    apis = [('sandbox_create_params', 0x848, '38bcb13f72f538f64686dd080e835e7dfab4c04de7543c2757b61bfd06282b87'),
            ('sandbox_set_param', 0x8c4, '5866c207ee5c34b37a3f5b878b27d826b84ef8d25ad0ae8151c87e49c4f45d33'),
            ('sandbox_compile_file', 0xa88, 'c4e11376bc9c0584d29f248a5ab0fc96bd80ee0b1ae8302d7afc9af697e65c91'),
            ('sandbox_free_profile', 0x1f0dc, 'f0e47579ecf6bf9e741b661f6412a8a5f8e3166872b0c3e62261d6d4a7fb9fdd'),
            ('sandbox_free_params', 0x1f128, '6ce717956e0f4cdfe1c9d558bf98ee4df63d1e3b3a239d50c7232c2aa843edd8')]
    checked_apis = []
    for name, rva, sha in apis:
        assert actual_image.exports['_' + name] == {'flags': 0, 'address': rva}
        assert hashlib.sha256(data[rva:rva + 16]).hexdigest() == sha
        checked_apis.append({'name': name, 'RVA': rva, 'actualPrefix16SHA': sha})

    review = {
        'schema': 'Independent finite HOST flags3 adapter V2 source and actual unsigned product peer v1',
        'reviewedCandidate': pin(candidate), 'compilerCompositionCandidate': pin(compiler / 'candidate.json'),
        'actualNativeClosureReport': pin(native / 'report.json'), 'actualFrozenInputsChecked': checked_freezes,
        'finiteLocalScopePassed': True, 'findings': [], 'actualStrongImportsIndependentlyChecked': 33,
        'actualNewCompilerFiveGuardBindings': checked_apis,
        'sourceReview': [
            {'lines': '31-39,151-185', 'finding': 'Corrected CHILD prefix exactly matches Runtime7 scope executable/resource path; role requires UID/eUID501, real main executable path and UUID. Three resources require canonical non-symlink file identity, UID501/mode0600/nlink1, stable FD/path metadata and full content hashes.'},
            {'lines': '86-149', 'finding': 'Fixed compiler/native handle dlsym guards require real path, UUID, export RVA and true code prefix. PAC is stripped only for inspection; callable dlsym pointer is retained. Dylib handles remain alive for the process so callee pointers stay valid.'},
            {'lines': '195-202,227-238', 'finding': 'Read-only 24B prefix and actual producer data hash admission does not replace the opaque object. Native apply receives the identical compiler return pointer. Same compiler frees actual profile then actual params once. Mac apply/notify is never called.'},
            {'lines': '71-84,207-240', 'finding': 'Compiler-provided error string is retained for caller. A missing public output buffer gets a local error string released by actual libSystem free. Actual apply return and errno, including errno zero on failure, are captured before logging and cleanup and restored on return.'},
            {'lines': '208-219', 'finding': 'Non3 flags preserve original arguments and true guarded native result without success fallback. Flags3 accepts only exact original resource and NULL public parameters. An atomic once gate allows at most one owned compile/apply sequence.'},
            {'lines': 'builder79-124', 'finding': 'Only source delta from V1 is actual VMM.bundle/Contents path. V1 known path defect stays explicit. Original Main/flags/fatal branch/PAC unchanged is an inactive recipe requirement; no patched Stage is produced. Existing 100 HOST mocks are inherited, not rerun.'}
        ],
        'unresolvedExecutionBoundaries': [
            'No iPad genuine compiler call or current boot-role answer was executed in this peer.',
            'HOST output hash admission is fail-closed; different genuine iPad output would be rejected and needs actual diagnostics rather than a fabricated identity.',
            'Mac27 serialized operation indexes and native iPad kernel bytecode semantics remain unproved. Native apply execution must be separately observed in the bounded owned process before recipe activation.',
            'This peer does not validate full sandbox policy equivalence, VM startup, guest boot, or existing 100 mock cases anew.'
        ],
        'StageIntegrationHeld': True, 'actualPatchedImageGenerated': False, 'signed': False,
        'deviceOperations': 0, 'nativeCompilerCalls': 0, 'nativeApplyCalls': 0, 'guestBooted': False,
        'inputs': [pin(path) for path in inputs]
    }
    save(OUT / 'review.json', review)
    save(OUT / 'freeze.json', {'schema': 'Independent inactive flags3 adapter V2 finite review freeze v1', 'files': review['inputs'] + [pin(OUT / 'review.json')], 'deviceOperations': 0})
    print(json.dumps({'review': pin(OUT / 'review.json'), 'freeze': pin(OUT / 'freeze.json')}))


if __name__ == '__main__':
    main()
