"""HOST-only real linker reexports; reuse the already frozen bridge object."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = NODE / 'sandbox-compiler-imports-compat-unsigned-local-v3-attempt1'
STAGE = NODE / 'independent27-owned-bundle-stage-v10-attempt1/candidate.json'
READER = NODE / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
OUT = NODE / 'sandbox-compiler-imports-compat-unsigned-local-v4-attempt1'
REEXPORTS = ['_malloc_type_calloc', '_malloc_type_malloc', '_malloc_type_realloc']


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    OUT.mkdir(exist_ok=False)
    spec = importlib.util.spec_from_file_location('independent_macho', READER)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    steps = []
    inputs = []

    def run(label, arguments):
        argv = list(map(str, arguments))
        env = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        process = subprocess.run(argv, capture_output=True, timeout=45, env=env)
        (OUT / (label + '.stdout')).write_bytes(process.stdout)
        (OUT / (label + '.stderr')).write_bytes(process.stderr)
        steps.append(dict(label=label, arguments=argv, exit=process.returncode,
                          stdout=pin(OUT / (label + '.stdout')),
                          stderr=pin(OUT / (label + '.stderr'))))
        (OUT / 'steps-in-progress.json').write_text(json.dumps(steps, indent=2) + '\n')
        if process.returncode:
            raise ValueError(label + ' failed')
        return process.stdout

    try:
        assert pin(READER)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'
        assert pin(OLD / 'candidate.json')['sha256'] == 'a9d47acc6eb45beab16067c5af67a2c0b7af487abc060809fcdad521079cf536'
        for row in json.loads((OLD / 'freeze.json').read_bytes())['files']:
            assert pin(row['path']) == row, ('changed old frozen input', row['path'])
        old = json.loads((OLD / 'candidate.json').read_bytes())
        stage = json.loads(STAGE.read_bytes())
        allocator_row = next(row for row in stage['stagedImages'] if row['key'] == 'VM27AllocatorProvider.dylib')
        allocator = Path(allocator_row['staged']['path'])
        assert pin(allocator) == allocator_row['staged']
        allocator_image = reader.MachO(allocator.read_bytes())
        assert allocator_image.uuid == 'da36155e4e3c3825b5b534b86d8754f1'
        for symbol in REEXPORTS:
            assert symbol in allocator_image.exports and not allocator_image.exports[symbol]['flags'] & 8
        native_index = NODE / 'current-native-header-export-index-v3/index.json'
        inputs = [pin(Path(__file__).resolve()), pin(READER), pin(STAGE), pin(allocator),
                  pin(OLD / 'candidate.json'), pin(OLD / 'freeze.json'), pin(OLD / 'imports.o'), pin(native_index)]
        inputs += old['inputs']
        exports = sorted(old['exactExports'] + REEXPORTS)
        (OUT / 'exports.list').write_text('\n'.join(exports) + '\n')
        (OUT / 'reexports.list').write_text('\n'.join(REEXPORTS) + '\n')
        binary = OUT / 'VM27SandboxCompilerImportsCompatV1.dylib'
        run('ios-link', ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64e',
            '-miphoneos-version-min=16.1', '-dynamiclib', OLD / 'imports.o', '-lSystem', allocator,
            '-install_name', '@loader_path/VM27SandboxCompilerImportsCompatV1.dylib',
            '-Wl,-reexported_symbols_list,' + str(OUT / 'reexports.list'),
            '-Wl,-exported_symbols_list,' + str(OUT / 'exports.list'),
            '-Wl,-undefined,error', '-Wl,-no_adhoc_codesign', '-o', binary])
        linked = binary.read_bytes()
        (OUT / 'actual-linker-output.dylib').write_bytes(linked)
        image = reader.MachO(linked)
        assert sorted(image.exports) == exports
        assert len(image.imports) == 13
        assert all(row['ordinal'] == 1 and not row['weak'] for row in image.imports)
        assert image.loads[0]['path'] == '/usr/lib/libSystem.B.dylib'
        assert image.loads[1]['path'] == '@rpath/VM27AllocatorProvider.dylib'
        assert all(load['cmd'] == 0xc for load in image.loads), 'Only exact symbol reexports, not an entire-library reexport'
        for symbol in REEXPORTS:
            assert image.exports[symbol] == dict(flags=8, ordinal=2, importedName='')
        commands = []
        changes = []
        for command in image.commands:
            raw = command['raw']
            if command['cmd'] == 0xc and command['at'] == image.loads[1]['at']:
                path = b'@loader_path/VM27AllocatorProvider.dylib\0'
                size = (24 + len(path) + 7) & ~7
                raw = raw[:24] + path + bytes(size-24-len(path))
                raw = bytearray(raw)
                struct.pack_into('<I', raw, 4, size)
                changes.append(dict(oldPath=image.loads[1]['path'], newPath=path[:-1].decode(),
                                    oldCommandSize=command['size'], newCommandSize=size))
            commands.append(bytes(raw))
        first = min(s['fileoff'] for s in image.sections if s['fileoff'] and s['size'])
        old_end = 32 + image.sizeofcmds
        new_end = 32 + sum(map(len, commands))
        assert new_end <= first and not any(linked[old_end:first]), 'actual zero padding capacity'
        updated = bytearray(linked)
        updated[32:first] = b''.join(commands) + bytes(first-new_end)
        struct.pack_into('<II', updated, 16, len(commands), new_end-32)
        assert updated[first:] == linked[first:]
        binary.write_bytes(updated)
        final = reader.MachO(updated)
        assert final.segments == image.segments and final.sections == image.sections
        assert final.uuid == image.uuid and final.exports == image.exports
        assert final.imports == image.imports and final.binds == image.binds
        old_image = reader.MachO(Path(old['binary']['path']).read_bytes())
        assert [row['name'] for row in final.imports] == [row['name'] for row in old_image.imports]
        assert not any(c['cmd'] == 0x1d for c in final.commands)
        run('ios-validate', ['xcrun', 'dyld_info', '-validate_only', binary])
        run('ios-exports-imports', ['xcrun', 'dyld_info', '-exports', '-imports', '-dependents', binary])
        run('ios-disassembly', ['xcrun', 'llvm-objdump', '-d', binary])
        for row in inputs:
            assert pin(row['path']) == row, ('input changed', row['path'])
        candidate = dict(schema='Unsigned Mac27 compiler import bridge with exact real allocator reexports v4',
            binary=pin(binary), actualUnmodifiedLinkerOutput=pin(OUT / 'actual-linker-output.dylib'),
            exactExports=exports, sevenDirectDefinitions=old['exactExports'],
            exactAllocatorReexports=[dict(symbol=symbol, export=final.exports[symbol],
                recursiveProvider=pin(allocator), providerUUID=allocator_image.uuid,
                trueProviderExport=allocator_image.exports[symbol]) for symbol in REEXPORTS],
            allocatorStageImageKey=allocator_row['key'], actualBorrowedAllocator=pin(allocator),
            actualBorrowedAllocatorCodeSignatureStaleUntilFinalSigning=allocator_row['codeSignatureStaleUntilFinalSigning'],
            actualBorrowedObject=pin(OLD / 'imports.o'), sourceAndHostChecksUnchanged=True,
            productionSourceRecompiled=False, priorHostChecksRerun=False,
            reexportsAreRealLinkerFlags8=True, entireLibraryReexportUsed=False,
            noAllocatorWrappersCopiedOrAdded=True, native13ImportsUnchanged=True,
            actualImports=final.imports, actualLoads=final.loads, actualUUID=final.uuid,
            actualMetadataChanges=changes, actualHeaderCapacity=dict(oldHeaderEnd=old_end,
                newHeaderEnd=new_end, firstSection=first, actualZeroPadding=True),
            allBytesAfterHeaderCapacityWholeUnchanged=True,
            actualIOSArm64e161LinkValidatePassed=True,
            originalSevenExportCandidate=pin(OLD / 'candidate.json'), inputs=inputs,
            steps=steps, deviceOperations=0, sandboxApplyCalls=0, signed=False,
            stageMerged=False, actualIPadCompilerRun=False,
            requiresIndependentSourceAndActualProductReview=True, findings=[])
        save('candidate.json', candidate)
        save('freeze.json', dict(schema='Exact three real allocator reexports bridge source and unsigned product freeze v4',
            files=inputs + [pin(p) for p in sorted(OUT.iterdir()) if p.is_file()],
            deviceOperations=0, sandboxApplyCalls=0))
        print(json.dumps(dict(candidate=pin(OUT / 'candidate.json'), freeze=pin(OUT / 'freeze.json'))))
    except Exception as error:
        save('failure.json', dict(error=str(error), inputs=inputs, steps=steps,
                                  deviceOperations=0, sandboxApplyCalls=0))
        raise


if __name__ == '__main__':
    main()
