"""Build a new unsigned app-private import bridge on HOST, never on iPad."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'VirtualMac/vz/host'
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'sandbox-compiler-imports-compat-unsigned-local-v3-attempt1'
ABI = NODE / 'mac27-sandbox-remaining-import-abi-host-v1-attempt1'
EXPORTS = sorted([
    '_SANDBOX_STORAGE_CLASS_GROUP_ANY',
    '_SANDBOX_STORAGE_CLASS_PROPERTY_WRITE_RESTRICTED',
    '__sandbox_enter_notify_libxpc', '_malloc_type_free',
    '_os_variant_is_basesystem', '_rootless_protected_volume_fd',
    '_sandbox_check_storage_class'])


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    OUT.mkdir(exist_ok=False)
    steps = []
    inputs = []

    def run(label, arguments, timeout=45):
        argv = list(map(str, arguments))
        environment = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        process = subprocess.run(argv, capture_output=True, timeout=timeout, env=environment)
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
        native_index = NODE / 'current-native-header-export-index-v3/index.json'
        assert pin(native_index)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
        current = json.loads(native_index.read_bytes())['images']
        darwin = current['/usr/lib/system/libsystem_darwin.dylib']
        assert darwin['UUID'] == '2f7e2d4e1ed3311699e28132b208bbd3'
        assert darwin['definitions']['_os_variant_is_recovery'] == dict(flags=0, offset=0x27c4)
        assert '_os_variant_is_basesystem' not in darwin['definitions']
        source = SOURCE / 'vm27_sandbox_compiler_imports_compat_v1.c'
        header = SOURCE / 'vm27_sandbox_compiler_imports_compat_v1.h'
        flags = ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64e',
                 '-miphoneos-version-min=16.1', '-std=c11', '-Wall', '-Wextra',
                 '-Werror', '-fvisibility=hidden', '-I', SOURCE]
        dependencies = run('ios-dependencies', flags + ['-MM', source]).decode().split(':', 1)[1].replace('\\\n', ' ')
        closure = {Path(__file__).resolve(), source, header}
        for token in shlex.split(dependencies):
            path = Path(token).resolve()
            if not path.is_relative_to(SOURCE) and path.name != 'SDKSettings.json':
                raise ValueError('unexpected local include ' + str(path))
            closure.add(path)
        evidence = [native_index,
            NODE / 'mac27-genuine-sandbox-compiler-host-audit-v1-attempt1/report.json',
            NODE / 'mac27-sandbox-compiler-reconstructed-host-v3-attempt1/symbols.a2s.batch.json',
            NODE / 'mac27-reconstructed-sandbox-compile-only-host-v3-attempt1/report.json',
            ABI / 'compiler-direct-call-graph.json', ABI / 'libsystem_sandbox.dylib',
            ABI / 'libsystem_darwin.dylib', ABI / 'apple-Libc-variant.c',
            ROOT / 'VirtualMac/vendor/libmalloc-typed-backport/upstream/SDK27.1-_malloc.h',
            ROOT / 'VirtualMac/vz/host/modern_typed_allocator_compat.c']
        inputs = [pin(path) for path in sorted(closure)] + [pin(path) for path in evidence]
        run('ios-compile', flags + ['-O2', '-c', source, '-o', OUT / 'imports.o'])
        export_file = OUT / 'exports.list'
        export_file.write_text('\n'.join(EXPORTS) + '\n')
        binary = OUT / 'VM27SandboxCompilerImportsProvider.dylib'
        run('ios-link', flags + ['-dynamiclib', OUT / 'imports.o',
            '-install_name', '@rpath/VM27SandboxCompilerImportsProvider.dylib',
            '-Wl,-undefined,error', '-Wl,-no_adhoc_codesign',
            '-Wl,-exported_symbols_list,' + str(export_file), '-o', binary])
        run('ios-validate', ['xcrun', 'dyld_info', '-validate_only', binary])
        dyld_exports = run('ios-exports', ['xcrun', 'dyld_info', '-exports', binary]).decode()
        actual_exports = sorted(line.split()[-1] for line in dyld_exports.splitlines() if line.lstrip().startswith('0x'))
        assert actual_exports == EXPORTS, (actual_exports, EXPORTS)
        imports = run('ios-imports', ['xcrun', 'dyld_info', '-imports', '-dependents', binary]).decode()
        assert 'libSystem.B.dylib' in imports
        assert '_malloc_type_' not in imports and '_os_variant_is_recovery' not in imports
        assert '/usr/lib/system/libsystem_darwin.dylib' in source.read_text()
        assert 'RTLD_DEFAULT' not in source.read_text()
        run('ios-disassembly', ['xcrun', 'llvm-objdump', '-d', binary])
        raw = binary.read_bytes()
        assert struct.unpack_from('<I', raw)[0] == 0xfeedfacf
        assert struct.unpack_from('<I', raw, 4)[0] == 0x100000c
        assert struct.unpack_from('<I', raw, 8)[0] & 0xffffff == 2
        offset = 32
        build_version = None
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            command, size = struct.unpack_from('<II', raw, offset)
            assert command != 0x1d, 'must remain unsigned'
            if command == 0x32:
                build_version = struct.unpack_from('<II', raw, offset + 8)
            offset += size
        assert build_version == (2, 0x100100), build_version
        cpp = OUT / 'typed-abi.cpp'
        cpp.write_text('''#include "vm27_sandbox_compiler_imports_compat_v1.h"
#include <type_traits>
static_assert(std::is_same_v<decltype(&VM27SandboxCompilerTypedFreeV1), void(*)(void*,uint64_t)>);
static_assert(std::is_same_v<decltype(&VM27SandboxCompilerIsBaseSystemV1), bool(*)(const char*)>);
static_assert(std::is_same_v<decltype(&VM27SandboxCompilerRootlessVolumeFDV1), int(*)(int)>);
static_assert(std::is_same_v<decltype(&VM27SandboxCompilerCheckStorageClassV1), int(*)(int,uint64_t,uint64_t)>);
static_assert(std::is_same_v<decltype(&VM27SandboxCompilerNotifyLibXPCV1), void(*)(void)>);
static_assert(sizeof(VM27SandboxStorageGroupAnyV1)==8 && sizeof(VM27SandboxStorageWriteRestrictedV1)==8);
''')
        run('ios-cpp-abi', ['xcrun', '--sdk', 'iphoneos', 'clang++', '-arch', 'arm64e',
            '-miphoneos-version-min=16.1', '-std=c++17', '-Wall', '-Wextra', '-Werror',
            '-I', SOURCE, '-c', cpp, '-o', OUT / 'typed-abi.o'])
        fixture = OUT / 'host-errors-and-owner-fixture.c'
        fixture.write_text('''#include "vm27_sandbox_compiler_imports_compat_v1.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern void *LegacyMalloc(size_t) __asm("_malloc");
static int TrapExpected(int notify) {
    pid_t pid=fork(); if(pid<0) return 0;
    if(!pid) {
        struct rlimit core={0,0},cpu={3,3};
        if(setrlimit(RLIMIT_CORE,&core) || setrlimit(RLIMIT_CPU,&cpu)) _exit(2);
        if(notify) VM27SandboxCompilerNotifyLibXPCV1();
        else (void)VM27SandboxCompilerIsBaseSystemV1("com.apple.sandbox");
        _exit(3);
    }
    int result=0; while(waitpid(pid,&result,0)<0) { if(errno!=EINTR) return 0; }
    return WIFSIGNALED(result) && WTERMSIG(result)==SIGTRAP;
}
int main(void) {
    if(VM27SandboxStorageGroupAnyV1!=0 || VM27SandboxStorageWriteRestrictedV1!=2) return 1;
    void *pointer=LegacyMalloc(4096); if(!pointer) return 2;
    ((unsigned char*)pointer)[4095]=97;
    VM27SandboxCompilerTypedFreeV1(pointer,UINT64_C(0xf123456789abcdef));
    VM27SandboxCompilerTypedFreeV1(NULL,0);
    errno=0; if(VM27SandboxCompilerRootlessVolumeFDV1(0)!=-1 || errno!=ENOTSUP) return 3;
    errno=0; if(VM27SandboxCompilerCheckStorageClassV1(0,2,0)!=-1 || errno!=ENOTSUP) return 4;
    if(!TrapExpected(0) || !TrapExpected(1)) return 5;
    puts("nativeRecoveryAnswerNotObserved=1 wrongImageTraps=1 unexpectedNotifyTraps=1 realLegacyAllocationReleased=1 explicitErrors=1 sandboxApplyCalls=0 deviceOperations=0");
    return 0;
}
''')
        host = []
        for label, extras in [('normal', []), ('sanitizers', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
            executable = OUT / ('host-' + label)
            run('host-' + label + '-build', ['xcrun', '--sdk', 'macosx', 'clang',
                '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-I', SOURCE,
                *extras, source, fixture, '-o', executable])
            result = run('host-' + label + '-run', [executable], timeout=15)
            assert b'wrongImageTraps=1 unexpectedNotifyTraps=1' in result
            host.append(dict(mode=label, output=pin(OUT / ('host-' + label + '-run.stdout')),
                             nativeRecoveryCalled=False, nativeSandboxApplyCalls=0))
        for row in inputs:
            assert pin(row['path']) == row, ('changed input', row['path'])
        candidate = dict(schema='Unsigned genuine Mac27 compiler import compatibility provider v1',
            binary=pin(binary), exactExports=EXPORTS, inputs=inputs, steps=steps,
            actualIOSArm64e161CompileLinkValidatePassed=True, actualTypedCppABICompilePassed=True,
            actualHostErrorAndAllocationChecks=host,
            reusedTypedAllocatorAPIs=['_malloc_type_malloc', '_malloc_type_calloc', '_malloc_type_realloc'],
            genuineStorageConstants=[dict(symbol='_SANDBOX_STORAGE_CLASS_GROUP_ANY', width=8, value=0),
                dict(symbol='_SANDBOX_STORAGE_CLASS_PROPERTY_WRITE_RESTRICTED', width=8, value=2)],
            nativeRecoveryRoute=dict(path='/usr/lib/system/libsystem_darwin.dylib',
                symbol='os_variant_is_recovery', UUID='2f7e2d4e1ed3311699e28132b208bbd3', RVA=0x27c4,
                resolution='fixed native dlopen handle; exact dladdr path, UUID and RVA guards',
                guardedCallPreservesAuthenticatedPointer=True, noRTLDDefault=True,
                answer='real native bool returned unchanged; guard failures trap',
                semanticDifference='iOS uses actual Recovery ReleaseType; Mac uses BaseSystem content',
                actualIPadAnswerObserved=False),
            unavailableAPIs=dict(rootless='int(int): -1 and errno ENOTSUP',
                storageClass='int(int,uint64_t,uint64_t): -1 and errno ENOTSUP',
                MacApplyNotification='void(void): diagnostic then trap'),
            directCallGraph=pin(ABI / 'compiler-direct-call-graph.json'),
            sandboxApplyCalls=0, deviceOperations=0, providerSigned=False, trustCacheAdded=False,
            actualIPadCompilerRun=False, actualCompiledBytecodeCompatibilityVerified=False,
            requiresIndependentSourceAndProductReview=True, finiteLocalScopePassed=True, findings=[])
        save(OUT / 'candidate.json', candidate)
        files = inputs + [pin(path) for path in sorted(OUT.iterdir()) if path.is_file()]
        save(OUT / 'freeze.json', dict(schema='Sandbox compiler import source and unsigned product freeze v1',
                                      files=files, deviceOperations=0, sandboxApplyCalls=0))
        print(json.dumps(dict(candidate=pin(OUT / 'candidate.json'), freeze=pin(OUT / 'freeze.json'))))
    except Exception as error:
        save(OUT / 'failure.json', dict(error=str(error), steps=steps, inputs=inputs,
                                      deviceOperations=0, sandboxApplyCalls=0))
        raise


if __name__ == '__main__':
    main()
