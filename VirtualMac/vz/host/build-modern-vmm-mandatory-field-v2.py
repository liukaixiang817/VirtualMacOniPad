#!/usr/bin/env python3
"""Validate the private single-field caller ABI with real Root9 source owners.

All native calls in the host fixture are mocked. The iOS provider is unsigned.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import runpy
import subprocess

S = Path(__file__).resolve().parent
N = S.parents[2] / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    output = parser.parse_args().out.resolve()
    if output.parent != N.resolve() or output.exists():
        raise ValueError('fresh diagnostic output required')
    output.mkdir(mode=0o700)
    root_builder = S / 'build-vm27-hv-public-vm-bootstrap-v9.py'
    root = runpy.run_path(str(root_builder))
    units = list(root['UNITS'])
    root_receipt = N / 'vm-hv-public-bootstrap-integration-local-v9-attempt7/candidate.json'
    frozen = json.loads(root_receipt.read_bytes())
    for source in frozen['actualIncludeClosure']:
        if pin(source['path']) != source:
            raise ValueError('Root9 source closure changed: ' + source['path'])
    adapter = S / 'modern_vmm_mandatory_field_v2.c'
    fixture = S / 'test-modern-vmm-mandatory-field-v2.m'
    wrapper = output / 'factory-release-wrapper.c'
    wrapper.write_text('#define VM27CPUFactoryBorrowReleaseV2 RealFactoryBorrowReleaseForFieldV2\n'
        '#include "modern_cpu_native_public_factory_v15.c"\n#undef VM27CPUFactoryBorrowReleaseV2\n')
    commands, models, closure = [], {}, set()
    def run(label, args):
        env = {key:value for key,value in os.environ.items() if not key.startswith('DYLD_')}
        env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
        result = subprocess.run(list(map(str, args)), capture_output=True, timeout=45, env=env)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, args=list(map(str,args)), exit=result.returncode,
            stdout=pin(output/(label+'.stdout')), stderr=pin(output/(label+'.stderr'))))
        (output / 'commands-in-progress.json').write_text(json.dumps(commands,indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout
    common = ['-std=c11','-Wall','-Wextra','-Werror','-I',S,'-DVM27_HV_VM_GUARD_LINKED=1']
    try:
        for mode, flags in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
            exe = output / mode
            sources = [wrapper if name=='modern_cpu_native_public_factory_v15.c' else S/name for name in units]
            run(mode+'-compile',['xcrun','--sdk','macosx','clang',*common,'-fno-objc-arc',
                '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1',*flags,*sources,adapter,fixture,
                '-framework','CoreFoundation','-lobjc','-o',exe])
            models[mode] = json.loads(run(mode+'-run',[exe]).splitlines()[-1])
        if models['normal'] != models['san'] or not models['normal']['actualProducedCPUIdentityAndBorrow']:
            raise RuntimeError('model mismatch')
        ios = ['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',*common]
        exported_units = {'modern_cpu_native_public_factory_v15.c','modern_cpu_config_os_object_v5.m',
            'vm27_hv_public_vm_bootstrap_v9.m','modern_vmm_mandatory_physical_frame_v1.c',
            'modern_vmm_physical_save53_v1.c','modern_vmm_mandatory_field_v2.c'}
        all_sources = [S/name for name in units+root['EXTRA']] + [adapter]
        objects = []
        for source in all_sources:
            obj = output/(source.stem+'.o'); dep=output/(source.stem+'.d');objects.append(obj)
            run(source.stem+'-ios',[*ios,*([] if source.name in exported_units else ['-fvisibility=hidden']),
                *(['-fno-objc-arc'] if source.suffix=='.m' else []),'-MMD','-MF',dep,'-c',source,'-o',obj])
            for token in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
                path=Path(token).resolve()
                if path.is_relative_to(S):closure.add(path)
        exports = set(frozen['exactExports']) | {'VM27VMMGetMandatoryFieldV2','VM27VMMSetMandatoryFieldV2','VM27VMMDrainMandatoryFieldBorrowV2'}
        export_file=output/'exports.txt';export_file.write_text(''.join('_'+name+'\n' for name in sorted(exports)))
        provider=output/'VM27Root9MandatoryFieldV2.unsigned.dylib'
        run('ios-link',[*ios,'-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc',
            '-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
            '-Wl,-exported_symbols_list,'+str(export_file),
            '-Wl,-install_name,@rpath/VM27Root9MandatoryFieldV2.dylib','-o',provider])
        run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
        symbols=run('ios-exports',['xcrun','nm','-gU',provider])
        actual=sorted(line.split()[-1].decode() for line in symbols.splitlines() if line.split())
        if actual != ['_'+name for name in sorted(exports)]:raise RuntimeError('actual provider exports mismatch')
        cpp=output/'typed-caller.cpp'
        cpp.write_text('#include "modern_vmm_mandatory_field_v2.h"\n'
            'static_assert(sizeof(hv_vcpu_t)==8 && sizeof(uint32_t)==4,"caller ABI");\n'
            'extern "C" int32_t caller(hv_vcpu_t cpu,uint32_t field,uint64_t value,void *out){\n'
            ' int32_t(*get)(hv_vcpu_t,uint32_t,void*)=VM27VMMGetMandatoryFieldV2;\n'
            ' int32_t(*set)(hv_vcpu_t,uint32_t,uint64_t)=VM27VMMSetMandatoryFieldV2;\n'
            ' int32_t(*drain)(void)=VM27VMMDrainMandatoryFieldBorrowV2;\n'
            ' return out?get(cpu,field,out):field?set(cpu,field,value):drain();}\n')
        typed = {}
        for sdk in ['macosx','iphoneos']:
            obj=output/(sdk+'-typed.o')
            run(sdk+'-typed',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',
                *(['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []),'-I',S,'-c',cpp,'-o',obj])
            names=sorted(line.split()[-1].decode() for line in run(sdk+'-typed-symbols',['xcrun','nm','-u',obj]).splitlines() if line.split())
            expected=sorted('_'+name for name in exports if name.startswith('VM27VMM') and name.endswith('V2'))
            if names != expected or not set(names).issubset(actual):raise RuntimeError('typed caller C symbols not joined')
            typed[sdk]=names
        for source in frozen['actualIncludeClosure']:
            if pin(source['path']) != source:raise RuntimeError('Root9 source changed during build')
        report=dict(schema='VMM genuine mandatory single-field caller ABI with Root9 owners v2',
            models=models, provider=pin(provider), exports=actual, typedCallers=typed,
            inheritedRoot9=pin(root_receipt), actualSourceClosure=[pin(p) for p in sorted(closure)],
            originalMandatoryCallsNotYetPatched=True, actualRoot9GuardLinked=True,
            noInventedCPUIdentity=True, noGetContextMemory=True, sourceSigned=False, sourceDeviceExecuted=False,
            originalVMMExecuted=False, fullIndependent27GuestBoot=False, nativeCalls=0, deviceOperations=0, commands=commands)
        (output/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
        files=[Path(__file__),fixture,root_builder,root_receipt]+sorted(closure)+[p for p in output.iterdir() if p.is_file()]
        (output/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in files],nativeCalls=0,deviceOperations=0),indent=2)+'\n')
        print(json.dumps(dict(candidate=pin(output/'candidate.json'),freeze=pin(output/'freeze.json'),models=models)))
    except BaseException as error:
        (output/'failure.json').write_text(json.dumps(dict(error=str(error),commands=commands),indent=2)+'\n')
        raise


if __name__=='__main__':
    main()
