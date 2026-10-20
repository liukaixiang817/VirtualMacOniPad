#!/usr/bin/env python3
"""Combined Root11 local validation and unsigned arm64e provider. No device I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

S=Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
UNITS=['modern_cpu_native_public_factory_v16.c','modern_cpu_kernel_lifecycle_v20.c',
 'modern_cpu_kernel_initialization_v3.c','modern_cpu_native_fields.c',
 'modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
 'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v5.m',
 'modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c',
 'modern_cpu_native_capability_seed.c','modern_gic_v3_engine_v1.c',
 'modern_gic_deadline_scheduler_v1.c','vm27_hv_public_vm_bootstrap_v11.m',
 'modern_vmm_mandatory_physical_frame_v1.c','modern_vmm_physical_save53_v1.c','modern_vmm_mandatory_field_v2.c']
EXTRA=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_tlbi_capability_values_v1.c',
 'modern_cpu_config_capability_query_v1.S']

def pin(p):
    p=Path(p).resolve();data=p.read_bytes()
    return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    out=a.out.resolve()
    if out.parent!=N.resolve():raise ValueError('Fresh diagnostic output required')
    out.mkdir(exist_ok=False);commands=[];models={};closure=set()
    initial=[pin(S/name) for name in UNITS]
    root10=N/'vm-hv-public-bootstrap-integration-local-v10-attempt3/candidate.json'
    root10freeze=N/'vm-hv-public-bootstrap-integration-local-v10-attempt3/freeze.json'
    frozen10=json.loads(root10.read_bytes())
    def verify_inherited():
        for row in json.loads(root10freeze.read_bytes())['files']:
            if pin(row['path'])!=row:raise RuntimeError('Frozen Root10 input changed: '+row['path'])
    verify_inherited()
    releaseWrapper=out/'factory16-release-wrapper.c'
    releaseWrapper.write_text('#define VM27CPUFactoryBorrowReleaseV2 RealFactoryBorrowReleaseForFieldV2\n'
      '#include "modern_cpu_native_public_factory_v16.c"\n#undef VM27CPUFactoryBorrowReleaseV2\n')
    def run(label,args):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
        r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45,env=env)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        receipt={'label':label,'argv':list(map(str,args)),'returncode':r.returncode,
                 'stdout':pin(out/(label+'.stdout')),'stderr':pin(out/(label+'.stderr'))}
        commands.append(receipt)
        (out/'commands-in-progress.json').write_text(json.dumps(commands,indent=2)+'\n')
        if r.returncode:raise RuntimeError(f'{label}: {r.stderr.decode(errors="replace")}')
        return r.stdout
    common=['-std=c11','-Wall','-Wextra','-Werror','-I',S,'-DVM27_HV_VM_GUARD_LINKED=1']
    try:
        for name in UNITS+EXTRA:
            dep=run(Path(name).stem+'-closure-before',['xcrun','--sdk','iphoneos','clang',
              '-arch','arm64e','-miphoneos-version-min=16.1',*common,
              *(['-fno-objc-arc'] if name.endswith('.m') else []),'-MM',S/name])
            for token in dep.decode().replace('\\\n',' ').split(':',1)[1].split():
                file=Path(token).resolve()
                if file.is_relative_to(S):closure.add(file)
        initialClosure=[pin(p) for p in sorted(closure)]
        for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
            exe=out/('root11-'+mode)
            run('build-'+mode,['xcrun','--sdk','macosx','clang',*common,'-fno-objc-arc',
              '-DVM27_CPU_CONFIG_TESTING=1','-DVM27_HV_VM_TESTING=1',*extra,
              *[releaseWrapper if n=='modern_cpu_native_public_factory_v16.c' else S/n for n in UNITS],S/'test-vm27-hv-public-vm-bootstrap-v11.m',
              '-framework','CoreFoundation','-lobjc','-o',exe])
            models[mode]=json.loads(run('run-'+mode,[exe]).splitlines()[-1])
        if models['normal']!=models['san'] or not models['normal']['actualRootGICFactoryRegistry']:
            raise RuntimeError('Combined model result mismatch')
        objects=[]
        ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',*common]
        for name in UNITS+EXTRA:
            obj=out/(Path(name).stem+'.o');dep=out/(Path(name).stem+'.d');objects.append(obj)
            exported=name in ['modern_cpu_native_public_factory_v16.c','modern_cpu_config_os_object_v5.m',
                             'vm27_hv_public_vm_bootstrap_v11.m','modern_vmm_mandatory_physical_frame_v1.c',
                             'modern_vmm_physical_save53_v1.c','modern_vmm_mandatory_field_v2.c']
            run(Path(name).stem+'-ios',[*ios,*([] if exported else ['-fvisibility=hidden']),
              *(['-fno-objc-arc'] if name.endswith('.m') else []),'-MMD','-MF',dep,'-c',S/name,'-o',obj])
            for token in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
                file=Path(token).resolve()
                if file.is_relative_to(S):closure.add(file)
        exports=set(frozen10['exactExports'])
        exports.update(['VM27VMMGetMandatoryFieldV2','VM27VMMSetMandatoryFieldV2','VM27VMMDrainMandatoryFieldBorrowV2'])
        exports.update(['hv_vcpu_get_vtimer_mask','hv_vcpu_set_vtimer_mask','VM27CPUFactoryBorrowAccessVtimerMaskV16'])
        exports.update(re.findall(r'\bhv_(?:return_t|gic_config_t|gic_state_t)\s+(hv_gic_\w+)\(',
                                 (S/'vm27_hv_public_vm_bootstrap_v11.m').read_text()))
        exports.update(['hv_vcpus_exit','VM27CPUFactoryVMGICDescribeV15','VM27CPUFactoryVMGICInstallV15',
          'VM27CPUFactoryVMGICTeardownV15','VM27CPUFactoryVMGICAccessV15','VM27CPUFactoryBorrowGICAccessV15',
          'VM27VMMAccessMandatoryPhysicalFrameV1','VM27VMMDrainMandatoryPhysicalFrameBorrowV1',
          'VM27VMMReadOriginalPhysicalSaveFieldV1'])
        exportFile=out/'exports.txt';exportFile.write_text(''.join('_'+n+'\n' for n in sorted(exports)))
        provider=out/'VM27HVVMCPUCombinedV11.dylib'
        run('ios-link',[*ios,'-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc',
          '-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
          '-Wl,-exported_symbols_list,'+str(exportFile),
          '-Wl,-install_name,@rpath/VM27HVVMCPUCombinedV11.dylib','-o',provider])
        run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
        symbols=run('ios-exports',['xcrun','nm','-gU',provider])
        actual=sorted(line.split()[-1].decode() for line in symbols.splitlines() if line.split())
        if actual!=['_'+n for n in sorted(exports)]:raise RuntimeError('Actual export mismatch')
        imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
        if re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_',imports):
            raise RuntimeError('Foreign virtualization dependency')
        data=provider.read_bytes();at=32
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            command,size=struct.unpack_from('<II',data,at)
            if command==0x1d:raise RuntimeError('Unexpected signing')
            at+=size
        if initial!=[pin(S/n) for n in UNITS]:raise RuntimeError('Sources changed during build')
        if initialClosure!=[pin(p) for p in sorted(closure)]:raise RuntimeError('Actual include closure changed during build')
        cpp=out/'typed-gic-caller.cpp'
        cpp.write_text('#include "vm27_hv_public_vm_bootstrap_v11.h"\n'
          'static_assert(sizeof(hv_gic_icc_reg_t)==2 && sizeof(hv_gic_redistributor_reg_t)==4,"actual SDK ABI");\n'
          'extern "C" hv_return_t typed_gic(hv_vcpu_t cpu,hv_gic_config_t config,uint32_t selector,uint64_t value,uint64_t *out){\n'
          ' hv_return_t (*create)(hv_gic_config_t)=hv_gic_create;\n'
          ' hv_return_t (*get)(hv_vcpu_t,hv_gic_icc_reg_t,uint64_t*)=hv_gic_get_icc_reg;\n'
          ' hv_return_t (*set)(hv_vcpu_t,hv_gic_redistributor_reg_t,uint64_t)=hv_gic_set_redistributor_reg;\n'
          ' hv_return_t (*msi)(hv_ipa_t,uint32_t)=hv_gic_send_msi;\n'
          ' hv_return_t (*cancel)(hv_vcpu_t*,uint32_t)=hv_vcpus_exit;\n'
          ' hv_return_t (*getmask)(hv_vcpu_t,bool*)=hv_vcpu_get_vtimer_mask;\n'
          ' hv_return_t (*setmask)(hv_vcpu_t,bool)=hv_vcpu_set_vtimer_mask;\n'
          ' switch(selector){case 0:return create(config);case 1:return get(cpu,(hv_gic_icc_reg_t)value,out);case 2:return set(cpu,(hv_gic_redistributor_reg_t)selector,value);case 3:return msi(value,selector);case 4:return setmask(cpu,(bool)value);case 5:{bool mask=false;return getmask(cpu,&mask);}default:return cancel(&cpu,1);}}\n')
        for sdk in ['macosx','iphoneos']:
            obj=out/(sdk+'-typed-gic.o')
            flags=['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []
            run(sdk+'-typed-gic',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',
              *flags,'-I',S,'-c',cpp,'-o',obj])
            syms=run(sdk+'-typed-gic-symbols',['xcrun','nm','-u',obj])
            expected=sorted([b'_hv_gic_create',b'_hv_gic_get_icc_reg',b'_hv_gic_set_redistributor_reg',
                             b'_hv_gic_send_msi',b'_hv_vcpus_exit',b'_hv_vcpu_get_vtimer_mask',b'_hv_vcpu_set_vtimer_mask'])
            if sorted(line.split()[-1] for line in syms.splitlines() if line.split())!=expected:
                raise RuntimeError('Actual typed C++ symbols mismatch')
        fieldCPP=out/'typed-field-caller.cpp'
        fieldCPP.write_text('#include "vm27_hv_public_vm_bootstrap_v11.h"\n'
          'static_assert(sizeof(hv_vcpu_t)==8 && sizeof(uint32_t)==4,"actual field ABI");\n'
          'extern "C" int32_t typed_field(hv_vcpu_t cpu,uint32_t field,uint64_t value,void *out){\n'
          ' int32_t(*get)(hv_vcpu_t,uint32_t,void*)=VM27VMMGetMandatoryFieldV2;\n'
          ' int32_t(*set)(hv_vcpu_t,uint32_t,uint64_t)=VM27VMMSetMandatoryFieldV2;\n'
          ' int32_t(*drain)(void)=VM27VMMDrainMandatoryFieldBorrowV2;\n'
          ' return out?get(cpu,field,out):field?set(cpu,field,value):drain();}\n')
        typedFields={}
        for sdk in ['macosx','iphoneos']:
            obj=out/(sdk+'-typed-field.o')
            flags=['-arch','arm64e','-miphoneos-version-min=16.1'] if sdk=='iphoneos' else []
            run(sdk+'-typed-field',['xcrun','--sdk',sdk,'clang++','-std=c++17','-Wall','-Wextra','-Werror',
              *flags,'-I',S,'-c',fieldCPP,'-o',obj])
            names=sorted(line.split()[-1].decode() for line in run(sdk+'-typed-field-symbols',['xcrun','nm','-u',obj]).splitlines() if line.split())
            expected=sorted('_'+n for n in ['VM27VMMGetMandatoryFieldV2','VM27VMMSetMandatoryFieldV2','VM27VMMDrainMandatoryFieldBorrowV2'])
            if names!=expected or not set(names).issubset(actual):raise RuntimeError('Actual single-field C++ ABI not joined')
            typedFields[sdk]=names
        verify_inherited()
        if len(exports)!=119:raise RuntimeError('Root11 exports must be inherited 116 plus the actual three field APIs')
        report={'schema':'independent27 actual Root11 GIC Timer19 Factory16 Life20 mandatory field V2 local v1',
          'provider':pin(provider),'commands':commands,'models':models,'exactExports':sorted(exports),
          'actualIncludeClosure':[pin(p) for p in sorted(closure)],'typedSingleFieldCallers':typedFields,
          'sourcePins':[pin(p) for p in sorted(closure|{Path(__file__).resolve(),S/'test-vm27-hv-public-vm-bootstrap-v11.m'})],
          'inheritedRoot10':pin(root10),'inheritedRoot10Freeze':pin(root10freeze),'strongRootGuard':True,'noForeignHVDependency':True,
          'deviceExecuted':False,'providerSigned':False,'providerLoaded':False,
          'originalVMMIntegrated':False,'fullPublicRunEquivalent':False,'fullIndependent27GuestBoot':False}
        with (out/'candidate.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
        print(json.dumps({'candidate':pin(out/'candidate.json'),'provider':pin(provider),'exports':len(exports),'models':models},indent=2))
    except BaseException as e:
        (out/'failure.json').write_text(json.dumps({'error':str(e),'commands':commands},indent=2)+'\n');raise

if __name__=='__main__':main()
