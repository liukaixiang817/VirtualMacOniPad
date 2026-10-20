"""Build one unsigned iPad owned CPU creation fixture; no device action."""
import hashlib,json,os,re,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'VirtualMac/vz/host'
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUTPUT=N/'cpu-owned-creation-device-unsigned-local-v3'
def pin(path):
    path=Path(path).resolve();data=path.read_bytes()
    return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def require(value,message):
    if not value:raise ValueError(message)
def main():
    aggregate=N/'cpu-native-run-producer-integration-local-v2'
    require(pin(aggregate/'candidate.json')['sha256']=='62215c99c1fd0a81fac6866916af9b505f0ae585b0c208847f8bf841affd53ae','actual alternate source aggregate')
    frozen=json.loads((aggregate/'freeze.json').read_text())
    for row in frozen['files']:
        require(pin(row['path'])=={k:row[k] for k in ('path','bytes','sha256')},'source aggregate drift '+row['path'])
    OUTPUT.mkdir(exist_ok=False);steps=[]
    def run(label,arguments):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        result=subprocess.run(list(map(str,arguments)),capture_output=True,env=env,timeout=30)
        (OUTPUT/(label+'.stdout')).write_bytes(result.stdout);(OUTPUT/(label+'.stderr')).write_bytes(result.stderr)
        steps.append({'label':label,'arguments':list(map(str,arguments)),'exit':result.returncode,
            'stdout':pin(OUTPUT/(label+'.stdout')),'stderr':pin(OUTPUT/(label+'.stderr'))})
        require(result.returncode==0,label+' failed');return result.stdout
    units=['cpu_owned_creation_device_fixture_v2.c','cpu_owned_creation_device_native_v1.S',
        'modern_cpu_public_register_setters_v1.c','modern_cpu_native_public_factory_v3.c',
        'modern_cpu_kernel_lifecycle_v7.c','modern_cpu_kernel_initialization_v3.c',
        'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c',
        'modern_cpu_kernel_system_v2.c','modern_cpu_native_exit_reducer_v1.c',
        'modern_cpu_config_os_object_v4.m','modern_cpu_config_capability_acquisition_v1.c',
        'modern_cpu_tlbi_capability_values_v1.c']
    common=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
        '-std=c11','-Wall','-Wextra','-Werror','-I',SOURCE,'-DVM27_CPU_CONFIG_TESTING=1',
        '-fvisibility=hidden','-ffunction-sections','-fdata-sections']
    objects=[]
    for name in units:
        obj=OUTPUT/(Path(name).stem+'.o');objects.append(obj)
        run(Path(name).stem+'-compile',common+(['-fno-objc-arc'] if name.endswith('.m') else [])+
            ['-c',SOURCE/name,'-o',obj])
    helper=OUTPUT/'cpu-owned-creation-v1'
    run('link',common+[*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip',
        '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',helper])
    run('validate',['xcrun','dyld_info','-validate_only',helper])
    imports=run('imports',['xcrun','dyld_info','-dependents','-imports',helper])
    disasm=run('disasm',['xcrun','llvm-objdump','--macho','--disassemble',helper])
    nm=run('symbols',['xcrun','nm',helper])
    require(not re.search(rb'_hv_|Hypervisor\.framework|Virtualization\.framework|VirtualMachineMonitor',imports),
        'forbidden old or native framework dependency')
    require(b'_VZKernelCPURunOwnedStepV7' not in nm and b'_VM27CPUFactoryRunOwnedStepV3' not in nm,
        'uninvoked Run primitive must be dead stripped')
    require(b'_VM27CPUConfigCapabilityKernelQueryV1' not in nm,'unused native0 acquisition must be dead stripped')
    data=helper.read_bytes();require(struct.unpack_from('<I',data)[0]==0xfeedfacf,'thin MachO')
    require(struct.unpack_from('<I',data,4)[0]==0x100000c and struct.unpack_from('<I',data,8)[0]&0xffffff==2,'arm64e')
    at=32;uuid=None;loads=[]
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        cmd,size=struct.unpack_from('<II',data,at);require(size>=8 and size%8==0 and at+size<=len(data),'commands')
        require(cmd!=0x1d,'unsigned original')
        if cmd==27:uuid=data[at+8:at+24].hex()
        if cmd in (12,0x80000018,0x8000001f,0x80000023):
            off=struct.unpack_from('<I',data,at+8)[0];loads.append({'command':cmd,'path':data[at+off:at+size].split(b'\0')[0].decode()})
        at+=size
    require(uuid and loads and all(r['command']==12 for r in loads),'ordinary actual dependencies')
    require({r['path'] for r in loads}=={'/usr/lib/libSystem.B.dylib','/usr/lib/libobjc.A.dylib',
        '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation'},'exact three native owners')
    fixture=(SOURCE/units[0]).read_text()
    require('VM27CPUFactoryRunOwnedStep' not in fixture and 'VZKernelCPURun' not in fixture,
        'fixture never invokes Run')
    inputs=[Path(__file__),*[SOURCE/x for x in units],aggregate/'candidate.json',aggregate/'freeze.json']
    inputs.extend(SOURCE.glob('modern_cpu_kernel*.h'))
    inputs.extend([SOURCE/'modern_cpu_public_register_setters_v1.h',SOURCE/'modern_cpu_native_public_factory_v2.h',
        SOURCE/'modern_cpu_config_os_object_v3.h',SOURCE/'modern_cpu_config_os_object_v3_private.h',
        SOURCE/'modern_cpu_native_public_factory_v3_private.h',SOURCE/'modern_cpu_config_capability_acquisition_v1.h',
        SOURCE/'modern_cpu_tlbi_capability_values_v1.h',SOURCE/'modern_cpu_pending_interrupt_values_v1.h',
        SOURCE/'modern_cpu_native_fields.h',SOURCE/'modern_cpu_native_exit_reducer_v1.h',SOURCE/'modern_cpu_kernel_system_fields.inc'])
    # Keep only existing private headers; exact referenced unit headers are
    # separately covered by the alternate aggregate's full freeze above.
    inputs=[p for p in inputs if p.is_file()]
    report={'schema':'Unsigned owned iPad CPU creation fixture v1','finiteBuildPassed':True,
        'candidate':pin(helper),'UUID':uuid,'dependencies':loads,'steps':steps,'inputs':[pin(p) for p in sorted(set(inputs))],
        'nativeOperationsAllowed':[1,2,6,7],'maximumCallsPerNativeOperation':1,'maximumCPUCount':1,
        'nativeContextOnlyFromSuccessfulOwn6':True,'allPublicOutputsOwnedLocalCStorage':True,
        'usesAlternateReciprocalOutputGuards':True,'full64ContextVersionRequired':True,
        'scalarSIMDReadbackRequired':True,'noPCExecutionClaim':True,'native0Present':False,
        'native9Present':False,'mappingOperationPresent':False,'cancelOperationPresent':False,
        'publicControl0SetterPresent':False,'featureProfileApplied':False,'TLBIHandlerImplemented':False,
        'architectureResetComplete':False,'memoryBindingComplete':False,'validExitProduced':False,
        'signed':False,'deviceExecuted':False,'full27Backend':False}
    (OUTPUT/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    files={p['path']:p for p in report['inputs']}
    for path in OUTPUT.iterdir():
        if path.is_file():files[str(path.resolve())]=pin(path)
    (OUTPUT/'freeze.json').write_text(json.dumps({'schema':'Finite owned create fixture build pins v1',
        'files':list(files.values())},indent=2)+'\n')
    print(json.dumps({'candidate':pin(OUTPUT/'candidate.json'),'freeze':pin(OUTPUT/'freeze.json'),
        'helper':pin(helper)}))
if __name__=='__main__':main()
