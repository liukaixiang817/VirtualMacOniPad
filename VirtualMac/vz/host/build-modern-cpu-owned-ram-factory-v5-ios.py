"""Link inert unsigned alternative SYS factory; never sign/load/run on iOS."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-owned-ram-integration-local-v3'
def pin(p):
    p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,name):
    if not v:raise ValueError(name)
need(not (D/'candidate.json').exists(),'new candidate, no frozen overwrite')
host=json.loads((D/'host-results.json').read_text());need(host['selected'][0]['checks']==host['selected'][1]['checks'] and host['selected'][0]['checks']>=209,'actual host model receipts')
steps=[]
def run(label,args):
    env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
    q=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=30)
    (D/(label+'.stdout')).write_bytes(q.stdout);(D/(label+'.stderr')).write_bytes(q.stderr)
    steps.append(dict(label=label,args=list(map(str,args)),exit=q.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
    (D/'ios-steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
    need(q.returncode==0,label+' failed');return q.stdout
units=['modern_cpu_native_public_factory_v5.c','modern_cpu_kernel_lifecycle_v9.c','modern_cpu_kernel_initialization_v3.c',
    'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v3.c',
    'modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v4.m','modern_cpu_native_self_memory_v1.c','modern_vm_memory_packet.c',
    'modern_cpu_config_capability_acquisition_v1.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']
common=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
    '-std=c11','-Wall','-Wextra','-Werror','-I',S]
objects=[]
for name in units:
    obj=D/(Path(name).stem+'.o');objects.append(obj)
    exported=name in ['modern_cpu_native_public_factory_v5.c','modern_cpu_config_os_object_v4.m']
    run(Path(name).stem+'-ios-compile',common+([] if exported else ['-fvisibility=hidden'])+
        (['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
headers=['modern_cpu_native_public_factory_v2.h','modern_cpu_native_public_factory_v3.h',
    'modern_cpu_native_public_factory_v4.h','modern_cpu_native_public_factory_v5.h','modern_cpu_config_os_object_v3.h']
exports=sorted(set(name for h in headers for name in re.findall(r'(VM27CPU(?:Factory|Config)\w+)\(', (S/h).read_text())))
need(len(exports)==28 and 'VM27CPUFactoryRAMMapV5' in exports,'six additional own RAM exports')
exportFile=D/'exports.txt';exportFile.write_text(''.join('_'+x+'\n' for x in exports))
provider=D/'VM27CPUFactoryRAMV5.dylib'
run('ios-link',common+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip',
    '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportFile),
    '-Wl,-install_name,@rpath/VM27CPUFactoryRAMV5.dylib','-o',provider])
run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
symbols=run('ios-exports',['xcrun','nm','-gU',provider]);imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',provider])
run('ios-disassembly',['xcrun','llvm-objdump','--macho','--disassemble',provider])
need(sorted(x.split()[-1].decode() for x in symbols.splitlines() if x.split())==['_'+x for x in exports],'actual exact own28 exports')
need(not re.search(rb'_hv_|Hypervisor|Virtualization|VirtualMachineMonitor',imports),'no genuine framework imports')
b=provider.read_bytes();at=32
for _ in range(struct.unpack_from('<I',b,16)[0]):
    cmd,size=struct.unpack_from('<II',b,at);need(cmd!=0x1d,'unsigned without signature');at+=size
source=(S/'modern_cpu_kernel_lifecycle_v9.c').read_text()
need(source.count('nativeTrap(')==9,'four lifecycle, existing9+8 and literal RAM3/5/4 expressions')
need(source.count('nativeTrap(cpu->vm->ops.context,8,NULL)')==1,'single exact masked SYS native8')
inputs=[Path(__file__),S/'build-modern-cpu-owned-ram-factory-v5.py',S/'test-modern-cpu-owned-ram-factory-v5.m',*[S/x for x in units]]
inputs+=list(S.glob('modern_cpu_kernel*.h'))+[S/x for x in headers]
inputs+=[S/x for x in ['modern_cpu_native_self_memory_v1.h','modern_vm_memory_packet.h','modern_cpu_kernel_system_fields.inc',
    'modern_cpu_config_os_object_v3_private.h','modern_cpu_config_os_object_v4_private.h',
    'modern_cpu_native_fields.h','modern_cpu_pending_interrupt_values_v1.h','modern_cpu_native_exit_reducer_v1.h',
    'modern_cpu_config_capability_acquisition_v1.h','modern_cpu_tlbi_capability_values_v1.h']]
need(all(source.count('nativeTrap(vm->ops.context,'+str(op)+',&packet)')==1 for op in [3,5,4]),'single literal native RAM expressions')
result=dict(schema='Own same-VM RAM Factory5 Lifecycle9 source integration v1',finiteLocalScopePassed=True,findings=[],
    candidate=pin(provider),exactOwnExports=exports,normalActualChecks=host['selected'][0]['checks'],ASanUBActualChecks=host['selected'][1]['checks'],
    legacyV7Factory3ActualRegressionChecks=host['legacy']['checks'],actualCFCreateDestroyEach=1,
    actualMacSelfTaskMachMemoryAPIsExecuted=True,allVMCPUSyncRunTrapsMocked=True,native8CallbackExecutedOnlyInModel=True,
    guardedConditionalNative8SourceImplemented=True,native8ArgumentsNull=True,native8NeverLoops=True,
    getterDirtyOrReadyMaskAndSetterReadyOnlyMask=True,successful8NoSecondReadyTestMatchesOriginal=True,
    SYSFactoryUsesRealBorrowOwnerEpochGeneration=True,fixedCreatorWriterBound=True,readOutputPreservedOnFailure=True,
    failedWriteAfterCopyPoisonKeepsOwnerCleanupHandle=True,requiredRange0x4108CheckedAgainstActualSelfMappings=True,
    writableFieldRangeCheckedSeparatelyFromReadOnlyMetadata=True,observedRegionEndIsNotKernelAllocationLength=True,
    sameVMOwnedRAMNative345SourceImplemented=True,ownedAnonymousRAMRetainedByVMRegistry=True,
    RAMChangesRefusedWithAnyCPUHandle=True,failedNativeMapProtectUnmapRetainsBacking=True,
    guestEXECFlagsOnlyEncodedNotExecutionProven=True,currentNativeStrongNamesClosed=False,providerSigned=False,providerLoaded=False,readyWritten=False,
    nativeCPUCallsExecuted=0,nativeVMCallsExecuted=0,native8CallsExecuted=0,native9CallsExecuted=0,deviceOperations=0,
    configurationFeaturesFalseAreNotDefaultInitializationProof=True,resetConstantsInvented=False,
    architectureResetComplete=False,memoryBindingComplete=False,fullPublicRunEquivalent=False,originalVMMIntegrated=False,full27Backend=False,
    inputs=[pin(p) for p in sorted(set(inputs))],hostSteps=json.loads((D/'steps-in-progress.json').read_text()),iosSteps=steps)
(D/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(candidate=pin(D/'candidate.json'),provider=pin(provider),ownExports=len(exports))))
