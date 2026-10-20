#!/usr/bin/env python3
"""Actual V5 source integration; only mock execution, unsigned inert iOS link."""
from pathlib import Path
import argparse, hashlib, json, os, re, runpy, struct, subprocess, sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H = R / 'VirtualMac/vz/host'
V5 = N / 'kernel-owned-borrow-drain-v5-local-v1'
ABI = N / 'vmm-public-adapter-gap-design-v1'
def require(ok, label):
    if not ok: raise ValueError(label)
def pin(p):
    p = p.resolve(); require(p.is_file() and not p.is_symlink(), 'regular input')
    b = p.read_bytes(); return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def verify(row): require(pin(Path(row['path'])) == row, 'input drift')
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output', type=Path, required=True); a=ap.parse_args()
    out=a.output.resolve(); require(out.is_relative_to(N), 'workspace output'); out.mkdir(exist_ok=False)
    source=out/'source'; source.mkdir(); inputs=[]; commands=[]; models=[]
    frozen=pin(V5/'freeze.json'); require(frozen['sha256']=='d546d1aa432a74c51b9ade5509465bbcbbff55f6fbb9a18a499e83d56fd9ad0f','immutable V5')
    prior=json.loads((V5/'freeze.json').read_text())['files']
    for row in prior: verify(row)
    inputs += [frozen,pin(ABI/'contract.json'),pin(ABI/'freeze.json'),pin(ABI/'audit.py')]
    for row in json.loads((ABI/'freeze.json').read_text())['files']: verify(row)
    baseline=V5/'local-build-v3/source'
    names=['modern_cpu_kernel_lifecycle_v5.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_native_fields.c',
        'modern_cpu_kernel_initialization_v2.c','modern_cpu_kernel_system_v2.c']
    for p in sorted(baseline.iterdir()):
        if p.name.startswith('modern_cpu_') and (p.suffix in ('.h','.inc') or p.name in names):
            actual=H/p.name; require(actual.read_bytes()==p.read_bytes(),'frozen source bytes '+p.name)
            inputs += [pin(p),pin(actual)]; (source/p.name).write_bytes(p.read_bytes())
    new=['modern_cpu_native_public_factory_v1.c','modern_cpu_native_public_factory_v1.h']
    for name in new:
        p=H/name; inputs.append(pin(p)); (source/name).write_bytes(p.read_bytes())
    test=R/'VirtualMac/scripts/tests/test-modern-cpu-native-public-factory-v1.c'
    inputs += [pin(test),pin(Path(__file__))]; (source/test.name).write_bytes(test.read_bytes()); (out/'builder-snapshot.py').write_bytes(Path(__file__).read_bytes())
    def run(label,argv,expected=0,sanitized=False):
        argv=list(map(str,argv)); env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        if sanitized: env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0'
        proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try: stdout,stderr=proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill();stdout,stderr=proc.communicate();(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr);raise
        (out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
        commands.append(dict(label=label,argv=argv,returncode=proc.returncode,directPID=proc.pid,reaped=True))
        require(proc.returncode==expected if expected is not None else proc.returncode!=0,label+' exit')
        return stdout,stderr
    units=[source/x for x in names]
    common=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-pthread','-I',source]
    for san in (False,True):
        flags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if san else []
        for white in (False,True):
            label='factory'+('-whitebox' if white else '')+('-sanitized' if san else '')
            executable=out/label
            run(label+'-compile',common+(['-DVM27_FACTORY_WHITEBOX'] if white else [])+[source/test.name,*([] if white else [source/new[0]]),*units,'-o',executable]+flags)
            stdout,stderr=run(label+'-run',[executable],sanitized=san); require(not stderr,'model stderr')
            result=json.loads(stdout);require(result['checks']>=150 and result['scenarios']==(13 if white else 12),'finite real integration model')
            models.append(dict(label=label,result=result))
    # Faults alter ONLY new copied adapter source, never any frozen V5 byte.
    original=(source/new[0]).read_text()
    faults=[('accept-foreign-config','config ? VZ_KERNEL_UNSUPPORTED','config ? VZ_KERNEL_OK'),
        ('claim-zero-exit-valid','d.vmEpoch = vm ? vm->epoch : 0;','d.exitRecordValid = true; d.vmEpoch = vm ? vm->epoch : 0;'),
        ('erase-exit-on-destroy-error','} else { Diagnose(diagnostic, status, &r, vm, entry, true); End(&entry->operation); }',
         '} else { memset(entry->exitStorage, 0, sizeof(*entry->exitStorage)); Diagnose(diagnostic, status, &r, vm, entry, true); End(&entry->operation); }')]
    negatives=[]
    for label,before,after in faults:
        require(original.count(before)==1,'single fault '+label); mutant=out/(label+'.c');mutant.write_text(original.replace(before,after))
        executable=out/label;run(label+'-compile',common+[source/test.name,mutant,*units,'-o',executable])
        stdout,stderr=run(label+'-reject',[executable],expected=None);require(b'FAIL ' in stderr,'actual model rejected '+label)
        negatives.append(dict(label=label,compiled=True,actualProcessRejected=True,stderrSHA256=hashlib.sha256(stderr).hexdigest()))
    # SDK proofs are unevaluated expressions: no Hypervisor link/load/call.
    sdkmodel=out/'sdk-abi-model.c'
    sdkmodel.write_text('''#include <Hypervisor/hv_vcpu.h>
#include <Hypervisor/hv_vcpu_config.h>
#include "modern_cpu_native_public_factory_v1.h"
#define S(x) _Static_assert(x,#x)
S(sizeof(hv_vcpu_t)==sizeof(VM27CPUFactoryIDV1));
S(sizeof(hv_return_t)==sizeof(VM27CPUFactoryMachStatusV1));
S(__builtin_types_compatible_p(hv_vcpu_config_t,VM27CPUFactoryForeignConfigV1));
S(sizeof(hv_vcpu_exit_t)==sizeof(VM27CPUFactoryExitV1));
S(offsetof(hv_vcpu_exit_t,reason)==offsetof(VM27CPUFactoryExitV1,reason));
S(offsetof(hv_vcpu_exit_t,exception.syndrome)==offsetof(VM27CPUFactoryExitV1,syndrome));
S(offsetof(hv_vcpu_exit_t,exception.virtual_address)==offsetof(VM27CPUFactoryExitV1,virtualAddress));
S(offsetof(hv_vcpu_exit_t,exception.physical_address)==offsetof(VM27CPUFactoryExitV1,physicalAddress));
S(__builtin_types_compatible_p(__typeof__(&hv_vcpu_create),hv_return_t(*)(hv_vcpu_t*,hv_vcpu_exit_t**,hv_vcpu_config_t)));
S(__builtin_types_compatible_p(__typeof__(&hv_vcpu_destroy),hv_return_t(*)(hv_vcpu_t)));
S(__builtin_types_compatible_p(__typeof__(&hv_vcpu_config_create),hv_vcpu_config_t(*)(void)));
S(__builtin_types_compatible_p(__typeof__(&hv_vcpu_config_get_feature_reg),hv_return_t(*)(hv_vcpu_config_t,hv_feature_reg_t,uint64_t*)));
S(HV_SUCCESS==0 && (uint32_t)HV_ERROR==0xfae94001u && (uint32_t)HV_BUSY==0xfae94002u && (uint32_t)HV_BAD_ARGUMENT==0xfae94003u && (uint32_t)HV_NO_RESOURCES==0xfae94005u && (uint32_t)HV_UNSUPPORTED==0xfae9400fu);
int main(void){return 0;}
''')
    run('actual-sdk-abi-compile',common+[sdkmodel,'-o',out/'sdk-abi-model']);run('actual-sdk-abi-run',[out/'sdk-abi-model'])
    sdkimports=run('actual-sdk-abi-imports',['xcrun','nm','-u',out/'sdk-abi-model'])[0].decode();require('_hv_' not in sdkimports,'unevaluated SDK only')
    # Reuse only the frozen read-only Mach-O parser, not a product builder or
    # report booleans. Resolve the actual private setter and CFRelease slots.
    parser=runpy.run_path(str(ABI/'audit.py'));image=parser['MachO'](parser['VM'].read_bytes()); inputs.append(pin(parser['VM']))
    bindings=[]
    for stub,name,ordinal in [(0x412d24,'_hv_vcpu_config_create',21),(0x412564,'__hv_vcpu_config_set_tlbi_workaround_enabled',21),
        (0x412d44,'_hv_vcpu_create',21),(0x411114,'_CFRelease',19)]:
        slot,binding=parser['authenticated_stub'](image,image.raw(stub,16),stub)
        record=binding['importRecord'];require(record['name']==name and record['ordinal']==ordinal and not record['weak'] and record['addend']==0,'actual config ABI binding')
        bindings.append(dict(stubRVA=hex(stub),slotRVA=hex(slot),words=list(struct.unpack('<4I',image.raw(stub,16))),binding=binding))
    frame=image.raw(0xb2310,0xb273c-0xb2310);require(hashlib.sha256(frame).hexdigest()=='de091ad073a33eb8106866bb378f95643a5f1420ed080de095ad18832cbddcf5','whole true create frame')
    require(struct.unpack('<I',image.raw(0xb236c,4))[0]==0x3941ae81,'config TLBI bool from +6b')
    (out/'genuine-create-frame.bin').write_bytes(frame)
    contract=dict(actualImage=pin(parser['VM']),actualUUID=image.uuid,configBindings=bindings,
        SDKRetainedObjectReleasedWithOSRelease=True,genuineCPUCreateCallerReleasesConfigWithCFRelease=True,
        genuineTLBISetterUnimplemented=True,OSObjectCFBridgeUnimplemented=True,nonnullForeignConfigRefusedBeforeNative=True,
        objectBytes=296,actualIDOffset=216,actualExitPointerOffset=224,exitBytes=32,
        nativeCreateFixedRequestSlot=0,returnedSlotNotPublicID=True,nativeDestroyArgumentNULL=True,
        genuineDestroyNonzeroFatalAssertion=True,genuineReason2FatalAssertion=True,callocExitNotCanceled=True,
        originalVMMDirectlyAdapted=False,nativeRun=False)
    (out/'genuine-config-create-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    # Unsigned iOS provider, no sign/deploy/load. Hide V5/pure internals; expose
    # only these application-owned factory/borrow APIs, no Apple hv_* aliases.
    ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-pthread','-I',source]
    objects=[]
    for unit in [source/new[0],*units]:
        obj=out/(unit.stem+'-ios.o');run(unit.stem+'-ios-compile',ios+([] if unit.name==new[0] else ['-fvisibility=hidden'])+['-c',unit,'-o',obj]);objects.append(obj)
    candidate=out/'VM27NativeCPUFactoryV1.dylib'
    run('unsigned-ios-link',ios+['-dynamiclib',*objects,'-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
        '-Wl,-install_name,@rpath/VM27NativeCPUFactoryV1.dylib','-o',candidate])
    run('ios-dyld-validate',['xcrun','dyld_info','-validate_only',candidate])
    exports=run('ios-exports',['xcrun','nm','-gU',candidate])[0].decode()
    exported=sorted(line.split()[-1] for line in exports.splitlines() if line.split())
    expected=sorted('_'+x for x in re.findall(r'VM27CPUFactoryMachStatusV1 (VM27CPUFactory\w+)\(', (source/new[1]).read_text()))
    require(exported==expected and len(expected)==9,'exact 9 own APIs')
    imports=run('ios-imports',['xcrun','nm','-u',candidate])[0].decode()
    deps=run('ios-dependencies',['otool','-L',candidate])[0].decode()
    require(not re.search(r'_(?:hv_|VZCPU27KernelTrapRaw)|Hypervisor|Virtualization|VirtualMachine',imports+deps),'zero native framework dependency')
    binary=candidate.read_bytes();cmds=struct.unpack_from('<I',binary,16)[0];at=32
    for _ in range(cmds):
        cmd,size=struct.unpack_from('<II',binary,at);require(cmd!=0x1d,'no code signature');at+=size
    v5text=(source/names[0]).read_text();require(v5text.count('nativeTrap(')==4 and 'NativeCPUCreate args = {0, 0};' in v5text,'frozen four native expressions')
    adapter=(source/new[0]).read_text();require('nativeTrap(' not in adapter and 'vm27_exit_' not in adapter,'not mock32 replacement/native trap addition')
    for row in prior:verify(row)
    for row in inputs:verify(row)
    result=dict(schema='Application-owned actual V5 native CPU factory and persistent32 integration v1',
        candidate=pin(candidate),inputs=inputs,sourceSnapshots=[pin(p) for p in sorted(source.iterdir())],commands=commands,
        models=models,compiledNegativeMutants=negatives,exactOwnExports=exported,undefinedImports=imports,dependencies=deps,
        preservedV5Freeze= frozen,preservedV5Files=len(prior),V5SourceChanged=False,
        actualV5SourceLinked=True,mockOnlyExitComponentUsed=False,nativeCallbackAdded=False,
        SDKConfigCreateDestroyAnd32BLayoutTypeChecks=13,persistent32AllocatedBeforeNativeCreate=True,
        createAndValidationFailureRetainsOwnerCleanup=True,realPthreadTLSAndVMEpochCPUGeneration=True,
        borrowRetainsCPUAndExitAllocation=True,destroyDrainsBeforeNativeAndPreservesFailure=True,
        publicStatusMappingIsExplicitOwnPolicy=True,originalDestroyFatalContractPreserved=True,
        newFactoryLifecycleSuccessCanProduceOwnIDAndStorage=True,exitRecordValid=False,
        nativeTrapExecuted=False,nativeCallsExecuted=0,nativeRunImplemented=False,runAllowedChanged=False,
        nativeMultiCPUAllocationProved=False,requestSlotExpanded=False,USEROrVIEWConstructed=False,
        old13Forwarding=False,nonnullOSObjectConfigImplemented=False,originalVMMDirectlyIntegrated=False,
        providerSigned=False,providerLoaded=False,deviceOperations=0,observedDefaultUsed=False,raw11CauseProved=False,
        initializationWriteAuthority=False,originalCNIdentityProved=False,full27Backend=False)
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps({'files':[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]},indent=2)+'\n')
    print(json.dumps({'candidate':pin(out/'candidate.json'),'freeze':pin(out/'freeze.json'),'binary':pin(candidate),'models':models}))
if __name__=='__main__':main()
