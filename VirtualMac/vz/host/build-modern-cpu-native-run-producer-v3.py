#!/usr/bin/env python3
"""Necessary source integration; mocked native callbacks on Mac, unsigned iOS only."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-native-run-producer-integration-local-v2'
def pin(p):
 p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def run(label,args,san=False):
 env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0'
 p=subprocess.run(list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=30)
 (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
 steps.append(dict(label=label,args=list(map(str,args)),exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
 need(p.returncode==0,label+' failed');return p.stdout
D.mkdir(exist_ok=True);need(not (D/'candidate.json').exists(),'new immutable candidate');steps=[]
units=['modern_cpu_native_public_factory_v3.c','modern_cpu_kernel_lifecycle_v7.c','modern_cpu_kernel_initialization_v3.c',
 'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c','modern_cpu_kernel_system_v2.c','modern_cpu_native_exit_reducer_v1.c','modern_cpu_config_os_object_v4.m']
test=S/'test-modern-cpu-native-run-producer-v3.m';common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall','-Wextra','-Werror','-I',S,'-DVM27_CPU_CONFIG_TESTING=1']
for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
 out=D/label;run(label+'-compile',common+flags+[S/x for x in units]+[test,'-framework','CoreFoundation','-lobjc','-o',out]);stdout=run(label+'-run',[out],san=label=='sanitized');result=json.loads(stdout.splitlines()[-1]);need(result['created']==result['destroyed']==8 and result['nativeCalls']==0,'actual model result')
# Build real acquisition only for inert iOS. The Mac executable uses the explicit
# fixture test stub above, with no native assembly linked or executed.
ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-I',S,'-fvisibility=hidden']
objects=[]
for name in units+['modern_cpu_config_capability_acquisition_v1.c','modern_cpu_tlbi_capability_values_v1.c','modern_cpu_config_capability_query_v1.S']:
 obj=D/(Path(name).stem+'.o');run(Path(name).stem+'-ios-compile',ios+(['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj]);objects.append(obj)
exports=[]
for header in ['modern_cpu_native_public_factory_v2.h','modern_cpu_native_public_factory_v3.h','modern_cpu_config_os_object_v3.h']:
 exports+=re.findall(r'(VM27CPU(?:Factory|Config)\w+)\(', (S/header).read_text())
exports=sorted(set(exports));exportFile=D/'exports.txt';exportFile.write_text(''.join('_'+x+'\n' for x in exports))
# Factory/OS APIs are exported explicitly; lifecycle and native trampoline are
# private. Export-list cannot override a hidden definition, so those two source
# units are rebuilt with default visibility while all dependencies stay hidden.
for name in ['modern_cpu_native_public_factory_v3.c','modern_cpu_config_os_object_v4.m']:
 obj=D/(Path(name).stem+'.o');run(Path(name).stem+'-ios-own-exports', [x for x in ios if x!='-fvisibility=hidden']+(['-fno-objc-arc'] if name.endswith('.m') else [])+['-c',S/name,'-o',obj])
provider=D/'VM27CPUFactoryRunProducerV3.dylib'
run('ios-link',ios+['-dynamiclib',*objects,'-framework','CoreFoundation','-lobjc','-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exportFile),'-Wl,-install_name,@rpath/VM27CPUFactoryRunProducerV3.dylib','-o',provider])
run('ios-validate',['xcrun','dyld_info','-validate_only',provider]);nm=run('ios-exports',['xcrun','nm','-gU',provider]);imports=run('ios-imports',['xcrun','nm','-u',provider]);deps=run('ios-deps',['otool','-L',provider]);disasm=run('ios-disasm',['xcrun','llvm-objdump','--macho','--disassemble',provider])
need(sorted(line.split()[-1].decode() for line in nm.splitlines() if line.split())==['_'+x for x in exports],'exact own exports')
need(not re.search(rb'_hv_|Hypervisor|Virtualization|VirtualMachineMonitor',imports+deps),'forbidden framework import')
b=provider.read_bytes();at=32
for _ in range(struct.unpack_from('<I',b,16)[0]):
 cmd,size=struct.unpack_from('<II',b,at);need(cmd!=0x1d,'unsigned');at+=size
need((S/'modern_cpu_kernel_lifecycle_v7.c').read_text().count('nativeTrap(')==5,'four inherited lifecycle plus one native9 expression')
need((S/'modern_cpu_config_capability_acquisition_v1.c').read_text().count('VM27CPUConfigCapabilityKernelQueryV1(0, buffer)')==1,'single literal0 acquisition')
inputs=[Path(__file__),test,*[S/x for x in units],S/'modern_cpu_config_capability_acquisition_v1.c',S/'modern_cpu_config_capability_acquisition_v1.h',S/'modern_cpu_config_capability_query_v1.S',S/'modern_cpu_tlbi_capability_values_v1.c']
inputs += list(S.glob('modern_cpu_kernel*.h'))+[S/'modern_cpu_config_os_object_v3.h',S/'modern_cpu_config_os_object_v3_private.h',S/'modern_cpu_config_os_object_v4_private.h',S/'modern_cpu_native_public_factory_v2.h',S/'modern_cpu_native_public_factory_v3.h',S/'modern_cpu_native_exit_reducer_v1.h',S/'modern_cpu_pending_interrupt_values_v1.h',S/'modern_cpu_native_fields.h',S/'modern_cpu_kernel_system_fields.inc',S/'modern_cpu_tlbi_capability_values_v1.h']
result=dict(schema='Application-owned reciprocal output guard and guarded native9 post-return producer source v3',finiteLocalScopePassed=True,findings=[],candidate=pin(provider),steps=steps,inputs=[pin(x) for x in sorted(set(inputs))],exactOwnExports=exports,normalAndSanitizedActualChecks=result['checks'],actualOwnCFObjectsCreated=8,actualOwnCFObjectsDestroyed=8,OSv2CrossOwnedAliasRepairInherited=True,OSv3RealObjectBorrowAndStableCFReference=True,genuineShapedOpaqueConfigAcceptedOnlyFromOwnRegistry=True,nativeCreatePacketFixedSlotZero=True,actualNativeContextVersionFull64=True,configurationAppliedBeforeIdentityPublication=True,nonzeroKeyPairAppliedByExactNative0eSliceInMock=True,realAcquisitionSourceLinkedOnlyInUnsignedIOS=True,hostModelUsesCapabilityStub=True,nativeFGTFeatureProfileApplied=False,TLBIInstructionHandlerImplemented=False,guardedSingleNative9PrimitiveSourceImplemented=True,nativeRunImplemented=False,fullPublicRunEquivalent=False,persistentExceptionPublicationSourceImplemented=True,validPublicExitProducedOnlyInMock=True,originalVMMDirectlyIntegrated=False,AppleOSObjectIdentity=False,providerSigned=False,providerLoaded=False,nativeCallsExecuted=0,deviceOperations=0,observedValueUsedAsDefault=False,kernelWriteWidthKnown=False,raw11CauseProved=False,full27Backend=False)
(D/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(candidate=pin(D/'candidate.json'),normalChecks=result['normalAndSanitizedActualChecks'],ownExports=len(exports))))
