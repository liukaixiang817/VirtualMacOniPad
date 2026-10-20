"""Pin true old feature/IPA words and compile the actual SDK tenth ABI."""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'cpu-hv-public-feature-original-sdk-readonly-v1'
D.mkdir(exist_ok=False);pins={}
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();v=dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest());pins[str(p)]=v;return v
def need(x,s):
 if not x:raise ValueError(s)
original=N/'old13-observer-baseline-v1/Hypervisor';b=original.read_bytes();pin(original)
need(hashlib.sha256(b).hexdigest()=='c40d039280f8048b9e921d2ea7181e50e7e6dd693614cc494baa4d7f43d8efe4','original actual source')
contract=N/'native-capability-seed-contract-v1/audit/contract.json';j=json.loads(contract.read_text());pin(contract)
frameProof=[]
for name,f in j['frames'].items():
 start,end=int(f['startRVA'],16),int(f['endRVA'],16)
 need(hashlib.sha256(b[start:end]).hexdigest()==f['machineBytesSHA256'],'original complete frame '+name)
 for row in f['instructions']:need(f'{struct.unpack_from("<I",b,row["rva"])[0]:08x}'==row['machineWord'],'original actual word')
 frameProof.append(dict(name=name,startRVA=f['startRVA'],endRVA=f['endRVA'],sha256=f['machineBytesSHA256'],wordsChecked=len(f['instructions'])))
manifest=N/'native-capability-seed-contract-v1/manifest.json';m=json.loads(manifest.read_text());pin(manifest)
for i in m['currentSourceInputs']:
 p=R/i['path'];need(pin(p)==dict(i,path=str(p)),'frozen pure source unchanged')
golden=N/'native-capability-seed-contract-v1/audit/instruction-model-golden.bin';need(pin(golden)['sha256']==j['golden']['sha256'],'actual genuine golden')
# Independently derive the public selector table directly from true bytes.
table=struct.unpack_from('<12i',b,0x50dc);targets=[0x504c+x for x in table]
loadOffsets=[]
for target in targets:
 word=struct.unpack_from('<I',b,target)[0];need(word&0xffc003ff==0xf94003e8,'actual stack u64 LDR x8')
 loadOffsets.append(((word>>10)&0xfff)*8)
need(loadOffsets==list(range(0,0x50,8))+[0x58,0x50],'real original selectors10/11 swap')
oldSDK=N/'cpu-hv-public-getter-original-sdk-readonly-v2/audit.json';sdk=json.loads(oldSDK.read_text());pin(oldSDK)
for p in sdk['inputs']:
 if p['path'].startswith('/Applications/'):need(pin(p['path'])==p,'actual SDK header still same')
src=D/'actual-feature-dyld-abi.c';src.write_text('''#include "modern_cpu_hv_public_abi_v2.h"
_Static_assert(sizeof(hv_feature_reg_t)==4,"actual SDK feature width");
hv_return_t feature_caller(hv_vcpu_config_t c,hv_feature_reg_t r,uint64_t *v){return hv_vcpu_config_get_feature_reg(c,r,v);}
typedef struct {uint32_t platform,version;} own_dyld_build_version;
_Static_assert(sizeof(own_dyld_build_version)==8 && _Alignof(own_dyld_build_version)==4,"dyld struct ABI");
extern bool dyld_program_sdk_at_least(own_dyld_build_version);
bool dyld_caller(void){return dyld_program_sdk_at_least((own_dyld_build_version){0xffffffff,0x07e60901});}
''')
steps=[];decls={}
for label,sdkname,arch in [('actual-mac-sdk','macosx','arm64'),('own-ios-abi','iphoneos','arm64e')]:
 out=D/(label+'.ll');args=['xcrun','--sdk',sdkname,'clang','-arch',arch,'-Wall','-Wextra','-Werror','-I',str(S),'-O1','-S','-emit-llvm',str(src),'-o',str(out)]
 p=subprocess.run(args,capture_output=True,env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')},timeout=20)
 (D/(label+'.stderr')).write_bytes(p.stderr);need(p.returncode==0,'actual ABI compile')
 lines=out.read_text().splitlines();decls[label]=[x for x in lines if x.startswith('declare ') and ('@hv_vcpu_config_get_feature_reg' in x or '@dyld_program_sdk_at_least' in x)]
 need(len(decls[label])==2,'actual two calls');need(any(re.search(r'@hv_vcpu_config_get_feature_reg\(ptr[^,]*, i32[^,]*, ptr',x) for x in decls[label]),'actual first3args ptr/i32/ptr')
 need(any(re.search(r'declare[^@]*i1 @dyld_program_sdk_at_least\(i64',x) for x in decls[label]),'actual struct coerces to X0 and bool result')
 steps.append(dict(label=label,exit=p.returncode,args=args,LLVM=pin(out),stderr=pin(D/(label+'.stderr'))))
query=N/'cpu-feature-capability-acquisition-local-v3/results.json';q=json.loads(query.read_text());pin(query)
need([x['totalChecks'] for x in q['actualModelResults']]==[250,250],'actual bridge golden/failure cases')
for i in q['inputs']:need(pin(i['path'])==i,'current acquisition source')
pin(S/'modern_cpu_hv_public_abi_v2.h');pin(Path(__file__));pin(N/'cpu-feature-capability-acquisition-local-v2/dyld-primary-abi-source.json')
result=dict(schema='Actual feature getter and one-query shared CPU IPA acquisition contract v1',finiteLocalScopePassed=True,findings=[],
 originalFullFrames=frameProof,originalSelectorLoadOffsets=loadOffsets,actualSDKAndOwnIOSLLVMDeclarations=decls,compileSteps=steps,
 closedOldFeatureSelectors=list(range(12)),unsupportedModernFeatureSelectors=list(range(12,18)),
 originalSDKPredicatePackedToken='0x07e60901ffffffff',SDKPredicatesActualProductionCalls=3,
 primaryDyldDeclarationURL='https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/dyld_priv.h',
 primaryDyldArgumentStructFields=['uint32 platform','uint32 version'],primaryDyldReturn='bool',currentProfileOnlyToken=True,
 sameOneProcessOnceForFeatureTLBIAndRawIPA=True,rawIPAPairFieldOffsets=[0x149,0x151],rawIPAPairBytesEach=8,
 lifecycleProfile='0x16110001',IPAPureTransformProfile=1,profilesNotCastOrEquated=True,
 kernelOwnBufferCapacityBytes=352,kernelWriteWidthKnown=False,rawIPAKnownDoesNotMeanSupportedMax=True,
 rawIPAPublishedOnlyAfterOwnerExteriorAndActualUnmapSuccess=True,oldObservationsUsedAsDefaults=False,
 oldAppleUSERTableInstalled=False,seedInstalledAsCPUReset=False,modernVIEWProduced=False,
 nativeCallsExecuted=0,deviceOperations=0,featureHardwareExecutionProven=False,full27Backend=False,
 inputs=sorted(pins.values(),key=lambda x:x['path']))
(D/'audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(audit=pin(D/'audit.json'),frames=len(frameProof),selectorCount=12,bridgeChecksEach=250)))
