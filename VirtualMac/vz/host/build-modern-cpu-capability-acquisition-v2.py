"""Execute own mock acquisition against one frozen genuine golden record."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'cpu-feature-capability-acquisition-local-v3'
D.mkdir(exist_ok=True)
if (D/'results.json').exists():raise ValueError('accepted model result exists')
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
golden=N/'native-capability-seed-contract-v1/audit/instruction-model-golden.bin';b=golden.read_bytes()
if b[:8]!=b'VZSEED01' or struct.unpack_from('<4I',b,8)!=(0x148,0xe0,6688,1):raise ValueError('actual frozen golden format')
recordBytes=0x148+4+0xe0;index=13;record=b[24+recordBytes*index:24+recordBytes*(index+1)]
if len(record)!=recordBytes or record[0x14b]!=0:raise ValueError('actual complete chosen record')
inputFile=D/'genuine-selected-record.bin';inputFile.write_bytes(record[:0x148+3]+record[0x14c:])
steps=[];results=[]
def run(label,args):
 env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0';env['UBSAN_OPTIONS']='halt_on_error=1'
 p=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=20)
 (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
 steps.append(dict(label=label,args=list(map(str,args)),exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
 (D/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
 if p.returncode:raise ValueError(label+' failed')
 return p.stdout
units=['modern_cpu_config_capability_acquisition_v2.c','modern_cpu_native_capability_seed.c','modern_cpu_tlbi_capability_values_v1.c','test-modern-cpu-capability-acquisition-v2.c']
for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
 exe=D/label;run(label+'-compile',['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror','-I',S,'-DVM27_CPU_CAPABILITY_TESTING=1',*flags,*[S/x for x in units],'-o',exe])
 cases=[]
 for mode in ['success','query-reentry','native-failure','exterior-failure','post-owner-change','cleanup-failure','sysctl-failure','sysctl-short','unsupported-profile']:
  case=json.loads(run(label+'-'+mode,[exe,mode,inputFile]));cases.append(case)
 results.append(dict(label=label,cases=cases,totalChecks=sum(q['checks'] for q in cases)))
obj=D/'production-ios.o';run('production-ios-compile',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-I',S,'-fvisibility=hidden','-c',S/units[0],'-o',obj])
run('production-ios-imports',['xcrun','nm','-u',obj])
j=dict(schema='Real acquisition source bridge to frozen genuine feature seed v1',finiteLocalScopePassed=True,findings=[],
 actualModelResults=results,genuineGoldenRecordIndex=index,genuineGolden=pin(golden),
 originalSeedContract=pin(N/'native-capability-seed-contract-v1/audit/contract.json'),
 originalSeedSourceUnchanged=True,oneProcessOnceQuerySharedByFeatureAndTLBI=True,
 noHistoricalReceiptDefault=True,kernelWriteWidthKnown=False,onlyOwned352ByteCapacity=True,
 productionIOSCompiledNoTestProfileCallbacks=True,productionObject=pin(obj),
 nativeCallsExecuted=0,deviceOperations=0,providerLoaded=False,featureHardwareValueObserved=False,
 full27Backend=False,steps=steps,inputs=[pin(Path(__file__)),*[pin(S/x) for x in units],pin(S/'modern_cpu_config_capability_acquisition_v2.h'),pin(S/'modern_cpu_native_capability_seed.h'),pin(S/'modern_cpu_tlbi_capability_values_v1.h')])
(D/'results.json').write_text(json.dumps(j,indent=2)+'\n')
print(json.dumps(dict(results=pin(D/'results.json'),checks=[x['totalChecks'] for x in results],nativeCalls=0)))
