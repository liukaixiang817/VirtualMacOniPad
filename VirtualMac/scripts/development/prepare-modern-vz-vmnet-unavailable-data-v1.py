#!/usr/bin/env python3
"""Only replace original VZ ordinal30 dependency name in inert data.

The private provider implements documented failure contracts, not networking.
The future diagnostic configuration must have network disabled and zero NICs.
"""
import argparse,hashlib,importlib.util,json,pathlib,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER=N/'vz-typed-routes-independent-review-v1/review.py'
assert hashlib.sha256(READER.read_bytes()).hexdigest()=='a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
spec=importlib.util.spec_from_file_location('vz_reader',READER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SOURCE=N/'vz-maxcpu-original-route-v1/build-v4/VZ27.maxcpu-leaf-route.inert.macho-data'
SOURCE_SHA='7853c1e4e88e5a18fff076563fcec72e490fd899bb4b1842659d2542454d8966'
PROVIDER=N/'vmnet-unavailable-contract-v1/ios/VM27VMNetUnavailable.dylib'
PROVIDER_SHA='165729cabbf26bf59e8aabad601516cb1bbe8fa47adf2eb53ad211c0686609c1'
SDK=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/System/Library/Frameworks/vmnet.framework/Versions/A/Headers/vmnet.h')
NEW='@loader_path/VM27VMNetUnavailable.dylib'
def provider(b):
 assert m.sha(b)==PROVIDER_SHA
 count,size=struct.unpack_from('<II',b,16);at=32;ids=[];deps=[];builds=[];uuid=[]
 for _ in range(count):
  c,z=struct.unpack_from('<II',b,at);assert z>=8 and z%8==0 and at+z<=32+size
  if c in m.DEP_COMMANDS or c==13:
   no,t,cur,compat=struct.unpack_from('<4I',b,at+8);assert 24<=no<z
   name,_=m.checked_string(b,at+no,at+z)
   (ids if c==13 else deps).append(dict(command=c,path=name,metadata=[t,cur,compat]))
  elif c==0x1b:assert z==24;uuid.append(b[at+8:at+24].hex())
  elif c==0x32:builds.append(list(struct.unpack_from('<4I',b,at+8)))
  at+=z
 assert at==32+size and len(ids)==len(uuid)==len(builds)==1
 assert ids[0]==dict(command=13,path='@rpath/VM27VMNetUnavailable.dylib',metadata=[1,65536,65536])
 assert len(deps)==1 and deps[0]['command']==12 and deps[0]['path']=='/usr/lib/libSystem.B.dylib'
 assert builds[0][0]==2 and builds[0][1]==0x100100
 return dict(ID=ids[0],UUID=uuid[0],strongDependencies=deps,build=builds[0],iOSExecuted=False,
     networkImplemented=False,disabledBackendOffersZeroInterfaces=True,physicalIPadInterfacesMeasured=False)
def derive(source):
 assert m.sha(source)==SOURCE_SHA
 a=m.parse(source);d=a['deps'][29]
 assert a['header'][3:5]==[79,9552] and len(a['deps'])==60 and len(a['imports'])==1056
 assert d['ordinal']==30 and d['cmd']==12 and d['at']==7512 and d['size']==80 and d['nameOffset']==24
 assert d['name']=='/System/Library/Frameworks/vmnet.framework/vmnet' and d['versions']==[2,65536,65536]
 data=bytearray(source);payload=NEW.encode()+b'\0';assert len(payload)<=56
 data[7536:7592]=payload+bytes(56-len(payload));return bytes(data)
def verify(source,candidate,p):
 assert candidate==derive(source);a=m.parse(source);b=m.parse(candidate)
 assert a['header']==b['header'] and a['segments']==b['segments'] and a['imports']==b['imports'] and a['nlists']==b['nlists']
 assert a['words']==b['words'] and len(b['words'])==26993
 for x,y in zip(a['deps'],b['deps']):
  assert x['cmd']==y['cmd'] and x['ordinal']==y['ordinal'] and x['versions']==y['versions']
  assert y['name']==(NEW if x['ordinal']==30 else x['name'])
 changes=[i for i,(x,y)in enumerate(zip(source,candidate))if x!=y]
 assert all(7536<=at<7592 for at in changes)
 return dict(changedBytes=len(changes),changedOffsets=changes,pathRegion=[7536,7592],
     previousAllRoutesRetained=True,strongFiveImportsUnchanged=[x for x in b['imports']if x['ordinal']==30],
     codeAndDataByteExact=True,all26993ChainWordsAndPACExact=True,provider=provider(p),signatureStale=True,
     originalVZLoaded=False,full27Backend=False,diagnosticPrecondition='network=disabled, zero NICs')
def negatives(source,candidate,p):
 a=m.parse(candidate);bad=[]
 def reject(name,b,q=p):
  try:verify(source,b,q)
  except(AssertionError,IndexError,ValueError,struct.error):bad.append(dict(name=name,rejected=True));return
  raise AssertionError(name)
 for name,at,mask in [('path',7536,1),('requiredCompatibility',7532,1),('code',9584,1),('newMaxCPUroute',a['imports'][560]['at'],1)]:
  q=bytearray(candidate);q[at]^=mask;reject(name,bytes(q))
 for x in a['imports']:
  if x['ordinal']==30:
   for label,d,mask in [('ordinal',0,1),('weak',1,1),('addend',4,1)]:
    q=bytearray(candidate);q[x['at']+d]^=mask;reject(f'import{x["index"]} {label}',bytes(q))
 word=next(x for x in a['words']if x['bind']and x['index']==735)
 q=bytearray(candidate);q[word['at']+7]^=128;reject('PAC',bytes(q))
 q=bytearray(candidate);struct.pack_into('<I',q,7512,0x80000018);reject('real weak LC',bytes(q))
 reject('trailing',candidate+b'\0');q=bytearray(p);q[0]^=1;reject('provider',candidate,bytes(q));return bad
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=pathlib.Path,required=True);args=parser.parse_args()
 out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
 s=SOURCE.read_bytes();p=PROVIDER.read_bytes();data=derive(s);proof=verify(s,data,p);controls=negatives(s,data,p)
 target=out/'VZ27.vmnet-disabled.inert.macho-data';target.write_bytes(data);target.chmod(0o600)
 steps=[]
 for label,argv in [('metadata',['xcrun','dyld_info','-platform','-dependents','-imports',str(target)]),('provider',['xcrun','dyld_info','-platform','-dependents','-imports','-exports','-validate_only',str(PROVIDER)])]:
  r=subprocess.run(argv,capture_output=True);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);assert r.returncode==0;steps.append(dict(label=label,exit=r.returncode))
 c=dict(schema='Original VZ vmnet disabled path-only inert v1',builder=m.pin(pathlib.Path(__file__)),reader=m.pin(READER),
     source=m.pin(SOURCE),binary=m.pin(target),provider=m.pin(PROVIDER),SDKHeader=m.pin(SDK),verification=proof,negativeControls=controls,staticTools=steps,
     originalStrongDependencyCount=60,originalImportCount=1056,deviceOperations=0,iOSProviderExecuted=False,originalVZLoaded=False,full27Backend=False,
     backendConfigurationEnforced=False,requiresFutureNetworkDisabledAdmission=True,signingCalls=0)
 (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
 print(json.dumps(dict(candidate=m.pin(out/'candidate.json'),binary=m.pin(target),negativeControls=len(controls))))
if __name__=='__main__':main()
