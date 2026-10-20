#!/usr/bin/env python3
"""Only replace original VZ ordinal24 dependency name in inert data.

The private provider stores the original consumed process-title state.
It provides a real own-process CF identity, not a system-global LSASN.
"""
import argparse,hashlib,importlib.util,json,pathlib,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER=N/'vz-typed-routes-independent-review-v1/review.py'
assert hashlib.sha256(READER.read_bytes()).hexdigest()=='a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
spec=importlib.util.spec_from_file_location('vz_reader',READER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SOURCE=N/'vz-vmnet-unavailable-original-route-v1/build-v1/VZ27.vmnet-disabled.inert.macho-data'
SOURCE_SHA='7974096ddd424704f32ce4d4a905bbc1f9aa19f9b98f2e0afd83f51eabcb8462'
PROVIDER=N/'process-title-state-contract-v1/ios/VM27PrivateProcessTitle.dylib'
PROVIDER_SHA='0e4654ed43bfeb38d4df18a60186079105a8c8fc69c6191978158263f5baf300'
ABI=N/'launchservices-genuine-contract-audit-v1/audit.json'
NEW='@loader_path/VM27PrivateProcessTitle.dylib'
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
 assert ids[0]==dict(command=13,path='@rpath/VM27PrivateProcessTitle.dylib',metadata=[1,65536,65536])
 assert len(deps)==2 and all(d['command']==12 for d in deps)
 assert [d['path'] for d in deps]==['/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation','/usr/lib/libSystem.B.dylib']
 assert builds[0][0]==2 and builds[0][1]==0x100100
 return dict(ID=ids[0],UUID=uuid[0],strongDependencies=deps,build=builds[0],iOSExecuted=False,
     realPrivateCFProcessIdentity=True,globalASNImplemented=False,realPrivateTitleStore=True,hostOSTitleChanged=False)
def derive(source):
 assert m.sha(source)==SOURCE_SHA
 a=m.parse(source);d=a['deps'][23]
 assert a['header'][3:5]==[79,9552] and len(a['deps'])==60 and len(a['imports'])==1056
 assert d['ordinal']==24 and d['cmd']==12 and d['at']==7008 and d['size']==88 and d['nameOffset']==24
 assert d['name']=='/System/Library/Frameworks/CoreServices.framework/CoreServices' and d['versions']==[2,80347136,65536]
 data=bytearray(source);payload=NEW.encode()+b'\0';assert len(payload)<=64
 data[7032:7096]=payload+bytes(64-len(payload));return bytes(data)
def verify(source,candidate,p):
 assert candidate==derive(source);a=m.parse(source);b=m.parse(candidate)
 assert a['header']==b['header'] and a['segments']==b['segments'] and a['imports']==b['imports'] and a['nlists']==b['nlists']
 assert a['words']==b['words'] and len(b['words'])==26993
 for x,y in zip(a['deps'],b['deps']):
  assert x['cmd']==y['cmd'] and x['ordinal']==y['ordinal'] and x['versions']==y['versions']
  assert y['name']==(NEW if x['ordinal']==24 else x['name'])
 changes=[i for i,(x,y)in enumerate(zip(source,candidate))if x!=y]
 assert all(7032<=at<7096 for at in changes)
 return dict(changedBytes=len(changes),changedOffsets=changes,pathRegion=[7032,7096],
     previousAllRoutesRetained=True,strongThreeImportsUnchanged=[x for x in b['imports']if x['ordinal']==24],
     codeAndDataByteExact=True,all26993ChainWordsAndPACExact=True,provider=provider(p),signatureStale=True,
     originalVZLoaded=False,full27Backend=False,diagnosticPrecondition='only own process-title caller subset')
def negatives(source,candidate,p):
 a=m.parse(candidate);bad=[]
 def reject(name,b,q=p):
  try:verify(source,b,q)
  except(AssertionError,IndexError,ValueError,struct.error):bad.append(dict(name=name,rejected=True));return
  raise AssertionError(name)
 for name,at,mask in [('path',7032,1),('requiredCompatibility',7028,1),('code',9584,1),('newMaxCPUroute',a['imports'][560]['at'],1)]:
  q=bytearray(candidate);q[at]^=mask;reject(name,bytes(q))
 for x in a['imports']:
  if x['ordinal']==24:
   for label,d,mask in [('ordinal',0,1),('weak',1,1),('addend',4,1)]:
    q=bytearray(candidate);q[x['at']+d]^=mask;reject(f'import{x["index"]} {label}',bytes(q))
 word=next(x for x in a['words']if x['bind']and x['index']==957)
 q=bytearray(candidate);q[word['at']+7]^=128;reject('PAC',bytes(q))
 q=bytearray(candidate);struct.pack_into('<I',q,7008,0x80000018);reject('real weak LC',bytes(q))
 reject('trailing',candidate+b'\0');q=bytearray(p);q[0]^=1;reject('provider',candidate,bytes(q));return bad
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=pathlib.Path,required=True);args=parser.parse_args()
 out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
 s=SOURCE.read_bytes();p=PROVIDER.read_bytes();data=derive(s);proof=verify(s,data,p);controls=negatives(s,data,p)
 target=out/'VZ27.private-process-title.inert.macho-data';target.write_bytes(data);target.chmod(0o600)
 steps=[]
 for label,argv in [('metadata',['xcrun','dyld_info','-platform','-dependents','-imports',str(target)]),('provider',['xcrun','dyld_info','-platform','-dependents','-imports','-exports','-validate_only',str(PROVIDER)])]:
  r=subprocess.run(argv,capture_output=True);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);assert r.returncode==0;steps.append(dict(label=label,exit=r.returncode))
 c=dict(schema='Original VZ private process title path-only inert v1',builder=m.pin(pathlib.Path(__file__)),reader=m.pin(READER),
     source=m.pin(SOURCE),binary=m.pin(target),provider=m.pin(PROVIDER),originalABI=m.pin(ABI),verification=proof,negativeControls=controls,staticTools=steps,
     originalStrongDependencyCount=60,originalImportCount=1056,deviceOperations=0,iOSProviderExecuted=False,originalVZLoaded=False,full27Backend=False,
     OSGlobalASNImplemented=False,hostOSTitleChanged=False,originalPrivateCFASNSemanticsComplete=False,signingCalls=0)
 (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
 print(json.dumps(dict(candidate=m.pin(out/'candidate.json'),binary=m.pin(target),negativeControls=len(controls))))
if __name__=='__main__':main()
