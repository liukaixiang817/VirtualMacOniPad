#!/usr/bin/env python3
"""Fixed8MiB typed private registry/consumer/parent data-only original27 contract."""
from pathlib import Path
import hashlib, importlib.util, json, os, plistlib, re, shutil, subprocess, sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];N=ROOT.parent/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
ORIGINAL=N/'vmm-runtime-aggregate-v1/build-v4/VirtualMachine27.twenty-one-strong.macos.unsigned'
ORIGINAL_SHA='42df45e72778512a2ea5054d01e2c940650e7a836f580b99723f8bce5f02266d'
RIGHTS={'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main(output):
 out=Path(output).resolve();out.mkdir(parents=True,mode=0o700,exist_ok=False);src=out/'source';src.mkdir();procs=[];files=[]
 for p in [Path(__file__)]+[ROOT/'vz/host'/n for n in ['modern_xpc_large_bundle_registry.c','modern_xpc_large_bundle_registry.h','modern_xpc_large_private_consumer.c','modern_xpc_large_private_consumer.h','modern_xpc_large_original_parent.c','modern_xpc_large_original_parent.h','modern_xpc_approved_code.h','modern_xpc_lwcr_policy.h','modern_xpc_private_endpoint.h','modern_xpc_bundle_registry.h']]+[ROOT/'scripts/tests'/n for n in ['test-modern-xpc-large-capacity.c','validate-modern-xpc-large-capacity.py']]:
  shutil.copyfile(p,src/p.name)
 spec=importlib.util.spec_from_file_location('B',ROOT/'scripts/development/build-modern-xpc-lwcr-policy.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
 def run(label,args):
  env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};c=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env);o,e=c.communicate(timeout=25);(out/(label+'.stdout')).write_bytes(o);(out/(label+'.stderr')).write_bytes(e);(out/(label+'.argv.json')).write_text(json.dumps(args,indent=2)+'\n');procs.append({'label':label,'PID':c.pid,'wait':c.returncode,'reaped':True});assert c.returncode==0,(label,c.returncode,o[-4000:],e[-4000:]);return o,e
 def sign(role,p,rights,label,execute=True):
  if role=='ios' and execute:B.target16(p)
  ent=p.parent/(p.name+'.entitlements');ent.write_bytes(plistlib.dumps(rights));run(label+'-sign',['codesign','--force','--sign','-','--timestamp=none','--identifier','com.virtualmac.diagnostics.large-capacity.'+p.name,'--entitlements',str(ent),str(p)]);run(label+'-strict',['codesign','--verify','--strict',str(p)]);_,e=run(label+'-identity',['codesign','-dvvv',str(p)]);r={'role':role,'name':p.name,'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p),'CDHash':re.search(rb'CDHash=([a-f0-9]{40})',e)[1].decode(),'UUID':B.uuid(p.read_bytes()),'entitlements':rights,'executableDeployment':execute};files.append(r);return r
 assert sha(ORIGINAL)==ORIGINAL_SHA
 data=out/'OriginalVMM27.data';shutil.copyfile(ORIGINAL,data);data.chmod(0o600);dataRow=sign('data',data,{},'original-data',False);assert dataRow['bytes']>2097152 and dataRow['bytes']<=8388608
 for role,sdk,target in [('macos','macosx','arm64e-apple-macos13'),('ios','iphoneos','arm64e-apple-ios16.1')]:
  d=out/role;d.mkdir();known={}
  for name,old in [('VM27ApprovedCode.dylib','xpc-approved-code-v1/build-v3'),('VM27LWCRPolicy.dylib','xpc-approved-code-v1/build-v3'),('VM27BundleRegistry.dylib','xpc-bundle-registry-v1/build-v4'),('VM27PrivateEndpoint.dylib','xpc-private-child-launch-v1/xpc-build-v4')]:
   c=json.loads((N/old/'candidate.json').read_text());r=next(x for x in c['candidates'] if x['name']==name and x['role']==role);p=d/name;shutil.copyfile(r['path'],p);assert sha(p)==r['sha256'];r={**r,'path':str(p),'source':r['path'],'unchanged':True,'executableDeployment':True};files.append(r);known[name]=r
  sdkpath=run(role+'-sdk',['xcrun','--sdk',sdk,'--show-sdk-path'])[0].decode().strip();base=['xcrun','clang','-target',target,'-isysroot',sdkpath,'-fptrauth-abi-version=0','-std=c11','-fblocks','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',str(src),'-Wl,-no_adhoc_codesign']
  for stem,lib,deps,frameworks in [('modern_xpc_large_bundle_registry','VM27LargeRegistry.dylib',['VM27LWCRPolicy.dylib'],['CoreFoundation']),('modern_xpc_large_private_consumer','VM27LargeConsumer.dylib',['VM27LargeRegistry.dylib','VM27ApprovedCode.dylib','VM27PrivateEndpoint.dylib','VM27LWCRPolicy.dylib'],[]),('modern_xpc_large_original_parent','VM27LargeParent.dylib',['VM27ApprovedCode.dylib'],[])]:
   p=d/lib;f=[v for fw in frameworks for v in ['-framework',fw]];run(role+'-'+stem,base+[str(src/(stem+'.c'))]+[str(d/name) for name in deps]+f+['-dynamiclib','-Wl,-install_name,@rpath/'+lib,'-o',str(p)]);known[lib]=sign(role,p,{},role+'-'+lib);run(role+'-'+lib+'-imports',['xcrun','dyld_info','-imports',str(p)])
  macros=[]
  for key,name in [('LREGISTRY','VM27LargeRegistry.dylib'),('LCONSUMER','VM27LargeConsumer.dylib'),('LPARENT','VM27LargeParent.dylib'),('REGISTRY','VM27BundleRegistry.dylib'),('APPROVED','VM27ApprovedCode.dylib'),('POLICY','VM27LWCRPolicy.dylib'),('ENDPOINT','VM27PrivateEndpoint.dylib')]:
   r=known[name];macros+=['#define VM27_'+key+'_SHA256 "'+r['sha256']+'"','#define VM27_'+key+'_BYTES '+str(r['bytes'])+'ULL','#define VM27_'+key+'_UUID "'+r['UUID']+'"']
  (d/'modern_xpc_large_pins.h').write_text('\n'.join(macros)+'\n');p=d/'large-capacity-data-probe';run(role+'-probe-compile',base+['-I',str(d),str(src/'test-modern-xpc-large-capacity.c')]+[str(d/name) for name in known]+['-Wl,-rpath,@executable_path','-o',str(p)]);r=sign(role,p,RIGHTS if role=='ios' else {},role+'-probe');run(role+'-probe-imports',['xcrun','dyld_info','-imports',str(p)])
  if role=='macos':run('macos-native',[str(p),str(data),dataRow['sha256'],str(dataRow['bytes']),dataRow['CDHash'],dataRow['UUID']])
 result={'candidates':files,'sourceSHA256':{p.name:sha(p) for p in src.iterdir()},'processes':procs,'originalUnsignedSource':{'path':str(ORIGINAL),'bytes':ORIGINAL.stat().st_size,'SHA256':ORIGINAL_SHA},'originalInputUnchanged':sha(ORIGINAL)==ORIGINAL_SHA,'dataFileExecuted':False,'originalVMMExecuted':False,'iOSExecuted':False,'deviceOperations':False,'systemModified':False,'capacityBytes':8388608,'plistCapacityBytes':65536};(out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'output':str(out),'candidateSHA256':sha(out/'candidate.json'),'files':files},indent=2))
if __name__=='__main__':assert len(sys.argv)==2;main(sys.argv[1])
