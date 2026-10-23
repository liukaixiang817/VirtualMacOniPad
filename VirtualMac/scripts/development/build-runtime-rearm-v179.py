#!/usr/bin/env python3
"""Runtime179: authenticated parent epoch retirement; unchanged guest device state."""
import copy,hashlib,importlib.util,json,plistlib,shutil,struct,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'independent27-signed-runtime-rearm-v179-attempt1'
spec=importlib.util.spec_from_file_location('primitives',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);pin=b.pin

def main():
 O.mkdir(mode=0o700);commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
  (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr)
  commands.append(dict(label=label,argv=args,exit=p.returncode));b.save(O/'commands.json',commands)
  if p.returncode:raise RuntimeError(label+': '+p.stderr.decode())
  return p.stdout
 oldpath=N/'independent27-signed-runtime-cross-wake-v176-attempt1/candidate.json';old=json.loads(oldpath.read_bytes())
 original=Path(old['runtimeRoot']);runtime=O/'runtime';m=plistlib.loads(Path(old['manifest']['path']).read_bytes());rows={x['id']:x for x in m['files']};previous=copy.deepcopy(rows)
 proofs={x['relativePath']:x for x in json.loads(Path(old['signatureVerification']['path']).read_bytes())['actualSignedFiles']}
 for row in rows.values():
  record=pin(original/row['path']);assert (record['bytes'],record['sha256'])==(row['bytes'],row['sha256'])
  b.copy_regular(original/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-std=c11','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fptrauth-abi-version=0','-I',S]
 def lib(name):return original/rows['parent:'+name]['path']
 transport=O/'VM27OriginalV10Transport.dylib';startup=O/'VM27OwnedAppStartupV3.dylib'
 run('transport',flags+['-dynamiclib',S/'modern_xpc_original_instance_transport_v11_lifecycle.c']+[lib(x) for x in ['VM27LargeConsumerV2.dylib','VM27ApprovedCode.dylib','VM27ClientRegistration.dylib','VM27BundleParentV1.dylib']]+['-framework','Security','-framework','CoreFoundation','-Wl,-install_name,@rpath/VM27OriginalV10Transport.dylib','-Wl,-rpath,@loader_path','-Wl,-current_version,1.0','-Wl,-compatibility_version,1.0','-Wl,-no_adhoc_codesign','-o',transport])
 p=json.loads((N/'owned-bundle-approved-startup-provider-v6-attempt3/candidate.json').read_bytes())
 identity=next(x for x in p['actualReusedObjects'] if Path(x['path']).name=='vm27_owned_app_parent_identity_v1.o');assert pin(identity['path'])==identity
 run('startup',flags+['-dynamiclib',S/'vm27_owned_app_child_startup_v7_rearm.c',identity['path'],lib('VM27LargeConsumerV2.dylib'),lib('VM27OwnedStartupV3.dylib'),lib('VM27LargeRegistry.dylib'),lib('VM27PrivateEndpoint.dylib'),transport,lib('VM27LWCRPolicy.dylib'),'-framework','CoreFoundation','-framework','Security','-Wl,-install_name,@loader_path/VM27OwnedAppStartupV3.dylib','-Wl,-rpath,@loader_path','-Wl,-no_adhoc_codesign','-o',startup])
 replaced={}
 for role in ['parent','child']:
  for name,source in [('VM27OriginalV10Transport.dylib',transport),('VM27OwnedAppStartupV3.dylib',startup)]:
   identity=role+':'+name;target=runtime/rows[identity]['path'];target.unlink();b.copy_regular(source,target);replaced[identity]=pin(source)
 # Only parent VZ's real public event setter is routed through the existing XF reexport.
 vzid='parent:VZ27.dylib';vz=runtime/rows[vzid]['path'];raw=bytearray(vz.read_bytes());im=b.image_profile(raw,'VZ');imp=im.imports[761]
 assert imp==dict(index=761,ordinal=19,weak=0,name='_xpc_connection_set_event_handler',at=4251720,addend=0)
 assert im.loads[28]['path']=='@loader_path/XF' and im.loads[18]['path']=='/usr/lib/libSystem.B.dylib'
 assert raw[imp['at']]==19;raw[imp['at']]=29;vz.write_bytes(raw);replaced[vzid]=pin(vz)
 changed_imports=[]
 for identity in replaced:
  oldim=b.image_profile((original/rows[identity]['path']).read_bytes(),identity);newim=b.image_profile((runtime/rows[identity]['path']).read_bytes(),identity)
  if identity==vzid:
   assert newim.uuid==oldim.uuid and newim.exports==oldim.exports and newim.loads==oldim.loads
   assert [x for x,y in zip(newim.imports,oldim.imports) if x!=y]==[dict(imp,ordinal=29)]
   for section in oldim.sections:
    at,size=section['fileoff'],section['size']
    if at and size and section['flags']&255 not in (1,12,18):assert raw[at:at+size]==oldim.data[at:at+size]
  else:
   additions={'_VM27OriginalClientRetireAfterExitV1','_VM27OriginalClientCopyLifecycleV1','_xpc_connection_set_event_handler'} if 'Transport' in identity else {'_VM27OwnedAppParentRetireAfterExitV1'}
   assert set(newim.exports)==set(oldim.exports)|additions
   def semantic(im):return {(im.loads[x['ordinal']-1]['path'] if x['ordinal']>0 else x['ordinal'],x['name'],x['weak'],x['addend']) for x in im.imports}
   changes=semantic(newim)-semantic(oldim)
   changed_imports.append(dict(id=identity,added=sorted(changes,key=str)))
  if identity.startswith('parent:'):
   run('sign-'+identity.replace(':','-'),['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.parent.'+(runtime/rows[identity]['path']).name,runtime/rows[identity]['path']])
 # Child image body and device providers are unchanged. Bundle resources need resealing.
 childid=m['childEntryContract']['childID'];child=runtime/rows[childid]['path'];xpc=child.parent.parent.parent
 entitlements=proofs[rows[childid]['path']]['embeddedEntitlements'];ent=O/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(entitlements))
 with tempfile.TemporaryDirectory(prefix='vm27-rearm-',dir='/private/tmp') as work:
  bundle=Path(work)/xpc.name;shutil.copytree(xpc,bundle);run('xattrs',['xattr','-cr',bundle])
  for identity in replaced:
   if identity.startswith('child:'):
    path=bundle/(runtime/rows[identity]['path']).relative_to(xpc)
    run('sign-'+identity.replace(':','-'),['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.child.'+path.name,path])
  run('sign-child',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','com.apple.Virtualization.VirtualMachine','--entitlements',ent,'--generate-entitlement-der',bundle]);run('verify-child',['codesign','--verify','--strict',bundle])
  for target in [child,runtime/rows['child-coderesources']['path']]+[runtime/rows[x]['path'] for x in replaced if x.startswith('child:')]:shutil.copyfile(bundle/target.relative_to(xpc),target)
 before=b.image_profile((original/rows[childid]['path']).read_bytes(),'oldVMM');after=b.image_profile(child.read_bytes(),'VMM')
 assert before.uuid==after.uuid and before.imports==after.imports and before.exports==after.exports and before.loads==after.loads
 for sec in before.sections:
  at,size=sec['fileoff'],sec['size']
  if at and size and sec['flags']&255 not in (1,12,18):assert before.data[at:at+size]==after.data[at:at+size]
 # Check added strong imports against actual role libraries or the captured native graph.
 nativepath=N/'current-native-header-export-index-v3/index.json';native=json.loads(nativepath.read_bytes())['images']
 images={row['id']:b.image_profile((runtime/row['path']).read_bytes(),row['id']) for row in rows.values() if row['kind']=='mach-o'}
 def resolve(name,image,role,seen):
  key=(str(image),name)
  if key in seen:return False
  seen=seen|{key}
  if isinstance(image,str):
   if image not in native:return False
   node=native[image];exports=node['definitions'];deps=node['dependencies']
   if name in exports:return True
   return any(d['command']==0x8000001f and resolve(name,d['path'],role,seen) for d in deps)
  if name in image.exports:return True
  return any(d['cmd']==0x8000001f and resolve(name,depimage(d['path'],role),role,seen) for d in image.loads)
 def depimage(path,role):
  if path.startswith(('@loader_path/','@rpath/')):return images[role+':'+path.rsplit('/',1)[-1]]
  return path
 for change in changed_imports:
  role=change['id'].split(':')[0]
  for path,name,weak,addend in change['added']:
   assert weak or (isinstance(path,str) and resolve(name,depimage(path,role),role,set())),(path,name)
 # New parent-only retirement entry is authenticated by UUID and export RVA.
 m['entries'].append(dict(fileID='parent:VM27OwnedAppStartupV3.dylib',symbol='VM27OwnedAppParentRetireAfterExitV1',rva=0))
 signed=[]
 for row in rows.values():
  path=runtime/row['path']
  if row['kind']=='mach-o':
   im=images[row['id']];external={int(k):(runtime/rows[v]['path']).read_bytes() for k,v in row.get('signatureSlots',{}).items()};proof=b.signature(path.read_bytes(),im.uuid,external)
   row.update(uuid=proof['uuid'],cdhash=proof['cdhash']);signed.append(dict(role=proofs[row['path']].get('role',row['id'].split(':')[0]),key=proofs[row['path']].get('key',path.name),relativePath=row['path'],actualSignedFile=pin(path),**proof))
  actual=pin(path);row.update(bytes=actual['bytes'],sha256=actual['sha256'])
 for e in m['entries']:
  if e['fileID'] in replaced:e['rva']=images[e['fileID']].exports['_'+e['symbol']]['address']
 contract=m['childEntryContract']
 if contract['providerID'] in replaced:contract['providerEntryRVA']=images[contract['providerID']].exports['_'+contract['symbol']]['address']
 graphid=m['dependencyProofID'];b.save(runtime/rows[graphid]['path'],dict(schema='Runtime179 lifecycle import delta proof',baselineCandidate=pin(oldpath),baselineProof=pin(original/rows[graphid]['path']),nativeIndex=pin(nativepath),changedStrongImports=changed_imports,finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],serializedGuestStateBodiesUnchanged=True,newDeviceGuestAcceptancePending=True))
 actual=pin(runtime/rows[graphid]['path']);rows[graphid].update(bytes=actual['bytes'],sha256=actual['sha256'])
 allowed=set(replaced)|{childid,'child-coderesources',graphid}
 for identity,row in rows.items():
  if identity not in allowed:assert row==previous[identity],identity
 # Exact directional save compatibility, based on unchanged VMM sections and whole CPU/GPU/device files.
 manifestpath=runtime/'VM27IndependentRuntimeManifestV1.plist';manifestpath.write_bytes(plistlib.dumps(m,fmt=plistlib.FMT_BINARY,sort_keys=True))
 audit=dict(schema='Runtime176 to179 exact saved-state compatibility audit',savedManifest=old['manifest'],currentManifest=pin(manifestpath),oldRuntimeSHA256=old['manifest']['sha256'],newRuntimeSHA256=pin(manifestpath)['sha256'],changedFileIDs=sorted(allowed),unchangedVMMSections=True,unchangedCPU99GIC19GPU24AndGuestDeviceProviders=True,parentVZOnlyOnePublicEventSetterImport=True,snapshotRestoreExecuted=False)
 b.save(O/'saved-state-compatibility-audit.json',audit)
 anchor=O/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(map(str,hashlib.sha256(manifestpath.read_bytes()).digest()))+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(manifestpath.stat().st_size)+';\n')
 anchorobj=O/'anchor.o';run('anchor',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios15.0','-I',S,'-c',anchor,'-o',anchorobj])
 probe=O/'preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\nint main(int n,char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)NSLog(@"%@",e);return ok?0:1;}}\n')
 exe=O/'preflight';run('compile-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('preflight',[exe,runtime])
 proofpath=O/'signature-verification.json';b.save(proofpath,dict(actualSignedFiles=signed,actualSignedImages=len(signed),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True))
 result=copy.deepcopy(old);result.update(schema='Runtime179 safe exited-parent lifecycle retirement; device acceptance pending',runtimeRoot=str(runtime),manifest=pin(manifestpath),anchorSource=pin(anchor),anchorIOSObject=pin(anchorobj),signatureVerification=pin(proofpath),builder=pin(__file__),baselineRuntimeCandidate=pin(oldpath),actualChangedRuntimeCDHashes=sorted({rows[x]['cdhash'] for x in allowed if rows[x]['kind']=='mach-o'}),actualProductPreflightPassed=True,deviceOperations=0,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,newDeviceGuestBootVerified=False,savedStateCompatibilityAudit=pin(O/'saved-state-compatibility-audit.json'))
 b.save(O/'candidate.json',result);print(json.dumps(dict(candidate=pin(O/'candidate.json'),manifest=pin(manifestpath),changedHashes=result['actualChangedRuntimeCDHashes'])))
if __name__=='__main__':main()
