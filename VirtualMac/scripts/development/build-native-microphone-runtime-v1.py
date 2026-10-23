#!/usr/bin/env python3
"""Runtime159: the native microphone input client's actual permission contract.

Only the owned VMM is re-signed. CPU91, GPU, every provider and all Apple
system files stay unchanged. No device operation occurs in this builder.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,subprocess,tempfile
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('native_audio_signature_primitives',BASE)
base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
pin,save=base.pin,base.save
CHILD='com.apple.Virtualization.VirtualMachine';UUID='4a6a588d1afd30f5a64d6304eb79be0b'
KEY='com.apple.private.tcc.allow'
def need(value,message):
 if not value:raise ValueError(message)
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
 ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 bp=a.baseline_runtime_candidate.resolve();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh Runtime159 directory')
 need(pin(BASE)['sha256']=='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d','frozen signing primitives')
 need(pin(bp)['sha256']=='d11b919e9b1bd315de26123b232590d628bcb8cfff137a5da006a7319c403a20','exact signed Runtime158')
 old=json.loads(bp.read_bytes());freeze=base.frozen_rows(bp.parent/'freeze.json')
 for row in (pin(bp),old['manifest'],old['signatureVerification']):base.actual_frozen(row,freeze,'baseline actual bytes')
 m=plistlib.loads(pathlib.Path(old['manifest']['path']).read_bytes());rows={r['id']:copy.deepcopy(r)for r in m['files']}
 root=pathlib.Path(old['runtimeRoot']);ev=json.loads(pathlib.Path(old['signatureVerification']['path']).read_bytes())
 need(old['localCodeSigned'] and old['actualProductPreflightPassed'] and ev['allCodePagesAndSpecialSlotsActuallyVerified'],'signed verified baseline')
 proofs={r['relativePath']:r for r in ev['actualSignedFiles']}
 for row in rows.values():
  q=pin(root/row['path']);base.actual_frozen(q,freeze,'baseline file')
  need((q['bytes'],q['sha256'])==(row['bytes'],row['sha256']),'whole baseline bytes')
  if row['kind']=='mach-o':need(proofs[row['path']]['actualSignedFile']==q and proofs[row['path']]['allPrimaryPagesAndSpecialSlotsVerified'],'actual previous signature evidence')
 cid=m['childEntryContract']['childID'];crid='child-coderesources';rel=rows[cid]['path']
 prior=proofs[rel];rights=copy.deepcopy(prior['embeddedEntitlements'])
 need(len(rights)==14 and KEY not in rights,'exact original 14 rights')
 rights[KEY]=['kTCCServiceMicrophone']
 o.mkdir(mode=0o700);runtime=o/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=60)
  (o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr)
  commands.append(dict(label=label,argv=argv,exit=p.returncode));save(o/'commands.json',commands)
  need(p.returncode==0,label+': '+p.stderr.decode(errors='replace')[-2000:])
 for row in rows.values():base.copy_regular(root/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 path=runtime/rel;before=path.read_bytes();image=base.image_profile(before,CHILD)
 need(image.uuid==UUID,'same original VMM')
 ent=o/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(rights,sort_keys=True))
 xpc=path.parent.parent.parent
 with tempfile.TemporaryDirectory(prefix='vm27-native-audio-client-sign-',dir='/private/tmp') as tmp:
  txpc=pathlib.Path(tmp)/xpc.name;txpc.mkdir(mode=0o700)
  for f in xpc.rglob('*'):
   if f.is_file():base.copy_regular(f,txpc/f.relative_to(xpc),executable=bool(f.stat().st_mode&0o111))
  run('sign-owned-child',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc])
  run('verify-owned-child',['codesign','--verify','--strict',txpc])
  for f in (path,runtime/rows[crid]['path']):
   mode=bool(f.stat().st_mode&0o111);f.unlink();base.copy_regular(txpc/f.relative_to(xpc),f,executable=mode)
 after=path.read_bytes();actual=base.image_profile(after,CHILD)
 for k in ('sections','imports','binds','exports','loads','uuid'):need(getattr(image,k)==getattr(actual,k),'VMM '+k+' unchanged')
 for sec in image.sections:
  at,z=sec['fileoff'],sec['size']
  if at and z and sec['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'every VMM backed section unchanged')
 resources=(runtime/rows[crid]['path']).read_bytes()
 sig=base.signature(after,UUID,{1:(runtime/rows['child-info']['path']).read_bytes(),3:resources})
 need(sig['embeddedEntitlements']==rights and len(rights)==15,'exact 14 rights plus native audio tool permission')
 need(sig['signatureFileOffset']==prior['signatureFileOffset'] and sig['codeLimit']==prior['codeLimit'],'same code/signature boundary')
 expected=bytearray(before[:prior['signatureFileOffset']])
 oc=next(c for c in image.commands if c['cmd']==0x1d);nc=next(c for c in actual.commands if c['cmd']==0x1d)
 need(oc['at']==nc['at'],'same signature command')
 expected[oc['at']+12:oc['at']+16]=after[nc['at']+12:nc['at']+16]
 ol=next(c for c in image.commands if c['cmd']==0x19 and c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT')
 nl=next(c for c in actual.commands if c['cmd']==0x19 and c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT')
 need(ol['at']==nl['at'],'same LINKEDIT command')
 for offset in (32,48):expected[ol['at']+offset:ol['at']+offset+8]=after[nl['at']+offset:nl['at']+offset+8]
 need(bytes(expected)==after[:sig['signatureFileOffset']],'all original pre-signature bytes preserved except signature extent')
 cp=pin(path);rows[cid].update(bytes=cp['bytes'],sha256=cp['sha256'],cdhash=sig['cdhash'])
 cr=pin(runtime/rows[crid]['path']);rows[crid].update(bytes=cr['bytes'],sha256=cr['sha256'])
 changed=[k for k in rows if rows[k]!=next(r for r in m['files']if r['id']==k)]
 need(cid in changed and set(changed)<={cid,crid},'only VMM signature and optional resource seal changed')
 for row in rows.values():
  if row['id']not in (cid,crid):need((runtime/row['path']).read_bytes()==(root/row['path']).read_bytes(),'every other runtime file whole')
 m['files']=[rows[r['id']]for r in m['files']]
 manifest=runtime/pathlib.Path(old['manifest']['path']).name;raw=plistlib.dumps(m,fmt=plistlib.FMT_BINARY,sort_keys=True);manifest.write_bytes(raw)
 anchor=o/'vm27_independent_runtime_product_anchor_v1.c'
 anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
 obj=o/'vm27_independent_runtime_product_anchor_v1.ios.o'
 run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios15.0','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=o/'actual-product-preflight.m'
 probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n')
 exe=o/'actual-product-preflight'
 run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe])
 run('run-actual-product-preflight',[exe,runtime])
 inherited=[dict(p,actualSignedFile=pin(runtime/p['relativePath']))for p in proofs.values()if p['relativePath']!=rel]
 sv=o/'signature-verification.json';save(sv,dict(actualSignedFiles=inherited+[dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=cp,**sig)],actualSignedImages=len(proofs),allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 contract=dict(schema='Actual native microphone input permission admission',actualNewEntitlements={KEY:['kTCCServiceMicrophone']},originalEntitlements=prior['embeddedEntitlements'],finalEntitlements=rights,allCPU91ObjectsWhole=True,allGPUAndInputAndOtherProvidersWhole=True,allVMMCodeAndImportsWhole=True,systemFilesChanged=False,nativeGuestExecutionNotClaimed=True)
 save(o/'native-audio-client-contract.json',contract)
 result=copy.deepcopy(old)
 historical={k:result.pop(k)for k in list(result)if k.startswith('actualChanged') or k.startswith('only') or 'Whole'in k or 'Unchanged'in k}
 result.update(schema='Actual Runtime159 native audio client entitlement; CPU91/GIC16 all code whole',runtimeRoot=str(runtime),manifest=pin(manifest),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(sv),builder=pin(__file__),baselineRuntimeCandidate=pin(bp),historicalRuntime158DeltaClaims=historical,nativeAudioClientContract=pin(o/'native-audio-client-contract.json'),actualChangedRuntimeCDHashes=[sig['cdhash']],actualChangedSignedRuntimeFiles=1,codeSigningCommandsActuallyPerformed=1,existingSignedImagesResigned=1,unchangedSignedImagesResigned=0,wholeByteUnchangedSignedImages=len(proofs)-1,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0,allCPU91ObjectsAndProvidersWholeRuntime158=True,allNonVMMImagesWholeRuntime158=True)
 save(o/'candidate.json',result)
 files=[pin(f)for f in o.rglob('*')if f.is_file()]+[pin(__file__),pin(BASE),pin(bp),old['manifest'],old['signatureVerification'],pin(bp.parent/'freeze.json'),pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c')]
 save(o/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),manifest=pin(manifest),child=cp,newChildCDHash=sig['cdhash'],changedRows=changed,entitlements=15,deviceOperations=0)))
if __name__=='__main__':main()
