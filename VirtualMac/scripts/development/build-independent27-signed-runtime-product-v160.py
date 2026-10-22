#!/usr/bin/env python3
"""Runtime150: child-scoped unsupported Bluetooth audio, ordinary audio retained.

Append one dependency within verified zero Mach-O header padding. All original
sections and load ordinals remain intact. Remove Runtime149's failed extra
entitlement, preserving the original fourteen. Local build/sign only.
"""
import argparse,copy,hashlib,importlib.util,json,pathlib,plistlib,struct,subprocess,sys,tempfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('bt_unavailable_signing',BASE);base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
pin,save=base.pin,base.save
CHILD='com.apple.Virtualization.VirtualMachine';UUID='4a6a588d1afd30f5a64d6304eb79be0b';LEAF='VM27BluetoothAudioUnavailableV1.dylib'
def need(v,message):
 if not v:raise ValueError(message)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve()
 need(o.parent==N and not o.exists(),'fresh Runtime150 output')
 bp=N/'independent27-signed-runtime-native-audio-client-v149-attempt1/candidate.json'
 op=N/'independent27-signed-runtime-exit-detail-snapshot-v148-attempt1/candidate.json'
 need(pin(BASE)['sha256']=='1f153b6b4498a4dcacd22fd7bb02f09fe65bcc79649a4842c994fb417ea9248d','signing primitives')
 need(pin(bp)['sha256']=='b2991f130111b655a22228e167211dd602f56044ec916a4760d88f4034330784','actual installed Runtime149')
 need(pin(op)['sha256']=='f94da55ace29038c6eb9c3800064661842fd7af43090506f272490babb487013','original Runtime148')
 old=json.loads(bp.read_bytes());original=json.loads(op.read_bytes());freeze=base.frozen_rows(bp.parent/'freeze.json')
 m=plistlib.loads(pathlib.Path(old['manifest']['path']).read_bytes());rows={r['id']:copy.deepcopy(r)for r in m['files']};root=pathlib.Path(old['runtimeRoot'])
 ev=json.loads(pathlib.Path(old['signatureVerification']['path']).read_bytes());proofs={r['relativePath']:r for r in ev['actualSignedFiles']}
 for row in rows.values():
  p=pin(root/row['path']);base.actual_frozen(p,freeze,'whole baseline');need((p['bytes'],p['sha256'])==(row['bytes'],row['sha256']),'baseline bytes')
  if row['kind']=='mach-o':need(proofs[row['path']]['actualSignedFile']==p and proofs[row['path']]['allPrimaryPagesAndSpecialSlotsVerified'],'baseline signed bytes')
 cid=m['childEntryContract']['childID'];rel=rows[cid]['path'];crid='child-coderesources';crrel=rows[crid]['path']
 oe=json.loads(pathlib.Path(original['signatureVerification']['path']).read_bytes());prior=next(r for r in oe['actualSignedFiles']if r['relativePath']==rel)
 rights=prior['embeddedEntitlements'];need(len(rights)==14 and 'com.apple.bluetooth.internalAudioTool'not in rights,'original14 rights')
 originalpath=pathlib.Path(original['runtimeRoot'])/rel;before=originalpath.read_bytes();need(pin(originalpath)==prior['actualSignedFile'],'whole original VMM')
 image=base.image_profile(before,CHILD);need(image.uuid==UUID,'original UUID')
 end=32+struct.unpack_from('<I',before,20)[0];first=min(s['fileoff']for s in image.sections if s['fileoff'] and s['size'])
 name=('@loader_path/'+LEAF).encode()+b'\0';size=(24+len(name)+7)&~7;command=struct.pack('<6I',12,size,24,0,0,0)+name;command+=b'\0'*(size-len(command))
 need(end+size<=first and not any(before[end:first]),'verified zero header padding, no section moved')
 raw=bytearray(before);raw[end:end+size]=command;struct.pack_into('<II',raw,16,len(image.commands)+1,end-32+size)
 o.mkdir(mode=0o700);runtime=o/'runtime';runtime.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=argv,exit=p.returncode));save(o/'commands.json',commands);need(p.returncode==0,label+': '+p.stderr.decode(errors='replace')[-3000:])
 for row in rows.values():base.copy_regular(root/row['path'],runtime/row['path'],executable=row['kind']=='mach-o')
 child=runtime/rel;child.write_bytes(raw);leaf=child.with_name(LEAF)
 run('compile-bt-audio-unavailable',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-dynamiclib','-O2','-fvisibility=hidden','-Wall','-Wextra','-Werror',S/'vm27_bluetooth_audio_unavailable_v1.c','-Wl,-install_name,@loader_path/'+LEAF,'-o',leaf])
 run('sign-bt-audio-unavailable',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.child.'+LEAF,leaf])
 run('verify-bt-audio-unavailable',['codesign','--verify','--strict',leaf]);run('validate-bt-audio-unavailable',['xcrun','dyld_info','-validate_only',leaf]);leaf.chmod(0o700)
 li=base.image_profile(leaf.read_bytes(),LEAF);ls=base.signature(leaf.read_bytes(),li.uuid)
 need(len(li.loads)==1 and li.loads[0]['path']=='/usr/lib/libSystem.B.dylib','only native libSystem dependency')
 need(any(s['name']=='__interpose' and s['size']==16 for s in li.sections),'actual one interpose pair')
 # Resolve all real imports from the same captured iPadOS native export graph.
 indexpath=N/'current-native-header-export-index-v3/index.json';index=json.loads(indexpath.read_bytes());need(pin(indexpath)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019','primary native index')
 def resolve(path,symbol,seen=()):
  need(path not in seen,'finite native reexport');im=index['images'][path];d=im['definitions'].get(symbol)
  if d:
   if d['flags']&8:
    ordinal=d.get('ordinal',d.get('reexportOrdinal'));target=next(x['path']for x in im['dependencies']if x['ordinal']==ordinal);return[dict(path=path,UUID=im['UUID'],symbol=symbol,definition=d)]+resolve(target,d.get('alias',d.get('name',d.get('importName',symbol)))or symbol,seen+(path,))
   return[dict(path=path,UUID=im['UUID'],symbol=symbol,definition=d,actualCompleteExportSource=im['actualCompleteExportSource'])]
  for dep in im['dependencies']:
   if dep['command']==0x8000001f:
    try:return[dict(path=path,UUID=im['UUID'],symbol=symbol,reexportOrdinal=dep['ordinal'])]+resolve(dep['path'],symbol,seen+(path,))
    except(KeyError,ValueError):pass
  raise ValueError('unresolved actual native symbol '+symbol)
 native=[dict(actualImport=r,requiredLoad=li.loads[r['ordinal']-1]['path'],actualRoute=resolve(li.loads[r['ordinal']-1]['path'],r['name']))for r in li.imports if not r['weak']]
 ent=o/'child.entitlements.plist';ent.write_bytes(plistlib.dumps(rights,sort_keys=True));xpc=child.parent.parent.parent
 with tempfile.TemporaryDirectory(prefix='vm27-bt-audio-unavailable-sign-',dir='/private/tmp')as tmp:
  txpc=pathlib.Path(tmp)/xpc.name;txpc.mkdir(mode=0o700)
  for f in xpc.rglob('*'):
   if f.is_file():base.copy_regular(f,txpc/f.relative_to(xpc),executable=bool(f.stat().st_mode&0o111))
  run('sign-owned-child',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',CHILD,'--entitlements',ent,'--generate-entitlement-der',txpc]);run('verify-owned-child',['codesign','--verify','--strict',txpc])
  for f in (child,runtime/crrel):
   mode=bool(f.stat().st_mode&0o111);f.unlink();base.copy_regular(txpc/f.relative_to(xpc),f,executable=mode)
 after=child.read_bytes();actual=base.image_profile(after,CHILD)
 for key in ('sections','imports','binds','exports','uuid'):need(getattr(actual,key)==getattr(image,key),'all original '+key+' unchanged')
 need(actual.loads[:-1]==image.loads and actual.loads[-1]['path']=='@loader_path/'+LEAF,'all original load ordinals plus one child-only dependency')
 for section in image.sections:
  at,z=section['fileoff'],section['size']
  if at and z and section['flags']&255 not in(1,12,18):need(before[at:at+z]==after[at:at+z],'all backed VMM sections whole')
 sig=base.signature(after,UUID,{1:(runtime/rows['child-info']['path']).read_bytes(),3:(runtime/crrel).read_bytes()});need(sig['embeddedEntitlements']==rights,'exact original14 rights restored')
 need(sig['signatureFileOffset']==prior['signatureFileOffset']and sig['codeLimit']==prior['codeLimit'],'same signature/code boundary')
 expected=bytearray(raw[:prior['signatureFileOffset']])
 sc=next(c for c in image.commands if c['cmd']==0x1d);expected[sc['at']+12:sc['at']+16]=after[sc['at']+12:sc['at']+16]
 lc=next(c for c in image.commands if c['cmd']==0x19 and c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT')
 for off in(32,48):expected[lc['at']+off:lc['at']+off+8]=after[lc['at']+off:lc['at']+off+8]
 need(bytes(expected)==after[:sig['signatureFileOffset']],'only appended load header and signature extent changed before signature')
 cp=pin(child);rows[cid].update(bytes=cp['bytes'],sha256=cp['sha256'],cdhash=sig['cdhash']);cr=pin(runtime/crrel);rows[crid].update(bytes=cr['bytes'],sha256=cr['sha256'])
 lp=pin(leaf);lid='child:'+LEAF;leafrel=str(leaf.relative_to(runtime));rows[lid]=dict(id=lid,path=leafrel,kind='mach-o',role='dependency',bytes=lp['bytes'],sha256=lp['sha256'],uuid=ls['uuid'],cdhash=ls['cdhash'])
 gid=m['dependencyProofID'];gp=runtime/rows[gid]['path'];graph=dict(schema='Runtime150 actual child Bluetooth endpoint admission',baselineRuntimeCandidate=pin(bp),baselineDependencyProof=pin(root/rows[gid]['path']),finalStrongDefinitionGraphClosed=True,unresolvedStrongImportRows=[],allOriginalVMMImportsAndLoadOrdinalsWhole=True,appendedChildLoad=actual.loads[-1],actualNewSignedLeaf=lp,actualNewStrongNativeImportRoutes=native,actualNativeIndex=pin(indexpath),systemFilesChanged=False);save(gp,graph);gpin=pin(gp);rows[gid].update(bytes=gpin['bytes'],sha256=gpin['sha256'])
 m['files']=[rows[r['id']]for r in m['files']]+[rows[lid]];manifest=runtime/pathlib.Path(old['manifest']['path']).name;data=plistlib.dumps(m,fmt=plistlib.FMT_BINARY,sort_keys=True);manifest.write_bytes(data)
 anchor=o/'vm27_independent_runtime_product_anchor_v1.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in hashlib.sha256(data).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(data))+';\n');obj=o/'vm27_independent_runtime_product_anchor_v1.ios.o'
 run('compile-anchor',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror','-c',anchor,'-o',obj])
 probe=o/'actual-product-preflight.m';probe.write_bytes((bp.parent/'actual-product-preflight.m').read_bytes());exe=o/'actual-product-preflight'
 run('compile-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe]);run('run-preflight',[exe,runtime])
 for identity,row in rows.items():
  if identity not in(cid,crid,gid,lid):need((runtime/row['path']).read_bytes()==(root/row['path']).read_bytes(),'all unrelated runtime files whole')
 inherited=[dict(p,actualSignedFile=pin(runtime/p['relativePath']))for p in proofs.values()if p['relativePath']!=rel];sv=o/'signature-verification.json';save(sv,dict(actualSignedFiles=inherited+[dict(role='child',key=CHILD,relativePath=rel,actualSignedFile=cp,**sig),dict(role='child',key=LEAF,relativePath=leafrel,actualSignedFile=lp,**ls)],actualSignedImages=len(proofs)+1,allCodeDirectoriesPrimarySHA256=True,allCodePagesAndSpecialSlotsActuallyVerified=True,inheritedSignatureProof=old['signatureVerification'],actualIOSImagesExecuted=False,deviceOperations=0))
 contract=dict(schema='Owned VMM Bluetooth HAL explicitly unavailable v1',source=pin(S/'vm27_bluetooth_audio_unavailable_v1.c'),actualNativePluginUUID='c3698098e6ca374a94ec504ae04c934b',actualNativeReturnRVA=0x367a8,exactService='com.apple.BTAudioHALPlugin.xpc',unsupportedResult='NULL/ENOTSUP; actual plugin existing failure branch',original14EntitlementsRestored=True,noSystemBluetoothOrIdentityChanges=True,nativeSpeakerPathUnchanged=True,allCPU91AndGPUAndInputCodeWhole=True,actualAudioPlaybackNotYetVerified=True);save(o/'bluetooth-audio-unavailable-contract.json',contract)
 result=copy.deepcopy(old);result.update(schema='Actual Runtime150 Bluetooth HAL unavailable only in owned child',runtimeRoot=str(runtime),manifest=pin(manifest),anchorSource=pin(anchor),anchorIOSObject=pin(obj),signatureVerification=pin(sv),builder=pin(__file__),baselineRuntimeCandidate=pin(bp),bluetoothAudioUnavailableContract=pin(o/'bluetooth-audio-unavailable-contract.json'),actualChangedRuntimeCDHashes=[sig['cdhash'],ls['cdhash']],actualChangedSignedRuntimeFiles=2,codeSigningCommandsActuallyPerformed=2,existingSignedImagesResigned=1,unchangedSignedImagesResigned=0,wholeByteUnchangedSignedImages=len(proofs)-1,actualProductPreflightPassed=True,actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False,deviceOperations=0,trustCacheOperations=0)
 result['historicalFailedRuntime149NativeAudioClientContract']=result.pop('nativeAudioClientContract');save(o/'candidate.json',result)
 files=[pin(f)for f in o.rglob('*')if f.is_file()]+[pin(__file__),pin(BASE),pin(bp),pin(op),pin(originalpath),pin(indexpath),pin(S/'vm27_bluetooth_audio_unavailable_v1.c'),pin(S/'vm27_independent_app_runtime_v4.m'),pin(S/'vm27_actual_executable_image_v1.c')];save(o/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),manifest=pin(manifest),newHashes=result['actualChangedRuntimeCDHashes'],originalRights=14,deviceOperations=0)))
if __name__=='__main__':main()
