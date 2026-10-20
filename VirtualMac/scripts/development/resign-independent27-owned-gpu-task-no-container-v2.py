#!/usr/bin/env python3
"""Root-only signature delta: native GPUTask adds genuine no-container only.

No compilation, source port, import re-resolution, fixture or device operation.
The prior actual five-unit compile/link and186-import proof remain historical.
"""
import argparse, copy, importlib.util, json, pathlib, plistlib, struct, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('gpu_signature_delta_primitives',BASE)
base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
pin,need,save,M=base.pin,base.need,base.save,base.m.MachO
OLD=N/'owned-gpu-task-server-source-port-v1-attempt3/candidate.json'
OLD_SHA='59fcae4500db3ffbc7caee331292593e637e1b6dd8296e50a946f707fdf546a9'
KEY='com.apple.private.security.no-container'
PRODUCT_KEYS=('task','compat','taskInfo','outerBundleInfo','taskCodeResources','defaultMetallib')

def exact(row):
 need(pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')},'exact actual input '+row['path'])
 return pathlib.Path(row['path'])

def semantics(rows):
 return [{k:v for k,v in r.items()if k not in('at','index')}for r in rows]

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--baseline-gpu-candidate',type=pathlib.Path,default=OLD)
 ap.add_argument('--output',type=pathlib.Path,required=True)
 a=ap.parse_args();prior=a.baseline_gpu_candidate.resolve();out=a.output.resolve()
 need(prior==OLD.resolve()and pin(prior)['sha256']==OLD_SHA,'actual compiled/signed GPU product attempt3 only')
 need(out.parent==N and not out.exists(),'fresh Root-only signature output')
 old=json.loads(prior.read_bytes());oldfreeze=json.loads((prior.parent/'freeze.json').read_bytes())
 need(old['schema']=='NativeGPUTaskOwnedEntryProductV1'and old['actualIOSCompileStrictLinkDyldAndSigningPassed']is True,
      'actual historical native compile/link/validation/signature product')
 for key in PRODUCT_KEYS+('sourcePlan','actualImportClosure'):exact(old[key])
 closure=json.loads(exact(old['actualImportClosure']).read_bytes())
 need(closure['unresolved']==[]and len(old['signedFiles'])==2,'actual closed historical186+shim import proof')
 oldroot=pathlib.Path(old['runtimeRoot']);oldsigs={s['actualSignedFile']['path']:s for s in old['signedFiles']}
 oldtask=oldsigs[old['task']['path']];ent=copy.deepcopy(oldtask['embeddedEntitlements'])
 need(len(ent)==6 and KEY not in ent and ent.get('com.apple.private.security.no-sandbox')is True and
      ent.get('com.apple.private.virtualization.plugin')is True,'actual six original GPU entitlements')
 need(not any('hypervisor'in k or k in('com.apple.private.virtualization','com.apple.security.virtualization')for k in ent),
      'no CPU/HV entitlement in original GPU role')
 ent[KEY]=True
 out.mkdir(mode=0o700);root=out/'gpu-task-flat';products={}
 for key in PRODUCT_KEYS:
  source=exact(old[key]);target=root/source.relative_to(oldroot)
  base.copy_regular(source,target,executable=key in('task','compat'));products[key]=target
 task=products['task'];compat=products['compat'];before=task.read_bytes();im=M(before)
 need(im.uuid==oldtask['uuid'],'same exact native Task UUID')
 # Observe actual copied pre-signing bytes, transfer only already-proven import semantics.
 transferred=copy.deepcopy(closure);transferred['historicalClosure']=old['actualImportClosure']
 transferred['allDefinitionSemanticsInheritedWithoutReresolution']=True
 transferred['actualCopiedPreSigningImages']=[pin(task),pin(compat)]
 for key in('task','compat'):
  path=products[key];image=M(path.read_bytes())
  selected=[r for r in transferred['rows']if r['image']['path']==old[key]['path']]
  need(semantics([r['actualImport']for r in selected])==semantics(image.imports),
       'every actual copied image import matches prior closed semantics')
  for row in selected:
   row['historicalPreSigningImage']=row['image'];row['image']=pin(path)
   row['definitionSemanticsInheritedFromActualHistoricalClosure']=True
 save(out/'actual-import-closure.json',transferred)
 entpath=out/'gpu-no-container.entitlements.plist';entpath.write_bytes(plistlib.dumps(ent,sort_keys=True))
 commands=[]
 def run(label,argv):
  argv=list(map(str,argv));r=subprocess.run(argv,capture_output=True,timeout=90)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,argv=argv,exit=r.returncode));save(out/'commands.json',commands)
  need(r.returncode==0,label+': '+r.stderr.decode(errors='replace')[-4000:])
 xpc=task.parent.parent.parent
 # Sign the freshly generated copy in /private/tmp, where File Provider does not attach FinderInfo.
 import tempfile
 with tempfile.TemporaryDirectory(prefix='vm27-gpu-no-container-sign-',dir='/private/tmp') as temporary:
  txpc=pathlib.Path(temporary)/xpc.name;txpc.mkdir(mode=0o700)
  for source in xpc.rglob('*'):
   if source.is_file():base.copy_regular(source,txpc/source.relative_to(xpc),executable=bool(source.stat().st_mode&0o111))
  run('sign-task-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256',
      '--identifier','com.apple.gpusw.ParavirtualizedGraphicsGPUTask','--entitlements',entpath,'--generate-entitlement-der',txpc])
  run('verify-task-xpc',['codesign','--verify','--strict',txpc])
  for destination in (task,products['taskCodeResources']):
   executable=bool(destination.stat().st_mode&0o111);destination.unlink()
   base.copy_regular(txpc/destination.relative_to(xpc),destination,executable=executable)
 run('validate-task',['xcrun','dyld_info','-validate_only',task])
 for key in PRODUCT_KEYS[1:]:
  now=pin(products[key]);need((now['bytes'],now['sha256'])==(old[key]['bytes'],old[key]['sha256']),
       'compat plus four resources byte-whole; no nested library re-sign '+key)
 after=task.read_bytes();new=M(after)
 need(new.uuid==im.uuid and new.sections==im.sections and new.imports==im.imports and new.binds==im.binds and
      new.exports==im.exports and new.loads==im.loads,'all native Task code/import/PAC/exports/geometry whole')
 sig=base.signature(after,im.uuid,{1:products['taskInfo'].read_bytes(),3:products['taskCodeResources'].read_bytes()})
 need(sig['embeddedEntitlements']==ent and sig['codeLimit']==oldtask['codeLimit'] and
      sig['signatureFileOffset']==oldtask['signatureFileOffset'],'exact seven entitlements; same original code limit and signature offset')
 # Only CodeDirectory/superblob size and its enclosing LINKEDIT extent may change before the signature.
 expected=bytearray(before[:oldtask['signatureFileOffset']])
 for cmd in(0x1d,0x19):
  ca=next(c for c in im.commands if c['cmd']==cmd and(cmd!=0x19 or c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT'))
  cb=next(c for c in new.commands if c['cmd']==cmd and(cmd!=0x19 or c['raw'][8:24].rstrip(b'\0')==b'__LINKEDIT'))
  need(ca['at']==cb['at'],'same native signing metadata command position')
  for offset,width in([(12,4)]if cmd==0x1d else[(32,8),(48,8)]):
   p=ca['at']+offset;expected[p:p+width]=after[p:p+width]
 need(bytes(expected)==after[:sig['signatureFileOffset']],'every other native pre-signature byte whole')
 signed=[]
 for key in('compat','task'):
  if key=='task':record=dict(actualSignedFile=pin(task),**sig)
  else:
   record=copy.deepcopy(oldsigs[old[key]['path']]);record['actualSignedFile']=pin(products[key])
  signed.append(record)
 result=copy.deepcopy(old)
 result.update(runtimeRoot=str(root),**{key:pin(products[key])for key in PRODUCT_KEYS},signedFiles=signed,
  actualImportClosure=pin(out/'actual-import-closure.json'),baselineCompiledAndSignedGPUProduct=pin(prior),
  baselineGPUFreeze=pin(prior.parent/'freeze.json'),resignBuilder=pin(__file__),actualResignCommands=pin(out/'commands.json'),
  actualIOSCompileStrictLinkDyldAndSigningPassedInheritedFrom=pin(prior),
  historicalCompileAndLinkAndImportResolutionReexecuted=False,actualNewCompileOperations=0,actualNewLinkOperations=0,
  actualImportDefinitionReresolutions=0,actualNewSigningOperations=1,actualNewDyldValidateOnlyPassed=True,
  actualOnlyTaskSignatureChanged=True,actualCompatAndFourResourcesWhole=True,
  actualOriginalSixGPUEntitlementsWhole=True,actualAddedEntitlements={KEY:True},
  actualNewTaskSignatureVerified=True,actualTaskExecuted=False,actualGuestLoadPassed=False,deviceOperations=0)
 save(out/'candidate.json',result)
 files=oldfreeze['files']+[pin(prior),pin(prior.parent/'freeze.json'),pin(__file__),pin(BASE)]
 files +=[pin(p)for p in out.rglob('*')if p.is_file()]
 save(out/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0,
     signatureOnlyDelta=True,newCompilationOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),task=pin(task),compat=pin(compat))))

if __name__=='__main__':main()
