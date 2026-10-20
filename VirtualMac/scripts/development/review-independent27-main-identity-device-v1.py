#!/usr/bin/env python3
"""Finite read-only review of exact eight-file/five-CD deployment packet."""
import argparse,ast,hashlib,importlib.util,io,json,pathlib,plistlib,shlex,struct,subprocess,sys,tarfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host';B=R/'VirtualMac/scripts/development'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();assert o.parent==N and not o.exists();o.mkdir();checks=[];inputs={}
 def check(ok,label):
  checks.append(dict(check=label,passed=bool(ok)))
  if not ok:raise AssertionError(label)
 def freeze(folder):
  f=folder/'freeze.json';inputs[str(f)]=pin(f)
  for row in json.loads(f.read_bytes())['files']:
   check(pin(row['path'])==row,'frozen actual pin '+row['path']);inputs[row['path']]=row
 packet=N/'independent27-main-identity-device-v1-attempt1';prior=N/'independent27-device-bootstrap-recovery-v4-attempt1'
 freeze(packet);c=json.loads((packet/'candidate.json').read_bytes());scope=json.loads((packet/'scope.json').read_bytes());oldscope=json.loads((prior/'scope.json').read_bytes())
 check(pin(packet/'candidate.json')['sha256']=='0cde0e8657e229fb9001be7e9528c051417e1570bbd564209e854fd2273f6cda','exact requested concrete packet candidate')
 check(len(scope['files'])==len(oldscope['files'])==252 and scope['directories']==oldscope['directories'],'same252 final owned files and directory geometry')
 oldrows={x['archivePath']:x for x in oldscope['files']};rows={x['archivePath']:x for x in scope['files']}
 check(rows.keys()==oldrows.keys(),'no additional final product destinations')
 changes=[]
 for name,row in rows.items():
  check(row['devicePath']==oldrows[name]['devicePath'] and row['mode']==oldrows[name]['mode'],'exact old own destination/mode '+name)
  if row['local']['sha256']!=oldrows[name]['local']['sha256']:changes.append(name)
 check(len(changes)==8 and {x['archivePath']for x in scope['deltaFiles']}==set(changes),'actual eight changed files and244 unchanged')
 check(len(scope['newTrustCacheCDHashes'])==5 and sorted(set(scope['trustCacheCDHashes'])-set(oldscope['trustCacheCDHashes']))==scope['newTrustCacheCDHashes'],'exact five fresh CD set difference')
 check(len(scope['trustCacheCDHashes'])==len(set(scope['trustCacheCDHashes']))==140 and len(set(scope['trustCacheCDHashes'])&set(oldscope['trustCacheCDHashes']))==135,'135 unchanged signed identities plus5 new')
 raw=(packet/'products.tar').read_bytes();check(len(raw)==scope['deltaArchiveBytes']==10905600 and hashlib.sha256(raw).hexdigest()==scope['deltaArchiveSHA256'],'exact finite delta archive bytes')
 rebuilt=io.BytesIO()
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive,tarfile.open(fileobj=rebuilt,mode='w:',format=tarfile.USTAR_FORMAT)as fresh:
  members=archive.getmembers();check(len(members)==8 and [m.name for m in members]==['new-'+str(i)for i in range(8)],'exact eight unique ordinary delta members')
  for item,row in zip(members,scope['deltaFiles'],strict=True):
   check(item.type==tarfile.REGTYPE and not item.linkname and not item.pax_headers and item.mode==0o600 and item.uid==item.gid==item.mtime==0 and item.size==row['new']['bytes'],'canonical ordinary USTAR shape '+item.name)
   data=archive.extractfile(item).read();check(hashlib.sha256(data).hexdigest()==row['new']['sha256'],'true selected new member bytes '+item.name)
   copy=tarfile.TarInfo(item.name);copy.mode=0o600;copy.uid=copy.gid=copy.mtime=0;copy.size=len(data);fresh.addfile(copy,io.BytesIO(data))
 check(rebuilt.getvalue()==raw,'no hidden tar data or extension padding')
 current=module('main_delta_controller_peer',packet/'control.py');previous=module('frozen_recovery_controller_peer',prior/'control.py')
 check(current.PROCESS_FUNCTIONS==previous.PROCESS_FUNCTIONS,'PID UID path PPID lstart cleanup exact inherited bytes')
 trees=[ast.parse((p/'control.py').read_text())for p in [packet,prior]]
 functions=lambda t:{x.name:ast.dump(x,include_attributes=False)for x in t.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
 for name in ['run_remote','prior_receipt']:
  check(functions(trees[0])[name]==functions(trees[1])[name],'exact inherited bounded transport/receipt function '+name)
 text=(packet/'control.py').read_text();gate=next(x for x in trees[0].body if isinstance(x,ast.FunctionDef)and x.name=='ready_gate');gateText=ast.get_source_segment(text,gate)
 for required in ["auth.get('authorized') is True","auth.get('humanUserAuthorization') is True","auth['scope'] == pin(packet/'scope.json')","auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']","auth['trustCacheRegistrationCount'] == 5","auth['initializationExternalWallSeconds'] == 45","review.get('controllerPacketCandidate') == pin(packet/'candidate.json')"]:
  check(required in gateText,'concrete new human/review exact gate '+required)
 check("previous = {'stage': 'preflight', 'verify': 'stage', 'trust': 'verify', 'launch': 'trust', 'post': 'launch'}" in text,'exact serial predecessor map; post accepts failed launch receipt')
 for marker in ["need(not output.exists(), 'serial action never repeated')","os.O_WRONLY|os.O_CREAT|os.O_EXCL","success=args.action != 'post'","data = (packet/'products.tar').read_bytes() if args.action == 'stage' else b''"]:
  check(marker in text,'once-only dispatch/action data '+marker)
 scripts={name:(packet/(name+'.sh')).read_text()for name in c['scripts']}
 for action,script in scripts.items():
  parsed=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);check(parsed.returncode==0,'real shell syntax '+action)
  check(script.count('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 ')==1,'actual external45 plus3 kill grace '+action)
  command=('sudo -k -S -p "" 'if action!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(script)
  check(len(command.encode())==c['quotedCommandBytes'][action] and len(command.encode())+10000<262144,'actual quoted ARG_MAX reserve '+action)
 stage=scripts['stage'];firstmove=stage.index('mv -f ')
 for row in scope['deltaFiles']:
  i=row['index'];path=shlex.quote(row['devicePath']);pending=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-main-identity-v1-'+str(i)+'.pending')))
  check(stage.index('cp -p '+path+' "$OWN_STAGE/backup-'+str(i)+'"')<firstmove,'all old exact backups precede first replacement '+str(i))
  check(stage.index(row['old']['sha256'])<firstmove and stage.index(row['new']['sha256'])<firstmove,'old and staged new SHA verified before mutation '+str(i))
  check('mv -f '+pending+' '+path in stage and 'check_own_file '+pending+' '+row['new']['sha256'] in stage,'same-parent pending atomic replacement exact identity '+str(i))
 check(stage.index('cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"')<firstmove and '80a2d77b0daa3fcd615e7ce62a482bcc311efb9e52a3464d8f93cc3a706413cb' in stage,'complete original671B log SHA backup before replacement')
 check('chown 0:0 "$OWN_STAGE"' in stage and '0:0:700' in stage and '[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]' in stage,'only absent own root0:0:700 stage created')
 trust=scripts['trust'];marker=trust.index(': > "$OWN_STAGE/trust-dispatched"');firsttrust=trust.index('jbctl trustcache add ')
 check(marker<firsttrust and trust.count('jbctl trustcache add ')==5,'five additions only after exclusive own once marker')
 for cd in scope['newTrustCacheCDHashes']:check(trust.count('jbctl trustcache add '+cd+'\n')==1,'single literal authorized add '+cd)
 fast=module('main_delta_fast_peer',B/'independent27_device_product_verify_fast_v1.py')
 for action in ['verify','trust','register','post']:
  check(fast.batch_check(scope)in shlex.split(scripts[action])[-1],'true all252 SHA/meta before action '+action)
 check(fast.cd_check(scope,scope['newTrustCacheCDHashes'])in shlex.split(trust)[-1],'all five true ldid CD checks before trust')
 originalBase=module('main_delta_original_bootstrap_peer',N/'independent27-device-bootstrap-controller-v3-attempt1/control.py')
 originalBase.DEVICE_STAGE=scope['deviceStage']
 original=originalBase.make_scripts(scope,previous.HEALTH.read_text());slow=previous.verify_products(scope);inside=lambda t:t.replace("'","'\"'\"'")
 check(scripts['launch']==original['launch'].replace(inside(slow),inside(fast.batch_check(scope)),1),'launch only verification span changes; full ownership cleanup identical')
 app=json.loads(pathlib.Path(c['appCandidate']['path']).read_bytes());runtime=json.loads(pathlib.Path(c['runtimeCandidate']['path']).read_bytes())
 linked=json.loads(pathlib.Path(app['sourceCandidate']['path']).read_bytes());paths={x['path']for x in linked['sourceFiles']}
 check(str(S/'vm27_independent_app_runtime_v4.m')in paths and str(S/'vm27_actual_executable_image_v1.c')in paths and str(S/'vm27_independent_app_runtime_v3.m')not in paths,'real Runtime4 and hidden helper whole-linked once without Runtime3')
 check(runtime['anchorSource'] in linked['sourceFiles'] and app['realCompiledManifestAnchor']==runtime['anchorSource'],'exact actual fresh product anchor strong source input')
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';m=module('main_delta_macho_peer',reader)
 data=pathlib.Path(app['binary']['path']).read_bytes();im=m.MachO(data);before=m.MachO(pathlib.Path(linked['binary']['path']).read_bytes())
 digestAt=im.file(im.base+im.exports['_VM27IndependentRuntimeManifestSHA256V1']['address']);sizeAt=im.file(im.base+im.exports['_VM27IndependentRuntimeManifestBytesV1']['address'])
 manifestBytes=pathlib.Path(runtime['manifest']['path']).read_bytes()
 check(data[digestAt:digestAt+32]==hashlib.sha256(manifestBytes).digest() and struct.unpack_from('<Q',data,sizeAt)[0]==len(manifestBytes)==42432,'actual signed main contains cf0226 manifest digest and42432 byte anchor')
 check(im.uuid==before.uuid and im.sections==before.sections and im.imports==before.imports and im.exports==before.exports and im.binds==before.binds,'App signing retains true identity/imports/sections/PAC bindwords')
 for sec in before.sections:
  p,z=sec['fileoff'],sec['size']
  if p and z and sec['flags']&255 not in [1,12,18]:check(before.data[p:p+z]==data[p:p+z],'signed App source section unchanged '+sec['name'])
 signatures=module('main_delta_signature_peer',B/'review-independent27-signed-runtime-product-v1.py')
 appRoot=pathlib.Path(app['app']);sig=signatures.signed_image(pathlib.Path(app['binary']['path']),app['actualSignature'],{1:(appRoot/'Info.plist').read_bytes(),3:(appRoot/'_CodeSignature/CodeResources').read_bytes()})
 check(sig['cdhash']=='591cd1f0285d7557e66dd3ada29eec68c5d8e8d3' and sig['embeddedEntitlements']==plistlib.loads((S/'VirtualMac.entitlements').read_bytes()),'actual new App primary pages Info/CodeResources slots and genuine XML/DER rights')
 check(len(data)==870288 and len(data)<=2*1024*1024,'actual signed App within unchanged self inspection limit')
 post=json.loads(pathlib.Path(c['priorActualPost']['path']).read_bytes());check(post['transportExit']==0,'actual previous device post completed successfully')
 report=dict(schema='Actual main identity eight-file delta deployment independent finite review v1',controllerPacketCandidate=pin(packet/'candidate.json'),
  finiteLocalScopePassed=True,findings=[],checks=checks,checkCount=len(checks),actualChangedFiles=8,actualUnchangedFiles=244,
  actualNewTrustEntries=scope['newTrustCacheCDHashes'],actualUnchangedSignedImages=135,actualSignedAppPrimarySignature=sig,
  maximumQuotedCommandBytes=c['maximumQuotedCommandBytes'],externalWallSeconds=45,killGraceSeconds=3,SSHTimeoutSeconds=55,
  sourceModelsRepeated=False,deviceOperations=0,nativeVMOperations=0,actualGuestBoot=False,
  inheritedMetadataBoundary='trustCacheFixedBatchCounts retains original full140 history; current trust script and fresh human gate add only the literal five new hashes.',
  scope=['Backup+per-file atomic replacement is reversible with retained exact old files; the eight-file update is not a transaction and partial failure must never be blindly retried.',
   'New five hashes require real human approval pinned to this scope; this review creates no authorization.',
   'True guest start, display and network remain unexecuted by this review.'])
 save(o/'review.json',report)
 allpins=[pin(p)for p in o.rglob('*')if p.is_file()]+list(inputs.values())+[pin(__file__),pin(reader),pin(B/'review-independent27-signed-runtime-product-v1.py'),pin(app['sourceCandidate']['path']),pin(runtime['anchorSource']['path'])]
 save(o/'freeze.json',dict(files=list({x['path']:x for x in allpins}.values())))
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[],checks=len(checks))))
if __name__=='__main__':main()
