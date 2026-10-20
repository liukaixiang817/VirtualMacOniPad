#!/usr/bin/env python3
"""Finite HOST review of actual nine-file/six-hash UIKit filter packet."""
import argparse,ast,hashlib,importlib.util,io,json,pathlib,shlex,struct,tarfile,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(r):
 need(pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},'actual pin '+r['path']);return pathlib.Path(r['path'])
def module(p,name):
 sp=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def body(script):
 first=script.index('/var/jb/usr/bin/timeout');at=script.index('/var/jb/bin/sh -c ',first)+len('/var/jb/bin/sh -c ');parts=shlex.split(script[at:]);need(len(parts)==1,'one exact bounded shell body');return parts[0]
def funcs(text):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def const(text,name):
 for n in ast.parse(text).body:
  if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets):return ast.literal_eval(n.value)
 raise ValueError(name)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh peer');d=a.candidate.parent;c=json.loads(a.candidate.read_bytes());sf=d/'freeze.json';f=json.loads(sf.read_bytes())
 for r in f['files']:actual(r)
 scope=json.loads(actual(c['scope']).read_bytes());oldpath=actual(scope['oldScope']);old=json.loads(oldpath.read_bytes());oldfolder=oldpath.parent;post=json.loads(actual(c['currentInstalledProductsPost']).read_bytes());stdout=actual(post['stdout']).read_text();actual(post['stderr']);actual(post['request']);need(post['transportExit']==0 and all(t in stdout for t in ['INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT','INDEPENDENT27_OWN_APP_AND_CHILD_OFF','OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF']),'actual normal failure post0/current installed253/health/off, no invented init result')
 files={r['archivePath']:r for r in scope['files']};oldfiles={r['archivePath']:r for r in old['files']};need(len(files)==len(scope['files'])==255 and len(oldfiles)==253 and set(oldfiles)<=set(files)and scope['directories']==old['directories'],'full255/no deletion/no new directory')
 delta=scope['deltaFiles'];need(len(delta)==9 and len({r['devicePath']for r in delta})==9 and sum(r['old']is not None for r in delta)==7 and sum(r['old']is None for r in delta)==2,'exact nine unique changes, seven replacements/two added own libraries')
 expected=[]
 for name,row in files.items():
  actual(row['local']);prior=oldfiles.get(name)
  if prior is None or prior['local']['sha256']!=row['local']['sha256']:expected.append(name)
  if prior:need(row['devicePath']==prior['devicePath']and row['mode']==prior['mode'],'existing path/mode preserved')
 need(expected==[r['archivePath']for r in delta],'independently derive exact changed set/order from full installed base')
 for i,row in enumerate(delta):
  need(row['index']==i and row['new']==files[row['archivePath']]['local']and row['devicePath']==files[row['archivePath']]['devicePath'],'delta actual output/target joins fullfile inventory')
  if row['old']:need(row['old']==oldfiles[row['archivePath']]['local'],'actual old wholefile retained for backup')
  else:need(row['archivePath'].endswith('/VM27OwnedUIKitMacEventFilter.dylib')and row['mode']==0o700,'only two actual new provider executable files')
 full=sorted(r['cdhash']for r in files.values()if 'cdhash'in r);new=sorted(set(full)-set(old['trustCacheCDHashes']));need(len(full)==len(set(full))==142 and full==scope['trustCacheCDHashes']and new==scope['newTrustCacheCDHashes']and len(new)==scope['trustCacheRegistrationCount']==6 and scope['trustCacheFixedBatchCounts']==[6],'actual exact142unique inventory/new6 set difference only')
 rt=json.loads(actual(c['runtimeCandidate']).read_bytes());app=json.loads(actual(c['appCandidate']).read_bytes());rp=json.loads(actual(c['actualSignedRuntimeIndependentPeer']).read_bytes());apj=json.loads(actual(c['inheritedActualSignedAppPeer']).read_bytes());need(rp['runtimeCandidate']==c['runtimeCandidate']and rp['passed']and rp['findings']==[]and apj['signedCandidate']==c['appCandidate']and apj['runtimeCandidate']==c['runtimeCandidate']and apj['findings']==[],'current Runtime10/App11 independent product peers, not historical Runtime8')
 sig=json.loads(actual(c['inheritedActualSignedRuntimeCDProof']).read_bytes());need(c['inheritedActualSignedRuntimeCDProof']==rt['signatureVerification']and sig['allCodePagesAndSpecialSlotsActuallyVerified']and len(sig['actualSignedFiles'])==141,'actual Runtime10 141 code files/all-page proof')
 for row in sig['actualSignedFiles']:
  local=files['runtime/'+row['relativePath']];need(local['local']==row['actualSignedFile']and local['cdhash']==row['cdhash']and row['allPrimaryPagesAndSpecialSlotsVerified'],'every runtime fullfile joins actual signed CD proof')
 need(files['VirtualMacIndependent27.app/VirtualMacIndependent27']['local']==app['binary']==apj['actualSignature']['file']and files['VirtualMacIndependent27.app/VirtualMacIndependent27']['cdhash']==apj['actualSignature']['cdhash'],'App11 exact main/CD independent proof')
 need(scope['actualRuntimeManifestFiles']==151 and c['actualFullFiles']==255 and c['actualFullCodeDirectoryHashes']==142 and not scope['newOwnDirectories'],'dynamic manifest/file/code counts truthful')
 raw=actual(c['archive']).read_bytes();need(c['archive']==scope['archive']and len(raw)==scope['deltaArchiveBytes']==19015680 and hashlib.sha256(raw).hexdigest()==scope['deltaArchiveSHA256'],'actual nine-file delta archive whole pin')
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w:',format=tarfile.USTAR_FORMAT)as tar:
  for row in delta:
   payload=actual(row['new']).read_bytes();item=tarfile.TarInfo('new-'+str(row['index']));item.uid=item.gid=item.mtime=0;item.mode=0o600;item.size=len(payload);tar.addfile(item,io.BytesIO(payload))
 need(stream.getvalue()==raw,'canonical USTAR wholebytes no extra/PAX/link/hidden payload')
 controller=actual(c['controller']).read_text();oldcontrol=(oldfolder/'control.py').read_text();nf,of=funcs(controller),funcs(oldcontrol);need({k for k in nf if nf[k]!=of[k]}=={'ready_gate','dispatch'},'only exact newready/archive+action dispatch functions differ')
 need(const(controller,'PROCESS_FUNCTIONS')==const(oldcontrol,'PROCESS_FUNCTIONS')and nf['run_remote']==of['run_remote']and nf['prior_receipt']==of['prior_receipt'],'real PIDUIDpathPPIDstart identity/signal/capture/SSH55/prior once guard byte/AST inherited')
 need("previous = {'preflight':'close-current-own','stage':'preflight','verify':'stage','trust':'verify','launch':'trust','post':'launch'}"in controller and "success=args.action != 'post'"in controller and "O_WRONLY|os.O_CREAT|os.O_EXCL"in controller and "need(not output.exists(), 'serial action never repeated')"in controller,'ordered true predecessor receipts/exclusive dispatch once; post can clean failed launch')
 for text0 in ["review.get('controllerPacketCandidate') == pin(packet/'candidate.json')","auth['scope'] == pin(packet/'scope.json')","auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']","continuing.get('necessaryHashesProbesAndOwnedProcessPermissionsAuthorized') is True","continuing.get('preserveIPadOSStability') is True","continuing.get('rootIsSoleDeviceOperator') is True"]:need(text0 in controller,'actual exact peer/continuing human scope gate '+text0)
 auth=json.loads(actual(scope['continuingHumanAuthorization']).read_bytes());need(auth['source']=='Direct human user message in this active conversation'and auth['necessaryHashesProbesAndOwnedProcessPermissionsAuthorized']and auth['preserveIPadOSStability'],'real actual direct human continuing authorization source, no fabricated new grant')
 fast=module(B/'independent27_device_product_verify_fast_v1.py','finite_delta_fast');before,after=fast.batch_check(old),fast.batch_check(scope);scripts={k:actual(r).read_text()for k,r in c['scripts'].items()};stage=body(scripts['stage']);first=min(stage.index('mv -f '),stage.index('mv -n '));need(stage.index('cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"')<first and stage.index('= "$own_log_meta" ]')<first,'real stable log backup before any replacement')
 for row in delta:
  i=row['index'];path=shlex.quote(row['devicePath']);temp=shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-uikit-filter-v1-'+str(i)+'.pending')))
  if row['old']:need(stage.index('cp -p '+path+' "$OWN_STAGE/backup-'+str(i)+'"')<first and ('check_own_file '+path+' '+row['old']['sha256'])in stage,'actual old7 exact SHA/mode backup before first mv')
  else:need(stage.index('backup-new-absent-'+str(i))<first and ('[ ! -e '+path+' ] && [ ! -L '+path+' ]')in stage and ('mv -n '+temp+' '+path)in stage,'actual new2 absence marker/no clobber')
  need(('cp "$OWN_STAGE/new-'+str(i)+'" '+temp)in stage and ('chown 501:501 '+temp)in stage and ('check_own_file '+temp+' '+row['new']['sha256'])in stage,'true same directory pending/actual new SHA/owner before mv')
 need('chown 0:0 "$OWN_STAGE"'in stage and '[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]'in stage and '[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]'in stage,'fresh Root-owned0700 stage never blind delete/reuse')
 verify=body(scripts['verify']);trust=body(scripts['trust']);need(after in verify and after in trust and fast.cd_check(scope,c['actualNativeCDSubset'])in verify and len(c['actualNativeCDSubset'])==3,'all255 fresh wholeSHA/meta+actualthree nativeCDs before only six additions')
 adds=[line.removeprefix('jbctl trustcache add ')for line in trust.splitlines()if line.startswith('jbctl trustcache add ')];need(adds==new and trust.count('jbctl trustcache info')==1 and 'own_actual_trust_info=$(jbctl trustcache info)'in trust and '[ "$own_actual_trust_exit" = 0 ]'in trust and "OWN_ACTUAL_TRUST_NATIVE_EXIT"in trust,'exactonce6 adds then one real native query/actual status/full raw info retained')
 need(trust.index('trust-dispatched')<trust.index('jbctl trustcache add ')and trust.index('jbctl trustcache info')>trust.rindex('jbctl trustcache add ')and all('expected["'+h+'"]'in trust for h in full)and "INDEPENDENT27_ACTUAL_ALL_ACTIVE_OWN_TRUST_MEMBERSHIP_EXACT"in trust,'perstage exclusive trustmarker/all142 actual membership check, no echo-only success')
 need(body(scripts['launch'])==body((oldfolder/'launch.sh').read_text()).replace(old['deviceStage'],scope['deviceStage']).replace(before,after,1),'launch exact inherited stable2s readiness/result1 and complete identity cleanup, only newfull255 guard')
 need(scripts['post']==(oldfolder/'post.sh').read_text().replace(old['deviceStage'],scope['deviceStage']).replace(before.replace("'","'\"'\"'"),after.replace("'","'\"'\"'"),1),'post entire exact inherited capture cleanup/health, only newfull255 guard')
 quoted={}
 for k,v in scripts.items():
  need('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+('20'if k=='close-current-own'else'45')+' /var/jb/bin/sh -c 'in v,'actual action20/45+3 external kill bound '+k);command=('sudo -k -S -p "" 'if k!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(v);quoted[k]=len(command.encode());need(quoted[k]+10000<262144,'actual currentARG_MAX reserve '+k)
 need(quoted==c['quotedCommandBytes']and max(quoted.values())==217224 and scope['bootSeconds']==1791813884 and not scope['guestBootRequested']and not scope['deviceReboot']and not scope['perPIDKernelPrivilegeModification']and scope['sandboxProfileApplied']is False,'true command bound/currentboot/no guest or unknown kernel changes')
 o.mkdir(mode=0o700);report=dict(schema='Actual UIKit filter nine-file six-trust device packet independent finite peer',controllerPacketCandidate=pin(a.candidate),packetFreeze=pin(sf),actualScope=pin(d/'scope.json'),actualArchive=c['archive'],actualRuntimeCandidate=c['runtimeCandidate'],actualAppCandidate=c['appCandidate'],actualCurrentBasePost=c['currentInstalledProductsPost'],actualSignedRuntime141Proof=c['inheritedActualSignedRuntimeCDProof'],actualSignedAppPeer=c['inheritedActualSignedAppPeer'],actualFull255WholeFilePinsAndMetadataVerified=True,actualFull142CDsJoinedToExactSignedFiles=True,actualChangedFiles=9,existingFilesUpdated=7,newFilesAdded=2,newDirectoriesAdded=0,actualNewTCs=new,actualPriorHashesNotReadded=True,actualCanonicalNineMemberUSTARReconstructed=True,allOld7BackupsAndNew2AbsenceMarkersAndLogBeforeFirstMove=True,actualSameDirectoryTempReplacements=True,rootStage0700FreshRequired=True,all255FreshSHAAndThreeNativeCDBeforeTrust=True,oneActualNativeTrustQueryAfterSixAdds=True,all142PresenceAndNativeReturnRequired=True,rawTrustTableOutputRetained=True,ProcessFunctionsWholeByteInherited=True,SSHAndPriorReceiptASTInherited=True,launchStable2sWholeInherited=True,launchAndPostExactIdentityCleanupInherited=True,actualContinuingHumanScopeRequired=True,allRemoteWallBounds20Or45PlusKill3=True,SSHTimeout55=True,actualMaximumQuotedCommand=217224,argMax262144Reserved10000=True,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,basicInputOnly=True,guestBootRequested=False,actualDeviceDispatch=False,deviceOperations=0,trustCacheOperations=0,findings=[],finiteLocalScopePassed=True)
 (o/'review.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(a.candidate),pin(sf),pin(d/'scope.json'),c['archive'],c['controller'],c['preparer'],c['runtimeCandidate'],c['appCandidate'],c['currentInstalledProductsPost'],post['request'],post['stdout'],post['stderr'],c['inheritedActualSignedRuntimeCDProof'],c['inheritedActualSignedAppPeer'],c['actualSignedRuntimeIndependentPeer'],scope['continuingHumanAuthorization'],scope['oldScope'],pin(oldfolder/'control.py'),pin(oldfolder/'launch.sh'),pin(oldfolder/'post.sh'),pin(B/'independent27_device_product_verify_fast_v1.py')]+list(c['scripts'].values())+[pin(o/'review.json')];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[])))
if __name__=='__main__':main()
