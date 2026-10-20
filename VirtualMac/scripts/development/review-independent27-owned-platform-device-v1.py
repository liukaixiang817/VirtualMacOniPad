#!/usr/bin/env python3
"""HOST-only finite independent review of the exact owned platform packet."""
import argparse, ast, hashlib, importlib.util, io, json, pathlib, plistlib, shlex, struct, subprocess, sys, tarfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development'
def need(v,reason):
 if not v:raise ValueError(reason)
def pin(p):
 p=pathlib.Path(p).resolve();raw=p.read_bytes();return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def frozen(p):
 v=json.loads(pathlib.Path(p).read_bytes());return {r['path']:{k:r[k]for k in ('path','bytes','sha256')}for r in v['files']}
def actual(row,rows=None):
 exact={k:row[k]for k in ('path','bytes','sha256')};need(pin(exact['path'])==exact,'actual immutable pin '+exact['path'])
 if rows is not None:need(rows.get(exact['path'])==exact,'pin anchored in packet freeze')
 return exact
def function(text,name):
 tree=ast.parse(text);return ast.get_source_segment(text,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name))
def constant(text,name):
 tree=ast.parse(text);n=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets));return ast.literal_eval(n.value)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
 o=args.output.resolve();need(o.parent==N and not o.exists(),'fresh peer diagnostics')
 c=json.loads(args.candidate.read_bytes());fp=args.candidate.parent/'freeze.json';f=frozen(fp)
 actual(pin(args.candidate),f)
 for row in f.values():actual(row)
 for key in ['scope','archive','controller','preparer','runtimeCandidate','appCandidate','currentInstalledProductsPost','continuingHumanAuthorization']:actual(c[key],f)
 scope=json.loads(pathlib.Path(c['scope']['path']).read_bytes());old=json.loads(pathlib.Path(scope['oldScope']['path']).read_bytes());actual(scope['oldScope'],f)
 need(c['actualChangedFiles']==7 and c['actualExistingFilesUpdated']==6 and c['actualNewFilesAdded']==1 and
      c['actualNewDirectoriesAdded']==1 and c['actualNewTrustEntries']==3 and c['actualUnchangedSignedImages']==137,
      'actual finite7 files/3 new trust entries')
 need(len(scope['files'])==253 and scope['actualRuntimeManifestFiles']==149 and scope['trustCacheFixedBatchCounts']==[3] and
      len(scope['trustCacheCDHashes'])==len(set(scope['trustCacheCDHashes']))==140,'253 complete files/149manifest/140unique total verification')
 need(scope['sandboxProfileApplied'] is False and scope['nativeSandboxApplyUnavailable']==45 and
      scope['nativeSandboxInitSuccessFabricated'] is False and scope['securityIsolationProfileDeferred'] is True and
      scope['ownedPlatformPreparationAPI']=='_VM27OwnedPlatformLaunchPrepareV1' and scope['compilerFutureDependenciesIncluded'] is False,
      'honest deferred sandbox and distinct owned preparation')
 changed=scope['deltaFiles'];need(len(changed)==7 and [r['index']for r in changed]==list(range(7)),'actual unique delta indices')
 prior={r['archivePath']:r for r in old['files']};current={r['archivePath']:r for r in scope['files']}
 need(len(current)==253 and len(prior)==252,'no duplicate inventory paths')
 added=set(current)-set(prior);need(len(added)==1 and set(prior)<=set(current),'only genuine Main resource added')
 real_changes={key for key,row in current.items()if key not in prior or row['local']['sha256']!=prior[key]['local']['sha256']}
 need(real_changes=={r['archivePath']for r in changed} and len(current)-len(real_changes)==246,'actual delta and246 unchanged files')
 for row in scope['files']:actual(row['local'],f)
 for row in changed:
  need(row['new']==current[row['archivePath']]['local'] and row['devicePath']==current[row['archivePath']]['devicePath'],'true delta joins complete inventory')
  if row['old'] is not None:need(row['old']==prior[row['archivePath']]['local'],'old genuine replacement pins');actual(row['old'],f)
  else:need(row['archivePath']in added and row.get('newResource')is True,'only genuinely new resource absent')
 new_cd=set(scope['newTrustCacheCDHashes']);need(len(new_cd)==3 and new_cd==set(scope['trustCacheCDHashes'])-set(old['trustCacheCDHashes']),'exact three new actual CDs, no repeats')
 need(len(set(scope['trustCacheCDHashes'])&set(old['trustCacheCDHashes']))==137,'137 old signed images retained')
 raw=pathlib.Path(c['archive']['path']).read_bytes();need(len(raw)==scope['deltaArchiveBytes']==10424320 and hashlib.sha256(raw).hexdigest()==scope['deltaArchiveSHA256'],'exact concrete delta archive')
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as tar:
  members=tar.getmembers();need([m.name for m in members]==['new-'+str(i)for i in range(7)],'only exact delta archive members')
  for member,row in zip(members,changed,strict=True):
   need(member.isreg()and not member.linkname and not member.pax_headers and member.uid==member.gid==member.mtime==0 and member.mode==0o600,'canonical ordinary USTAR member')
   data=tar.extractfile(member).read();need(len(data)==member.size==row['new']['bytes']and hashlib.sha256(data).hexdigest()==row['new']['sha256'],'actual archive bytes')
   off=member.offset;need(raw[off+257:off+263]==b'ustar\0'and raw[off+263:off+265]==b'00','true canonical USTAR format')
 auth=json.loads(pathlib.Path(c['continuingHumanAuthorization']['path']).read_bytes())
 need(auth['source']=='Direct human user message in this active conversation' and
      all(auth.get(k)is True for k in ['necessaryHashesProbesAndOwnedProcessPermissionsAuthorized','continuesUntilActualIndependentMacOS27GuestAcceptance','preserveIPadOSStability','rootIsSoleDeviceOperator']),
      'continuing genuine human authorized necessary stable owned scope')
 ctrl=pathlib.Path(c['controller']['path']).read_text();prior_ctrl=pathlib.Path(c['priorController']['path']).read_text()
 identical={k:function(ctrl,k)==function(prior_ctrl,k)for k in ['run_remote','prior_receipt']}
 need(all(identical.values())and constant(ctrl,'PROCESS_FUNCTIONS')==constant(prior_ctrl,'PROCESS_FUNCTIONS'),'original exact process identity/transport preserved')
 processes=constant(ctrl,'PROCESS_FUNCTIONS')
 need(all(s in processes for s in ['OWN_APP_MAIN','OWN_CHILD_MAIN','own_app_start','own_child_start','kill -"$own_signal" "$own_pid"','lstart','uid','ppid']), 'actual PID/path/UID/PPID/start signal guards retained')
 ready=function(ctrl,'ready_gate')
 for token in ['controllerPacketCandidate','specificUserAuthorization','continuingHumanAuthorization','derivedFromContinuingDirectHumanAuthorization','newTrustCacheCDHashes','initializationExternalWallSeconds','sandboxProfileApplied']:
  need(token in ready,'actual exact current scope/peer/human ready gate: '+token)
 need('previous = {\'preflight\': \'close-current-own\'' in ctrl and "'post': 'launch'" in ctrl and "data = (packet/'products.tar').read_bytes() if args.action == 'stage'" in ctrl,'actual serial predecessors and onlystage archive')
 scripts={}
 for action,row in c['scripts'].items():
  actual(row,f);text=pathlib.Path(row['path']).read_text();scripts[action]=text
  result=subprocess.run(['/bin/sh','-n'],input=text.encode(),capture_output=True);need(result.returncode==0,'syntax only shell check')
  cmd=('sudo -k -S -p "" 'if action!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(text)
  need(len(cmd.encode())==c['quotedCommandBytes'][action] and len(cmd.encode())+10000<262144,'true actual ARG_MAX reserve')
  seconds=20 if action=='close-current-own'else 45
  need('/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c 'in text,'external declared remote wall bound')
 need(c['maximumQuotedCommandBytes']==max(c['quotedCommandBytes'].values())==216108 and c['transportTimeoutSeconds']==55,'actual maximum wire/SSH55')
 stage=shlex.split(scripts['stage'])[-1]
 first_mv=stage.index('mv ')
 for row in changed:
  needle='backup-'+str(row['index'])if row['old']is not None else'backup-new-absent-'+str(row['index'])
  need(needle in stage[:first_mv],'all seven old backups/absence records before first replacement')
 need('backup-app-log'in stage[:first_mv]and 'ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128'in stage[:first_mv],'true log2199/fullSHA backup before mutation')
 need(stage.index('mkdir -m 700 /private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/')<first_mv and
      'chown 501:501 /private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/'in stage,'one owned resource directory created after backups')
 need(stage.count('mv -f ')==6 and stage.count('mv -n ')==1 and '.VM27-owned-platform-v1-'in stage,'six sameparent replacements and one no-clobber addition')
 trust=shlex.split(scripts['trust'])[-1]
 additions=[line.split()[-1]for line in trust.splitlines()if line.startswith('jbctl trustcache add ')]
 need(additions==sorted(new_cd)and trust.index('trust-dispatched')<trust.index('jbctl trustcache add '),'single exclusive marker before exact3 additions')
 need(all(scripts[a].count('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT')>=1 for a in ['preflight','verify','trust','launch','post','close-current-own']),'all full actual product checks retained')
 close=shlex.split(scripts['close-current-own'])[-1]
 need(close.count(processes)==1,'one unchanged process-helper block')
 close=close.replace(processes,'',1)
 need('[ "$own_child_pid" = 0 ]'in close and 'signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app'in close and
      'signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app'in close and
      'signal_own TERM "$own_child_pid"'not in close,'only exact own App close; child forbidden')
 need(not any(line.lstrip().startswith(('killall ', 'reboot ', '/sbin/reboot')) for text in scripts.values() for line in text.splitlines()),'no unknown/system process cleanup command')
 old_post=json.loads(pathlib.Path(c['currentInstalledProductsPost']['path']).read_bytes());need(old_post['transportExit']==0,'actual current prior post0')
 actual(old_post['stdout'],f);need(b'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT'in pathlib.Path(old_post['stdout']['path']).read_bytes(),'actual full current products prior success')
 runtime_peer=N/'independent27-runtime8-signed-delta-independent-review-v1-attempt1/review.json';rp=json.loads(runtime_peer.read_bytes())
 need(rp['findings']==[]and rp['candidate']==c['runtimeCandidate']and rp['unchangedSignedWholebytes']==137,'real Runtime8 finite signed peer')
 app=json.loads(pathlib.Path(c['appCandidate']['path']).read_bytes());sig=load('owned_platform_app_signed_peer',B/'review-independent27-signed-runtime-product-v2.py')
 app_root=pathlib.Path(app['app']);expected=app['actualSignature'];actual(expected['file'],f)
 got=sig.signed_image(pathlib.Path(expected['file']['path']),expected,{1:(app_root/'Info.plist').read_bytes(),3:(app_root/'_CodeSignature/CodeResources').read_bytes()})
 need(json.loads(json.dumps(got))==expected and got['actualCodePages']==55 and got['cdhash']in new_cd,'actual changed App signature primary55/all slots')
 need(got['embeddedEntitlements']==plistlib.loads((R/'VirtualMac/vz/host/VirtualMac.entitlements').read_bytes()),'unchanged true Parent App entitlements')
 need(app['runtimeCandidate']==c['runtimeCandidate'],'actual new Runtime8 App linkage anchor contract')
 app_peer=N/'independent27-app10-genuine-ssh-finite-peer-v1-attempt1/review.json';apv=json.loads(app_peer.read_bytes());need(apv['findings']==[],'existing genuine SSH lifecycle source peer')
 o.mkdir(mode=0o700)
 report=dict(schema='Independent explicit owned platform device exact packet finite peer v1',controllerPacketCandidate=pin(args.candidate),packetFreeze=pin(fp),actualScope=c['scope'],
  runtimeSignedPeer=pin(runtime_peer),app10SourcePeer=pin(app_peer),actualChangedAppSignature=got,
  actualDeltaFiles=7,actualExistingFilesReplaced=6,actualNewResourceFiles=1,actualNewResourceDirectories=1,
  actualNewTrustEntries=sorted(new_cd),actualFullCodeDirectoryInventoryForVerification=140,actualManifestRows=149,actualCompleteProductFiles=253,
  actualUnchangedSignedImages=137,actualUnchangedFiles=246,actualCanonicalDeltaUSTAR=True,archive=c['archive'],
  exactProcessIdentityAndSignalBodyUnchanged=True,exactTransportAndPriorReceiptFunctionsUnchanged=identical,
  actualAllBackupsAndNewResourceAbsenceBeforeFirstReplacement=True,actualExclusiveTrustMarkerBeforeOnlyThreeNewHashes=True,
  continuingHumanAuthorization=c['continuingHumanAuthorization'],readyRequiresCurrentScopeAndExactPeerAndDerivedHumanAuthorization=True,
  actualRemoteWallSeconds=dict(close=20,actions=45,SSH=55),actualQuotedMaximumBytes=216108,actualARGMAX=262144,reservedEnvironmentBytes=10000,
  mode='explicit-owned-platform-preparation',sandboxApplied=False,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,
  nativeSandboxInitSuccessFabricated=False,guestSSHVerified=False,actualOwnedPlatformPreparationExecuted=False,
  findings=[],finiteLocalScopePassed=True,deviceOperations=0,trustCacheOperations=0,guestBoot=False)
 (o/'review.json').write_text(json.dumps(report,indent=2)+'\n')
 sources=[pin(__file__),pin(args.candidate),pin(fp),c['scope'],c['archive'],c['controller'],c['preparer'],c['runtimeCandidate'],c['appCandidate'],c['priorController'],c['currentInstalledProductsPost'],c['continuingHumanAuthorization'],pin(runtime_peer),pin(app_peer),pin(B/'review-independent27-signed-runtime-product-v2.py')]+list(c['scripts'].values())
 (o/'freeze.json').write_text(json.dumps(dict(files=sources+[pin(o/'review.json')],deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[])))
if __name__=='__main__':main()
