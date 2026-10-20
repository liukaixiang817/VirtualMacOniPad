#!/usr/bin/env python3
"""Finite HOST review of one-main update packet and its serial driver; no dispatch."""
import ast, hashlib, importlib.util, io, json, pathlib, shlex, subprocess, sys, tarfile
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},r['path'];return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def body(t):
 at=t.index('/var/jb/bin/sh -c ',t.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ');parts=shlex.split(t[at:]);assert len(parts)==1;return parts[0]
def functions(t):return {x.name:ast.dump(x,include_attributes=False)for x in ast.parse(t).body if isinstance(x,ast.FunctionDef)}
def main():
 p=N/'independent27-ssh-deferred-app-device-v1-attempt1';cp=p/'candidate.json';c=json.loads(cp.read_bytes());assert pin(cp)['sha256']=='cb00bca4b84b467de0f8c8540ae06f310d7c40f6234cc04c2a0729b3691682ac'
 for row in json.loads((p/'freeze.json').read_bytes())['files']:exact(row)
 s=json.loads(exact(c['scope']).read_bytes());op=exact(s['oldScope']);old=json.loads(op.read_bytes());oldp=op.parent
 apppeer=json.loads(exact(s['inheritedActualSignedAppPeer']).read_bytes());assert apppeer['findings']==[] and apppeer['finiteLocalScopePassed'] and apppeer['signedCandidate']==c['appCandidate'] and apppeer['runtimeCandidate']==c['runtimeCandidate']
 oldrows={x['archivePath']:x for x in old['files']};newrows={x['archivePath']:x for x in s['files']};assert set(oldrows)==set(newrows) and len(newrows)==255 and s['directories']==old['directories']
 changed=[k for k in newrows if newrows[k]['local']['sha256']!=oldrows[k]['local']['sha256']];assert changed==['VirtualMacIndependent27.app/VirtualMacIndependent27']
 for k in newrows:
  if k not in changed:
   assert {n:v for n,v in newrows[k].items()if n!='local'}=={n:v for n,v in oldrows[k].items()if n!='local'}
   assert {n:v for n,v in newrows[k]['local'].items()if n!='path'}=={n:v for n,v in oldrows[k]['local'].items()if n!='path'}
 row=s['deltaFiles'][0];assert len(s['deltaFiles'])==1 and row['old']==oldrows[changed[0]]['local'] and row['new']==newrows[changed[0]]['local']==apppeer['actualSignature']['file']
 assert row['devicePath']==old['deviceAppMain'] and s['newOwnDirectories']==[] and s['existingOwnFilesUpdated']==1 and s['newOwnFilesAdded']==0
 full=s['trustCacheCDHashes'];assert len(full)==len(set(full))==142 and len(set(full)-set(old['trustCacheCDHashes']))==1
 assert s['newTrustCacheCDHashes']==[apppeer['actualSignature']['cdhash']]==['afeccdbc7e89a0fed56261bc2de9c586eae16ffa'] and s['trustCacheFixedBatchCounts']==[1]
 assert s['runtimeCandidate']==old['runtimeCandidate'] and s['continuingHumanAuthorization']==old['continuingHumanAuthorization'] and s['bootSeconds']==1791813884
 for r in s['files']:exact(r['local'])
 proof=json.loads(exact(s['inheritedActualSignedRuntimeCDProof']).read_bytes());pr={x['actualSignedFile']['path']:x for x in proof['actualSignedFiles']}
 assert len(pr)==141 and all(pr[x['local']['path']]['actualSignedFile']==x['local'] and pr[x['local']['path']]['cdhash']==x['cdhash'] and pr[x['local']['path']]['allPrimaryPagesAndSpecialSlotsVerified'] for x in s['files']if x['archivePath'].startswith('runtime/')and'cdhash'in x)
 post=json.loads(exact(s['currentInstalledProductsPost']).read_bytes());assert post['transportExit']==0
 actualpost=exact(post['stdout']).read_text();exact(post['stderr']);exact(post['request']);assert all(x in actualpost for x in ['INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT','INDEPENDENT27_OWN_APP_AND_CHILD_OFF','OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF'])
 raw=exact(c['archive']).read_bytes();stream=io.BytesIO()
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as archive:
  members=archive.getmembers();assert len(members)==1;m=members[0];assert m.name=='new-0'and m.isreg()and not m.linkname and not m.pax_headers and m.uid==m.gid==m.mtime==0 and m.mode==0o600 and m.size==row['new']['bytes'];payload=archive.extractfile(m).read();assert hashlib.sha256(payload).hexdigest()==row['new']['sha256']
 with tarfile.open(fileobj=stream,mode='w:',format=tarfile.USTAR_FORMAT)as archive:
  item=tarfile.TarInfo('new-0');item.mode=0o600;item.uid=item.gid=item.mtime=0;item.size=len(payload);archive.addfile(item,io.BytesIO(payload))
 assert raw==stream.getvalue()and len(raw)==901120
 ctrl=exact(c['controller']).read_text();oldctrl=(oldp/'control.py').read_text().replace(old['deviceStage'],s['deviceStage'])
 guard="    need(scope['bootSeconds']==1791813884 and scope['sandboxProfileApplied'] is False and\n         scope['nativeSandboxInitSuccessFabricated'] is False and scope['actualNativeCDSubsetCount']==3,\n         'current boot and truthful basic-only profile')\n"
 assert ctrl==oldctrl.replace(guard,guard+guard,1)
 nf,of=functions(ctrl),functions(oldctrl);assert all(nf[k]==of[k]for k in ['dispatch','run_remote','prior_receipt','prefix','off_check'])
 newmodule=load(p/'control.py','finite_app13_control');oldmodule=load(oldp/'control.py','finite_app12_control');assert newmodule.PROCESS_FUNCTIONS==oldmodule.PROCESS_FUNCTIONS
 fast=load(B/'independent27_device_product_verify_fast_v1.py','finite_app13_fast');before=fast.batch_check(old);after=fast.batch_check(s)
 scripts={k:exact(r).read_text()for k,r in c['scripts'].items()};assert list(scripts)==['close-current-own','preflight','stage','verify','trust','launch','post']
 close=body(scripts['close-current-own']);assert newmodule.PROCESS_FUNCTIONS in close and 'cleanup_own >/dev/null 2>&1 || own_close_status=$?'in close and '[ "$own_close_status" = 0 ] || exit "$own_close_status"'in close and newmodule.off_check()in close
 health=(p/'health-root.sh').read_bytes();assert health==(oldp/'health-root.sh').read_bytes()
 pre=body(scripts['preflight']);assert before in pre and health.decode()in pre and '[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]'in pre
 stage=body(scripts['stage']);assert stage.index('cp -p '+shlex.quote(row['devicePath']))<stage.index('cp -p "$OWN_LOG"')<stage.index('mv -f ')
 assert stage.count('mv -f ')==1 and stage.index('= "$own_log_meta" ]')<stage.index('mv -f ')and stage.index('mv -f ')<stage.index(': > "$OWN_LOG"')
 for token in ['chown 0:0 "$OWN_STAGE"','0:0:700','backup-0','backup-app-log','16777219:47534875','.VM27-ssh-deferred-app-v1-0.pending','set -C; : > "$OWN_STAGE/stage-complete"']:assert token in stage,token
 verify=body(scripts['verify']);assert after in verify and fast.cd_check(s,s['actualNativeCDSubset'])in verify and len(s['actualNativeCDSubset'])==3
 trust=body(scripts['trust']);assert after in trust and trust.index('trust-dispatched')<trust.index('jbctl trustcache add ')
 assert [x[len('jbctl trustcache add '):]for x in trust.splitlines()if x.startswith('jbctl trustcache add ')]==s['newTrustCacheCDHashes']
 assert trust.count('jbctl trustcache info')==1 and '[ "$own_actual_trust_exit" = 0 ]'in trust and all('expected["'+h+'"]'in trust for h in full)
 oldlaunch=body((oldp/'launch.sh').read_text()).replace(old['deviceStage'],s['deviceStage']);assert body(scripts['launch'])==oldlaunch.replace(before,after,1)
 quoted=lambda t:t.replace("'","'\"'\"'")
 assert scripts['post']==(oldp/'post.sh').read_text().replace(old['deviceStage'],s['deviceStage']).replace(quoted(before),quoted(after),1)
 sizes={}
 for action,t in scripts.items():
  assert '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+('20'if action=='close-current-own'else'45')+' /var/jb/bin/sh -c 'in t
  assert subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True).returncode==0
  command=('sudo -k -S -p "" 'if action!='launch'else'')+'/var/jb/bin/sh -c '+shlex.quote(t);sizes[action]=len(command.encode());assert sizes[action]+10000<262144
 assert sizes==c['quotedCommandBytes']and max(sizes.values())==217236
 o=N/'independent27-app13-only-main-device-independent-peer-v1-attempt1';o.mkdir(mode=0o700)
 report=dict(schema='App13 one-main concrete packet finite independent peer v1',controllerPacketCandidate=pin(cp),packetFreeze=pin(p/'freeze.json'),actualScope=c['scope'],actualFullFiles=255,actualFullCodeHashes=142,actualOnlyChangedFile=row['devicePath'],actualNewTrustEntries=s['newTrustCacheCDHashes'],unchangedFiles254=True,Runtime10WholeUnchanged=True,actualSignedAppPeer=s['inheritedActualSignedAppPeer'],currentSuccessfulExactCleanupPost=s['currentInstalledProductsPost'],onlyMainCanonicalUSTARVerified=True,allOldFileAndStableLogBackupsBeforeFirstAtomicMove=True,exactPIDUIDPPIDPathStartTimeProcessFunctionsWholeUnchanged=True,closeSignalOutputSuppressedAndExplicitStatusRequired=True,readyContinuingAuthorizationAndExactPacketPeerGatesPreserved=True,serialOncePriorLockAndFailedLaunchPostPreserved=True,actualSingleTrustQueryAll142MembershipRequired=True,actualLaunchStable2sAndPostWholeInheritedExceptActualProductGuard=True,remoteClose20Others45AndSSH55=True,maximumQuotedCommandBytes=217236,deviceOperations=0,trustCacheOperations=0,guestBootRequested=False,findings=[],passed=True,finiteLocalScopePassed=True)
 review=o/'review.json';review.write_text(json.dumps(report,indent=2)+'\n')
 rows=[pin(__file__),pin(cp),pin(p/'freeze.json'),c['scope'],c['controller'],c['preparer'],c['archive'],pin(op),pin(oldp/'control.py'),s['continuingHumanAuthorization'],s['inheritedActualSignedRuntimeCDProof'],s['inheritedActualSignedAppPeer'],s['currentInstalledProductsPost'],post['request'],post['stdout'],post['stderr'],pin(B/'independent27_device_product_verify_fast_v1.py'),pin(review)]+list(c['scripts'].values())
 freeze=o/'freeze.json';freeze.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(review=pin(review),freeze=pin(freeze),findings=[])))
 serialp=N/'independent27-ssh-deferred-app-device-serial-source-v1-attempt1/candidate.json';sc=json.loads(serialp.read_bytes())
 for r in json.loads((serialp.parent/'freeze.json').read_bytes())['files']:exact(r)
 oldserial=exact(sc['priorFrozenSource']).read_text();newserial=exact(sc['source']).read_text()
 assert sc['controllerPacketCandidate']==pin(cp)and newserial==oldserial.replace('App12 one-main','App13 one-main').replace('independent27-vm-class-app-device-v1-attempt1','independent27-ssh-deferred-app-device-v1-attempt1').replace('cf09a9a51e73c71d09f89e3d029655f0426a0b4232f69713fae8b626f310c048',pin(cp)['sha256'])
 compile(newserial,sc['source']['path'],'exec')
 so=N/'independent27-app13-serial-seven-source-independent-peer-v1-attempt1';so.mkdir(mode=0o700);sr=so/'review.json'
 sr.write_text(json.dumps(dict(schema='App13 serial seven source finite independent peer v1',sourceCandidate=pin(serialp),source=sc['source'],controllerPacketCandidate=pin(cp),concretePacketPeer=pin(review),onlyPacketHashPathAndAppLabelDelta=True,allSevenActualControllerDispatchesPreserved=True,originalReadyPriorOnceLockAndReceiptGatesPreserved=True,oneGetpassMemoryOnlyRestoredAndCleared=True,failedLaunchActualReceiptOnlyOncePostPreserved=True,noDeviceExecutionInReview=True,deviceOperations=0,findings=[],passed=True,finiteLocalScopePassed=True),indent=2)+'\n')
 sf=so/'freeze.json';sf.write_text(json.dumps(dict(files=[pin(__file__),pin(serialp),pin(serialp.parent/'freeze.json'),sc['source'],sc['priorFrozenSource'],pin(cp),pin(p/'freeze.json'),pin(review),pin(freeze),pin(sr)],deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(serialReview=pin(sr),serialFreeze=pin(sf),findings=[])))
if __name__=='__main__':main()
