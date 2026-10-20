#!/usr/bin/env python3
"""HOST finite V2-to-V3 review: three native CD reads and exact signed-byte proof."""
import argparse, ast, hashlib, json, pathlib, re, shlex, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(v):
 need(pin(v['path'])=={k:v[k]for k in ('path','bytes','sha256')},'actual pin '+v['path']);return pathlib.Path(v['path'])
def main():
 p=argparse.ArgumentParser();p.add_argument('--candidate',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve()
 need(out.parent==N and not out.exists(),'fresh finite peer');c=json.loads(a.candidate.read_bytes());fp=a.candidate.parent/'freeze.json'
 for row in json.loads(fp.read_bytes())['files']:actual(row)
 olddir=N/'independent27-owned-platform-init-only-v2-attempt1';oldc=json.loads((olddir/'candidate.json').read_bytes());olds=json.loads((olddir/'scope.json').read_bytes());s=json.loads(actual(c['scope']).read_bytes())
 priorpeer=N/'independent27-owned-platform-reboot-init-independent-peer-v2-attempt1/review.json';v=json.loads(priorpeer.read_bytes());need(v['findings']==[]and v['controllerPacketCandidate']==pin(olddir/'candidate.json'),'actual already reviewed V2')
 need(s['files']==olds['files']and s['directories']==olds['directories']and s['trustCacheCDHashes']==olds['trustCacheCDHashes']and s['newTrustCacheCDHashes']==olds['newTrustCacheCDHashes']and len(s['files'])==253,'same253 wholebytes inventory and exact139 missing trust subset')
 allowed={'schema','deviceStage','exactFullProductsAndSignedCDProofInherited','actualNativeCDSubset','actualNativeCDSubsetCount','all140NativeCodeDirectoriesRequeried','inheritedActualSignedRuntimeCDProof','inheritedActualSignedAppPeer'}
 need({k for k in set(s)|set(olds)if s.get(k)!=olds.get(k)}==allowed,'only explicit CD proof/subset and stage metadata scope delta')
 subset=['e43846ee132f920ab8d6fdfb3adef64184368de6','464c666df31f9853e3ff73ce6f652359fa644d72','c8e5ae89c4cdb2c197eb206fde4aa29e3be62385']
 need(c['actualNativeCDSubset']==s['actualNativeCDSubset']==subset and c['actualNativeCDSubsetCount']==s['actualNativeCDSubsetCount']==3 and s['all140NativeCodeDirectoriesRequeried']is False,'explicit actual App/Child/Premain native subset, no false140 native claim')
 proof=json.loads(actual(c['inheritedActualSignedRuntimeCDProof']).read_bytes());rows=proof['actualSignedFiles'];inventory={row['archivePath']:row for row in s['files']}
 need(len(rows)==139 and proof['allCodeDirectoriesPrimarySHA256']is True and proof['allCodePagesAndSpecialSlotsActuallyVerified']is True,'actual139 original HOST signed pages/slots proof retained')
 joined=[]
 for row in rows:
  inv=inventory['runtime/'+row['relativePath']]
  need(row['actualSignedFile']==inv['local']and row['cdhash']==inv['cdhash']and row['primaryCodeDirectorySHA256'][:40]==row['cdhash']and row['allPrimaryPagesAndSpecialSlotsVerified']is True,'genuine HOST signed file/CD exactly equals full device SHA inventory')
  joined.append(row['cdhash'])
 app=json.loads(actual(c['inheritedActualSignedAppPeer']).read_bytes());need(app['findings']==[]and app['signedProductChecksPassed']is True and app['signedCandidate']==c['appCandidate']and app['runtimeCandidate']==c['runtimeCandidate']and app['actualSignature']['cdhash']==subset[0],'true current final App signature and runtime pin')
 appc=json.loads(actual(c['appCandidate']).read_bytes());main=appc['actualSignature']['file'];need(main==inventory['VirtualMacIndependent27.app/VirtualMacIndependent27']['local']and appc['actualSignature']['cdhash']==subset[0],'App signed wholefile exactly equals complete device SHA inventory')
 need(set(joined+[subset[0]])==set(s['trustCacheCDHashes'])and len(set(joined+[subset[0]]))==140,'all140 CD identities derive from exact signed wholefiles, no unverified zero substitution')
 control=actual(c['controller']).read_text();need(control==(olddir/'control.py').read_text().replace(olds['deviceStage'],s['deviceStage']),'controller wholebytes preserved except unique owned stage path')
 need(actual(c['health']).read_bytes()==(olddir/'health-root.sh').read_bytes()and actual(c['readinessLoop']).read_bytes()==(olddir/'readiness-loop.sh').read_bytes(),'health/stable2s loop exact original bytes')
 scripts={k:actual(row).read_text()for k,row in c['scripts'].items()}
 for k,t in scripts.items():
  need(subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True).returncode==0,'shell syntax '+k)
  command=('sudo -k -S -p "" ' if k!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(t)
  need(len(command.encode())==c['quotedCommandBytes'][k]and len(command.encode())+10000<262144,'actual command budget '+k)
  if k!='preflight':need(t==(olddir/(k+'.sh')).read_text().replace(olds['deviceStage'],s['deviceStage']),'other four scripts wholebytes unchanged except stage path')
 oldbody=shlex.split((olddir/'preflight.sh').read_text())[-1].replace(olds['deviceStage'],s['deviceStage']);newbody=shlex.split(scripts['preflight'])[-1]
 oldcalls=[line for line in oldbody.splitlines(keepends=True)if line.startswith('verify_cd ')];newcalls=[line for line in newbody.splitlines(keepends=True)if line.startswith('verify_cd ')]
 need(len(oldcalls)==140 and len(newcalls)==3 and [shlex.split(line)[-1]for line in newcalls]==subset,'only140 calls replaced by true3 ordered CD calls')
 expected=[['verify_cd',next(row['devicePath']for row in s['files']if row.get('cdhash')==h),h]for h in subset]
 need([shlex.split(line)for line in newcalls]==expected,'true exact App/Child/Premain device paths')
 rebuilt=oldbody.replace(''.join(oldcalls),''.join(newcalls),1).replace('INDEPENDENT27_NEW_BOOT_INIT_PREFLIGHT_ALL253_AND140CD_EXACT_NO_PRODUCT_UPDATES','INDEPENDENT27_NEW_BOOT_INIT_PREFLIGHT_ALL253_AND3_NATIVE_CD_EXACT_NO_PRODUCT_UPDATES')
 need(rebuilt==newbody,'full253 metadata/SHA and log/stage changes preserve original preflight; truthful3-CD status marker')
 timeout=olddir/'device-receipts/preflight/receipt.json';tr=json.loads(timeout.read_bytes());ttext=actual(tr['stdout']).read_text();actual(tr['request']);actual(tr['stderr'])
 need(tr['transportExit']==124 and 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT'in ttext,'retain actual failed prior preflight124/full253 passed; no fabricated success')
 completed=len(re.findall(r'^OWN_CD_READ ',ttext,re.M));need(completed==82,'actual observed completed CD reads82 preserved')
 need(c['actualChangedFiles']==0 and c['actualNewTrustEntries']==139 and c['maximumQuotedCommandBytes']==242792 and c['transportTimeoutSeconds']==55 and c['sandboxProfileApplied']is False and c['nativeSandboxApplyUnavailable']==45,'unchanged scope/139 restore/45-55 bounds/deferred isolation')
 out.mkdir(mode=0o700);report=dict(schema='Independent initialization V3 three native CD subset finite delta peer',controllerPacketCandidate=pin(a.candidate),packetFreeze=pin(fp),actualScope=c['scope'],inheritedV2FinitePeer=pin(priorpeer),actualPriorTimeoutReceipt=pin(timeout),actualPriorTransportExit=124,actualPriorCompletedNativeCDReads=82,actual253WholeDeviceSHAMetadataBodyUnchanged=True,actualInheritedHOSTSignedRuntimeFiles=139,actualSignedRuntimeFileCDJoins=139,actualCurrentSignedAppJoined=True,all140SignedCodeIdentitiesProvenByExactDeviceWholebytes=True,actualNativeCDSubset=subset,actualNativeCDSubsetCount=3,all140NativeCDRequeried=False,onlyNativeCDCallsReduced=True,otherFourRemoteScriptsWholebytesUnchangedExceptStage=True,controllerWholebytesUnchangedExceptStage=True,stable2sReadinessAndHealthWholebytesUnchanged=True,actualMissingRuntimeTrustRestorationCount=139,AppTrustNotRepeated=True,productChanges=0,remoteCloseSeconds=20,otherRemoteSeconds=45,SSHSeconds=55,actualQuotedMaximumBytes=242792,ARGMAX=262144,reservedEnvironmentBytes=10000,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,noFutureInitializationSuccessInvented=True,deviceOperations=0,trustCacheOperations=0,guestBootRequested=False,guestSSHVerified=False,findings=[],finiteLocalScopePassed=True)
 (out/'review.json').write_text(json.dumps(report,indent=2)+'\n');pins=[pin(__file__),pin(a.candidate),pin(fp),c['scope'],c['preparer'],c['controller'],c['health'],c['readinessLoop'],c['inheritedActualSignedRuntimeCDProof'],c['inheritedActualSignedAppPeer'],c['runtimeCandidate'],c['appCandidate'],pin(priorpeer),pin(timeout),tr['request'],tr['stdout'],tr['stderr'],pin(olddir/'candidate.json'),pin(olddir/'scope.json'),pin(olddir/'control.py')]+list(c['scripts'].values())+[pin(out/'review.json')]
 (out/'freeze.json').write_text(json.dumps(dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))
if __name__=='__main__':main()
