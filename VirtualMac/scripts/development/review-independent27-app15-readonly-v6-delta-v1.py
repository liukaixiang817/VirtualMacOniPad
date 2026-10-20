#!/usr/bin/env python3
"""Finite new initializer binding of the frozen readonly source. No device or future success claim."""
import hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development';sys.path.insert(0,str(B))
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')};return pathlib.Path(r['path'])
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def main():
 cp=N/'independent27-app15-guest-readonly-v6-attempt1/candidate.json';c=json.loads(cp.read_bytes())
 for r in json.loads((cp.parent/'freeze.json').read_bytes())['files']:exact(r)
 oldp=N/'independent27-app14-guest-readonly-v6-attempt1/candidate.json';old=json.loads(oldp.read_bytes());priorp=N/'independent27-app14-guest-readonly-v6-delta-independent-peer-v1-attempt1/review.json';prior=json.loads(priorp.read_bytes());assert prior['findings']==[]and prior['readonlyPacketCandidate']==pin(oldp)
 assert c['builder']==old['builder']and c['common']==old['common']and exact(c['runner']).read_bytes()==exact(old['runner']).read_bytes()
 b=load(exact(c['builder']),'app15_readonly_same_builder');common=load(exact(c['common']),'app15_readonly_same_common');initp=exact(c['initializerCandidate']);init=json.loads(initp.read_bytes());scope=json.loads(exact(init['scope']).read_bytes())
 assert init['appCandidate']['sha256']=='3d780eb134d82540008e0e4ca59f997ad504e3f6033eb2ea93d0c58fe1ac9049'and init['actualFullFiles']==255 and init['actualFullCodeDirectoryHashes']==142
 app=json.loads(exact(init['appCandidate']).read_bytes());assert next(x for x in scope['files']if x['devicePath']==scope['deviceAppMain'])['local']==app['binary']and app['actualSignature']['cdhash']=='5ebc12915534597c97f6f80f3e33d2eafb03a18f'
 ctl=load(exact(c['controller']),'app15_readonly_actual_initializer');assert pin(initp.parent/'control.py')==c['controller']
 fast=load(B/'independent27_device_product_verify_fast_v1.py','app15_readonly_actual_fast');body=ctl.prefix(0)+b.UI_ONLY_GUARD+ctl.HEALTH.read_text()+fast.batch_check(scope)+common.guest_shell()+'''
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_read_prior_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_read_prior_log_sha" ]
check_owned_ui_child_off
'''
 script=exact(c['script']).read_text();assert script==common.bounded(body,ctl,40,0)
 assert subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True).returncode==0
 assert subprocess.run(['/bin/sh','-n'],input=body.encode(),capture_output=True).returncode==0
 assert common.quoted_size(script,True)==c['maximumRemoteCommandBytes']==219012 and 219012+10000<262144
 runner=exact(c['runner']).read_text();assert "review.get('readonlyPacketCandidate') == common.pin(packet / 'candidate.json')"in runner and 'common.initializer_success'in runner and 'new exclusive actual read receipt directory'in runner
 assert c['requiresActualSameInitializerLaunch0AndPost0']and c['requiresIndependentReadonlyPacketReview']and c['actualOwnedChildOffRequiredBeforeAndAfter']and c['fixedOwnedLogBeforeAfterStableMetadataAndSHARequired']and c['ownedUIAppIdentityMustRemainStable']
 assert c['metadataOnlyFiles']==['AuxiliaryStorage','Disk.img']and c['smallCopyAndSHA']==['MachineIdentifier','HardwareModel','VirtualMac.plist']
 assert c['processSignals']==c['deviceWrites']==c['deviceOperations']==0 and not c['actualGuestReadPerformed']and not c['actualGuestStarted']and not c['readyForDeviceExecution']
 assert 'kill -'not in body and 'uiopen 'not in body and 'jbctl trustcache add'not in body and 'sha256sum "$OWN_GUEST/Disk.img"'not in body
 o=N/'independent27-app15-guest-readonly-v6-delta-independent-peer-v1-attempt1';o.mkdir(mode=0o700);report=dict(schema='App15 inactive readonlyV6 exact initializer finite delta peer',readonlyPacketCandidate=pin(cp),packetFreeze=pin(cp.parent/'freeze.json'),priorReadonlyPeer=pin(priorp),actualNewInitializer=c['initializerCandidate'],actualSignedAppCandidate=init['appCandidate'],actualApp15ImageBound=True,actual255ProductsWholeGuardRegenerated=True,sourceBuilderCommonAndRunnerWholeUnchanged=True,actualQuotedInnerAndOuterSyntaxBothPassed=True,actualOwnUIIdentityAndChildOffAndLogStabilityGuardInherited=True,metadataOnlyAuxAnd256GiBDisk=True,onlyThreeSmallFilesSHAAndCopy=True,requiresActualNewInitializerLaunch0AndPost0AtDispatch=True,futureSuccessReceiptNotSynthesized=True,remote40Kill3SSH55Retained=True,maximumRemoteCommandBytes=219012,deviceOperations=0,actualGuestReadPerformed=False,actualGuestStarted=False,findings=[],passed=True,finiteLocalScopePassed=True)
 rp=o/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(cp.parent/'freeze.json'),pin(oldp),pin(priorp),c['builder'],c['common'],c['runner'],c['script'],c['controller'],c['initializerCandidate'],init['scope'],init['appCandidate'],pin(ctl.HEALTH),pin(B/'independent27_device_product_verify_fast_v1.py'),pin(rp)]
 fp=o/'freeze.json';fp.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(fp),findings=[])))
if __name__=='__main__':main()
