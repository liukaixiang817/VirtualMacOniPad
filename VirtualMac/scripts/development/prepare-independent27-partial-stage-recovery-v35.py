#!/usr/bin/env python3
"""HOST-only exact Device34 CSR-tail recovery from actual failed stage and read0."""
import argparse,copy,hashlib,importlib.util,json,pathlib,re,shlex,shutil,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-cpu-sys-exception-ssh-device-v34-attempt1';READ=N/'independent27-device34-partial-stage-readonly-v1-attempt1/receipt.json'
CONTROL=B/'independent27_partial_stage_recovery_controller_v1.py';ACTIONS=('stage','verify','trust','launch','post');MARKER='recovery-stage-complete-v35'
def need(v,w):
 if not v:raise ValueError(w)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def exact(row):need(pin(row['path'])==row,'exact input '+row['path']);return pathlib.Path(row['path'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh recovery output')
 need(pin(OLD/'candidate.json')['sha256']=='3fa89491a6c8a7d28ba539e8c8c08cce5c87fa5eb9e1e4abf2e53cf8e9d1ca5d' and pin(READ)['sha256']=='ba7cadff770e81f353ff1a92b8048469e6bfd6c219257923c711ab1108d63a61','fixed actual original and partial read')
 old=json.loads((OLD/'candidate.json').read_bytes());scope=copy.deepcopy(json.loads(exact(old['scope']).read_bytes()));read=json.loads(READ.read_bytes());need(read['transportExit']==0 and read['deviceWrites']==0 and read['signals']==0,'real partial read0')
 text=exact(read['stdout']).read_text();exact(read['stderr']);need('OWN_APP_CHILD_OFF_NO_SIGNAL' in text and 'READONLY_PARTIAL_STAGE_COMPLETE_NO_WRITES_NO_SIGNALS' in text,'real own off and complete partial read')
 original_stage=OLD/'device-receipts/stage/receipt.json';failed=json.loads(original_stage.read_bytes());need(failed['transportExit']==124,'actual original stage124 preserved');[exact(failed[k])for k in ('request','stdout','stderr')]
 for action in ('verify','trust','launch','post'):need(not (OLD/'device-receipts'/action).exists()and not(OLD/(action+'-dispatched.json')).exists(),'original later phases never ran')
 rows=scope['deltaFiles'];need(len(rows)==9 and rows[6]['old'] is None and rows[8]['archivePath']=='VirtualMacIndependent27.app/_CodeSignature/CodeResources','exact nine targets and CSR tail')
 metas=dict(re.findall(r'^ACTUAL ([^ ]+) ([0-9:]+)$',text,re.M));hashes={label:(digest,path)for label,digest,path in re.findall(r'^SHA256 ([^ ]+) ([a-f0-9]{64})  (.+)$',text,re.M)}
 for i,row in enumerate(rows):
  expected=row['new']if i<8 else row['old'];label='target-'+str(i);need(hashes[label]==(expected['sha256'],row['devicePath'])and metas[label].split(':')[2:]==['501','501',format(row['mode'],'o'),'1',str(expected['bytes'])],'real exact partial target '+str(i))
 csr=rows[8];pending=str(pathlib.PurePosixPath(csr['devicePath']).parent/'.VM27-cpu-sys-exception-ssh-v34-8.pending');stage=scope['deviceStage']
 for label,expected,path,owner,mode in [('pending-8',csr['new'],pending,'501:501','644'),('backup-8',csr['old'],stage+'/backup-8','501:501','644'),('new-8',csr['new'],stage+'/new-8','0:0','600')]:
  need(hashes[label]==(expected['sha256'],path)and ':'.join(metas[label].split(':')[2:])==owner+':'+mode+':1:'+str(expected['bytes']),'real exact '+label)
 need(re.search(r'^ACTUAL_GUESTTOOLS_DIR [0-9]+:[0-9]+:501:501:755:[0-9]+$',text,re.M),'actual installed owned GuestTools directory')
 stage_stdout=exact(failed['stdout']).read_text();found=re.findall(r'^OWN_PRIOR_LOG_BACKUP metadata=([0-9:]+) sha256=([a-f0-9]{64})$',stage_stdout,re.M);need(len(found)==1,'one real original log backup');log_meta,log_sha=found[0];need(log_meta=='16777223:47755349:501:501:600:1:18340:1792066748:1792066748'and log_sha=='fc0047625e850e8f9227aa5ede8f934b01788c88993be9c480e8ff837c97d453','actual original backed up log')
 sp=importlib.util.spec_from_file_location('exact_dev34_prefix',OLD/'control.py');base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
 q=shlex.quote;body=base.prefix(0)+base.off_check()
 body+='''check_exact_recovery() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "$4:$5:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
 for marker in ('stage-complete',MARKER,'trust-dispatched','recovery-trust-dispatched-v35'):
  body+='[ ! -e '+q(stage+'/'+marker)+' ] && [ ! -L '+q(stage+'/'+marker)+' ] || exit 8\n'
 def check(path,file,owner='501:501',mode=0o600):return 'check_exact_recovery '+q(path)+' '+file['sha256']+' '+str(file['bytes'])+' '+owner+' '+format(mode,'o')+'\n'
 for i,row in enumerate(rows):
  body+=check(row['devicePath'],row['new']if i<8 else row['old'],mode=row['mode'])
  if row['old']:body+=check(stage+'/backup-'+str(i),row['old'],mode=row['mode'])
  else:body+='[ "$(stat -c %u:%g:%a:%h:%s '+q(stage+'/backup-new-absent-'+str(i))+')" = 0:0:600:1:0 ]\n'
  if i<8:
   temporary=str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-cpu-sys-exception-ssh-v34-'+str(i)+'.pending'));body+='[ ! -e '+q(temporary)+' ] && [ ! -L '+q(temporary)+' ] || exit 8\n'
 body+=check(pending,csr['new'],mode=csr['mode'])+check(stage+'/new-8',csr['new'],owner='0:0')
 parent=str(pathlib.PurePosixPath(csr['devicePath']).parent);body+='[ -d '+q(parent)+' ] && [ ! -L '+q(parent)+' ]\n[ "$(realpath '+q(parent)+')" = '+q(parent)+' ]\n'
 guest=scope['deviceApp']+'/GuestTools';body+='[ -d '+q(guest)+' ] && [ ! -L '+q(guest)+' ]\n[ "$(realpath '+q(guest)+')" = '+q(guest)+' ]\n[ "$(stat -c %u:%g:%a '+q(guest)+')" = 501:501:755 ]\n'
 body+=check(stage+'/backup-app-log',dict(sha256=log_sha,bytes=18340))
 body+='[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]\n[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = '+q(log_meta)+' ]\n[ "$(sha256sum "$OWN_LOG" | cut -d \' \' -f1)" = '+log_sha+' ]\n'
 body+=check(csr['devicePath'],csr['old'],mode=csr['mode'])
 body+='mv -f '+q(pending)+' '+q(csr['devicePath'])+'\n'+check(csr['devicePath'],csr['new'],mode=csr['mode'])+'[ ! -e '+q(pending)+' ] && [ ! -L '+q(pending)+' ]\n'
 body+='[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = '+q(log_meta)+' ]\n[ "$(sha256sum "$OWN_LOG" | cut -d \' \' -f1)" = '+log_sha+' ]\n: > "$OWN_LOG"\n[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = 16777223:47755349:501:501:600:1:0 ]\n'
 body+='(umask 077; set -C; : > "$OWN_STAGE/'+MARKER+'")\nprintf \'OWN_DEVICE34_EXACT_CSR_TAIL_RECOVERY_STAGE_COMPLETE_NO_TRUST_OR_LAUNCH\\n\'\n'
 def wrap(body):return 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c '+q(body)+'\n'
 inner_syntax=subprocess.run(['/bin/sh','-n'],input=body.encode(),capture_output=True);need(inner_syntax.returncode==0,'actual new recovery inner syntax')
 scripts={'stage':wrap(body)}
 for action in ACTIONS[1:]:
  raw=(OLD/(action+'.sh')).read_text();need(('stage-complete'in raw)==(action in ('verify','trust')),'actual inherited completion guards');scripts[action]=raw.replace('stage-complete',MARKER).replace('trust-dispatched','recovery-trust-dispatched-v35')
 need(CONTROL.is_file(),'actual fresh five-phase controller required before freeze')
 out.mkdir(mode=0o700);(out/'stage-inner-syntax.stderr').write_bytes(inner_syntax.stderr);shutil.copyfile(CONTROL,out/'control.py');shutil.copyfile(OLD/'products.tar',out/'products.tar');shutil.copyfile(OLD/'health-root.sh',out/'health-root.sh')
 scope['schema']='Exact recovery after actual Device34 stage124 and actual read0; only existing CSR pending rename and backed-up owned-log tail'
 scope['historicalPrePartialInstalledProductsPost']=scope.pop('currentInstalledProductsPost');scope['currentInstalledProductsPartialState']=pin(READ);scope['originalFailedStageReceipt']=pin(original_stage);scope['originalStageFailurePreserved']=True;scope['recoveryOnlyProductReplacement']=csr['devicePath'];scope['recoveryDoesNotReplayOriginalStage']=True;scope['completionMarker']=MARKER;scope['originalStageCompleteNotFabricated']=True;scope['recoveryProductCopiesOrPermissionChanges']=0
 save(out/'scope.json',scope);scriptpins={}
 for action,raw in scripts.items():
  p=subprocess.run(['/bin/sh','-n'],input=raw.encode(),capture_output=True);need(p.returncode==0,'actual syntax '+action);(out/(action+'.sh')).write_text(raw);(out/(action+'-syntax.stderr')).write_bytes(p.stderr);scriptpins[action]=pin(out/(action+'.sh'))
 sizes={action:len((('sudo -k -S -p \"\" 'if action!='launch'else '')+'/var/jb/bin/sh -c '+q(raw)).encode())for action,raw in scripts.items()};need(max(sizes.values())+10000<262144,'actual fresh ARG_MAX reserve')
 candidate=copy.deepcopy(old);candidate.update(maximumQuotedCommandBytes=max(sizes.values()),quotedCommandBytes=sizes,schema='Fresh exact Device34 partial-stage recovery five-phase packet',preparer=pin(__file__),scope=pin(out/'scope.json'),archive=pin(out/'products.tar'),controller=pin(out/'control.py'),scripts=scriptpins,actions=list(ACTIONS),originalPacket=pin(OLD/'candidate.json'),originalFailedStageReceipt=pin(original_stage),actualPartialStateReceipt=pin(READ),currentInstalledProductsPost=None,currentInstalledProductsPartialState=pin(READ),priorAllInstalledProductsAndCurrentHealthActualPassed=False,originalFailedStagePreserved=True,archiveUploadedByRecovery=False,onlyOneExistingCSRPendingRenamed=True,ownedBackedUpLogTailCompleted=True,readyForDeviceExecution=False,deviceOperations=0,trustCacheOperations=0)
 save(out/'candidate.json',candidate)
 original_rows=json.loads((OLD/'freeze.json').read_bytes())['files'];pins=[pin(x)for x in out.iterdir()if x.is_file()]+[pin(__file__),pin(CONTROL),pin(OLD/'candidate.json'),pin(OLD/'scope.json'),pin(OLD/'freeze.json'),pin(OLD/'control.py'),pin(original_stage),pin(READ),read['stdout'],read['stderr']]+[failed[k]for k in ('request','stdout','stderr')]+original_rows
 for action in ('close-current-own','preflight'):
  p=OLD/'device-receipts'/action/'receipt.json';r=json.loads(p.read_bytes());need(r['transportExit']==0,'real original admission0');pins+=[pin(p)]+[r[k]for k in ('request','stdout','stderr')]
 save(out/'freeze.json',dict(files=list({r['path']:r for r in pins}.values()),deviceOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),scope=pin(out/'scope.json'),freeze=pin(out/'freeze.json'),stage=scriptpins['stage'],actions=list(ACTIONS))))
if __name__=='__main__':main()
