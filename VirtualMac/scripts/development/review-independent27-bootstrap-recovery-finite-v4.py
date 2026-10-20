#!/usr/bin/env python3
"""HOST-only bounded review of the fixed V4 recovery packet; no dispatch."""
import ast
import hashlib
import importlib.util
import json
import pathlib
import shlex
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P = N / 'independent27-device-bootstrap-recovery-v4-attempt1'
OLD = N / 'independent27-device-bootstrap-controller-v3-attempt1'
OUT = N / 'independent27-bootstrap-recovery-independent-peer-v4-attempt1'
def pin(p):
    p = pathlib.Path(p).resolve()
    data = p.read_bytes()
    return dict(path=str(p), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result
def main():
    OUT.mkdir(exist_ok=False)
    checks=[]
    def check(name,value):
        if not value: raise AssertionError(name)
        checks.append(name)
    c=json.loads((P/'candidate.json').read_bytes())
    check('ExactRootCandidate',pin(P/'candidate.json')['sha256']=='7a9c96aa99f5de88bdfe43b7734848bf5f5545c32472544601213f3f0b3c08cf')
    freeze=json.loads((P/'freeze.json').read_bytes())
    for row in freeze['files']: check('FrozenPin:'+row['path'],pin(row['path'])==row)
    old=load('vm27_peer_old3',OLD/'control.py')
    new=load('vm27_peer_recovery4',P/'control.py')
    fast=load('vm27_peer_fast',R/'VirtualMac/scripts/development/independent27_device_product_verify_fast_v1.py')
    scope=json.loads((P/'scope.json').read_bytes())
    check('ScopeByteIdenticalAuthorizedOriginal',(P/'scope.json').read_bytes()==(OLD/'scope.json').read_bytes() and c['authorizedOriginalScope']==pin(OLD/'scope.json'))
    check('CanonicalArchiveIdenticalOriginal',pin(P/'products.tar')['sha256']==pin(OLD/'products.tar')['sha256'] and pin(P/'products.tar')['bytes']==46714880)
    check('140ExactUniqueCD',len(scope['trustCacheCDHashes'])==len(set(scope['trustCacheCDHashes']))==140)
    check('NoNewHashesOrProducts',len(scope['files'])==252 and len(scope['directories'])==53)
    old_scripts=old.make_scripts(scope,old.HEALTH.read_text());final=fast.batch_check(scope);staged=fast.batch_check(scope,True)
    scripts={a:(P/(a+'.sh')).read_text() for a in c['scripts']}
    def wrap(body,uid):
        return old.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    def unwrap(script,uid):
        prefix=old.prefix(uid);check('RealPrefix'+str(uid)+str(len(script)),script.startswith(prefix))
        args=shlex.split(script[len(prefix):]);check('RealRemoteTimeout45Kill3'+str(len(script)),args[:-1]==['/var/jb/usr/bin/timeout','--signal=TERM','--kill-after=3','45','/var/jb/bin/sh','-c'])
        return args[-1]
    sizes={}
    for action,script in scripts.items():
        check('ScriptExactPin:'+action,pin(P/(action+'.sh'))==c['scripts'][action])
        result=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True)
        check('ShellSyntax:'+action,result.returncode==0)
        unwrap(script,501 if action=='launch' else 0)
        cmd=('sudo -k -S -p "" ' if action!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        sizes[action]=len(cmd.encode())
        check('ArgmaxExact:'+action,sizes[action]==c['allQuotedCommandBytes'][action] and sizes[action]+10000<262144)
    inside=lambda s:s.replace("'","'\"'\"'")
    check('LaunchOnlyExactVerifierDelta',scripts['launch']==old_scripts['launch'].replace(inside(old.verify_products(scope)),inside(final),1))
    for action in ('register','post'):
        check('RegisterPostOnlyVerifierPlusTimeoutDelta:'+action,scripts[action]==wrap(old_scripts[action].replace(old.verify_products(scope,include_cd=True),final,1),0))
    check('ProcessFunctionsByteIdentical',new.PROCESS_FUNCTIONS==old.PROCESS_FUNCTIONS)
    for name in ('prefix','off_check','run_remote','prior_receipt','validate_archive'):
        nodes=lambda p:{x.name:ast.dump(x,include_attributes=False) for x in ast.parse(p.read_text()).body if isinstance(x,ast.FunctionDef)}
        check('OriginalFunctionASTIdentical:'+name,nodes(P/'control.py')[name]==nodes(OLD/'control.py')[name])
    recover=unwrap(scripts['recover-stage'],0);recheck=unwrap(scripts['staged-recheck'],0)
    check('StagedRecheckReadOnlyExact',staged in recheck and all(k not in recheck for k in ['chown ','mv ','jbctl ','uiopen ','uicache ']))
    for text in (recover,recheck):
        check('OldStage85402OffBeforeUse'+str(len(text)),'own_old_stage_pid=$(ps -p 85402 -o pid= || true)\n[ -z "$own_old_stage_pid" ]' in text)
        check('ExactOwnedStageBeforeUse'+str(len(text)),'= 16777220:47302920:0:501:700 ]' in text)
    check('OnlyOwnStageChownNonrecursive',recover.count('chown ')==1 and 'chown 0:0 "$OWN_STAGE"' in recover and 'chown -' not in recover)
    check('FinalTargetsMustBeAbsent','[ ! -e "$OWN_RUNTIME" ] && [ ! -L "$OWN_RUNTIME" ]' in recover and '[ ! -e "$OWN_APP" ] && [ ! -L "$OWN_APP" ]' in recover)
    check('ExactlyTwoOwnMoves',recover.count('\nmv ')==2 and '\nmv "$OWN_STAGE/runtime" "$OWN_RUNTIME"\n' in recover and '\nmv "$OWN_STAGE/VirtualMacIndependent27.app" "$OWN_APP"\n' in recover)
    check('RuntimeSameVolumeIdentity','[ "$(stat -c %d:%i "$OWN_RUNTIME")" = "$own_runtime_identity" ]' in recover)
    check('FinalAll252VerifiedAfterMoves',recover.index(final)>recover.index('mv "$OWN_STAGE/VirtualMacIndependent27.app"'))
    check('NoRecoveryTrustOrGuestExecution',all(k not in recover for k in ['jbctl ','uiopen ','uicache ','rm ']))
    stage_identity='''
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %d:%i:%u:%g:%a "$OWN_STAGE")" = 16777220:47302920:0:0:700 ]
'''
    added=[]
    for i in range(14):
        hashes=scope['trustCacheCDHashes'][10*i:10*(i+1)]
        common=old.prefix(0)+old.off_check()+stage_identity+final+fast.cd_check(scope,hashes)
        a='verify-cd-'+str(i+1)
        check('PreflightExactTenAndAllSHA:'+a,scripts[a]==wrap(common+f"printf 'INDEPENDENT27_CD_PREFLIGHT_{i+1}_COMPLETE\\n'\n",0))
        a='trust-'+str(i+1);body=unwrap(scripts[a],0)
        expect=common+f'(umask 077; set -C; : > "$OWN_STAGE/{a}-dispatched")\n'
        for k,h in enumerate(hashes):
            expect+=f'jbctl trustcache add {h}\n'+f"printf 'OWN_TC_ADDED {10*i+k+1} {h}\\n'\n"
        expect+=f"printf 'INDEPENDENT27_EXACT_TRUST_BATCH_{i+1}_COMPLETE\\n'\n"
        check('TrustExactTenAfterHashesBeforeOnceMarker:'+a,body==expect)
        added+=hashes
    check('Exactly140OnceNativeTCAdds',added==scope['trustCacheCDHashes'] and sum(s.count('jbctl trustcache add ') for s in scripts.values())==140)
    source=(P/'control.py').read_text()
    check('AuthorizationOriginalScopePlusCurrentBytes','authorizedOriginalScope' in source and "pin(packet/'scope.json')['sha256'] == auth['scope']['sha256']" in source and "pin(packet/'scope.json')['bytes'] == auth['scope']['bytes']" in source)
    check('PredecessorsAll14VerifiedBeforeFirstTrust',"'trust-1': 'verify-cd-14'" in source and 'previous = VERIFY_ACTIONS[VERIFY_ACTIONS.index(args.action)-1]' in source and 'previous = TRUST_ACTIONS[TRUST_ACTIONS.index(args.action)-1]' in source and "'launch': 'trust-14'" in source)
    check('LocalOnceAndSerialNoRetry',"os.O_EXCL" in source and "need(not output.exists(), 'serial action never repeated')" in source and "'SSH 55-second timeout; no retry'" in source)
    check('GuestBootNotRequested',c['guestBootRequested'] is False and 'virtualmac27://runtime-startup' in scripts['launch'] and 'virtualmac27://guest-start' not in scripts['launch'])
    models=N/'independent27-controller-v2-finite-local-review-v1-attempt1/process-models.json'
    m=json.loads(models.read_bytes());check('InheritedFiveFiniteProcessModels',len(m)==5 and [r['exit'] for r in m]==[0,0,77,77,77] and all(r['actualSignals']==0 for r in m))
    oldreview=N/'independent27-final-firmware-products-controller-peer-v1-attempt1/controller-review.json'
    check('Original140ProductPeerGreen',json.loads(oldreview.read_bytes())['findings']==[])
    read=N/'independent27-staged-fast-verify-readonly-v1/receipt.json';rr=json.loads(read.read_bytes());check('ActualReadOnlyTenCDGreen',rr['transportExit']==0 and rr['deviceWrites']==0 and pathlib.Path(rr['stdout']['path']).read_text().count('OWN_CD_READ ')==10)
    report=dict(schema='Finite independent exact authorized bootstrap recovery V4 HOST review',controllerPacketCandidate=pin(P/'candidate.json'),packetFreeze=pin(P/'freeze.json'),finiteRecoveryControllerScopePassed=True,readyForRootSerialDispatchAfterReadyBinding=True,findings=[],checks=checks,freezePinsChecked=len(freeze['files']),actualFixedTrustAdditionCount=140,actualCDPreflightBatchCounts=[10]*14,actualTrustBatchCounts=[10]*14,quotedCommands=sizes,maxQuotedCommandBytes=max(sizes.values()),environmentReserveBytes=10000,kernelArgmaxBytes=262144,remoteWallSeconds=45,remoteKillAfterSeconds=3,transportTimeoutSeconds=55,localModelsReexecuted=False,processFunctionsByteIdentical=True,realGuestBootProven=False,deviceOperations=0,scopeLimits=['Actual SSH stage3 timeout left remote process alive; no generic timeout termination assumption. New remote timeout wraps all actions and prevents trusted continuation after failure.','Old stage85402 absence and exact Stage dev/ino precondition required. HOST peer does not execute device process checks.','Staged recheck is read-only predecessor; recovery chowns only owned stage then moves to absent targets and validates final entire set.','Actual initialization may execute original27 constructor/child Main; guest-start not requested. No exact native call count claimed before device execution.','No reboot action; if later needed notify user and pause awaiting user.','Unknown process identity cleanup refuses signals and retains result. No broad kill/delete/global trust clear.'],evidence=[pin(models),pin(oldreview),pin(read),pin(N/'independent27-stage-recovery-readonly-v2/receipt.json'),pin(N/'independent27-staging-filesystems-readonly-v1/receipt.json'),pin(N/'independent27-kernel-argmax-readonly-v1/receipt.json'),pin(N/'independent27-fast-product-verify-peer-v1-attempt1/review.json')],reviewerSource=pin(__file__))
    (OUT/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    (OUT/'freeze.json').write_text(json.dumps(dict(files=[pin(__file__),pin(OUT/'review.json')]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(OUT/'review.json'),freeze=pin(OUT/'freeze.json'),checks=len(checks))))
if __name__=='__main__': main()
