#!/usr/bin/env python3
"""Add actual diagnostic/kernel provenance; reuse every frozen V5 product byte."""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE=N/'owned-platform-launch-premain-v5-local-attempt4'
CAUSE=N/'native-sandbox-enotsup-production-route-offline-v1-attempt1'
OUT=N/'owned-platform-launch-premain-v5-finalization-v1-attempt1'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,value):
    with p.open('x') as f:f.write(json.dumps(value,indent=2)+'\n')
def main():
    assert not OUT.exists()
    assert pin(BASE/'candidate.json')['sha256']=='bf0e4262d66b9606c15e7814cfeaef25be42e71eee6b32beeccb53b80105232d'
    assert pin(BASE/'freeze.json')['sha256']=='8f1ac0a4eee91a2bd45e1390d8ab78b868ba7a4f2a6f88376f35a4163918b03d'
    inputs={}
    for freeze in (BASE/'freeze.json',CAUSE/'freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']:
            assert pin(row['path'])==row,row['path'];inputs[row['path']]=row
        inputs[str(freeze)]=pin(freeze)
    c=json.loads((BASE/'candidate.json').read_bytes());contract=c['ownPlatformPrepContract']
    receipt=contract['nativeApplyReceipt'];assert pin(receipt['path'])==receipt
    assert receipt['bytes']==1430 and receipt['sha256']=='e576ac0b4c690c1e5e0ccce1269762900b055c968742f7477ada1aa3185a5e37'
    text=pathlib.Path(receipt['path']).read_text()
    assert 'APPLY_RESULT count=1 return=-1 errno=45' in text and 'ACTUAL_NATIVE_COMPAT_PROCESS_STATUS=72' in text
    assert contract['sourcePin']['path'] in inputs and contract['headerPin']['path'] in inputs
    assert pin(c['childOnlyPreMain']['path'])==c['childOnlyPreMain']
    cause=json.loads((CAUSE/'report.json').read_bytes())
    assert cause['passed'] and cause['findings']==[] and cause['operation0Decision']['profileBytecodeParsed'] is False
    contract['actualNativeKernelCause']=pin(CAUSE/'report.json')
    contract['actualNativeKernelCauseFreeze']=pin(CAUSE/'freeze.json')
    contract['nativeLastDiagnosticErrno']=45;contract['policyDeferred']=True
    # The exact adapter synchronously waits for Configuration and genuine Hello
    # acknowledgement and returns startupStatus. The boolean in V5 is written
    # only after that actual bootstrap returns 0; acquired failure owners cannot
    # grant this preparation. Include those unchanged implementations as proof.
    bootstrap=R/'VirtualMac/vz/host/vm27_owned_app_child_bootstrap_v3.inc'
    body=bootstrap.read_text()
    assert body.count('dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))')==2
    assert 'status=ChildPrepareAndPublishV3(o,&c,&actualPrepared,&hello);' in body
    assert 'status=o->startupStatus;int released=UnlockV1(&o->mutex);return status?status:released;' in body
    prep=pathlib.Path(contract['sourcePin']['path']).read_text()
    assert 'ActualOwnedBootstrapCompletedV5 = ActualChildStartupOwnerV4 != NULL;' in prep
    assert 'VM27OwnedAppChildBootstrapBeforeMainV3(&ActualChildStartupOwnerV4)) _exit(78);' in prep
    assert '!ActualOwnedBootstrapCompletedV5 || !ActualChildStartupOwnerV4' in prep
    c.update(schema='Explicit own platform launch preparation V5 with actual native/kernel provenance finalization v1',
        finalizationBuilder=pin(__file__),inheritedCandidate=pin(BASE/'candidate.json'),inheritedFreeze=pin(BASE/'freeze.json'),
        actualNativeDiagnosticEvidence=receipt,actualCurrentKernelCause=pin(CAUSE/'report.json'),
        actualCurrentKernelCauseFreeze=pin(CAUSE/'freeze.json'),
        actualBootstrapSynchronousSuccessEvidence=pin(bootstrap),
        actualConstructorRequiresSuccessfulReturnAndOwner=True,
        unchangedDSOSourceAndModelsReused=True,additionalCompilerCalls=0,additionalTestsExecuted=0,
        exactMac27CompiledBlobFormatNotInspectedByKernelOperation0=True,
        minimumSourcePreparationScopePassed=True)
    OUT.mkdir(mode=0o700);save(OUT/'candidate.json',c)
    for p in [BASE/'candidate.json',CAUSE/'report.json',bootstrap,pathlib.Path(receipt['path']),pathlib.Path(__file__),OUT/'candidate.json']:
        inputs[str(p.resolve())]=pin(p)
    assert all(pin(row['path'])==row for row in inputs.values())
    save(OUT/'freeze.json',dict(schema='Owned preMain V5 finalization exact reused products plus native evidence freeze',
        files=list(inputs.values()),deviceOperations=0,signingCalls=0,sourceEdits=0,compileCalls=0,testsRepeated=0))
    print(json.dumps(dict(candidate=pin(OUT/'candidate.json'),freeze=pin(OUT/'freeze.json'),
        childOnlyPreMain=c['childOnlyPreMain'],currentDefinitions=c['actualNativeDefinitionProof'])))
if __name__=='__main__':main()
