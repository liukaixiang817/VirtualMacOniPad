"""Join the genuine current trace trie using both actual command fragments."""
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands,inventory,mapping

def join(s,images):
    p,n=s.p,s.p.NODE
    pd=n/'ipad-current-hid-trace-exports-plan-v1'
    combined=n/'ipad-current-trace-unwind-original-cn-read-plan-v1'
    cap=n/'ipad-current-trace-unwind-original-cn-readonly-v1'
    declared=json.loads((pd/'derivation.json').read_bytes());hp=Path(declared['currentHeaders']['path']);headers=json.loads(hp.read_bytes())
    assert p.pin(hp)==declared['currentHeaders'] and len(headers['headers'])==14
    pins=[p.pin(Path(__file__)),p.pin(hp)]
    for plan in (pd,combined):
        for pin in json.loads((plan/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        pins.append(p.pin(plan/'freeze.json'))
    capture=s.checked_capture(cap,combined/'request.json',hp)
    assert capture['readerSHA256']=='c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
    original=json.loads((pd/'request.json').read_bytes())['ranges'];assert original==[declared['request']]
    captured=next(x for x in capture['ranges']if x['name']=='system-trace-exports')
    assert {k:captured[k]for k in ('cache','offset','length')}=={k:declared['request'][k]for k in ('cache','offset','length')}
    cp=Path(declared['completeActualCommands']['path']);assert p.pin(cp)==declared['completeActualCommands']
    prefix,tail=Path(declared['actualPrefix']['path']),Path(declared['actualTail']['path'])
    assert p.pin(prefix)==declared['actualPrefix']and p.pin(tail)==declared['actualTail']
    assert cp.read_bytes()==prefix.read_bytes()+tail.read_bytes()
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    table_tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows=inventory(archive.read_bytes()[:4096],table_tail.read_bytes(),headers)
    target=[x for x in rows if x['path']=='/usr/lib/system/libsystem_trace.dylib'];assert target==[declared['actualImage']]
    raw=cp.read_bytes();parsed=commands(p,raw,target[0]);assert parsed['UUID']=='cdca424284413402a6436a03c3eb9c15'
    actual_mapping=mapping(headers,parsed['exportVA'],parsed['exportLength'])
    assert actual_mapping=={k:declared['request'][k]for k in ('cache','offset','length')}
    tp=Path(captured['path']);exports=s.primary.trie(tp.read_bytes());assert len(tp.read_bytes())==parsed['exportLength']
    dependencies=images[s.primary.canonical_path('/usr/lib/libSystem.B.dylib')]['dependencies']
    dep=next(x for x in dependencies if x['ordinal']==30)
    assert dep['path']==parsed['path']and dep['command']==0x8000001f
    key=s.primary.canonical_path(parsed['path']);assert key not in images
    images[key]=dict(path=parsed['path'],UUID=parsed['UUID'],header=p.pin(cp),trie=p.pin(tp),
        exports=exports,dependencies=parsed['dependencies'],currentCapture=True)
    negatives=[]
    for label,bad in [('wrong UUID',dict(target[0],UUID='0'*32)),('wrong path',dict(target[0],path='/wrong')),
        ('wrong address',dict(target[0],address=target[0]['address']+4)),('wrong text size',dict(target[0],textSize=target[0]['textSize']+4))]:
        try:commands(p,raw,bad)
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong current trace identity')
    for label,bad in [('truncated commands',raw[:-1]),('trailing commands',raw+b'\0')]:
        try:commands(p,bad,target[0])
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong current trace commands')
    proofs=[s.primary.resolve(images,'/usr/lib/libSystem.B.dylib',name)for name in ('_os_log_create','_os_log_type_enabled')]
    for proof in proofs:
        assert proof['status']=='actualDirectExport' and proof['reexportDependency']==dep
        assert proof['nested']['owner']==parsed['path']and proof['nested']['UUID']==parsed['UUID']
    pins += [p.pin(x)for x in [archive,table_tail,prefix,tail,cp,tp,pd/'request.json',pd/'derivation.json',combined/'request.json']+
        [cap/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]+[Path(x['path'])for x in capture['ranges']]]
    return pins,dict(actualPath=parsed['path'],actualUUID=parsed['UUID'],actualImage=target[0],commands=p.pin(cp),trie=p.pin(tp),
        exportCount=len(exports),actualCurrentMapping=actual_mapping,actualLibSystemReexport=dep,
        twoOriginalUHCurrentStrongDefinitions=proofs,negativeControls=negatives,newlyDeclaredNativeImages=1,
        actualCombinedReceipt=p.pin(cap/'receipt.json'),actualCurrentDefinitionEvidenceOnly=True,
        actualOriginalUHCallerExecuted=False,deviceOperations=0,full27Backend=False)
