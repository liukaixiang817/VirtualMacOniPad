"""Join the actual libunwind export trie derived from captured full commands."""
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands,inventory,mapping

def join(s,images):
    p,n=s.p,s.p.NODE
    pd=n/'ipad-current-metal-unwind-exports-plan-v1';cap=n/'ipad-current-metal-unwind-exports-readonly-v1'
    combined=n/'ipad-current-trace-unwind-original-cn-read-plan-v1'
    prefixcap=n/'ipad-current-trace-unwind-original-cn-readonly-v1'
    d=json.loads((pd/'derivation.json').read_bytes());hp=Path(d['currentHeaders']['path']);headers=json.loads(hp.read_bytes())
    assert p.pin(hp)==d['currentHeaders']and len(headers['headers'])==14
    pins=[p.pin(Path(__file__)),p.pin(hp)]
    for plan in (pd,combined):
        for pin in json.loads((plan/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path']))==pin;pins.append(pin)
        pins.append(p.pin(plan/'freeze.json'))
    receipts=[]
    for directory,plan in ((prefixcap,combined),(cap,pd)):
        receipt=s.checked_capture(directory,plan/'request.json',hp)
        assert receipt['readerSHA256']=='c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
        receipts.append(receipt)
        pins += [p.pin(x)for x in [plan/'request.json']+[directory/name for name in
            ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]+[Path(x['path'])for x in receipt['ranges']]]
    cp=Path(d['completeActualCommands']['path']);prefix=Path(d['actualPrefix']['path'])
    assert p.pin(cp)==d['completeActualCommands']and p.pin(prefix)==d['actualPrefix']
    raw=cp.read_bytes();assert raw==prefix.read_bytes()[:len(raw)]and len(raw)==1960
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin';tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    expected=[x for x in rows if x['path']=='/usr/lib/system/libunwind.dylib'];assert expected==[d['actualImage']]
    parsed=commands(p,raw,expected[0]);assert parsed['UUID']=='41f6058d8f923691ad00f37a64a36be4'
    capture=receipts[1]['ranges'];assert len(capture)==1
    actual_mapping=mapping(headers,parsed['exportVA'],parsed['exportLength'])
    assert actual_mapping=={k:capture[0][k]for k in ('cache','offset','length')}=={k:d['request'][k]for k in ('cache','offset','length')}
    tp=Path(capture[0]['path']);exports=s.primary.trie(tp.read_bytes());assert len(tp.read_bytes())==800==parsed['exportLength']
    dependency=next(x for x in images[s.primary.canonical_path('/usr/lib/libSystem.B.dylib')]['dependencies']if x['ordinal']==d['actualLibSystemReexport']['ordinal'])
    assert dependency==d['actualLibSystemReexport']and dependency['command']==0x8000001f
    key=s.primary.canonical_path(parsed['path']);assert key not in images
    images[key]=dict(path=parsed['path'],UUID=parsed['UUID'],header=p.pin(cp),trie=p.pin(tp),
        exports=exports,dependencies=parsed['dependencies'],currentCapture=True)
    proof=s.primary.resolve(images,'/usr/lib/libSystem.B.dylib','__Unwind_Resume')
    assert proof['status']=='actualDirectExport' and proof['reexportDependency']==dependency
    assert proof['nested']['owner']==parsed['path']and proof['nested']['UUID']==parsed['UUID']and proof['nested']['export']['flags']==0
    negatives=[]
    for label,bad in [('wrong UUID',dict(expected[0],UUID='0'*32)),('wrong path',dict(expected[0],path='/wrong')),
        ('wrong address',dict(expected[0],address=expected[0]['address']+4)),('wrong text size',dict(expected[0],textSize=expected[0]['textSize']+4))]:
        try:commands(p,raw,bad)
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong current unwind identity')
    for label,bad in [('truncated commands',raw[:-1]),('trailing commands',raw+b'\0')]:
        try:commands(p,bad,expected[0])
        except(AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong current unwind commands')
    pins += [p.pin(x)for x in (cp,tp,prefix,archive,tail,pd/'derivation.json')]
    return pins,dict(actualPath=parsed['path'],actualUUID=parsed['UUID'],actualImage=expected[0],commands=p.pin(cp),trie=p.pin(tp),
        exportCount=len(exports),actualCurrentMapping=actual_mapping,actualLibSystemReexport=dependency,
        actualNativeUnwindResumeDefinition=proof,negativeControls=negatives,newlyDeclaredNativeImages=1,
        actualExportReceipt=p.pin(cap/'receipt.json'),actualCurrentDefinitionEvidenceOnly=True,
        actualOriginalVZOrMDCallerExecuted=False,deviceOperations=0,full27Backend=False)
