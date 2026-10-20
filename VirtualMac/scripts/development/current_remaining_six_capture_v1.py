"""Join six current native tables from actual bounded prefixes/tails/tries.

No export aliases or missing umbrella reexports are inferred from name matches.
"""
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands,inventory,mapping


def join(s,images):
    p,n=s.p,s.p.NODE
    prefix_plan=n/'ipad-current-vz-remaining-stock-prefix-plan-v2'
    export_plan=n/'ipad-current-vz-stock-exports-and-tail-plan-v1'
    mg_plan=n/'ipad-current-mobilegestalt-exports-plan-v1'
    prefix_cap=n/'ipad-current-vz-remaining-stock-prefix-readonly-v1'
    export_cap=n/'ipad-current-vz-stock-exports-and-tail-readonly-v1'
    mg_cap=n/'ipad-current-mobilegestalt-exports-readonly-v1'
    d=json.loads((export_plan/'derivation.json').read_bytes())
    mg=json.loads((mg_plan/'derivation.json').read_bytes())
    hp=Path(d['headers']['path']);headers=json.loads(hp.read_bytes())
    assert p.pin(hp)==d['headers'] and len(headers['headers'])==14
    pins=[p.pin(Path(__file__)),p.pin(hp)]
    for plan in (prefix_plan,export_plan,mg_plan):
        for row in json.loads((plan/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(plan/'freeze.json'))
    receipts=[]
    for cap,plan in ((prefix_cap,prefix_plan),(export_cap,export_plan),(mg_cap,mg_plan)):
        receipt=s.checked_capture(cap,plan/'request.json',hp)
        assert receipt['readerSHA256']==p.pin(cap/'reader-source.py')['sha256']=='c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
        assert (cap/'manifest.json').read_bytes()==(plan/'request.json').read_bytes()
        involved={'main'}|{row['cache']for row in receipt['ranges']}
        script=(cap/'script.sh').read_text()
        assert all(script.count(row['sha256'])==2 for row in headers['headers']if row['name']in involved)
        receipts.append(receipt)
        pins += [p.pin(path)for path in [plan/'request.json']+[cap/name for name in
            ('receipt.json','manifest.json','stdout','stderr','script.sh','reader-source.py')]+[Path(row['path'])for row in receipt['ranges']]]
    assert (receipts[0]['requestedRanges'],receipts[0]['requestedBytes'])==(6,24576)
    assert (receipts[1]['requestedRanges'],receipts[1]['requestedBytes'])==(6,43008)
    assert (receipts[2]['requestedRanges'],receipts[2]['requestedBytes'])==(1,19400)
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    rows=[];negatives=[]
    expected_count={
        '/usr/lib/libMobileGestalt.dylib':None,
        '/usr/lib/system/libcorecrypto.dylib':None,
        '/usr/lib/system/libsystem_info.dylib':None,
        '/usr/lib/system/libsystem_darwin.dylib':None,
        '/usr/lib/libsandbox.1.dylib':None,
        '/System/Library/Frameworks/Accelerate.framework/Frameworks/vImage.framework/vImage':None}
    source=d['actualImagesAndRanges'];assert len(source)==6
    assert {row['actualInventoryImage']['path']for row in source}==set(expected_count)
    for row in source:
        image=row['actualInventoryImage']
        assert [item for item in table if item['path']==image['path']]==[image]
        prefix=Path(row['actualPrefix']['path']);assert p.pin(prefix)==row['actualPrefix']
        prefix_range=next(item for item in receipts[0]['ranges']if item['path']==str(prefix))
        assert mapping(headers,image['address'],4096)=={k:prefix_range[k]for k in ('cache','offset','length')}
        if image['path']=='/usr/lib/libMobileGestalt.dylib':
            assert image==mg['actualInventoryImage'] and row['completeImageIdentityVerified'] is False
            cp=Path(mg['actualCompleteCommands']['path']);trailer=Path(mg['tail']['path'])
            assert p.pin(cp)==mg['actualCompleteCommands']and p.pin(trailer)==mg['tail']
            assert cp.read_bytes()==prefix.read_bytes()+trailer.read_bytes() and len(cp.read_bytes())==4384
            trailer_range=next(item for item in receipts[1]['ranges']if item['path']==str(trailer))
            assert mapping(headers,image['address']+4096,288)=={k:trailer_range[k]for k in ('cache','offset','length')}
            request=mg['exportRequest'];captured=receipts[2]['ranges'][0]
            pins.append(p.pin(trailer))
        else:
            assert row['completeImageIdentityVerified'] is True
            cp=Path(row['completeCommands']['path']);assert p.pin(cp)==row['completeCommands']
            assert cp.read_bytes()==prefix.read_bytes()[:len(cp.read_bytes())]
            request=row['exportRequest'];captured=next(item for item in receipts[1]['ranges']if item['name']==request['name'])
        parsed=commands(p,cp.read_bytes(),image)
        assert parsed['path']==image['path'] and parsed['UUID']==image['UUID']
        proof_map=mapping(headers,parsed['exportVA'],parsed['exportLength'])
        assert proof_map=={k:request[k]for k in ('cache','offset','length')}=={k:captured[k]for k in ('cache','offset','length')}
        trie=Path(captured['path']);assert len(trie.read_bytes())==parsed['exportLength']
        exports=s.primary.trie(trie.read_bytes())
        for entry in exports.values():
            if entry['flags']&8:assert 1<=entry['ordinal']<=len(parsed['dependencies'])
        key=s.primary.canonical_path(parsed['path']);assert key not in images
        images[key]=dict(path=parsed['path'],UUID=parsed['UUID'],header=p.pin(cp),trie=p.pin(trie),
            exports=exports,dependencies=parsed['dependencies'],currentCapture=True)
        rows.append(dict(actualPath=parsed['path'],actualUUID=parsed['UUID'],actualInventoryImage=image,
            completeCommands=p.pin(cp),dependencies=parsed['dependencies'],trie=p.pin(trie),exportCount=len(exports),actualCurrentMapping=proof_map))
        for label,wrong in [('wrong UUID',dict(image,UUID='0'*32)),('wrong path',dict(image,path='/wrong')),
                            ('wrong base',dict(image,address=image['address']+4)),('wrong text extent',dict(image,textSize=image['textSize']+4))]:
            try:commands(p,cp.read_bytes(),wrong)
            except (AssertionError,ValueError):negatives.append(dict(owner=image['path'],name=label,rejected=True))
            else:raise AssertionError('wrong actual native image accepted')
        for label,bad in [('truncated commands',cp.read_bytes()[:-1]),('trailing commands',cp.read_bytes()+b'\0')]:
            try:commands(p,bad,image)
            except (AssertionError,ValueError):negatives.append(dict(owner=image['path'],name=label,rejected=True))
            else:raise AssertionError('wrong actual command extent accepted')
        pins += [p.pin(path)for path in (cp,prefix,trie)]
    pins += [p.pin(path)for path in (archive,tail,export_plan/'derivation.json',mg_plan/'derivation.json')]
    return pins,dict(images=rows,newlyDeclaredNativeImages=6,negativeControls=negatives,
        actualReceipts=[p.pin(cap/'receipt.json')for cap in (prefix_cap,export_cap,mg_cap)],
        actualExportDefinitionsOnly=True,uncapturedUmbrellaReexportsRemainUnproved=True,
        functionsExecuted=False,providerLoaded=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
