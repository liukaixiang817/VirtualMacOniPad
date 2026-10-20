"""Strict current MediaKit definitions only, no device I/O or function calls."""
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands,inventory,mapping

def join(s,images):
    p,n=s.p,s.p.NODE;out=n/'ipad-current-mediakit-exports-plan-v1'
    d=json.loads((out/'derivation.json').read_bytes());heads=Path(d['headers']['path']);headers=json.loads(heads.read_bytes())
    assert p.pin(heads)==d['headers']and len(headers['headers'])==18
    pins=[p.pin(Path(__file__)),p.pin(heads)];receipts=[]
    for plan,cap,length in((n/'ipad-current-mediakit-current-prefix-plan-v1',n/'ipad-current-mediakit-command-prefix-readonly-v1',4096),
                            (out,n/'ipad-current-mediakit-exports-readonly-v1',2936)):
        for row in json.loads((plan/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(plan/'freeze.json'))
        receipt=s.checked_capture(cap,plan/'request.json',heads)
        assert receipt['readerSHA256']==p.pin(cap/'reader-source.py')['sha256']=='742595c2ecd4bf119ba454c17a3e135c7ea4e546336f675dc1eccf32534ddfef'
        assert receipt['requestedRanges']==1 and receipt['requestedBytes']==length
        assert (cap/'manifest.json').read_bytes()==(plan/'request.json').read_bytes()
        receipts.append(receipt);pins += [p.pin(file)for file in cap.iterdir()if file.is_file()]
    expected=d['actualInventoryImage'];assert expected['path']=='/System/Library/PrivateFrameworks/MediaKit.framework/MediaKit'and expected['UUID']=='bb1e22a209273ee8a614cc87ff8f34c3'
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin';tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    assert [row for row in table if row['path']==expected['path']]==[expected]
    prefix=Path(d['actualPrefix']['path']);complete=Path(d['completeCommands']['path']);trie=n/'ipad-current-mediakit-exports-readonly-v1/mediakit-exports.bin'
    assert p.pin(prefix)==d['actualPrefix']and p.pin(complete)==d['completeCommands']
    assert len(complete.read_bytes())==2344 and complete.read_bytes()==prefix.read_bytes()[:2344]
    parsed=commands(p,complete.read_bytes(),expected);assert parsed==d['parsedActualCommands']
    assert mapping(headers,expected['address'],4096)=={k:receipts[0]['ranges'][0][k]for k in('cache','offset','length')}
    actual_map=mapping(headers,parsed['exportVA'],parsed['exportLength'])
    assert actual_map=={k:receipts[1]['ranges'][0][k]for k in('cache','offset','length')}=={k:d['exportRequest'][k]for k in('cache','offset','length')}
    assert actual_map==dict(cache='44-linkedit',offset=160423824,length=2936)
    tree=s.primary.trie(trie.read_bytes());assert len(trie.read_bytes())==parsed['exportLength']
    for entry in tree.values():
        if entry['flags']&8:assert 1<=entry['ordinal']<=len(parsed['dependencies'])
    key=s.primary.canonical_path(parsed['path']);assert key not in images
    images[key]=dict(path=parsed['path'],UUID=parsed['UUID'],exports=tree,dependencies=parsed['dependencies'],currentCapture=True,header=p.pin(complete),trie=p.pin(trie))
    pins += [p.pin(file)for file in(archive,tail,complete,prefix,trie,out/'derivation.json')]
    return pins,dict(actualPath=parsed['path'],actualUUID=parsed['UUID'],completeCommands=p.pin(complete),trie=p.pin(trie),
        exportCount=len(tree),dependencies=parsed['dependencies'],actualCurrentMapping=actual_map,
        currentReceipts=[p.pin(n/(name+'/receipt.json'))for name in('ipad-current-mediakit-command-prefix-readonly-v1','ipad-current-mediakit-exports-readonly-v1')],
        definitionsOnly=True,originalFunctionsExecuted=0,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
