"""Join seven new current stock owners and verify one fresh repeated malloc table."""
import json
from pathlib import Path

from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p,n=s.p,s.p.NODE
    headers_path=n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers=json.loads(headers_path.read_bytes())
    assert len(headers['headers'])==13 and headers['mainUUID']=='1995ea169d0a33a0b78962cf99891168'
    derivation_path=n/'ipad-current-vz-six-native-exports-plan-v1/derivation.json'
    derivation=json.loads(derivation_path.read_bytes())
    assert derivation['headers']==p.pin(headers_path)
    captures=[]
    pins=[p.pin(Path(__file__)),p.pin(headers_path),p.pin(derivation_path)]
    for directory,manifest in [
        (n/'ipad-current-vz-eight-native-commands-readonly-v1',n/'ipad-current-vz-eight-native-commands-plan-v1/request.json'),
        (n/'ipad-current-vz-native-tails-two-exports-readonly-v1',n/'ipad-current-vz-native-tails-two-exports-plan-v1/request.json'),
        (n/'ipad-current-vz-six-native-exports-readonly-v1',n/'ipad-current-vz-six-native-exports-plan-v1/request.json')]:
        receipt=s.checked_capture(directory,manifest,headers_path)
        assert receipt['readerSHA256']==p.pin(directory/'reader-source.py')['sha256']=='ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
        captures.append((directory,receipt))
        pins.append(p.pin(manifest))
        pins.extend(p.pin(directory/name) for name in ['receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py'])
        pins.extend(p.pin(Path(row['path'])) for row in receipt['ranges'])
    archive=n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail=n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    actual_rows=inventory(archive.read_bytes()[:4096],tail.read_bytes(),headers)
    actual_inventory=n/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    assert actual_rows==json.loads(actual_inventory.read_bytes())
    pins.extend(p.pin(path) for path in [archive,tail,actual_inventory])
    proofs=[]
    repeated=[]
    initial_count=len(images)
    negatives=[]
    for declared in derivation['definitions']:
        expected=[row for row in actual_rows if row['path']==declared['image']['path']]
        assert expected==[declared['image']]
        cp=Path(declared['actualCommands']['path'])
        assert p.pin(cp)==declared['actualCommands']
        raw=cp.read_bytes()
        stem=declared['stem']
        prefix=(captures[0][0]/(stem+'-commands-prefix.bin')).read_bytes()
        if len(raw)>4096:
            suffix=(captures[1][0]/(stem+'-commands-tail.bin')).read_bytes()
            assert raw==prefix+suffix
        else:
            assert raw==prefix[:len(raw)]
        parsed=commands(p,raw,expected[0])
        mapped=mapping(headers,parsed['exportVA'],parsed['exportLength'])
        assert mapped=={key:declared['exportRange'][key] for key in ['cache','offset','length']}
        matching=[row for directory,receipt in captures for row in receipt['ranges'] if row['name']==stem+'-exports']
        assert len(matching)==1 and all(matching[0][key]==mapped[key] for key in ['cache','offset','length'])
        tp=Path(matching[0]['path'])
        exports=s.primary.trie(tp.read_bytes())
        assert len(tp.read_bytes())==parsed['exportLength']
        for entry in exports.values():
            if entry['flags']&8:
                assert 1<=entry['ordinal']<=len(parsed['dependencies'])
        key=s.primary.canonical_path(parsed['path'])
        if key in images:
            assert key==s.primary.canonical_path('/usr/lib/system/libsystem_malloc.dylib')
            previous=images[key]
            assert previous['path']==parsed['path'] and previous['UUID']==parsed['UUID']
            assert Path(previous['header']['path']).read_bytes()==raw
            assert Path(previous['trie']['path']).read_bytes()==tp.read_bytes()
            assert previous['exports']==exports and previous['dependencies']==parsed['dependencies']
            repeated.append(dict(path=parsed['path'],UUID=parsed['UUID'],
                                 preservedExistingCurrentCommands=previous['header'],
                                 preservedExistingCurrentTrie=previous['trie'],
                                 freshActualCurrentCommands=p.pin(cp),freshActualCurrentTrie=p.pin(tp),
                                 commandsAndTrieWholeBytesIdentical=True,dependenciesIdentical=True,
                                 currentTableNotReplaced=True,newlyDeclaredNativeImage=False))
        else:
            images[key]=dict(path=parsed['path'],UUID=parsed['UUID'],header=p.pin(cp),trie=p.pin(tp),
                             exports=exports,dependencies=parsed['dependencies'],currentCapture=True)
        proofs.append(dict(path=parsed['path'],UUID=parsed['UUID'],base=parsed['text']['address'],
                           actualInventoryRow=expected[0],commands=p.pin(cp),trie=p.pin(tp),
                           exportCount=len(exports),dependencies=parsed['dependencies'],actualMapping=mapped,
                           actualCurrentCapture=True,stockFunctionsExecuted=False))
        pins.extend(p.pin(path) for path in [cp,tp])
        for label,wrong in [('wrong UUID',dict(expected[0],UUID='0'*32)),
                            ('wrong install name',dict(expected[0],path='/wrong')),
                            ('wrong text base',dict(expected[0],address=expected[0]['address']+4)),
                            ('wrong text extent',dict(expected[0],textSize=expected[0]['textSize']+4))]:
            try:
                commands(p,raw,wrong)
            except (AssertionError,ValueError):
                negatives.append(dict(owner=parsed['path'],name=label,rejected=True))
            else:
                raise AssertionError('accepted malformed actual current native identity')
        for label,bad in [('truncated commands',raw[:-1]),('added command bytes',raw+b'\0')]:
            try:
                commands(p,bad,expected[0])
            except (AssertionError,ValueError):
                negatives.append(dict(owner=parsed['path'],name=label,rejected=True))
            else:
                raise AssertionError('accepted malformed native command span')
    assert len(proofs)==8 and len(negatives)==48 and len(repeated)==1
    assert len(images)==initial_count+7
    malloc_image=images[s.primary.canonical_path('/usr/lib/system/libsystem_malloc.dylib')]
    malloc_entry=malloc_image['exports']['_malloc']
    malloc_proof=next(row for row in proofs if row['path']==malloc_image['path'])
    assert malloc_entry['flags']==0 and malloc_proof['base']+malloc_entry['offsetOrAbsoluteAddress']==0x195110e54
    assert malloc_image['UUID']=='39fb1f8c48ef3dd08d74ff55e8d07c60'
    return pins,dict(actualCommandAndExportProofs=proofs,actualInventoryCount=len(actual_rows),
                     newlyDeclaredNativeImages=7,repeatedIdenticalActualNativeCapture=repeated,
                     actualMallocStrongDefinition=malloc_entry,actualMallocAddress=0x195110e54,
                     actualMallocMatchesCapturedIOKitGOTTarget=True,negativeControls=negatives,
                     archivedTrieOrLeafBodyUsed=False,uncapturedReexportsRemainUnknown=True,
                     completeNativeDependencyGraphProven=False,stockFunctionsExecuted=False)
