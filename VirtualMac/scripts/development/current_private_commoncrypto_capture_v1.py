"""Join the actual current CommonCrypto leaf and two literal libSystem exports.

This proves definitions only. It does not execute CRC/SHA, EFI or any VM code.
"""
import copy
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    plan = n/'ipad-current-private-commoncrypto-exports-plan-v1'
    prior = n/'ipad-current-private-commoncrypto-command-prefix-plan-v1'
    prefix_capture = n/'ipad-current-private-commoncrypto-command-prefix-readonly-v1'
    export_capture = n/'ipad-current-private-commoncrypto-exports-readonly-v1'
    declaration = json.loads((plan/'derivation.json').read_bytes())
    hp = Path(declaration['currentHeaders']['path'])
    assert p.pin(hp) == declaration['currentHeaders']
    headers = json.loads(hp.read_bytes()); assert len(headers['headers']) == 14
    pins = [p.pin(Path(__file__)), p.pin(hp)]
    for frozen in (plan, prior):
        for row in json.loads((frozen/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path'])) == row
            pins.append(row)
        pins.append(p.pin(frozen/'freeze.json'))
    receipts = []
    for directory, request in ((prefix_capture, prior/'request.json'),
                               (export_capture, plan/'request.json')):
        receipt = s.checked_capture(directory, request, hp)
        assert receipt['readerSHA256'] == p.pin(directory/'reader-source.py')['sha256'] == 'c6cea43fd413a7823ad7c38e7844617834bc1e1f399ef128637e3266cb4a4b7b'
        assert json.loads((directory/'manifest.json').read_bytes()) == json.loads(request.read_bytes())
        involved = {'main'} | {row['cache'] for row in receipt['ranges']}
        script = (directory/'script.sh').read_text()
        assert all(script.count(row['sha256']) == 2 for row in headers['headers'] if row['name'] in involved)
        receipts.append(receipt)
        pins += [p.pin(x) for x in [request] + [directory/name for name in
                 ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')] +
                 [Path(row['path']) for row in receipt['ranges']]]
    cp = Path(declaration['actualCompleteCommands']['path'])
    prefix = Path(declaration['actualPrefix']['path'])
    assert p.pin(cp) == declaration['actualCompleteCommands'] and p.pin(prefix) == declaration['actualPrefix']
    raw = cp.read_bytes(); assert len(raw) == 2368 and raw == prefix.read_bytes()[:2368]
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    actual = [row for row in table if row['path'] == '/usr/lib/system/libcommonCrypto.dylib']
    assert actual == [declaration['actualImage']]
    parsed = commands(p, raw, actual[0]); assert parsed['UUID'] == '8894eafd280331b5ba03d771b2922cc1'
    assert parsed == declaration['actualParsedCommands']
    assert mapping(headers, actual[0]['address'],4096) == {k:receipts[0]['ranges'][0][k] for k in ('cache','offset','length')}
    assert len(receipts[1]['ranges']) == 1
    captured = receipts[1]['ranges'][0]
    actual_map = mapping(headers, parsed['exportVA'], parsed['exportLength'])
    assert actual_map == {k:captured[k] for k in ('cache','offset','length')} == {k:declaration['request'][k] for k in ('cache','offset','length')}
    trie = Path(captured['path']); assert len(trie.read_bytes()) == parsed['exportLength'] == 4328
    exports = s.primary.trie(trie.read_bytes()); assert len(exports) == 233
    for row in exports.values():
        if row['flags'] & 8: assert 1 <= row['ordinal'] <= len(parsed['dependencies'])
    dependency = next(row for row in images[s.primary.canonical_path('/usr/lib/libSystem.B.dylib')]['dependencies'] if row['ordinal'] == 2)
    assert dependency == declaration['actualLibSystemReexport'] and dependency['command'] == 0x8000001f
    key = s.primary.canonical_path(parsed['path']); assert key not in images
    images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp),trie=p.pin(trie),
                      exports=exports,dependencies=parsed['dependencies'],currentCapture=True)
    definitions = {}
    for symbol, rva in (('_CNCRC',43920),('_CC_SHA256',3532)):
        expected = dict(symbol=symbol,flags=0,offsetOrAbsoluteAddress=rva)
        assert exports[symbol] == expected
        proof = s.primary.resolve(images, '/usr/lib/libSystem.B.dylib', symbol)
        assert proof['status'] == 'actualDirectExport' and proof['reexportDependency'] == dependency
        assert proof['nested']['owner'] == parsed['path'] and proof['nested']['UUID'] == parsed['UUID'] and proof['nested']['export'] == expected
        definitions[symbol] = proof
    negatives = []
    for label, wrong in [('wrong UUID',dict(actual[0],UUID='0'*32)),
                          ('wrong path',dict(actual[0],path='/wrong')),
                          ('wrong base',dict(actual[0],address=actual[0]['address']+4)),
                          ('wrong text size',dict(actual[0],textSize=actual[0]['textSize']+4))]:
        try: commands(p, raw, wrong)
        except (AssertionError,ValueError): negatives.append(dict(name=label,rejected=True))
        else: raise AssertionError('wrong current CommonCrypto identity accepted')
    for label, wrong in [('truncated commands',raw[:-1]),('trailing commands',raw+b'\0')]:
        try: commands(p, wrong, actual[0])
        except (AssertionError,ValueError): negatives.append(dict(name=label,rejected=True))
        else: raise AssertionError('wrong current CommonCrypto commands accepted')
    for symbol in definitions:
        damaged = copy.deepcopy(images); del damaged[key]['exports'][symbol]
        assert s.primary.resolve(damaged, '/usr/lib/libSystem.B.dylib',symbol)['status'] != 'actualDirectExport'
        negatives.append(dict(name='missing actual leaf '+symbol,rejected=True))
    pins += [p.pin(x) for x in (cp,trie,prefix,archive,tail,plan/'derivation.json')]
    return pins, dict(actualPath=parsed['path'],actualUUID=parsed['UUID'],actualImage=actual[0],
        commands=p.pin(cp),trie=p.pin(trie),exportCount=len(exports),actualCurrentMapping=actual_map,
        actualLibSystemReexport=dependency,actualNativeDefinitions=definitions,
        negativeControls=negatives,newlyDeclaredNativeImages=1,actualExportReceipt=p.pin(export_capture/'receipt.json'),
        exactCurrentDefinitionEvidenceOnly=True,CRCOrSHAFunctionExecuted=False,EFIExecuted=False,
        providerLoaded=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
