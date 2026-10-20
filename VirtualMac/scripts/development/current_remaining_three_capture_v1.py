"""Join three current native tables from bounded actual commands and tries.

Accelerate has an empty trie and real LC_REEXPORT dependencies. Its definitions
are resolved through those exact dependencies, never through a basename alias.
"""
import json
from pathlib import Path

from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    prefix_plan = n / 'ipad-current-vz-last-three-stock-prefix-plan-v1'
    export_plan = n / 'ipad-current-vz-last-three-stock-exports-plan-v1'
    prefix_cap = n / 'ipad-current-vz-last-three-stock-prefix-readonly-v1'
    export_cap = n / 'ipad-current-vz-last-three-stock-exports-readonly-v1'
    derivation = json.loads((export_plan / 'derivation.json').read_bytes())
    hp = Path(derivation['headers']['path'])
    headers = json.loads(hp.read_bytes())
    previous_hp = n / 'ipad-current-cache-trace-header-readonly-v1/headers.json'
    previous = json.loads(previous_hp.read_bytes())
    assert p.pin(hp) == derivation['headers'] and len(headers['headers']) == 17
    assert headers['mainUUID'] == previous['mainUUID']
    assert all(next(row for row in headers['headers'] if row['name'] == old['name']) == old
               for old in previous['headers'])
    assert {row['name'] for row in headers['headers']} - {row['name'] for row in previous['headers']} == {'15', '33', '39'}
    pins = [p.pin(Path(__file__)), p.pin(hp), p.pin(previous_hp)]
    for plan in (prefix_plan, export_plan):
        for pin in json.loads((plan / 'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path'])) == pin
            pins.append(pin)
        pins.append(p.pin(plan / 'freeze.json'))
    receipts = []
    for cap, plan, length in ((prefix_cap, prefix_plan, 12288), (export_cap, export_plan, 4896)):
        receipt = s.checked_capture(cap, plan / 'request.json', hp)
        assert receipt['readerSHA256'] == p.pin(cap / 'reader-source.py')['sha256'] == '64b5c04dcf1413a7fdb971ba680fabc50cb95fd3906d2acdb8a0aaa7c734adc6'
        assert (receipt['requestedRanges'], receipt['requestedBytes']) == (3, length)
        assert (cap / 'manifest.json').read_bytes() == (plan / 'request.json').read_bytes()
        involved = {'main'} | {row['cache'] for row in receipt['ranges']}
        script = (cap / 'script.sh').read_text()
        assert all(script.count(row['sha256']) == 2 for row in headers['headers'] if row['name'] in involved)
        receipts.append(receipt)
        pins += [p.pin(path) for path in [plan / 'request.json'] + [cap / name for name in
            ('receipt.json', 'manifest.json', 'stdout', 'stderr', 'script.sh', 'reader-source.py')] +
            [Path(row['path']) for row in receipt['ranges']]]
    archive = n.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n / 'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    expected = {'/usr/lib/libz.1.dylib',
        '/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer',
        '/System/Library/Frameworks/Accelerate.framework/Accelerate'}
    assert {row['actualInventoryImage']['path'] for row in derivation['actualImagesAndRanges']} == expected
    rows, negatives = [], []
    for row in derivation['actualImagesAndRanges']:
        image = row['actualInventoryImage']
        assert [item for item in table if item['path'] == image['path']] == [image]
        prefix, cp = Path(row['actualPrefix']['path']), Path(row['completeCommands']['path'])
        assert p.pin(prefix) == row['actualPrefix'] and p.pin(cp) == row['completeCommands']
        assert cp.read_bytes() == prefix.read_bytes()[:len(cp.read_bytes())]
        prefix_range = next(item for item in receipts[0]['ranges'] if item['path'] == str(prefix))
        assert mapping(headers, image['address'], 4096) == {k: prefix_range[k] for k in ('cache', 'offset', 'length')}
        parsed = commands(p, cp.read_bytes(), image)
        request = row['exportRequest']
        captured = next(item for item in receipts[1]['ranges'] if item['name'] == request['name'])
        proof_map = mapping(headers, parsed['exportVA'], parsed['exportLength'])
        assert proof_map == {k: request[k] for k in ('cache', 'offset', 'length')} == {k: captured[k] for k in ('cache', 'offset', 'length')}
        trie = Path(captured['path'])
        assert len(trie.read_bytes()) == parsed['exportLength']
        exports = s.primary.trie(trie.read_bytes())
        for entry in exports.values():
            if entry['flags'] & 8:
                assert 1 <= entry['ordinal'] <= len(parsed['dependencies'])
        if image['path'].endswith('/Accelerate'):
            assert trie.read_bytes() == bytes(8) and not exports
            assert [(dep['ordinal'], dep['command'], dep['path']) for dep in parsed['dependencies'][:2]] == [
                (1, 0x8000001f, '/System/Library/Frameworks/Accelerate.framework/Frameworks/vImage.framework/vImage'),
                (2, 0x8000001f, '/System/Library/Frameworks/Accelerate.framework/Frameworks/vecLib.framework/vecLib')]
        key = s.primary.canonical_path(parsed['path'])
        assert key not in images
        images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp), trie=p.pin(trie),
            exports=exports, dependencies=parsed['dependencies'], currentCapture=True)
        rows.append(dict(actualPath=parsed['path'], actualUUID=parsed['UUID'], actualInventoryImage=image,
            completeCommands=p.pin(cp), dependencies=parsed['dependencies'], trie=p.pin(trie),
            exportCount=len(exports), actualCurrentMapping=proof_map))
        for label, wrong in [('wrong UUID', dict(image, UUID='0' * 32)), ('wrong path', dict(image, path='/wrong')),
                            ('wrong base', dict(image, address=image['address'] + 4)),
                            ('wrong text extent', dict(image, textSize=image['textSize'] + 4))]:
            try:
                commands(p, cp.read_bytes(), wrong)
            except (AssertionError, ValueError):
                negatives.append(dict(owner=image['path'], name=label, rejected=True))
            else:
                raise AssertionError('wrong actual native image accepted')
        for label, bad in [('truncated commands', cp.read_bytes()[:-1]), ('trailing commands', cp.read_bytes() + b'\0')]:
            try:
                commands(p, bad, image)
            except (AssertionError, ValueError):
                negatives.append(dict(owner=image['path'], name=label, rejected=True))
            else:
                raise AssertionError('wrong actual command extent accepted')
        pins += [p.pin(path) for path in (cp, prefix, trie)]
    pins += [p.pin(path) for path in (archive, tail, export_plan / 'derivation.json')]
    return pins, dict(images=rows, newlyDeclaredNativeImages=3, negativeControls=negatives,
        actualReceipts=[p.pin(cap / 'receipt.json') for cap in (prefix_cap, export_cap)],
        originalFourteenHeaderRowsPreserved=True, actualExportDefinitionsOnly=True,
        functionsExecuted=False, providerLoaded=False, deviceOperations=0, nativeCPUCalls=0,
        uncapturedReexportsRemainUnproved=True, full27Backend=False)
