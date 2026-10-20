"""Join the actual system sandbox leaf; libsandbox.1 is a different image.

This reads only frozen local capture data. Export definitions are not proof of
calling sandbox APIs or of changing any process or system policy.
"""
import json
from pathlib import Path

from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    prefix_plan = n / 'ipad-current-copyfile-prefix-plan-v1'
    export_plan = n / 'ipad-current-copyfile-exports-plan-v1'
    prefix_cap = n / 'ipad-current-copyfile-prefix-readonly-v1'
    export_cap = n / 'ipad-current-copyfile-exports-readonly-v1'
    d = json.loads((export_plan / 'derivation.json').read_bytes())
    hp = Path(d['headers']['path'])
    headers = json.loads(hp.read_bytes())
    assert p.pin(hp) == d['headers'] and len(headers['headers']) == 17
    pins = [p.pin(Path(__file__)), p.pin(hp)]
    for plan in (prefix_plan, export_plan):
        for pin in json.loads((plan / 'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path'])) == pin
            pins.append(pin)
        pins.append(p.pin(plan / 'freeze.json'))
    receipts = []
    for cap, plan, length in ((prefix_cap, prefix_plan, 4096), (export_cap, export_plan, 232)):
        receipt = s.checked_capture(cap, plan / 'request.json', hp)
        assert receipt['readerSHA256'] == p.pin(cap / 'reader-source.py')['sha256'] == '64b5c04dcf1413a7fdb971ba680fabc50cb95fd3906d2acdb8a0aaa7c734adc6'
        assert (receipt['requestedRanges'], receipt['requestedBytes']) == (1, length)
        assert (cap / 'manifest.json').read_bytes() == (plan / 'request.json').read_bytes()
        involved = {'main'} | {row['cache'] for row in receipt['ranges']}
        script = (cap / 'script.sh').read_text()
        assert all(script.count(row['sha256']) == 2 for row in headers['headers'] if row['name'] in involved)
        receipts.append(receipt)
        pins += [p.pin(path) for path in [plan / 'request.json'] + [cap / name for name in
            ('receipt.json', 'manifest.json', 'stdout', 'stderr', 'script.sh', 'reader-source.py')] +
            [Path(row['path']) for row in receipt['ranges']]]
    assert len(d['actualImagesAndRanges']) == 1
    row = d['actualImagesAndRanges'][0]
    image = row['actualInventoryImage']
    assert image['path'] == '/usr/lib/system/libcopyfile.dylib'
    assert image['UUID'] == '51df2060e4fb3725861222054dc47725'
    archive = n.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n / 'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    assert [item for item in table if item['path'] == image['path']] == [image]
    prefix, cp = Path(row['actualPrefix']['path']), Path(row['completeCommands']['path'])
    assert p.pin(prefix) == row['actualPrefix'] and p.pin(cp) == row['completeCommands']
    assert cp.read_bytes() == prefix.read_bytes()[:len(cp.read_bytes())]
    assert mapping(headers, image['address'], 4096) == {k: receipts[0]['ranges'][0][k] for k in ('cache', 'offset', 'length')}
    parsed = commands(p, cp.read_bytes(), image)
    captured, request = receipts[1]['ranges'][0], row['exportRequest']
    proof_map = mapping(headers, parsed['exportVA'], parsed['exportLength'])
    assert proof_map == {k: request[k] for k in ('cache', 'offset', 'length')} == {k: captured[k] for k in ('cache', 'offset', 'length')}
    trie = Path(captured['path'])
    assert len(trie.read_bytes()) == parsed['exportLength']
    exports = s.primary.trie(trie.read_bytes())
    for entry in exports.values():
        if entry['flags'] & 8:
            assert 1 <= entry['ordinal'] <= len(parsed['dependencies'])
    key = s.primary.canonical_path(parsed['path'])
    assert key not in images
    images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp), trie=p.pin(trie),
        exports=exports, dependencies=parsed['dependencies'], currentCapture=True)
    negatives = []
    for label, wrong in [('wrong UUID', dict(image, UUID='0' * 32)), ('wrong path', dict(image, path='/usr/lib/libsandbox.1.dylib')),
                        ('wrong base', dict(image, address=image['address'] + 4)),
                        ('wrong text extent', dict(image, textSize=image['textSize'] + 4))]:
        try:
            commands(p, cp.read_bytes(), wrong)
        except (AssertionError, ValueError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise AssertionError('wrong actual system sandbox image accepted')
    for label, bad in [('truncated commands', cp.read_bytes()[:-1]), ('trailing commands', cp.read_bytes() + b'\0')]:
        try:
            commands(p, bad, image)
        except (AssertionError, ValueError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise AssertionError('wrong actual command extent accepted')
    pins += [p.pin(path) for path in (cp, prefix, trie, archive, tail, export_plan / 'derivation.json')]
    return pins, dict(actualPath=parsed['path'], actualUUID=parsed['UUID'], actualInventoryImage=image,
        completeCommands=p.pin(cp), dependencies=parsed['dependencies'], trie=p.pin(trie),
        exportCount=len(exports), actualCurrentMapping=proof_map,
        actualReceipts=[p.pin(cap / 'receipt.json') for cap in (prefix_cap, export_cap)],
        differentOwnerNeverSubstituted=True, negativeControls=negatives,
        copyfileFunctionExecuted=False, processPolicyChanged=False, systemPolicyChanged=False,
        actualExportDefinitionsOnly=True, providerLoaded=False, deviceOperations=0,
        nativeCPUCalls=0, full27Backend=False)
