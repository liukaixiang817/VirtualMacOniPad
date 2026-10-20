"""Join three genuine current libSystem leaf tables from actual bounded receipts."""
import json
from pathlib import Path
import struct

from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    hp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    assert len(headers['headers']) == 13
    pd = n/'ipad-current-hid-system-three-exports-plan-v1'
    declaration = json.loads((pd/'derivation.json').read_bytes())
    assert declaration['currentHeaders'] == p.pin(hp)
    pins = [p.pin(Path(__file__)), p.pin(hp)]
    for folder in ('ipad-current-hid-system-three-command-prefixes-plan-v2', 'ipad-current-hid-system-three-exports-plan-v1'):
        fp = n/folder/'freeze.json'
        for pin in json.loads(fp.read_bytes())['files']:
            assert p.pin(Path(pin['path'])) == pin
            pins.append(pin)
        pins.append(p.pin(fp))
    caps = []
    for directory, plan in [('ipad-current-hid-system-three-command-prefixes-readonly-v1', 'ipad-current-hid-system-three-command-prefixes-plan-v2'),
                            ('ipad-current-hid-system-three-exports-readonly-v1', 'ipad-current-hid-system-three-exports-plan-v1')]:
        directory, manifest = n/directory, n/plan/'request.json'
        receipt = s.checked_capture(directory, manifest, hp)
        assert receipt['readerSHA256'] == p.pin(directory/'reader-source.py')['sha256'] == 'ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
        caps.append((directory, receipt))
        pins += [p.pin(path) for path in [manifest]+[directory/name for name in
                 ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]+
                 [Path(row['path']) for row in receipt['ranges']]]
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    pins += [p.pin(archive), p.pin(tail)]
    libsystem = images[s.primary.canonical_path('/usr/lib/libSystem.B.dylib')]
    proofs, negatives = [], []
    before = len(images)
    for declared in declaration['definitions']:
        expected = [row for row in rows if row['path'] == declared['image']['path']]
        assert expected == [declared['image']]
        dependency = next(x for x in libsystem['dependencies'] if x['ordinal'] == declared['actualLibSystemReexport']['ordinal'])
        assert dependency == declared['actualLibSystemReexport'] and dependency['command'] == 0x8000001f
        cp = Path(declared['completeActualCommands']['path'])
        assert p.pin(cp) == declared['completeActualCommands']
        raw = cp.read_bytes()
        stem = cp.name.removesuffix('-commands.bin')
        assert (caps[0][0]/(stem+'-commands-prefix.bin')).read_bytes()[:len(raw)] == raw
        parsed = commands(p, raw, expected[0])
        tp = caps[1][0]/(stem+'-exports.bin')
        captured = next(x for x in caps[1][1]['ranges'] if x['path'] == str(tp))
        assert {key: captured[key] for key in ('cache', 'offset', 'length')} == mapping(headers, parsed['exportVA'], parsed['exportLength'])
        assert parsed['dependencies'] == declared['actualDependencies']
        exports = s.primary.trie(tp.read_bytes())
        assert len(tp.read_bytes()) == parsed['exportLength']
        for entry in exports.values():
            if entry['flags'] & 8:
                assert 1 <= entry['ordinal'] <= len(parsed['dependencies'])
        key = s.primary.canonical_path(parsed['path'])
        assert key not in images
        images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp), trie=p.pin(tp),
                           exports=exports, dependencies=parsed['dependencies'], currentCapture=True)
        proofs.append(dict(path=parsed['path'], UUID=parsed['UUID'], actualInventoryRow=expected[0],
                           commands=p.pin(cp), trie=p.pin(tp), exportCount=len(exports),
                           actualLibSystemReexport=dependency, actualMapping=declared['request'],
                           currentActualCapture=True, functionABIOrProcessNamespaceProven=False))
        pins += [p.pin(cp), p.pin(tp)]
        for label, malformed in [('wrong UUID', dict(expected[0], UUID='0'*32)),
                                 ('wrong install name', dict(expected[0], path='/wrong')),
                                 ('wrong text base', dict(expected[0], address=expected[0]['address']+4)),
                                 ('wrong text extent', dict(expected[0], textSize=expected[0]['textSize']+4))]:
            try:
                commands(p, raw, malformed)
            except (AssertionError, ValueError):
                negatives.append(dict(owner=parsed['path'], name=label, rejected=True))
            else:
                raise AssertionError('accepted incorrect current leaf identity')
        for label, malformed in [('truncated complete commands', raw[:-1]), ('added command bytes', raw+b'\0')]:
            try:
                commands(p, malformed, expected[0])
            except (AssertionError, ValueError):
                negatives.append(dict(owner=parsed['path'], name=label, rejected=True))
            else:
                raise AssertionError('accepted incorrect current command bytes')
    assert len(proofs) == 3 and len(images) == before+3 and len(negatives) == 18
    return pins, dict(actualCommandAndExportProofs=proofs, newlyDeclaredNativeImages=3,
                      checkedReceiptPins=[p.pin(directory/'receipt.json') for directory, _ in caps],
                      negativeControls=negatives, definitionEvidenceOnly=True,
                      uncapturedReexportsRemainUnknown=True, currentCompleteProviderGraphProven=False,
                      deviceOperations=0, frameworkLoads=0, nativeCPUCalls=0, full27Backend=False)
