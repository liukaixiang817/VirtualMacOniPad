"""Join two actual old-host Swift leaf tables, retaining unknown reexports."""
import copy
import json
from pathlib import Path
from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    head_path = n / 'ipad-current-cache-swift-leaf-headers-v1/headers.json'
    heads = json.loads(head_path.read_bytes())
    assert len(heads['headers']) == 12 and heads['mainUUID'] == '1995ea169d0a33a0b78962cf99891168'
    root = n / 'current-swift-two-stock-definitions-readonly-v1'
    report = json.loads((root / 'audit.json').read_bytes())
    assert report['headers'] == p.pin(head_path) and report['unverifiedReexportTargetsRemainUnknown']
    assert report['deviceWrites'] == report['nativeCPUCalls'] == report['newFrameworksLoaded'] == 0
    pins = [p.pin(Path(__file__)), p.pin(head_path), p.pin(root / 'audit.json')]
    for frozen in (root, n / 'ipad-current-swift-two-exports-plan-v1'):
        for row in json.loads((frozen / 'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path'])) == row
            pins.append(row)
        pins.append(p.pin(frozen / 'freeze.json'))
    capture_specs = [
        (n / 'ipad-current-swift-two-commands-readonly-v1', n / 'ipad-current-swift-two-commands-plan-v1/request.json'),
        (n / 'ipad-current-swift-iokit-stackprobe-readonly-v1', n / 'ipad-current-swift-iokit-stackprobe-plan-v1/request.json')]
    captures = []
    for directory, request in capture_specs:
        receipt = s.checked_capture(directory, request, head_path)
        assert receipt['readerSHA256'] == p.pin(directory / 'reader-source.py')['sha256'] == '6cb61cbad0775c70b229f6c25fca4305bcb35c640c3f492bac6fc5954193f922'
        captures.append((directory, receipt))
        pins.append(p.pin(request))
        pins += [p.pin(directory / name) for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]
        pins += [p.pin(Path(row['path'])) for row in receipt['ranges']]
    # This exact immutable main header contract and the actual captured tail
    # determine image identity. No archived leaf trie or machine code is used.
    archive = n.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    prefix = archive.read_bytes()[:4096]
    tail_path = n / 'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    actual_rows = inventory(prefix, tail_path.read_bytes(), heads)
    inventory_path = n / 'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    assert actual_rows == json.loads(inventory_path.read_bytes())
    pins += [p.pin(archive), p.pin(tail_path), p.pin(inventory_path)]
    proofs, originals = [], []
    for declared in report['images']:
        expected = [row for row in actual_rows if row['path'] == declared['path']]
        assert len(expected) == 1 and expected[0]['UUID'] == declared['UUID']
        cp, tp, ep = [Path(declared[key]['path']) for key in ('commands', 'trie', 'exports')]
        assert all(p.pin(path) == declared[key] for key, path in zip(('commands', 'trie', 'exports'), (cp, tp, ep)))
        prefix_name = cp.name.removesuffix('-commands.bin') + '-commands-prefix.bin'
        prefix_file = captures[0][0] / prefix_name
        actual_prefix = prefix_file.read_bytes()
        header = cp.read_bytes()
        assert len(actual_prefix) == 4096 and actual_prefix[:len(header)] == header
        parsed = commands(p, header, expected[0])
        assert parsed['text']['address'] == declared['base']
        assert [{key: dep[key] for key in ('ordinal', 'path', 'command')} for dep in parsed['dependencies']] == declared['dependencies']
        mapped = mapping(heads, parsed['exportVA'], parsed['exportLength'])
        actual_span = [row for directory, receipt in captures for row in receipt['ranges'] if row['path'] == str(tp)]
        assert len(actual_span) == 1 and mapped == {key:actual_span[0][key] for key in ('cache','offset','length')}
        assert mapped['cache'] == '44-linkedit'
        exports = s.primary.trie(tp.read_bytes())
        assert exports == json.loads(ep.read_bytes()) and len(exports) == declared['exportCount']
        assert len(tp.read_bytes()) == parsed['exportLength']
        for entry in exports.values():
            if entry['flags'] & 8:
                assert 1 <= entry['ordinal'] <= len(parsed['dependencies'])
        key = s.primary.canonical_path(parsed['path'])
        assert key not in images
        images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp), trie=p.pin(tp),
            exports=exports, dependencies=parsed['dependencies'], currentCapture=True)
        proofs.append(dict(path=parsed['path'], UUID=parsed['UUID'], actualInventoryRow=expected[0],
            commands=p.pin(cp), trie=p.pin(tp), exports=p.pin(ep), exportCount=len(exports),
            actualMapping=mapped, exactCurrentCapture=True, stockFunctionsExecuted=False))
        pins += [p.pin(cp), p.pin(tp), p.pin(ep), p.pin(prefix_file)]
        originals.append((header, expected[0]))
    assert len(proofs) == 2
    negatives = []
    for header, expected in originals:
        for label, changed in [('wrong UUID', dict(expected, UUID='0' * 32)),
                               ('wrong install name', dict(expected, path='/wrong')),
                               ('wrong text base', dict(expected, address=expected['address'] + 4)),
                               ('wrong text extent', dict(expected, textSize=expected['textSize'] + 4))]:
            try: commands(p, header, changed)
            except (AssertionError, ValueError): negatives.append(dict(owner=expected['path'], name=label, rejected=True))
            else: raise AssertionError('accepted wrong current Swift identity')
        for label, raw in [('truncated commands', header[:-1]), ('added commands', header + b'\0')]:
            try: commands(p, raw, expected)
            except (AssertionError, ValueError): negatives.append(dict(owner=expected['path'], name=label, rejected=True))
            else: raise AssertionError('accepted malformed current Swift commands')
    unknown = copy.deepcopy(images)
    owner = s.primary.canonical_path('/usr/lib/swift/libswiftObjectiveC.dylib')
    unknown[owner]['exports']['_VM27_UNKNOWN_REEXPORT_NEGATIVE'] = dict(symbol='_VM27_UNKNOWN_REEXPORT_NEGATIVE', flags=8, ordinal=4, importedName='')
    assert s.primary.resolve(unknown, owner, '_VM27_UNKNOWN_REEXPORT_NEGATIVE')['status'] == 'uncapturedOwner'
    negatives.append(dict(name='actual weak Darwin reexport target not captured stays unknown', rejected=True))
    return pins, dict(source=p.pin(root / 'audit.json'), actualCommandAndExportProofs=proofs,
        actualCurrentInventoryImages=len(actual_rows), guardedExactMainHeaderAndActualTail=True,
        archivedTrieOrLeafBodyUsed=False, negativeControls=negatives,
        completeCurrentSystemDependencyGraphProven=False, stockFunctionsExecuted=False)
