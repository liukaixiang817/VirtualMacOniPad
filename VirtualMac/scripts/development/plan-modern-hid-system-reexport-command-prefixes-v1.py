#!/usr/bin/env python3
"""Plan three actual current libSystem leaf command reads, without device work."""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('finite_frontier', HERE/'audit-modern-genuine-hid-current-frontier-v14.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
s, p = f.s, f.p
from current_hid_extra_three_capture_v1 import inventory, mapping
from macho_chained_import_records_v1 import read as actual_imports


def main():
    n = p.NODE
    out = n/'ipad-current-hid-system-three-command-prefixes-plan-v2'
    assert not out.exists()
    images = {}
    pins = s.join_capture(images, 'system', n/'ipad-current-cache-system-headers-v1/headers.json')
    extra, _ = f.join_hid_extra(s, images)
    pins += extra
    headers_path = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(headers_path.read_bytes())
    assert p.pin(headers_path)['sha256'] == '8bdfbfcdcf35e4e070bdb1142613dfc88d82d9f63cec18e4ff906818d13d58ba'
    assert len(headers['headers']) == 13
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    inventory_file = n/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    assert rows == json.loads(inventory_file.read_bytes()) and len(rows) == 2600
    previous = n/'universalhid-current-exact-frontier-audit-v16/audit.json'
    audit = json.loads(previous.read_bytes())
    uh = next(x for x in audit['auditedImages'] if x['name'] == 'UniversalHID')
    uh_file = Path(uh['image']['path'])
    assert p.pin(uh_file) == uh['image']
    parsed = actual_imports(uh_file.read_bytes(), p.commands)
    imported = {x['index']: x for x in parsed['imports']}
    expected_indices = [303, 304, 308, 310, 314, 315, 316, 317, 330, 518, 519, 520]
    queries = [x for x in uh['imports'] if x['index'] in expected_indices]
    assert len(queries) == 12
    for row in queries:
        actual = imported[row['index']]
        assert actual['name'] == row['symbol'] and actual['ordinal'] == row['ordinal'] == 5
        assert not actual['weak'] and actual['addend'] == row['addend'] == 0
        assert row['dependency'] == '/usr/lib/libSystem.B.dylib'
        assert row['proof']['status'] == 'ownerHasNoDefinitionReexportsUnverified'
    owners = [('/usr/lib/system/libsystem_blocks.dylib', 'system-blocks', 11, [303, 304, 520]),
              ('/usr/lib/system/libdispatch.dylib', 'dispatch', 6, [314, 315, 316, 317, 518, 519]),
              ('/usr/lib/system/libsystem_m.dylib', 'system-math', 21, [308]),
              ('/usr/lib/system/libsystem_trace.dylib', 'system-trace', 30, [310, 330])]
    deps = images['/usr/lib/libSystem.B.dylib']['dependencies']
    request, proofs, deferred = [], [], []
    for path, stem, ordinal, indices in owners:
        dependency = next(x for x in deps if x['ordinal'] == ordinal)
        assert dependency['path'] == path and dependency['command'] == 0x8000001f
        found = [row for row in rows if row['path'] == path]
        assert len(found) == 1 and found[0]['textSize'] >= 4096
        image = found[0]
        proof = dict(image=image, actualLibSystemReexport=dependency,
                     potentialStrongQueries=[x for x in queries if x['index'] in indices],
                     particularLeafDefinitionProven=False, functionABIOrProcessBindingProven=False)
        if stem == 'system-trace':
            try:
                mapping(headers, image['address'], 4096)
            except AssertionError:
                proof.update(currentMemberHeaderNotCaptured=True, requestDeferredUntilActualHeaderGuard=True)
            else:
                raise AssertionError('trace unexpectedly mapped by frozen thirteen current members')
            deferred.append(proof)
            continue
        mapped = mapping(headers, image['address'], 4096)
        row = dict(name=stem+'-commands-prefix', **mapped)
        assert row['offset'] >= 4096
        request.append(row)
        proof.update(range=row, actualGuardedMap=True, completeCommandsCaptured=False)
        proofs.append(proof)
    assert len(request) == 3 and sum(x['length'] for x in request) == 12288
    reader = HERE/'read-ipad-current-cache-ranges-readonly-v8.py'
    assert p.pin(reader)['sha256'] == 'ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
    negatives = []
    for label, va, size in [('nil image address', 0, 4096), ('crossing image map', proofs[0]['image']['address'], 1 << 40)]:
        try:
            mapping(headers, va, size)
        except AssertionError:
            negatives.append(dict(name=label, rejected=True))
        else:
            raise AssertionError('accepted wrong request mapping')
    out.mkdir(mode=0o700)
    p.save(out/'request.json', dict(ranges=request))
    p.save(out/'derivation.json', dict(schema='Three current libSystem reexport command prefix requests v1',
        currentMainUUID=headers['mainUUID'], currentHeaders=p.pin(headers_path), reader=p.pin(reader),
        actualInventory=p.pin(inventory_file), previousExactFrontier=p.pin(previous), actualUH=p.pin(uh_file),
        exactOriginalStrongQueries=queries, proposedLeaves=proofs, deferredLeaves=deferred,
        requestedRanges=3, requestedBytes=12288, negativeControls=negatives,
        deviceOperations=0, nativeCPUCalls=0, frameworkLoads=0, actualDefinitionsNotYetCaptured=True,
        full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [headers_path, archive, tail, inventory_file, previous, uh_file, reader,
                                    Path(__file__), out/'request.json', out/'derivation.json', out/'source.py']]
    unique = {}
    for row in pins:
        if row['path'] in unique:
            assert unique[row['path']] == row
        unique[row['path']] = row
    p.save(out/'freeze.json', dict(files=list(unique.values()), deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), freeze=p.pin(out/'freeze.json'), ranges=request)))


if __name__ == '__main__':
    main()
