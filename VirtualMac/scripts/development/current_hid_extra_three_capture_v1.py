"""Join three actual current stock image identities, commands and export tries.

The main prefix is accepted only after its whole 4096 bytes match the current
before/after guarded header. The remainder of the image table, commands and
tries all come from bounded actual read receipts. Definition evidence only.
"""
import hashlib
import json
from pathlib import Path
import struct

from DyldExtractor.dyld.dyld_structs import dyld_cache_header


def inventory(prefix, tail, headers):
    assert len(prefix) == 4096 and len(tail) == 356352
    main = [x for x in headers['headers'] if x['name'] == 'main']
    assert len(main) == 1 and hashlib.sha256(prefix).hexdigest() == main[0]['sha256']
    body = prefix + tail
    head = dyld_cache_header.from_buffer_copy(body)
    assert bytes(head.uuid).hex() == headers['mainUUID'] == '1995ea169d0a33a0b78962cf99891168'
    assert head.imagesTextOffset == 83824 and head.imagesTextCount == 2600
    assert head.imagesTextOffset + head.imagesTextCount * 32 <= len(body)
    rows = []
    for index in range(head.imagesTextCount):
        uuid, address, size, offset = struct.unpack_from('<16sQII', body, head.imagesTextOffset + index * 32)
        assert 4096 <= offset < len(body)
        end = body.find(b'\0', offset)
        assert offset < end < len(body)
        path = body[offset:end].decode()
        assert path.startswith('/')
        rows.append(dict(index=index, path=path, UUID=uuid.hex(), address=address,
                         textSize=size, pathOffset=offset))
    assert len(set(x['path'] for x in rows)) == len(rows)
    return rows


def commands(p, header, expected):
    assert len(header) >= 32 and struct.unpack_from('<I', header)[0] == 0xfeedfacf
    count, length = struct.unpack_from('<II', header, 16)
    assert len(header) == 32 + length and 0 < count <= length // 8
    at = 32
    ids, uuids, exports = [], [], []
    for _ in range(count):
        assert at + 8 <= len(header)
        command, size = struct.unpack_from('<II', header, at)
        assert size >= 8 and size % 8 == 0 and at + size <= len(header)
        if command == 13:
            assert size >= 24
            off = struct.unpack_from('<I', header, at + 8)[0]
            assert 24 <= off < size and b'\0' in header[at + off:at + size]
            ids.append(header[at + off:at + size].split(b'\0')[0].decode())
        elif command == 27:
            assert size == 24
            uuids.append(header[at + 8:at + 24].hex())
        elif command == 0x80000033:
            assert size == 16
            exports.append(struct.unpack_from('<II', header, at + 8))
        at += size
    assert at == len(header) and ids == [expected['path']] and uuids == [expected['UUID']]
    if not exports:
        exports = [struct.unpack_from('<II', header, at + 40)
                   for command, at, size in p.commands(header)
                   if command == 0x80000022 and size == 48]
    assert len(exports) == 1 and exports[0][1] > 0
    text = [x for x in p.segments(header) if x['name'] == '__TEXT']
    link = [x for x in p.segments(header) if x['name'] == '__LINKEDIT']
    assert len(text) == len(link) == 1 and text[0]['address'] == expected['address']
    assert text[0]['size'] == expected['textSize']
    offset, length = exports[0]
    assert link[0]['fileoff'] <= offset and offset + length <= link[0]['fileoff'] + link[0]['filesize']
    return dict(path=ids[0], UUID=uuids[0], text=text[0], linkedit=link[0],
                exportOffset=offset, exportLength=length,
                exportVA=link[0]['address'] + offset - link[0]['fileoff'],
                dependencies=p.dependencies(header))


def mapping(headers, va, length):
    assert length > 0
    matches = [(row, part) for row in headers['headers'] for part in row['maps']
               if part['address'] <= va and va + length <= part['address'] + part['size']]
    assert len(matches) == 1
    row, part = matches[0]
    return dict(cache=row['name'], offset=part['fileOffset'] + va - part['address'], length=length)


def join(s, images):
    p, n = s.p, s.p.NODE
    header_path = n / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    headers = json.loads(header_path.read_bytes())
    roots = [n / name for name in (
        'ipad-current-cache-hid-extra-inventory-v1', 'ipad-current-cache-hid-extra-exports-plan-v1',
        'current-hid-extra-three-stock-definitions-readonly-v1')]
    pins = [p.pin(Path(__file__)), p.pin(header_path)]
    for root in roots:
        for pin in json.loads((root / 'freeze.json').read_bytes())['files']:
            assert p.pin(Path(pin['path'])) == pin
            pins.append(pin)
        pins.append(p.pin(root / 'freeze.json'))
    captures = []
    for name, request in (
        ('commands', n / 'ipad-current-cache-hid-extra-plan-v1/request.json'),
        ('leaf-capture', roots[0] / 'next-request.json'),
        ('exports', roots[1] / 'request.json')):
        directory = n / ('ipad-current-cache-hid-extra-' + name + '-readonly-v1')
        receipt = s.checked_capture(directory, request, header_path)
        assert receipt['readerSHA256'] == p.pin(directory / 'reader-source.py')['sha256']
        assert receipt['requestedRanges'] == len(receipt['ranges'])
        assert receipt['readerSHA256'] == '42cb53bcd59b526ef602fd09c0b59542e9a050203b10b7bab240b57e8563370e'
        assert json.loads((directory / 'manifest.json').read_bytes()) == json.loads(request.read_bytes())
        captures.append((directory, receipt))
        pins.append(p.pin(request))
        pins.extend(p.pin(directory / file) for file in ('receipt.json', 'manifest.json', 'script.sh',
                    'stdout', 'stderr', 'reader-source.py'))
        pins.extend(p.pin(Path(row['path'])) for row in receipt['ranges'])
    archive = n.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin'
    prefix = archive.read_bytes()[:4096]
    pins.append(p.pin(archive))
    actual_inventory = inventory(prefix, (captures[0][0] / 'main-image-table-tail.bin').read_bytes(), headers)
    assert actual_inventory == json.loads((roots[0] / 'current-images.json').read_bytes())
    report = json.loads((roots[2] / 'audit.json').read_bytes())
    assert report['headers'] == p.pin(header_path) and not report['allStockDependencyClosureProven']
    assert report['deviceWrites'] == report['nativeCPUCalls'] == report['newFrameworksLoaded'] == 0
    originals, proofs = [], []
    for declared in report['images']:
        expected = [row for row in actual_inventory if row['path'] == declared['path']]
        assert len(expected) == 1 and expected[0]['UUID'] == declared['UUID']
        cp, tp = Path(declared['commands']['path']), Path(declared['trie']['path'])
        assert p.pin(cp) == declared['commands'] and p.pin(tp) == declared['trie']
        header = cp.read_bytes()
        if cp.parent == roots[1]:
            stem = cp.name.removesuffix('-commands.bin')
            actual_prefix = (captures[1][0] / (stem + '-commands-prefix.bin')).read_bytes()
            assert len(actual_prefix) == 4096 and actual_prefix[:len(header)] == header
        else:
            assert cp == captures[0][0] / 'coregraphics-commands.bin'
        parsed = commands(p, header, expected[0])
        assert declared['base'] == parsed['text']['address']
        actual_deps = [{key: dep[key] for key in ('ordinal', 'path', 'command')} for dep in parsed['dependencies']]
        assert actual_deps == declared['dependencies']
        mapped = mapping(headers, parsed['exportVA'], parsed['exportLength'])
        captured = [row for directory, receipt in captures for row in receipt['ranges'] if row['path'] == str(tp)]
        assert len(captured) == 1 and mapped == {key: captured[0][key] for key in ('cache', 'offset', 'length')}
        assert mapped['cache'] == '44-linkedit' and len(tp.read_bytes()) == parsed['exportLength']
        tree = s.primary.trie(tp.read_bytes())
        ep = Path(declared['exports']['path'])
        assert p.pin(ep) == declared['exports'] and tree == json.loads(ep.read_bytes())
        assert len(tree) == declared['exportCount']
        for entry in tree.values():
            if entry['flags'] & 8:
                assert 1 <= entry['ordinal'] <= len(parsed['dependencies'])
        key = s.primary.canonical_path(parsed['path'])
        assert key not in images
        images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(cp), trie=p.pin(tp),
                          exports=tree, dependencies=parsed['dependencies'], currentCapture=True)
        proofs.append(dict(path=parsed['path'], UUID=parsed['UUID'], inventoryRow=expected[0],
                           commands=p.pin(cp), trie=p.pin(tp), exportCount=len(tree), actualMapping=mapped,
                           exportVA=parsed['exportVA'], currentCapture=True,
                           providerLoaded=False, functionABIOrMetadataSemanticsNewlyProven=False))
        originals.append((header, expected[0]))
    assert len(proofs) == 3
    negatives = []
    def reject(label, operation):
        try:
            operation()
        except (AssertionError, ValueError, UnicodeDecodeError, struct.error):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise AssertionError('accepted counterexample: ' + label)
    header, expected = originals[0]
    reject('unread main prefix byte mismatch', lambda: inventory(bytes([prefix[0] ^ 1]) + prefix[1:],
           (captures[0][0] / 'main-image-table-tail.bin').read_bytes(), headers))
    reject('truncated actual main tail', lambda: inventory(prefix, b'', headers))
    reject('wrong current UUID identity', lambda: commands(p, header, dict(expected, UUID='0' * 32)))
    reject('wrong current install name', lambda: commands(p, header, dict(expected, path='/wrong')))
    reject('wrong current text base', lambda: commands(p, header, dict(expected, address=expected['address'] + 1)))
    reject('wrong current text extent', lambda: commands(p, header, dict(expected, textSize=expected['textSize'] + 1)))
    reject('truncated complete command bytes', lambda: commands(p, header[:-1], expected))
    reject('added complete command bytes', lambda: commands(p, header + b'\0', expected))
    damaged = bytearray(header); struct.pack_into('<I', damaged, 36, 0)
    reject('zero load command extent', lambda: commands(p, damaged, expected))
    damaged_count = bytearray(header); struct.pack_into('<I', damaged_count, 16, 0)
    reject('zero load command count', lambda: commands(p, damaged_count, expected))
    reject('unmapped export VA', lambda: mapping(headers, 0, 8))
    reject('export span crosses actual mapping', lambda: mapping(headers, proofs[0]['exportVA'], 1 << 40))
    return pins, dict(source=p.pin(roots[2] / 'audit.json'), actualInventoryImages=len(actual_inventory),
        archivePrefix4096ExactGuardedCurrentHeaderContract=True, unreadArchiveTrieUsed=False,
        actualCommandAndExportProofs=proofs, negativeControls=negatives,
        completeCurrentSystemDependencyGraphProven=False, currentStockFunctionsExecuted=False)
