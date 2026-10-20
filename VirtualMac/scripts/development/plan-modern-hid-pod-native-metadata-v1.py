#!/usr/bin/env python3
"""Two minimal native metadata requests; archived .27 is request-only evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pod_metadata_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    headers = p.ROOT / 'DeviceDiagnostics/2026-10-02-macos27-backend/ipad-cache-headers.bin'
    archived = headers.read_bytes()[27 * 4096:28 * 4096]
    archived_copy = out / 'archived27-request-only.header.bin'
    archived_copy.write_bytes(archived)
    assert len(archived) == 4096 and archived[88:104].hex() == '08193a3ab05d3ab2a931a09d2a1dc98a'
    assert p.pin(archived_copy)['sha256'] == '8276c3e17b75e5ebd24a7b5f524ebc23df555f10459f6154466e2c80687066a1'
    at, count = struct.unpack_from('<II', archived, 16)
    assert count == 6 and at == 512
    maps = [dict(zip(('address', 'size', 'fileOffset', 'maxProt', 'initProt'),
                     struct.unpack_from('<QQQII', archived, at + i * 32))) for i in range(count)]
    images = s.primary.captured_images()
    rows, requests, inputs = [], [], [Path(__file__), Path(s.__file__), Path(s.primary.__file__), headers, archived_copy]
    for name, owner, symbol, expected in (
        ('foundation-uuid-metadata', '/System/Library/Frameworks/Foundation.framework/Foundation', '_$s10Foundation4UUIDVN', 0x1de611370),
        ('swiftcore-uint64-metadata', '/usr/lib/swift/libswiftCore.dylib', '_$ss6UInt64VN', 0x1de5e6b50)):
        image = images[owner]
        command_path = Path(image['header']['path'])
        command = command_path.read_bytes()
        texts = [struct.unpack_from('<Q', command, ca + 24)[0] for cmd, ca, length in p.commands(command)
                 if cmd == 0x19 and command[ca + 8:ca + 24].rstrip(b'\0') == b'__TEXT']
        assert len(texts) == 1
        proof = s.primary.resolve(images, owner, symbol)
        assert proof['status'] == 'actualDirectExport' and proof['export']['flags'] == 0
        address = texts[0] + proof['export']['offsetOrAbsoluteAddress']
        assert address == expected
        start, length = address - 8, 24
        matching = [m for m in maps if m['address'] <= start and start + length <= m['address'] + m['size']]
        assert len(matching) == 1
        mapping = matching[0]
        offset = mapping['fileOffset'] + start - mapping['address']
        assert offset >= 4096
        requests.append(dict(name=name, cache='27', offset=offset, length=length))
        rows.append(dict(owner=owner, actualDefinition=proof, actualCommands=p.pin(command_path),
                         actualTrie=image['trie'], metadataVA=address, firstNeededVA=start,
                         bytes=length, archivedOnlyMapping=mapping, fileOffset=offset,
                         fields=['VWT authenticated slot at metadata-8', 'metadata kind', 'descriptor authenticated slot'],
                         current27HeaderRequiredBeforeCapture=True, metadataOrVWTBytesAlreadyProven=False))
        inputs.extend([command_path, Path(image['trie']['path'])])
    request = out / 'request.json'
    p.save(request, dict(schema='bounded-current-iPad-POD-metadata-first-pointers-v1', ranges=requests))
    p.save(out / 'derivation.json', dict(schema='Actual trie to archived-only request mapping v1',
        actualMainCacheUUID='1995ea169d0a33a0b78962cf99891168',
        expected27UUID=archived[88:104].hex(), expected27Header=p.pin(archived_copy), archivedOnlyMaps=maps,
        records=rows, request=p.pin(request), requestedRanges=2, requestedBytes=48,
        archived27IsNotCurrentCapture=True, current27HeaderRequiredBeforeCapture=True,
        VWTFollowupMustUseCurrentReadPointers=True, deviceOperations=0, nativeExecuted=False))
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in inputs + [request, out / 'derivation.json']],
        deviceOperations=0, nativeExecuted=False))
    print(json.dumps(dict(request=p.pin(request), ranges=requests)))


if __name__ == '__main__':
    main()
