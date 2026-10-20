"""Join the actual bounded libsystem_kernel command/trie captures only."""
import json
from pathlib import Path
import struct


def join(s, images):
    p = s.p
    headers = p.NODE / 'ipad-current-cache-pod-leaf-headers-v3/headers.json'
    commands = p.NODE / 'ipad-current-cache-kernel-commands-readonly-v1'
    exports = p.NODE / 'ipad-current-cache-kernel-exports-readonly-v1'
    cp = p.NODE / 'ipad-current-cache-kernel-commands-plan-v1/request.json'
    ep = p.NODE / 'ipad-current-cache-kernel-exports-plan-v1/request.json'
    report = p.NODE / 'current-kernel-two-pod-definitions-readonly-v1/audit.json'
    freeze = json.loads((report.parent / 'freeze.json').read_bytes())['files']
    for row in freeze:
        assert p.pin(Path(row['path'])) == row
    for directory, plan in ((commands, cp), (exports, ep)):
        receipt = s.checked_capture(directory, plan, headers)
        assert receipt['readerSHA256'] == p.pin(directory / 'reader-source.py')['sha256']
    header_path, trie_path = commands / 'libsystem-kernel-commands.bin', exports / 'libsystem-kernel-exports.bin'
    header = header_path.read_bytes()
    assert len(header) == 32 + struct.unpack_from('<I', header, 20)[0]
    path = uuid = export = None
    for command, at, size in p.commands(header):
        if command == 13:
            start = struct.unpack_from('<I', header, at + 8)[0]
            assert 24 <= start < size and b'\0' in header[at + start:at + size]
            path = header[at + start:at + size].split(b'\0')[0].decode()
        elif command == 27:
            uuid = header[at + 8:at + 24].hex()
        elif command == 0x80000033:
            export = struct.unpack_from('<II', header, at + 8)
    if export is None:
        dyld = [struct.unpack_from('<II', header, at + 40) for command, at, size in p.commands(header) if command == 0x80000022]
        assert len(dyld) == 1
        export = dyld[0]
    assert path == '/usr/lib/system/libsystem_kernel.dylib' and uuid == 'ff27fc8f90ba3332ab7ac5bc2d9ca7b1'
    segments = p.segments(header)
    text = next(x for x in segments if x['name'] == '__TEXT')
    link = next(x for x in segments if x['name'] == '__LINKEDIT')
    require = dict(name='libsystem-kernel-exports', cache='44-linkedit', offset=export[0], length=export[1])
    actual = json.loads(ep.read_bytes())['ranges']
    assert actual == [require] and export == (148522472, 30296)
    va = link['address'] + export[0] - link['fileoff']
    heads = json.loads(headers.read_bytes())
    matches = [(row, m) for row in heads['headers'] for m in row['maps'] if m['address'] <= va and va + export[1] <= m['address'] + m['size']]
    assert len(matches) == 1
    row, mapping = matches[0]
    assert row['name'] == require['cache'] and mapping['fileOffset'] + va - mapping['address'] == require['offset']
    tree = s.primary.trie(trie_path.read_bytes())
    assert len(tree) == 1478
    for symbol, offset in (('_vm_read_overwrite', 191204), ('_mach_task_self_', 438465968)):
        assert tree[symbol] == dict(symbol=symbol, flags=0, offsetOrAbsoluteAddress=offset)
        target = text['address'] + offset
        owner = [(member, m) for member in heads['headers'] for m in member['maps'] if m['address'] <= target < m['address'] + m['size']]
        assert len(owner) == 1
    key = s.primary.canonical_path(path)
    assert key not in images
    images[key] = dict(path=path, UUID=uuid, header=p.pin(header_path), trie=p.pin(trie_path),
        exports=tree, dependencies=p.dependencies(header), currentCapture=True)
    paths = [Path(__file__), headers, cp, ep, report, header_path, trie_path]
    for directory in (commands, exports):
        paths.extend(directory / name for name in ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py'))
    return [p.pin(path) for path in paths]
