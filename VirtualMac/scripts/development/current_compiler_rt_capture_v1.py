"""Join current compiler_rt commands and its literal named upward export alias.

The upward dependency is followed only for the exact flags8 export. It never
participates in generic reexport searches. All bytes come from prior actual
bounded reads; this helper performs no device operations.
"""
import copy
import json
from pathlib import Path
import struct
from current_hid_extra_three_capture_v1 import commands, inventory, mapping


def join(s, images):
    p, n = s.p, s.p.NODE
    hp = n/'ipad-current-cache-swift-leaf-headers-v1/headers.json'
    headers = json.loads(hp.read_bytes()); assert len(headers['headers']) == 12
    assert p.pin(hp)['sha256'] == '14f615bb9d0ba7f82e4ac7f651573c34083d08bca5db46c4ebd30edfeff52343'
    latest = json.loads((n/'ipad-current-cache-trace-header-readonly-v1/headers.json').read_bytes())
    for row in headers['headers']:
        now = next(x for x in latest['headers'] if x['name'] == row['name'])
        assert all(now[key] == row[key] for key in ('UUID', 'sha256', 'maps'))
    pins = [p.pin(Path(__file__)), p.pin(hp)]
    captures = []
    for directory, request in (
        ('ipad-current-iokit-methods-stackprobe-readonly-v1', 'ipad-current-iokit-methods-stackprobe-plan-v1/request.json'),
        ('ipad-current-static-cn-stackprobe-fullbody-readonly-v1', 'ipad-current-static-cn-stackprobe-fullbody-plan-v1/request.json')):
        directory, request = n/directory, n/request
        receipt = s.checked_capture(directory, request, hp)
        assert receipt['readerSHA256'] == p.pin(directory/'reader-source.py')['sha256'] == '6c57415095485a5e29a9ff856582bbe9373cf52afd765a964cb70914c9022ccc'
        assert json.loads((directory/'manifest.json').read_bytes()) == json.loads(request.read_bytes())
        script = (directory/'script.sh').read_text()
        involved = {'main'} | {x['cache'] for x in receipt['ranges']}
        assert all(script.count(row['sha256']) == 2 for row in headers['headers'] if row['name'] in involved)
        captures.append((directory, receipt))
        pins += [p.pin(x) for x in [request]+[directory/name for name in
                 ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]+
                 [Path(row['path']) for row in receipt['ranges']]]
    prefix = captures[0][0]/'compiler-rt-header-prefix.bin'
    trie_path = captures[1][0]/'compiler-rt-exports.bin'
    raw = prefix.read_bytes(); assert len(raw) == 4096
    size = 32+struct.unpack_from('<I', raw, 20)[0]; assert size == 1864
    raw = raw[:size]
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    table = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    actual = [row for row in table if row['path'] == '/usr/lib/system/libcompiler_rt.dylib']
    assert len(actual) == 1 and actual[0]['UUID'] == '40b763c8a78c35dda61b996b5296486f'
    parsed = commands(p, raw, actual[0])
    prefix_row = next(x for x in captures[0][1]['ranges'] if x['path'] == str(prefix))
    export_row = next(x for x in captures[1][1]['ranges'] if x['path'] == str(trie_path))
    assert mapping(headers, actual[0]['address'], 4096) == {k:prefix_row[k] for k in ('cache','offset','length')}
    assert mapping(headers, parsed['exportVA'], parsed['exportLength']) == {k:export_row[k] for k in ('cache','offset','length')}
    assert parsed['exportLength'] == len(trie_path.read_bytes()) == 1112
    exports = s.primary.trie(trie_path.read_bytes())
    for item in exports.values():
        if item['flags'] & 8:
            assert 1 <= item['ordinal'] <= len(parsed['dependencies'])
    upward = parsed['dependencies'][3]
    assert upward['ordinal'] == 4 and upward['command'] == 0x80000023 and upward['path'] == '/usr/lib/system/libsystem_pthread.dylib'
    named = exports['___chkstk_darwin']
    assert named == dict(symbol='___chkstk_darwin', flags=8, ordinal=4, importedName='____chkstk_darwin')
    libsystem = images[s.primary.canonical_path('/usr/lib/libSystem.B.dylib')]
    dependency = next(x for x in libsystem['dependencies'] if x['path'] == parsed['path'])
    assert dependency['command'] == 0x8000001f
    key = s.primary.canonical_path(parsed['path']); assert key not in images
    images[key] = dict(path=parsed['path'], UUID=parsed['UUID'], header=p.pin(prefix),
        completeCommandSliceBytes=size, trie=p.pin(trie_path), exports=exports,
        dependencies=parsed['dependencies'], currentCapture=True)
    proof = s.primary.resolve(images, '/usr/lib/libSystem.B.dylib', '___chkstk_darwin')
    assert proof['status'] == 'actualDirectExport' and proof['reexportDependency'] == dependency
    assert proof['nested']['namedReexport'] == named
    leaf = proof['nested']['nested']
    assert leaf['owner'] == upward['path'] and leaf['export'] == dict(symbol='____chkstk_darwin', flags=0, offsetOrAbsoluteAddress=2984)
    negatives = []
    for label, wrong in [('wrong UUID', dict(actual[0], UUID='0'*32)),
                          ('wrong name', dict(actual[0], path='/wrong')),
                          ('wrong base', dict(actual[0], address=actual[0]['address']+4)),
                          ('wrong text extent', dict(actual[0], textSize=actual[0]['textSize']+4))]:
        try: commands(p, raw, wrong)
        except (AssertionError, ValueError): negatives.append(dict(name=label, rejected=True))
        else: raise AssertionError('wrong compiler_rt identity accepted')
    for label, damaged in [('truncated commands', raw[:-1]), ('extra commands', raw+b'\0')]:
        try: commands(p, damaged, actual[0])
        except (AssertionError, ValueError): negatives.append(dict(name=label, rejected=True))
        else: raise AssertionError('wrong compiler_rt command extent accepted')
    for label, mutation in [('literal alias spelling', dict(named, importedName='___chkstk_darwin')),
                             ('wrong alias ordinal', dict(named, ordinal=3))]:
        damaged = copy.deepcopy(images); damaged[key]['exports']['___chkstk_darwin'] = mutation
        assert s.primary.resolve(damaged, parsed['path'], '___chkstk_darwin')['status'] != 'actualDirectExport'
        negatives.append(dict(name=label, rejected=True))
    assert '____chkstk_darwin' not in images[key]['exports']
    before = s.primary.resolve(images, parsed['path'], '____chkstk_darwin')
    assert before['status'] == 'actualExportAbsent'
    assert s.primary.resolve(images, upward['path'], '____chkstk_darwin')['status'] == 'actualDirectExport'
    negatives.append(dict(name='upward does not authorize generic search', rejected=True))
    pins += [p.pin(x) for x in (archive, tail, prefix, trie_path)]
    return pins, dict(actualPath=parsed['path'], actualUUID=parsed['UUID'], inventoryRow=actual[0],
        capturedPrefix=p.pin(prefix), completeCommandSliceBytes=size, trie=p.pin(trie_path),
        exportCount=len(exports), dependencies=parsed['dependencies'], actualLibSystemReexport=dependency,
        actualNamedAliasUpwardDependency=upward, exactLiteralNamedExport=named,
        actualNativeStackProbeDefinition=proof, negativeControls=negatives,
        exactCurrentDefinitionEvidenceOnly=True, genericUpwardReexportSearchAllowed=False,
        actualReceipts=[p.pin(directory/'receipt.json') for directory, _ in captures],
        newlyDeclaredNativeImages=1, providerLoaded=False, deviceOperations=0, full27Backend=False)
