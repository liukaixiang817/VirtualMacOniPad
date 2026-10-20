#!/usr/bin/env python3
"""Supplement frozen IOKit initializer evidence with the actual current malloc definition."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('iokit_actual_allocation', HERE/'plan-modern-iokit-native-allocation-chain-v1.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
s, p, ro = a.s, a.p, a.ro
from current_hid_extra_three_capture_v1 import commands, inventory, join, mapping


def reject(negatives, label, operation):
    try:
        operation()
    except (AssertionError, ValueError, struct.error):
        negatives.append(dict(name=label, rejected=True))
    else:
        raise AssertionError('accepted negative: '+label)


def definition_at(base, entry, expected):
    assert entry['flags'] == 0 and 'ordinal' not in entry
    assert base + entry['offsetOrAbsoluteAddress'] == expected


def main():
    n = p.NODE
    out = n/'iokit-current-malloc-definition-readonly-v1'
    assert not out.exists()
    previous_path = n/'iokit-native-double-initializer-readonly-v3/audit.json'
    previous = json.loads(previous_path.read_bytes())
    assert p.pin(previous_path)['sha256'] == '40afdf39c97741e31a4d2aa5c0e5d262b73e959320fb717523abb22562cf8810'
    assert previous['actualMallocNamedDefinitionCaptured'] is False
    pins = [p.pin(previous_path)]
    for pin in json.loads((previous_path.parent/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
        pins.append(pin)
    pins.append(p.pin(previous_path.parent/'freeze.json'))
    images = {}
    pins += s.join_capture(images, 'system', n/'ipad-current-cache-system-headers-v1/headers.json')
    extra, _ = join(s, images)
    pins += extra
    hp = n/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    headers = json.loads(hp.read_bytes())
    assert p.pin(hp)['sha256'] == '8bdfbfcdcf35e4e070bdb1142613dfc88d82d9f63cec18e4ff906818d13d58ba'
    captures = []
    for directory, plan in [('ipad-current-vz-eight-native-commands-readonly-v1', 'ipad-current-vz-eight-native-commands-plan-v1'),
                            ('ipad-current-vz-native-tails-two-exports-readonly-v1', 'ipad-current-vz-native-tails-two-exports-plan-v1')]:
        directory, manifest = n/directory, n/plan/'request.json'
        receipt = s.checked_capture(directory, manifest, hp)
        assert receipt['readerSHA256'] == p.pin(directory/'reader-source.py')['sha256'] == 'ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
        captures.append((directory, receipt))
        pins += [p.pin(path) for path in [manifest, hp]+[directory/name for name in
                  ('receipt.json', 'manifest.json', 'script.sh', 'stdout', 'stderr', 'reader-source.py')]+
                  [Path(row['path']) for row in receipt['ranges']]]
    archive = n.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin'
    tail = n/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    rows = inventory(archive.read_bytes()[:4096], tail.read_bytes(), headers)
    expected = [row for row in rows if row['path'] == '/usr/lib/system/libsystem_malloc.dylib']
    assert len(expected) == 1
    expected = expected[0]
    old = images[s.primary.canonical_path(expected['path'])]
    assert old['UUID'] == expected['UUID'] == '39fb1f8c48ef3dd08d74ff55e8d07c60'
    prefix = captures[0][0]/'system-malloc-commands-prefix.bin'
    complete = n/'ipad-current-vz-six-native-exports-plan-v1/complete-commands/system-malloc-commands.bin'
    raw = complete.read_bytes()
    assert len(raw) == 2904 and prefix.read_bytes()[:len(raw)] == raw
    prefix_range = [row for row in captures[0][1]['ranges'] if row['name'] == 'system-malloc-commands-prefix']
    assert len(prefix_range) == 1
    assert {key: prefix_range[0][key] for key in ('cache', 'offset', 'length')} == mapping(headers, expected['address'], 4096)
    parsed = commands(p, raw, expected)
    trie = captures[1][0]/'system-malloc-exports.bin'
    trie_range = [row for row in captures[1][1]['ranges'] if row['name'] == 'system-malloc-exports']
    assert len(trie_range) == 1
    assert {key: trie_range[0][key] for key in ('cache', 'offset', 'length')} == mapping(headers, parsed['exportVA'], parsed['exportLength'])
    exports = s.primary.trie(trie.read_bytes())
    assert len(exports) == 104 and len(trie.read_bytes()) == parsed['exportLength'] == 2544
    assert Path(old['header']['path']).read_bytes() == raw
    assert Path(old['trie']['path']).read_bytes() == trie.read_bytes() and old['exports'] == exports
    assert old['dependencies'] == parsed['dependencies']
    slide = n/'ipad-current-iokit-native-initializer-chains-readonly-v2/iokit-message-dispatch-slide-header.bin'
    cc = n/'ipad-current-iokit-native-allocation-chain-readonly-v1'
    chain = ro.chain((cc/'iokit-event-allocation-chain-prefix.bin').read_bytes(),
                     struct.unpack('<H', (cc/'iokit-event-allocation-page-start.bin').read_bytes())[0],
                     0x1e22da000, slide.read_bytes(), [0x1e22da8b8])
    pointer = chain['requestedSlots'][0]
    ro.expected_auth(pointer, 0, 0)
    assert chain == previous['actualMallocGOTChain'] and pointer['target'] == 0x195110e54
    malloc = exports['_malloc']
    definition_at(parsed['text']['address'], malloc, pointer['target'])
    assert s.primary.resolve(images, expected['path'], '_malloc')['status'] == 'actualDirectExport'
    negatives = []
    for label, altered in [('wrong UUID', dict(expected, UUID='0'*32)),
                           ('wrong install name', dict(expected, path='/wrong')),
                           ('wrong text base', dict(expected, address=expected['address']+4)),
                           ('wrong text extent', dict(expected, textSize=expected['textSize']+4))]:
        reject(negatives, label, lambda altered=altered: commands(p, raw, altered))
    for label, altered in [('truncated commands', raw[:-1]), ('added commands', raw+b'\0')]:
        reject(negatives, label, lambda altered=altered: commands(p, altered, expected))
    for label, altered in [('weak definition flag', dict(malloc, flags=4)),
                           ('reexport flag', dict(malloc, flags=8, ordinal=1)),
                           ('different target RVA', dict(malloc, offsetOrAbsoluteAddress=malloc['offsetOrAbsoluteAddress']+4))]:
        reject(negatives, label, lambda altered=altered: definition_at(parsed['text']['address'], altered, pointer['target']))
    reject(negatives, 'wrong authenticated GOT target', lambda: definition_at(parsed['text']['address'], malloc, pointer['target']+4))
    out.mkdir(mode=0o700)
    p.save(out/'exports.json', exports)
    p.save(out/'audit.json', dict(schema='Actual current malloc named definition and captured IOKit PAC target supplement v1',
        previousFrozenInitializerAudit=p.pin(previous_path), previousAuditPreservedWhole=True,
        actualCurrentMallocInventoryRow=expected, actualCurrentMallocCommands=p.pin(complete),
        actualCurrentMallocTrie=p.pin(trie), actualExportCount=104, actualDefinition=malloc,
        actualDefinitionAddress=parsed['text']['address']+malloc['offsetOrAbsoluteAddress'],
        actualCapturedIOKitGOTChain=chain, actualNamedDefinitionMatchesGenuineInitializerGOT=True,
        olderActualCaptureCommandsAndTrieWholeBytesMatchNewActualCapture=True,
        olderDefinitionTableAlreadyDeclared=True, newlyDeclaredNativeImages=0,
        actualCaptureReceipts=[p.pin(directory/'receipt.json') for directory, _ in captures],
        negativeControls=negatives, definitionEvidenceOnly=True,
        actualMallocFunctionExecuted=False, actualIOKitNewTypesKernelConsumerProven=False,
        actualIOKitConstructorsExecuted=False, originalHIDLoaded=False, originalVZLoaded=False,
        deviceOperations=0, nativeCPUCalls=0, frameworkLoads=0, full27Backend=False))
    (out/'source.py').write_bytes(Path(__file__).read_bytes())
    pins += [p.pin(path) for path in [archive, tail, prefix, complete, trie, slide,
              cc/'iokit-event-allocation-chain-prefix.bin', cc/'iokit-event-allocation-page-start.bin',
              Path(__file__), out/'audit.json', out/'exports.json', out/'source.py']]
    unique = {}
    for pin in pins:
        if pin['path'] in unique:
            assert unique[pin['path']] == pin
        unique[pin['path']] = pin
    p.save(out/'freeze.json', dict(files=list(unique.values()), deviceOperations=0, full27Backend=False))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), freeze=p.pin(out/'freeze.json'),
                          actualMallocVA=pointer['target'], negativeControls=len(negatives), uniquePins=len(unique))))


if __name__ == '__main__':
    main()
