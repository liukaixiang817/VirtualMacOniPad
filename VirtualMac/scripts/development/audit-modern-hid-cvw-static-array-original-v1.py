#!/usr/bin/env python3
"""Bounded genuine CVW helper bytes and actual HID VWT/static ISA matrix."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cvw_genuine', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('cvw_helpers', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
SOURCE = p.NODE / 'universalhid-typedthrow-real-reexport-data-v1/candidate.json'
NAMES = ['_swift_cvw_' + suffix for suffix in ('initializeBufferWithCopyOfBuffer', 'destroy', 'initWithCopy',
    'assignWithCopy', 'initWithTake', 'assignWithTake', 'initStructMetadataWithLayoutString')]


def branch(pc, word):
    delta = (word & 0x3ffffff) << 2
    return pc + delta - (0x10000000 if delta & 0x8000000 else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for pin in json.loads((SOURCE.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
    source = json.loads(SOURCE.read_bytes())
    inputs = [p.pin(Path(__file__)), p.pin(Path(h.__file__)), p.pin(SOURCE),
              p.pin(p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-BytecodeLayouts.cpp')]
    matrices = []
    for image in source['images']:
        pin = image['candidate']
        raw = Path(pin['path']).read_bytes()
        imports = {row['index']: row for row in p.imports(raw)['imports']}
        counts, witnesses, arrays = collections.Counter(), [], []
        for row in p.chain_entries(raw):
            if not row['bind']:
                continue
            name = imports[row['import_index']]['name']
            if name in NAMES:
                counts[name] += 1
            if name == NAMES[0]:
                size, stride, flags, extra = struct.unpack_from('<QQII', raw, row['fileoff'] + 64)
                witnesses.append(dict(fileoff=row['fileoff'], originalVA=row['address'], pointerWord=row['word'],
                    authenticated=row['auth'], size=size, stride=stride, flags=flags, extraInhabitants=extra,
                    incomplete=bool(flags & 0x00400000), nonInline=bool(flags & 0x00020000)))
            if name.endswith('StaticArrayStorageCN'):
                sentinel, count, capacity = struct.unpack_from('<3Q', raw, row['fileoff'] + 8)
                assert sentinel == 0x80000004ffffffff and capacity == count * 2 and count > 0
                assert row['auth'] and (row['word'] >> 49 & 3) == 2 and (row['word'] >> 32 & 65535) == 0x6ae1 and (row['word'] >> 48 & 1)
                arrays.append(dict(fileoff=row['fileoff'], originalVA=row['address'], pointerWord=row['word'],
                                   actualISAImport=imports[row['import_index']], sentinel=sentinel, count=count, capacity=capacity,
                                   actualAddressDiverseDA2Discriminator=0x6ae1))
        assert len(witnesses) == (65 if image['name'] == 'UniversalHID' else 1)
        assert len(arrays) == (40 if image['name'] == 'UniversalHID' else 2)
        assert sum(row['incomplete'] for row in witnesses) == (1 if image['name'] == 'UniversalHID' else 0)
        matrices.append(dict(name=image['name'], candidate=pin, actualCVWBindCounts=dict(counts), actualBufferVWTs=witnesses,
                             actualStaticArrayISAs=arrays, genuineImmortalArrayHeadersVerified=True))
        inputs.append(pin)
    reads, functions = [], []
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        def read(address, size, purpose):
            assert 0 < size <= 1024 * 1024
            off, context = cache.convertAddr(address)
            data = context.getBytes(off, size)
            assert len(data) == size
            reads.append(dict(address=address, bytes=size, offset=off, cacheUUID=bytes(context.header.uuid).hex(),
                              sha256=hashlib.sha256(data).hexdigest(), purpose=purpose))
            return data
        exports = p.GenuineCacheExports(cache)
        core = exports.image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0'
        hdr = read(core['base'], 32, 'Core header extent')
        hdr = read(core['base'], 32 + struct.unpack_from('<I', hdr, 20)[0], 'complete genuine Core header')
        for command, at, size in h.commands(hdr):
            if command == 0x19 and hdr[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
                link, lfo = struct.unpack_from('<Q', hdr, at + 24)[0], struct.unpack_from('<Q', hdr, at + 40)[0]
            elif command == 0x26:
                off, length = struct.unpack_from('<II', hdr, at + 8)
        encoded = read(link + off - lfo, length, 'complete genuine Core function starts')
        starts, address, at = [], core['base'], 0
        while at < len(encoded):
            delta, at = h.uleb(encoded, at)
            if not delta:
                break
            address += delta
            starts.append(address)
        inverse = {core['base'] + value.address: name for name, value in core['exports'].items() if value.flags == 0}
        added = set()
        def capture(address, role):
            if address in added:
                return
            assert address in starts
            end = starts[starts.index(address) + 1]
            assert end - address <= 65536
            data = read(address, end - address, 'genuine CVW complete function: ' + role)
            file = out / ('Core-' + hex(address)[2:] + '.bin')
            file.write_bytes(data)
            edges = []
            for offset in range(0, len(data), 4):
                word = struct.unpack_from('<I', data, offset)[0]
                if word & 0xfc000000 in (0x94000000, 0x14000000):
                    destination = branch(address + offset, word)
                    if not address <= destination < end:
                        edges.append(dict(pc=address + offset, target=destination, directSymbol=inverse.get(destination),
                                          targetIsCoreFunctionStart=destination in starts))
            functions.append(dict(role=role, entry=address, nextStart=end, code=p.pin(file),
                                  instructions=h.decode_body(data, address), directOutgoingEdges=edges))
            inputs.append(p.pin(file))
            added.add(address)
        hookslots = []
        for name in NAMES:
            address = core['base'] + core['exports'][name].address
            capture(address, name)
            body = Path(functions[-1]['code']['path']).read_bytes()
            adrp_offset = 12 if name == NAMES[0] else 0
            adrp, load = struct.unpack_from('<2I', body, adrp_offset)
            assert adrp & 0x9f00001f == 0x90000008 and load & 0xffc003e0 == 0xf9400100
            immediate = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
            if immediate & 0x100000:
                immediate -= 0x200000
            slot = ((address + adrp_offset) & ~0xfff) + (immediate << 12) + ((load >> 10 & 0xfff) * 8)
            data = read(slot, 8, 'real CVW runtime function hook control ' + name)
            hookslots.append(dict(symbol=name, address=slot, raw=data.hex(), slotValue=struct.unpack('<Q', data)[0],
                                  copiedOrNilSynthesized=False, originalHookSemanticsNotBypassed=True))
        # These actual direct branch destinations are the native bytecode and
        # alternate witness delegates, not stand-in bodies invented from names.
        helper_addresses = {edge['target'] for fn in functions for edge in fn['directOutgoingEdges']
                            if edge['targetIsCoreFunctionStart'] and edge['directSymbol'] is None}
        helper_addresses.add(0x194e4b67c)  # actual ADRP+ADD address-taken buffer helper
        for address in sorted(helper_addresses):
            capture(address, 'genuine private CVW entry/delegate')
        for sub in subs:
            sub.close()
    report = dict(schema='Genuine HID compact value witness and static-array ISA audit v1',
        source=p.pin(SOURCE), inputs=inputs, localGenuineCacheReads=reads,
        originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalSwiftCoreUUID=core['UUID'],
        actualHIDMatrices=matrices, completeOriginalCVWEntriesAndFirstHelperBodies=functions,
        actualOriginalRuntimeHookControls=hookslots, originalEntryCount=7, actualStaticArrayISACount=42,
        originalCVWRuntimeHookSemanticsRequireSeparateClosure=True,
        actualIndirectDispatchTablesAndRecursiveHelpersClosed=False,
        incompleteDynamicVWTRequiresRealLayoutCompletion=True,
        ordinaryFactoryMetadataIsNotOriginalStaticCNData=True,
        generalMemcpyOrWrongMetadataAliasPermitted=False, originalDIKAndVZIdentityGuardsChanged=False,
        candidateReadyForNativeLoading=False, originalUHLoaded=False, originalVZLoaded=False,
        nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    p.save(out / 'freeze.json', dict(files=inputs + [p.pin(out / 'audit.json')], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), genuineFunctions=len(functions), actualStaticISAs=42)))


if __name__ == '__main__':
    main()
