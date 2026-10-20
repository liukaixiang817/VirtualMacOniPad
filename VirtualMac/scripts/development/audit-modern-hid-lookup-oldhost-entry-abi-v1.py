#!/usr/bin/env python3
"""Inspect exact UH/UHK signed lookup entries; parser equivalence stays unproved."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lookup_entry_read', HERE / 'audit-modern-coro-allocation-original-abi-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p, h = r.p, r.h
STATE = p.NODE / 'vz-state2-oldhost-entry-data-v1/candidate.json'
NAMES = ('_swift_getTypeByMangledNameInContext2', '_swift_getTypeByMangledNameInContextInMetadataState2')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    for row in json.loads((STATE.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    state = json.loads(STATE.read_bytes())
    provider = state['unchangedRuntimeProvider']['candidate']
    assert state['exactSixFileBackedProviderSectionsMatchReference']
    assert not state['fullSwift27ParserEquivalent'] and not state['allOriginalVZTypesProvenResolvable']
    inputs = [p.pin(x) for x in (Path(__file__), Path(h.__file__), STATE,
        p.ROOT / 'VirtualMac/vz/host/modern_swift_lookup_compat.cpp',
        p.ROOT / 'VirtualMac/vz/host/modern_swift_lookup_provider.cpp',
        p.ROOT / 'VirtualMac/vz/host/modern_swift_lookup_compat.h',
        p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-RuntimeFunctions.def')]
    calls = {}
    for framework in ('UniversalHID', 'UniversalHIDKit'):
        rawpath = h.ORIGINAL / 'raw' / framework
        memopath = h.ORIGINAL / (framework + '-symbols.a2s.batch.json')
        raw = rawpath.read_bytes()
        memo = json.loads(memopath.read_bytes())['symbols']
        targets = {int(a, 16): v[0] for a, v in memo.items() if v and v[0] in NAMES}
        assert targets == {0x2a0072430: NAMES[0], 0x2a0072440: NAMES[1]}
        found = []
        for section in h.sections(raw):
            if section['name'] != '__text':
                continue
            for delta in range(0, section['bytes'], 4):
                word = struct.unpack_from('<I', raw, section['fileoff'] + delta)[0]
                if word & 0xfc000000 != 0x94000000:
                    continue
                pc = section['address'] + delta
                target = r.branch_target(pc, word)
                if target not in targets:
                    continue
                code = raw[section['fileoff'] + delta - 64:section['fileoff'] + delta + 48]
                assert len(code) == 112
                if targets[target] == NAMES[0]:
                    assert list(struct.unpack_from('<2I', code, 56)) == [0xd2800002, 0xd2800003]
                    contract = dict(signedContext=None, genericArguments=None, parameters='x0=relative type name, x1=length, x2=null, x3=null')
                else:
                    assert list(struct.unpack_from('<3I', code, 52)) == [0x52801fe0, 0xd2800003, 0xd2800004]
                    contract = dict(metadataState=255, signedContext=None, genericArguments=None,
                                    parameters='x0=0xff, x1=relative type name, x2=length, x3=null, x4=null')
                found.append(dict(symbol=targets[target], pc=pc, stub=target, windowStart=pc - 64,
                                  code=code.hex(), instructions=h.decode_body(code, pc - 64), **contract))
        assert len(found) == 2 and {x['symbol'] for x in found} == set(NAMES)
        calls[framework] = found
        inputs += [p.pin(rawpath), p.pin(memopath)]
    reads = []
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
        core = p.GenuineCacheExports(cache).image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0'
        extent = read(core['base'], 32, 'Core header extent')
        header = read(core['base'], 32 + struct.unpack_from('<I', extent, 20)[0], 'complete Core header')
        for command, at, size in h.commands(header):
            if command == 0x19 and header[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
                link, fileoff = struct.unpack_from('<Q', header, at + 24)[0], struct.unpack_from('<Q', header, at + 40)[0]
            elif command == 0x26:
                offset, length = struct.unpack_from('<II', header, at + 8)
        encoded = read(link + offset - fileoff, length, 'complete exact Core function starts')
        at, value, starts = 0, core['base'], []
        while at < len(encoded):
            delta, at = h.uleb(encoded, at)
            if not delta:
                break
            value += delta
            starts.append(value)
        functions = []
        islands = []
        for name, stub in zip(NAMES, (0x2a0072430, 0x2a0072440)):
            export = core['exports'][name]
            assert export.flags == 0
            entry = core['base'] + export.address
            assert entry in starts
            end = starts[starts.index(entry) + 1]
            assert entry < end <= entry + 65536
            body = read(entry, end - entry, 'full genuine signed entry ' + name)
            path = out / (name.removeprefix('_') + '.bin')
            path.write_bytes(body)
            obj = out / (name.removeprefix('_') + '.inspection-only.macho-object')
            h.inspection_container(obj, entry, body)
            # Both entries contain the same real AUTDA/XPACD/compare/BRK path.
            assert list(struct.unpack_from('<7I', body, 8)) == [0xd296bc71, 0xdac11a30, 0xaa1003f1,
                0xdac147f1, 0xeb11021f, 0x54000040, 0xd4388e40]
            functions.append(dict(symbol=name, entry=entry, nextStart=end, code=p.pin(path), inspectionContainer=p.pin(obj),
                                  instructions=h.decode_body(body, entry)))
            inputs += [p.pin(path), p.pin(obj)]
            code = read(stub, 16, 'exact genuine call island ' + name)
            adrp, add, load, branch = struct.unpack('<4I', code)
            assert adrp & 0x9f00001f == 0x90000011
            assert add & 0xffc003ff == 0x91000231 and load == 0xf9400230 and branch == 0xd71f0a11
            immediate = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
            if immediate & 0x100000:
                immediate -= 0x200000
            slot = (stub & ~0xfff) + (immediate << 12) + (add >> 10 & 0xfff)
            off, context = cache.convertAddr(slot)
            mapping = next(m for m, c in cache.mappings if c is context and m.address <= slot < m.address + m.size)
            index = context.mappings.index((mapping, context))
            expanded = h.dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset + index * h.dyld_cache_mapping_and_slide_info.SIZE)
            slide = h.dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
            assert slide.version == 5
            page = (slot - expanded.address) // slide.page_size
            start = context.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page * 2)[0]
            assert start != 0xffff
            pageoff = expanded.fileOffset + page * slide.page_size
            cursor = pageoff + start
            for _ in range(slide.page_size // 8):
                assert pageoff <= cursor <= pageoff + slide.page_size - 8
                word = context.readFormat('<Q', cursor)[0]
                target, auth, key, diversity, addressdiversity, delta = h.decodeV5Pointer(word, slide.value_add)
                if cursor == off:
                    break
                assert delta and cursor < off
                cursor += delta
            else:
                raise AssertionError('actual call slot not in original slide chain')
            assert target == entry and auth and key == 0 and addressdiversity
            islands.append(dict(stub=stub, instructions=code.hex(), slot=slot, pointerWord=word,
                target=target, auth=auth, key=key, diversity=diversity, addressDiversity=addressdiversity,
                exactOriginalExportMatched=True, exactSlide5MembershipVerified=True))
        for sub in subs:
            sub.close()
    report = dict(schema='Exact four HID signed lookup old-host entry ABI audit v1',
        originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalSwiftCoreUUID=core['UUID'],
        sourceLimitedState2Candidate=p.pin(STATE), wholeActualOldHostProvider=provider, inputs=inputs,
        reads=reads, actualOriginalFunctions=functions, exactAuthenticatedCallIslands=islands, originalCallers=calls,
        callerSignedContextsAndGenericArgumentsAllNull=True, externalSwiftCCAndPACEntryABICompatible=True,
        sourceLookupGuardsUnchanged=True, existingProviderSixSectionsVerifiedByPinnedState2Candidate=True,
        typeQueriesThroughSharedCallerHelpersStillRequireFullNameSchemaAudit=True,
        compatibilityScope='finite genuine old-host authenticated entry delegation only; nullable lookup result and metadata state retained',
        fullSwift27ParserEquivalent=False, allOriginalHIDTypesProvenResolvable=False,
        fullCurrentLoadGraphProven=False, metadataCompatibilityProven=False,
        originalUHLoaded=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    inputs += [provider, p.pin(out / 'audit.json')]
    p.save(out / 'freeze.json', dict(files=inputs, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), originalCallers=4, exactEntryABI=True, fullParser=False)))


if __name__ == '__main__':
    main()
