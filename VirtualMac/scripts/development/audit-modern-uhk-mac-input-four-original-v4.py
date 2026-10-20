#!/usr/bin/env python3
"""Read the four genuine UHK macOS input dependencies and their real callers.

This never loads a provider or invokes an event API. It records complete LC26
function bounds, authenticated island bindings and class-reference loads.
Class names alone are not evidence that an iOS replacement is compatible.
"""
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('macinput_p', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('macinput_h', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
UHK = '/System/Library/PrivateFrameworks/UniversalHIDKit.framework/Versions/A/UniversalHIDKit'
SL = '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'
APPKIT = '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit'
NAMES = ('_SLEventGetDoubleValueField', '_SLEventGetIntegerValueField', '_OBJC_CLASS_$_NSEvent', '_OBJC_CLASS_$_NSTouch')


def branch(pc, word):
    delta = (word & 0x3ffffff) << 2
    return pc + delta - (0x10000000 if delta & 0x8000000 else 0)


def adrp(pc, word):
    if word & 0x9f000000 != 0x90000000:
        return None
    delta = ((word >> 5 & 0x7ffff) << 2) | (word >> 29 & 3)
    if delta & 0x100000:
        delta -= 0x200000
    return (word & 31), (pc & ~0xfff) + (delta << 12)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    reads, by_read, images, pages, ptrs, functions = [], {}, {}, {}, {}, {}
    pins = [p.pin(Path(__file__)), p.pin(Path(p.__file__)), p.pin(Path(h.__file__))]
    contract_path = p.ORIGINAL / 'original-contract.json'
    contract = json.loads(contract_path.read_bytes())
    facts = next(r for r in contract['providers'] if r['name'] == 'UniversalHIDKit')
    assert facts['UUID'] == 'e6801a30bcfe35eb9c88206d35fa1397'
    raw_path = p.ORIGINAL / 'raw/UniversalHIDKit'
    raw = raw_path.read_bytes()
    assert p.pin(raw_path) == facts['extractedRaw']
    pins += [p.pin(contract_path), p.pin(raw_path)]
    text_section = next(r for r in h.sections(raw) if r['name'] == '__text')
    code = raw[text_section['fileoff']:text_section['fileoff'] + text_section['bytes']]
    assert len(code) == 37864 and len(code) % 4 == 0
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        try:
            genuine = p.GenuineCacheExports(cache)
            def read(va, size, purpose):
                assert 0 < size <= 2 * 1024 * 1024
                if (va, size) in by_read:
                    return by_read[(va, size)][0]
                off, ctx = cache.convertAddr(va)
                body = ctx.getBytes(off, size)
                assert len(body) == size
                path = out / ('read-%04d.bin' % len(reads))
                path.write_bytes(body)
                row = dict(address=va, bytes=size, purpose=purpose, physicalUUID=bytes(ctx.header.uuid).hex(),
                           offset=off, data=p.pin(path))
                reads.append(row); pins.append(row['data']); by_read[(va, size)] = (body, row)
                return body
            def image(owner):
                if owner not in images:
                    item = genuine.image(owner)
                    prefix = read(item['base'], 32, owner + ': command extent')
                    header = read(item['base'], 32 + struct.unpack_from('<I', prefix, 20)[0], owner + ': full commands')
                    parsed = p.contract_reader.parse(header)
                    assert parsed['UUID'] == item['UUID']
                    link = next(r for r in p.segments(header) if r['name'] == '__LINKEDIT')
                    start_off, start_size = next(struct.unpack_from('<II', header, at + 8)
                        for cmd, at, size in p.commands(header) if cmd == 0x26)
                    encoded = read(link['address'] + start_off - link['fileoff'], start_size, owner + ': LC26')
                    starts, cursor, va = [], 0, item['base']
                    while cursor < len(encoded):
                        delta, cursor = h.uleb(encoded, cursor)
                        if not delta:
                            break
                        va += delta; starts.append(va)
                    assert starts == sorted(set(starts)) and encoded[cursor:] == b'\0' * (len(encoded) - cursor)
                    images[owner] = dict(item=item, header=header, starts=starts)
                return images[owner]
            def capture(owner, va):
                im = image(owner)
                index = bisect.bisect_right(im['starts'], va) - 1
                assert 0 <= index < len(im['starts']) - 1
                begin, end = im['starts'][index:index + 2]
                assert begin <= va < end and end - begin <= 65536
                if (owner, begin) not in functions:
                    body = read(begin, end - begin, owner + ': exact function')
                    functions[(owner, begin)] = dict(owner=owner, start=begin, end=end, exactLC26Bounds=True,
                        data=by_read[(begin, end - begin)][1]['data'], instructions=h.decode_body(body, begin))
                return functions[(owner, begin)]
            def pointer(va):
                off, ctx = cache.convertAddr(va)
                mapping = next(m for m, c in cache.mappings if c is ctx and m.address <= va < m.address + m.size)
                number = ctx.mappings.index((mapping, ctx))
                expanded = h.dyld_cache_mapping_and_slide_info(ctx.file, ctx.header.mappingWithSlideOffset + number * h.dyld_cache_mapping_and_slide_info.SIZE)
                slide = h.dyld_cache_slide_info5(ctx.file, expanded.slideInfoFileOffset)
                assert slide.version == 5 and slide.page_size in (4096, 16384)
                page_index = (va - expanded.address) // slide.page_size
                page_va = expanded.address + page_index * slide.page_size
                identity = (id(ctx), number, page_index)
                if identity not in pages:
                    start_raw = read(page_va, slide.page_size, 'actual slide5 full page')
                    chain_start = ctx.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page_index * 2)[0]
                    assert chain_start != 0xffff
                    nodes, cursor = {}, chain_start
                    for _ in range(slide.page_size // 8):
                        assert 0 <= cursor <= len(start_raw) - 8
                        word = struct.unpack_from('<Q', start_raw, cursor)[0]
                        target, auth, key, div, addr_div, delta = h.decodeV5Pointer(word, slide.value_add)
                        nodes[page_va + cursor] = dict(slot=page_va + cursor, word=word, target=target, auth=bool(auth),
                            key=key, diversity=div, addressDiversity=bool(addr_div), nextBytes=delta,
                            actualPageStart=chain_start, actualSlideValueAdd=slide.value_add,
                            actualSlide5ChainMembership=True, actualPage=by_read[(page_va, slide.page_size)][1]['data'])
                        if delta == 0:
                            break
                        assert delta > 0; cursor += delta
                    else:
                        raise ValueError('unterminated actual slide5 page')
                    pages[identity] = nodes
                row = pages[identity][va]
                ptrs[va] = row
                return row
            definitions = [genuine.resolve(SL if name.startswith('_SLEvent') else APPKIT, name) for name in NAMES]
            assert all(r and r['exportFlags'] == 0 for r in definitions)
            uhk = image(UHK)
            assert uhk['item']['UUID'] == facts['UUID'] and uhk['item']['base'] == facts['base']
            native_section = next(r for g in p.segments(uhk['header']) for r in g['sections'] if r['name'] == '__text')
            assert native_section['address'] == text_section['address'] and native_section['size'] == len(code)
            actual_code = read(native_section['address'], native_section['size'], 'genuine UHK full original text')
            extracted_text_matches_current_original = actual_code == code
            code = actual_code
            for row in definitions[:2]:
                capture(row['exportPath'], row['exportAddress'])
            target_names = {row['exportAddress']: row['exportedSymbol'] for row in definitions[:2]}
            branches = {}
            for delta in range(0, len(code), 4):
                pc = text_section['address'] + delta
                word = struct.unpack_from('<I', code, delta)[0]
                if word & 0xfc000000 in (0x94000000, 0x14000000):
                    dest = branch(pc, word)
                    if not text_section['address'] <= dest < text_section['address'] + len(code):
                        branches.setdefault(dest, []).append(pc)
            islands, edges = [], []
            for dest, callers in sorted(branches.items()):
                body = read(dest, 16, 'UHK external branch prefix')
                w = struct.unpack('<4I', body)
                page = adrp(dest, w[0])
                if page is None or page[0] != 17 or w[1] & 0xffc003ff != 0x91000231 or w[2:] != (0xf9400230, 0xd71f0a11):
                    continue
                slot = page[1] + (w[1] >> 10 & 0xfff)
                binding = pointer(slot)
                if binding['target'] not in target_names:
                    continue
                name = target_names[binding['target']]
                assert binding['auth'] and binding['key'] == 0 and binding['addressDiversity']
                islands.append(dict(address=dest, symbol=name, slot=slot, binding=binding,
                    data=by_read[(dest, 16)][1]['data'], instructions=h.decode_body(body, dest)))
                for pc in callers:
                    function = capture(UHK, pc)
                    edges.append(dict(pc=pc, island=dest, symbol=name, functionStart=function['start']))
            p.save(out / 'branch-bindings-progress.json', dict(definitions=definitions, pointers=list(ptrs.values()), branches=branches, reads=reads, matchingIslands=islands, matchingEdges=edges, accepted=False))
            assert {r['symbol'] for r in edges} == set(NAMES[:2]), (len(branches), len(islands), edges)
            memo_path = p.ORIGINAL / 'UniversalHIDKit-symbols.a2s.batch.json'
            memo = json.loads(memo_path.read_bytes())['symbols']; pins.append(p.pin(memo_path))
            class_slots = {int(va, 16): row[0][6:] for va, row in memo.items()
                           if row[0] in ('__got.' + NAMES[2], '__got.' + NAMES[3])}
            assert len(class_slots) == 2
            class_refs = []
            for slot, name in class_slots.items():
                binding = pointer(slot)
                assert binding['target'] == next(r['exportAddress'] for r in definitions if r['exportedSymbol'] == name)
                for delta in range(0, len(code), 4):
                    pc = text_section['address'] + delta
                    page = adrp(pc, struct.unpack_from('<I', code, delta)[0])
                    if page is None:
                        continue
                    for distance in range(4, min(28, len(code) - delta), 4):
                        word = struct.unpack_from('<I', code, delta + distance)[0]
                        if word & 0xffc00000 == 0xf9400000 and word >> 5 & 31 == page[0]:
                            address = page[1] + (word >> 10 & 0xfff) * 8
                            if address == slot:
                                function = capture(UHK, pc)
                                class_refs.append(dict(symbol=name, slot=slot, binding=binding, adrpPC=pc,
                                    loadPC=pc + distance, resultRegister=word & 31, functionStart=function['start']))
            assert {r['symbol'] for r in class_refs} == set(NAMES[2:])
            summary = dict(schema='Genuine original UHK four macOS input dependencies readonly v4',
                cacheUUID=contract['cacheUUID'], originalUHKUUID=facts['UUID'], originalUHKRaw=facts['extractedRaw'],
                originalText=text_section, extractedTextMatchesCurrentOriginal=extracted_text_matches_current_original,
                actualText=by_read[(native_section['address'], native_section['size'])][1]['data'], definitions=definitions, originalIslandBindings=islands,
                actualSLEventCallers=edges, actualObjCClassLoads=class_refs,
                functions=list(functions.values()), actualPointers=list(ptrs.values()), reads=reads,
                sourceReadOnly=True, originalProviderLoaded=False, eventAPIsExecuted=False,
                classMethodABIClosureProven=False, currentIOSInputCompatibilityProven=False,
                nativeIOSExecuted=False, deviceOperations=0, nativeCPUCalls=0, full27Backend=False)
            p.save(out / 'audit.json', summary)
            pins.append(p.pin(out / 'audit.json'))
            p.save(out / 'freeze.json', dict(files=pins, deviceOperations=0, nativeIOSExecuted=False))
            print(json.dumps(dict(audit=p.pin(out / 'audit.json'), SLCallers=len(edges),
                classLoads=len(class_refs), completeFunctions=len(functions), reads=len(reads))))
        finally:
            for ctx in subs:
                ctx.close()


if __name__ == '__main__':
    main()
