#!/usr/bin/env python3
"""Capture original IOKit three-symbol machine, object and UH caller contracts.

No provider is built or loaded. Current old-host allocation/initializer ABI is
an explicit independent boundary, even when its named export already exists.
"""
import argparse
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_original_p', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('iokit_original_h', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
OWNER = '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
UH = '/System/Library/PrivateFrameworks/UniversalHID.framework/Versions/A/UniversalHID'
NAMES = ('_IOHIDEventCreateForceStageEvent', '_IOHIDEventCreateTouchSensitiveButtonEventWithRadius',
         '_kIOHIDServiceRequestTerminateKey')


def branch(pc, word):
    displacement = (word & 0x3ffffff) << 2
    return pc + displacement - (0x10000000 if displacement & 0x8000000 else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    pins = [p.pin(Path(__file__)), p.pin(Path(p.__file__)), p.pin(Path(h.__file__))]
    reads, pointers, functions, images, pages = [], [], {}, {}, {}
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        try:
            genuine = p.GenuineCacheExports(cache)
            def read(address, size, name):
                assert 0 < size <= 2 * 1024 * 1024
                offset, context = cache.convertAddr(address)
                body = context.getBytes(offset, size)
                assert len(body) == size
                path = out / (name + '.bin')
                assert not path.exists()
                path.write_bytes(body)
                record = dict(address=address, bytes=size, originalCacheUUID=bytes(context.header.uuid).hex(),
                              fileOffset=offset, data=p.pin(path))
                reads.append(record); pins.append(record['data'])
                return body
            def text(address, name):
                body = read(address, 128, name)
                at = body.find(b'\0')
                assert 0 < at < len(body)
                return body[:at].decode()
            def pointer(address):
                offset, context = cache.convertAddr(address)
                mapping = next(m for m, c in cache.mappings if c is context and m.address <= address < m.address + m.size)
                number = context.mappings.index((mapping, context))
                expanded = h.dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset + number * h.dyld_cache_mapping_and_slide_info.SIZE)
                slide = h.dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
                assert slide.version == 5 and slide.page_size in (4096, 16384)
                page = (address - expanded.address) // slide.page_size
                page_va = expanded.address + page * slide.page_size
                identity = (bytes(context.header.uuid).hex(), page_va)
                if identity not in pages:
                    start = context.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page * 2)[0]
                    assert start != 0xffff
                    body = read(page_va, slide.page_size, 'original-slide5-page-' + hex(page_va)[2:])
                    rows, cursor = {}, start
                    for _ in range(slide.page_size // 8):
                        assert 0 <= cursor <= len(body) - 8
                        word = struct.unpack_from('<Q', body, cursor)[0]
                        target, auth, key, diversity, addr, delta = h.decodeV5Pointer(word, slide.value_add)
                        rows[page_va + cursor] = dict(slot=page_va + cursor, word=word, target=target, auth=bool(auth),
                            key=key, diversity=diversity, addressDiversity=bool(addr), nextBytes=delta,
                            actualSlide5ChainMembership=True, actualSlideValueAdd=slide.value_add,
                            actualPageStart=start, actualPage=reads[-1]['data'])
                        if not delta:
                            break
                        assert delta > 0
                        cursor += delta
                    else:
                        raise ValueError('unterminated original slide5 page')
                    pages[identity] = rows
                row = pages[identity][address]
                if not any(x['slot'] == address for x in pointers): pointers.append(row)
                return row
            def image(path):
                if path not in images:
                    item = genuine.image(path)
                    prefix = read(item['base'], 32, 'original-' + Path(path).name + '-header-prefix')
                    header = read(item['base'], 32 + struct.unpack_from('<I', prefix, 20)[0], 'original-' + Path(path).name + '-commands')
                    link = next(x for x in p.segments(header) if x['name'] == '__LINKEDIT')
                    off, size = next(struct.unpack_from('<II', header, at + 8) for cmd, at, sz in p.commands(header) if cmd == 0x26)
                    encoded = read(link['address'] + off - link['fileoff'], size, 'original-' + Path(path).name + '-function-starts')
                    starts, cursor, address = [], 0, item['base']
                    while cursor < len(encoded):
                        delta, cursor = h.uleb(encoded, cursor)
                        if not delta: break
                        address += delta; starts.append(address)
                    assert starts == sorted(set(starts)) and encoded[cursor:] == b'\0' * (len(encoded) - cursor)
                    images[path] = dict(item=item, header=header, starts=starts)
                return images[path]
            def capture(path, address):
                row = image(path)
                index = bisect.bisect_right(row['starts'], address) - 1
                assert 0 <= index < len(row['starts']) - 1
                begin, end = row['starts'][index:index + 2]
                assert begin <= address < end and end - begin <= 65536
                if begin not in functions:
                    body = read(begin, end - begin, 'original-function-' + hex(begin)[2:])
                    functions[begin] = dict(start=begin, end=end, exactLC26Bounds=True,
                        owner=path, data=reads[-1]['data'], instructions=h.decode_body(body, begin))
                return functions[begin]
            iokit = image(OWNER)['item']
            assert iokit['UUID'] == '0e4cf3e4b0c2312ab1470bd4978ef0b7'
            original_definitions = [genuine.resolve(OWNER, name) for name in NAMES]
            assert all(x['exportFlags'] == 0 for x in original_definitions)
            constructors = [capture(OWNER, x['exportAddress']) for x in original_definitions[:2]]
            assert [(x['start'], x['end'] - x['start']) for x in constructors] == [(0x184db89e0, 140), (0x184db8388, 180)]
            allocator = genuine.resolve(OWNER, '__IOHIDEventCreate')
            assert allocator['exportAddress'] == 0x184d9048c
            allocation_body = capture(OWNER, allocator['exportAddress'])
            assert allocation_body['end'] == 0x184d904f0
            constructor_edges = []
            for item in constructors:
                raw = Path(item['data']['path']).read_bytes()
                edges = [dict(pc=item['start'] + at, target=branch(item['start'] + at, word))
                         for at in range(0, len(raw), 4) if (word := struct.unpack_from('<I', raw, at)[0]) & 0xfc000000 == 0x94000000]
                assert len(edges) == 1 and edges[0]['target'] == allocator['exportAddress']
                constructor_edges.extend(edges)
            objc_selectors = []
            for start, expected in [(0x188002490, 'allocWithZone:'), (0x188035070, 'initWithSize:type:timestamp:options:')]:
                raw = read(start, 16, 'original-objc-selector-island-' + hex(start)[2:])
                adrp, add, jump, trap = struct.unpack('<4I', raw)
                assert adrp & 0x9f00001f == 0x90000001 and add & 0xffc003ff == 0x91000021
                imm = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
                if imm & 0x100000: imm -= 0x200000
                address = (start & ~0xfff) + (imm << 12) + (add >> 10 & 0xfff)
                assert branch(start + 8, jump) == 0x188000800 and trap == 0xd4200020
                selector = text(address, 'original-selector-' + hex(address)[2:])
                assert selector == expected
                objc_selectors.append(dict(island=start, raw=reads[-2]['data'], selectorAddress=address, selector=selector))
            dispatch_definition = genuine.resolve('/usr/lib/libobjc.A.dylib', '_objc_msgSend')
            assert dispatch_definition['exportAddress'] == 0x188000800
            dispatch = capture(dispatch_definition['exportPath'], dispatch_definition['exportAddress'])
            event_class = pointer(0x1e06d0438)
            actual_class = genuine.resolve(OWNER, '_OBJC_CLASS_$_HIDEvent')
            assert event_class['target'] == actual_class['exportAddress']
            class_body = read(event_class['target'], 40, 'original-HIDEvent-class')
            ro = pointer(event_class['target'] + 32)
            ro_address = ro['target'] & ~7
            ro_body = read(ro_address, 72, 'original-HIDEvent-class-RO')
            # The actual low tag selects a relative list of method lists.
            # LLVM's runtime reader documents its signed48 offset + image16.
            # https://github.com/llvm/llvm-project/blob/main/lldb/source/Plugins/LanguageRuntime/ObjC/AppleObjCRuntime/AppleObjCClassDescriptorV2.cpp
            method_tagged = pointer(ro_address + 32)['target']
            assert method_tagged & 1
            list_address = method_tagged ^ 1
            list_header = read(list_address, 8, 'original-HIDEvent-relative-list-list-header')
            entry_size, list_count = struct.unpack('<II', list_header)
            assert entry_size == 8 and 0 < list_count < 32
            relative_lists = read(list_address, 8 + 8 * list_count, 'original-HIDEvent-relative-list-list-complete')
            opts = read(cache.header.sharedRegionStart + cache.header.objcOptsOffset,
                        cache.header.objcOptsSize, 'original-objc-optimization-header')
            assert struct.unpack_from('<I', opts)[0] == 4 and len(opts) == 136
            selector_base = cache.header.sharedRegionStart + struct.unpack_from('<Q', opts, 48)[0]
            assert selector_base == 0x1f4924a80
            method_lists = []
            matched_methods = []
            for list_index in range(list_count):
                list_entry = list_address + 8 + 8 * list_index
                packed = struct.unpack_from('<Q', relative_lists, 8 + 8 * list_index)[0]
                relative = packed >> 16
                if relative & (1 << 47): relative -= 1 << 48
                method_address = list_entry + relative
                method_head = read(method_address, 8, 'original-HIDEvent-method-list-header-' + str(list_index))
                flags, count = struct.unpack('<II', method_head)
                assert flags & 0xe0000000 == 0xe0000000 and flags & 0xfffc == 12 and 0 < count < 1000
                methods_raw = read(method_address, 8 + 12 * count, 'original-HIDEvent-method-list-complete-' + str(list_index))
                entries = []
                for index in range(count):
                    entry = method_address + 8 + index * 12
                    name_rel, type_rel, imp_rel = struct.unpack_from('<IIi', methods_raw, 8 + index * 12)
                    name_address = selector_base + name_rel
                    # Compare bounded bytes without retaining unrelated selector reads.
                    offset, ctx = cache.convertAddr(name_address)
                    name = ctx.getBytes(offset, 128).split(b'\0')[0].decode()
                    entries.append(dict(index=index, name=name, nameAddress=name_address,
                                        typeAddress=selector_base + type_rel, implementation=entry + 8 + imp_rel))
                    if name == 'initWithSize:type:timestamp:options:':
                        types = text(selector_base + type_rel, 'original-HIDEvent-initializer-type-encoding')
                        implementation = entry + 8 + imp_rel
                        owner = max((im for im in cache.images if im.address <= implementation), key=lambda im:im.address)
                        owner_path = cache.readString(owner.pathFileOffset).rstrip(b'\0').decode()
                        function = capture(owner_path, implementation)
                        matched_methods.append(dict(listIndex=list_index, index=index, name=name,
                                                    typeEncoding=types, function=function))
                method_lists.append(dict(address=method_address, signed48Relative=relative,
                    packedEntry=packed, cacheImageIndex=packed & 0xffff, entries=entries, flags=flags))
            assert len(matched_methods) == 1
            constant_pointer = pointer(original_definitions[2]['exportAddress'])
            constant = read(constant_pointer['target'], 32, 'original-RequestTerminate-CFString')
            string_isa = pointer(constant_pointer['target'])
            literal = pointer(constant_pointer['target'] + 16)
            value = text(literal['target'], 'original-RequestTerminate-literal')
            assert value == 'RequestTerminate' and struct.unpack_from('<Q', constant, 24)[0] == 16
            class_reference = genuine.resolve('/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation', '___CFConstantStringClassReference')
            assert class_reference and string_isa['target'] == class_reference['exportAddress']
            assert string_isa['auth'] and string_isa['key'] == 2 and string_isa['diversity'] == 0x6ae1 and string_isa['addressDiversity']
            uh = image(UH)
            text_segment = next(x for x in p.segments(uh['header']) if x['name'] == '__TEXT')
            section = next(x for x in text_segment['sections'] if x['name'] == '__text')
            code = read(section['address'], section['size'], 'original-UH-complete-text-for-three-symbol-xrefs')
            call_targets = {0x2a00b1e00:NAMES[0], 0x2a00b1e70:NAMES[1]}
            caller_edges = []
            for at in range(0, len(code), 4):
                word = struct.unpack_from('<I', code, at)[0]
                if word & 0xfc000000 == 0x94000000:
                    target = branch(section['address'] + at, word)
                    if target in call_targets:
                        caller = capture(UH, section['address'] + at)
                        caller_edges.append(dict(pc=section['address'] + at, target=target, symbol=call_targets[target], caller=caller['start']))
            assert len(caller_edges) > 0 and set(x['symbol'] for x in caller_edges) == set(NAMES[:2])
            islands = []
            for start, expected in call_targets.items():
                raw = read(start, 16, 'original-UH-auth-island-' + hex(start)[2:])
                adrp, add, load, jump = struct.unpack('<4I', raw)
                assert adrp & 0x9f00001f == 0x90000011 and add & 0xffc003ff == 0x91000231
                assert load == 0xf9400230 and jump == 0xd71f0a11
                imm = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
                if imm & 0x100000: imm -= 0x200000
                slot = (start & ~0xfff) + (imm << 12) + (add >> 10 & 0xfff)
                bind = pointer(slot)
                target = next(x['exportAddress'] for x in original_definitions if x['exportedSymbol'] == expected)
                assert bind['target'] == target and bind['auth'] and bind['key'] == 0 and bind['diversity'] == 0 and bind['addressDiversity']
                islands.append(dict(island=start, symbol=expected, binding=bind))
            got = pointer(0x2c8124a78)
            assert not got['auth'] and got['target'] == original_definitions[2]['exportAddress']
            # Exact constant GOT ADRP followed by scaled 64-bit load.
            constant_callers = []
            for at in range(0, len(code) - 4, 4):
                word, next_word = struct.unpack_from('<II', code, at)
                if word & 0x9f000000 != 0x90000000 or next_word & 0xffc00000 != 0xf9400000: continue
                reg = word & 31
                if next_word >> 5 & 31 != reg: continue
                imm = ((word >> 5 & 0x7ffff) << 2) | (word >> 29 & 3)
                if imm & 0x100000: imm -= 0x200000
                address = ((section['address'] + at) & ~0xfff) + (imm << 12) + ((next_word >> 10 & 0xfff) << 3)
                if address == got['slot']:
                    caller = capture(UH, section['address'] + at)
                    constant_callers.append(dict(pc=section['address'] + at, gotSlot=address, caller=caller['start']))
            assert constant_callers
            report = dict(schema='Original27 IOKit missing three exact machine and object ABI capture v1',
                originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalIOKitUUID=iokit['UUID'],
                originalDefinitions=original_definitions, constructors=constructors, actualAllocator=allocator,
                completeAllocator=allocation_body, exactConstructorCalls=constructor_edges,
                actualObjCSelectors=objc_selectors, actualObjCDispatchDefinition=dispatch_definition, actualObjCDispatch=dispatch,
                originalHIDEventClass=dict(definition=actual_class, classPointer=event_class, roPointer=ro,
                    flags=struct.unpack_from('<I', ro_body)[0], instanceStart=struct.unpack_from('<I', ro_body, 4)[0],
                    instanceSize=struct.unpack_from('<I', ro_body, 8)[0], initializer=matched_methods[0],
                    relativeMethodLists=method_lists, selectorBase=selector_base),
                requestTerminateConstant=dict(symbolPointer=constant_pointer, immutableCFStringISA=string_isa,
                    classDefinition=class_reference, literalPointer=literal, value=value, length=16,
                    actualObjectKind='CFConstantString', objectPointerNotCString=True, processLifetime=True),
                originalUHConstructorCallers=caller_edges, originalUHAuthenticatedConstructorIslands=islands,
                originalUHConstantGOT=got, originalUHConstantCallers=constant_callers,
                functions=list(functions.values()), actualSlide5Pointers=pointers, originalReadRanges=reads,
                originalReturnOwnedCreateConvention=True, currentIOKitAllocatorABIProven=False,
                currentIOKitNewEventTypeAcceptanceProven=False, currentIOKitObjectDataLayoutProven=False,
                providerImplementationReady=False, originalImagesLoaded=False, deviceOperations=0,
                originalFunctionExecuted=False, nativeHVCalls=0, full27Backend=False)
            p.save(out / 'audit.json', report)
            pins.append(p.pin(out / 'audit.json'))
            p.save(out / 'freeze.json', dict(files=list({x['path']:x for x in pins}.values()), deviceOperations=0))
            print(json.dumps(dict(audit=p.pin(out / 'audit.json'), functions=len(functions),
                constructorCallers=len(caller_edges), constantCallers=len(constant_callers), pointers=len(pointers))))
        finally:
            for sub in subs: sub.close()


if __name__ == '__main__':
    main()
