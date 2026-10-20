#!/usr/bin/env python3
"""Capture genuine dispatch/PAC/handler bytes for the observed HID CVW schema."""
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
spec = importlib.util.spec_from_file_location('observed_cvw_route', HERE / 'prepare-modern-hid-bitwise-take-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
s, p = r.s, r.p
spec = importlib.util.spec_from_file_location('observed_disassembly', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
from current_kernel_capture_v1 import join as join_kernel
from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info, dyld_cache_slide_info5
from DyldExtractor.converter.slide_info import decodeV5Pointer
SOURCE = p.NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json'
PROGRAMS = p.NODE / 'universalhid-cvw-layout-programs-readonly-v1/audit.json'
ORIGINAL = p.NODE / 'universalhid-cvw-static-original-abi-readonly-v1/audit.json'
TAG_NAMES = {0: 'End', 2: 'NativeStrong', 8: 'Bridge', 10: 'ObjC', 14: 'Existential', 20: 'MultiPayloadEnumFN'}


def branch(pc, word):
    delta = (word & 0x3ffffff) << 2
    return pc + delta - (0x10000000 if delta & 0x8000000 else 0)


def auth_contract(word, add, diversity):
    target, auth, key, actual, address_diversity, delta = decodeV5Pointer(word, add)
    assert auth and key == 0 and actual == diversity and not address_diversity
    return dict(originalTarget=target, key=key, diversity=actual, addressDiversity=False, nextBytes=delta)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    source, programs, original = [r.r.checked(path) for path in (SOURCE, PROGRAMS, ORIGINAL)]
    inputs = [Path(__file__), Path(h.__file__), SOURCE, PROGRAMS, ORIGINAL]
    images = s.primary.captured_images()
    current_pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        current_pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    current_pins += join_kernel(s, images)
    assert len(images) == 17
    definitions = []
    for owner, names in (('/usr/lib/swift/libswiftCore.dylib', ('_swift_retain', '_swift_release', '_swift_bridgeObjectRetain', '_swift_bridgeObjectRelease')),
                         ('/usr/lib/libobjc.A.dylib', ('_objc_retain', '_objc_release')),
                         ('/usr/lib/libSystem.B.dylib', ('_memcpy',))):
        for name in names:
            proof = s.primary.resolve(images, owner, name)
            assert proof['status'] == 'actualDirectExport'
            definitions.append(dict(owner=owner, symbol=name, actualCurrentDefinition=proof))
    registry, metadata = [], []
    for image in programs['images']:
        latest = next(x['candidate'] for x in source['images'] if x['name'] == image['name'])
        raw = Path(latest['path']).read_bytes()
        reference = Path(image['candidate']['path']).read_bytes()
        # Only later import ordinals differ. Every observed program, metadata
        # and callback must still have exactly the prior audited bytes.
        layouts = {}
        for item in image['uniqueLayouts']:
            va = item['candidateVA']
            segment = next(x for x in p.segments(raw) if x['address'] <= va < x['address'] + x['size'])
            at = segment['fileoff'] + va - segment['address']
            body = raw[at:at + item['completeStorageBytes']]
            assert body == reference[at:at + len(body)] and hashlib.sha256(body).hexdigest() == item['bytesSHA256']
            assert struct.unpack_from('<Q', body, 0)[0] in (0, 1 << 63)
            record = dict(owner=image['name'], programRVA=va - 0x100000000, bytes=len(body), sha256=item['bytesSHA256'], bytesHex=body.hex())
            registry.append(record)
            layouts[va] = record
        for row in image['completedMetadata']:
            assert not row['flags'] & (0x100000 | 0x400000)
            metadata.append(dict(owner=image['name'], metadataRVA=row['candidateVA'] - 0x100000000,
                vwtRVA=row['candidateVWT'] - 0x100000000, programRVA=row['candidateLayout'] - 0x100000000,
                size=row['size'], stride=row['stride'], flags=row['flags'], extraInhabitants=row['extraInhabitants'],
                expectedProgramSHA256=layouts[row['candidateLayout']]['sha256']))
        inputs += [Path(latest['path']), Path(image['candidate']['path'])]
    assert len(registry) == 37 and len(metadata) == 65
    p.save(out / 'observed-registry.json', dict(programs=registry, completedOriginalMetadata=metadata,
        completedUHMetadata=64, completedUHKMetadata=1, separatelyIncompleteOriginalUHPODMetadata=1,
        allCompleteMetadataBitwiseTakable=True, productionRuntimeIdentityChecked=False))
    reads, tables, functions, negatives = [], [], {}, []
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        def read(va, size, purpose):
            assert 0 < size <= 1024 * 1024
            offset, context = cache.convertAddr(va)
            body = context.getBytes(offset, size)
            assert len(body) == size
            reads.append(dict(address=va, bytes=size, originalCacheUUID=bytes(context.header.uuid).hex(),
                fileOffset=offset, sha256=hashlib.sha256(body).hexdigest(), purpose=purpose))
            return body
        genuine = p.GenuineCacheExports(cache)
        core = genuine.image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0'
        prefix = read(core['base'], 32, 'original Core header extent')
        header = read(core['base'], 32 + struct.unpack_from('<I', prefix, 20)[0], 'original complete Core load commands')
        header_file = out / 'original-core-commands.bin'
        header_file.write_bytes(header)
        inputs.append(header_file)
        link = next(x for x in p.segments(header) if x['name'] == '__LINKEDIT')
        off, size = next(struct.unpack_from('<II', header, at + 8) for command, at, length in p.commands(header) if command == 0x26)
        encoded = read(link['address'] + off - link['fileoff'], size, 'original exact LC26 function start index')
        index_file = out / 'original-core-function-starts.bin'
        index_file.write_bytes(encoded)
        inputs.append(index_file)
        starts, at, address = [], 0, core['base']
        while at < len(encoded):
            delta, at = h.uleb(encoded, at)
            if not delta: break
            address += delta
            starts.append(address)
        def capture(address):
            index = bisect.bisect_right(starts, address) - 1
            assert 0 <= index < len(starts) - 1
            begin, end = starts[index:index + 2]
            assert begin <= address < end and end - begin <= 65536
            if begin not in functions:
                body = read(begin, end - begin, 'original observed dispatch owning complete function')
                path = out / ('Core-' + hex(begin)[2:] + '.bin')
                path.write_bytes(body)
                functions[begin] = dict(start=begin, end=end, body=p.pin(path), instructions=h.decode_body(body, begin))
                inputs.append(path)
            return functions[begin]
        inverse = {core['base'] + x.address: name for name, x in core['exports'].items() if x.flags == 0}
        objc = genuine.image('/usr/lib/libobjc.A.dylib')
        inverse.update({objc['base'] + x.address: name for name, x in objc['exports'].items() if x.flags == 0})
        external_definitions = [(name, genuine.resolve(owner, name)) for owner, name in (
            ('/usr/lib/libobjc.A.dylib', '_objc_retain'), ('/usr/lib/libobjc.A.dylib', '_objc_release'),
            ('/usr/lib/system/libsystem_c.dylib', '_memcpy'))]
        islands, island_pages = [], {}
        def island(address, allow_unmatched=False):
            code = read(address, 16, 'original observed external authenticated call island')
            adrp, add, load, jump = struct.unpack('<4I', code)
            assert adrp & 0x9f00001f == 0x90000011
            assert add & 0xffc003ff == 0x91000231 and load == 0xf9400230 and jump == 0xd71f0a11
            immediate = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
            if immediate & 0x100000: immediate -= 0x200000
            slot = (address & ~0xfff) + (immediate << 12) + (add >> 10 & 0xfff)
            offset, slot_context = cache.convertAddr(slot)
            slot_mapping = next(m for m, c in cache.mappings if c is slot_context and m.address <= slot < m.address + m.size)
            number = slot_context.mappings.index((slot_mapping, slot_context))
            slot_expanded = dyld_cache_mapping_and_slide_info(slot_context.file, slot_context.header.mappingWithSlideOffset + number * dyld_cache_mapping_and_slide_info.SIZE)
            slot_slide = dyld_cache_slide_info5(slot_context.file, slot_expanded.slideInfoFileOffset)
            assert slot_slide.version == 5 and slot_slide.page_size == 16384
            index = (slot - slot_expanded.address) // slot_slide.page_size
            page_address = slot_expanded.address + index * slot_slide.page_size
            page_start = slot_context.readFormat('<H', slot_expanded.slideInfoFileOffset + len(slot_slide) + index * 2)[0]
            assert page_start != 0xffff
            if page_address not in island_pages:
                data = read(page_address, slot_slide.page_size, 'original external call island slide5 complete page')
                path = out / ('external-auth-page-' + hex(page_address)[2:] + '.bin')
                path.write_bytes(data)
                inputs.append(path)
                island_pages[page_address] = (data, p.pin(path))
            data, page_pin = island_pages[page_address]
            cursor = page_start
            for visits in range(slot_slide.page_size // 8):
                assert 0 <= cursor <= len(data) - 8
                word = struct.unpack_from('<Q', data, cursor)[0]
                target, auth, key, diversity, address_diversity, delta = decodeV5Pointer(word, slot_slide.value_add)
                if page_address + cursor == slot: break
                assert delta and page_address + cursor < slot
                cursor += delta
            else: raise AssertionError('no real external island chain membership')
            assert auth and key == 0 and address_diversity
            matches = [(name, proof) for name, proof in external_definitions if proof['exportAddress'] == target]
            assert len(matches) == 1 or (allow_unmatched and not matches)
            record = dict(originalIsland=address, exactFourWords=code.hex(), originalSlot=slot, originalWord=hex(word),
                originalTarget=target, exactOriginalExport=matches[0][0] if matches else None,
                actualOriginalDefinitionChain=matches[0][1] if matches else None,
                originalDefinitionStatus='actualNamedDefinition' if matches else 'additionalUnverifiedWholeFunctionBranch',
                auth=True, key=0, diversity=diversity,
                addressDiversity=True, actualSlide5ChainMembership=True, actualSlidePage=page_pin,
                actualSlideValueAdd=slot_slide.value_add, actualSlidePageStart=page_start)
            islands.append(record)
            return record
        table_info = [('destroy', 0x1e9880958, 0x7bf0, 0x194e4a3b4),
                      ('assignCopy', 0x1e9880a10, 0x0390, 0x194e4a8dc),
                      ('initCopy', 0x1e9880ac8, 0x1358, 0x194e4aef8)]
        page_va = 0x1e9880000
        page_offset, context = cache.convertAddr(page_va)
        mapping = next(m for m, c in cache.mappings if c is context and m.address <= page_va < m.address + m.size)
        mapping_index = context.mappings.index((mapping, context))
        expanded = dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset + mapping_index * dyld_cache_mapping_and_slide_info.SIZE)
        slide = dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
        assert slide.version == 5 and slide.page_size == 16384
        page_index = (page_va - expanded.address) // slide.page_size
        start = context.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page_index * 2)[0]
        assert start != 0xffff
        assert page_va == expanded.address + page_index * slide.page_size
        page = read(page_va, slide.page_size, 'actual original dispatch page with all slide5 chain words')
        page_file = out / 'original-dispatch-auth-page.bin'
        page_file.write_bytes(page)
        inputs.append(page_file)
        chain, cursor = {}, start
        for visits in range(slide.page_size // 8):
            assert 0 <= cursor <= len(page) - 8
            word = struct.unpack_from('<Q', page, cursor)[0]
            target, auth, key, diversity, address_diversity, delta = decodeV5Pointer(word, slide.value_add)
            chain[page_va + cursor] = word
            if not delta: break
            cursor += delta
        else: raise AssertionError('unterminated actual dispatch slide5 chain')
        for role, va, discriminator, default_helper in table_info:
            whole = page[va - page_va:va - page_va + 23 * 8]
            path = out / (role + '-original-dispatch-table.bin')
            path.write_bytes(whole)
            inputs.append(path)
            entries = []
            for tag, name in TAG_NAMES.items():
                slot = va + tag * 8
                assert slot in chain
                word = struct.unpack_from('<Q', whole, tag * 8)[0]
                assert chain[slot] == word
                decoded = auth_contract(word, slide.value_add, discriminator)
                function = capture(decoded['originalTarget'])
                entries.append(dict(tag=tag, name=name, actualSlot=slot, actualWord=hex(word),
                    actualSlide5ChainMembership=True, decoded=decoded, owningFunctionStart=function['start'],
                    targetOffsetInFunction=decoded['originalTarget'] - function['start']))
                for label, bit in [('auth', 63), ('discriminator', 34), ('address-diversity', 50)]:
                    try: auth_contract(word ^ (1 << bit), slide.value_add, discriminator)
                    except AssertionError: negatives.append(dict(name=role + ' ' + name + ' ' + label, rejected=True))
                    else: raise AssertionError('accepted corrupt observed dispatch authentication')
            assert all(x['owningFunctionStart'] == default_helper for x in entries), 'actual inline dispatcher blocks, not fabricated C helpers'
            labels = sorted(set(decodeV5Pointer(struct.unpack_from('<Q', whole, tag * 8)[0], slide.value_add)[0]
                                for tag in range(23) if tag != 13))
            function = functions[default_helper]
            body = Path(function['body']['path']).read_bytes()
            for row in entries:
                begin = row['decoded']['originalTarget']
                following = next((x for x in labels if x > begin and x < function['end']), function['end'])
                assert begin < following <= function['end']
                row['boundedObservedBlockEnd'] = following
                calls = []
                for pc in range(begin, following, 4):
                    word = struct.unpack_from('<I', body, pc - default_helper)[0]
                    if word & 0xfc000000 not in (0x14000000, 0x94000000): continue
                    target = branch(pc, word)
                    if default_helper <= target < function['end']: continue
                    if core['base'] <= target < starts[-1]:
                        child = capture(target)
                        calls.append(dict(pc=pc, target=target, exactSymbol=inverse.get(target),
                            actualFunctionStart=child['start'], targetIsActualFunctionEntry=target == child['start']))
                    else:
                        calls.append(dict(pc=pc, target=target, actualAuthenticatedExternalIsland=island(target)))
                row['directExternalCalls'] = calls
            tables.append(dict(role=role, originalDefaultHelper=default_helper, tableVA=va, storage=p.pin(path),
                exactEntries=23, observedEntries=entries, IA0FixedDiscriminator=discriminator, addressDiversity=False))
        secondary = []
        for role, base, discriminator, arguments in (
            ('destroy', 0x1e9880478, 0x1086, 4),
            ('assignCopy', 0x1e9880758, 0x58f2, 5),
            ('initCopy', 0x1e98805e8, 0x58f2, 5)):
            slot = base + 20 * 8
            assert slot in chain
            word = chain[slot]
            def secondary_auth(value):
                target, auth, key, actual, address_diversity, delta = decodeV5Pointer(value, slide.value_add)
                assert auth and key == 0 and actual == discriminator and address_diversity
                return dict(originalTarget=target, key=key, diversity=actual, addressDiversity=True, nextBytes=delta)
            decoded = secondary_auth(word)
            fn = capture(decoded['originalTarget'])
            assert fn['start'] == decoded['originalTarget']
            direct = []
            data = Path(fn['body']['path']).read_bytes()
            for pc in range(fn['start'], fn['end'], 4):
                opcode = struct.unpack_from('<I', data, pc - fn['start'])[0]
                if opcode & 0xfc000000 not in (0x14000000, 0x94000000): continue
                target = branch(pc, opcode)
                if fn['start'] <= target < fn['end']: continue
                if core['base'] <= target < starts[-1]:
                    child = capture(target)
                    direct.append(dict(pc=pc, target=target, exactSymbol=inverse.get(target),
                        actualFunctionStart=child['start'], targetIsActualFunctionEntry=target == child['start']))
                else:
                    direct.append(dict(pc=pc, target=target, actualAuthenticatedExternalIsland=island(target, allow_unmatched=True)))
            secondary.append(dict(role=role, tag=20, sourceSecondaryTableVA=base, actualSlot=slot,
                actualWord=hex(word), decoded=decoded, actualSlide5ChainMembership=True,
                exactOriginalCompleteFunction=fn['body'], originalABIArguments=arguments,
                originalSourceABI='metadata, reader pointer, offset pointer, destination/value, optional source',
                directCalls=direct, allWholeFunctionBranchesProvenReachableByObservedSchema=False,
                unobservedWholeFunctionDependenciesAreNotSynthesized=True))
            for label, bit in [('auth', 63), ('discriminator', 34), ('address-diversity', 50)]:
                try: secondary_auth(word ^ (1 << bit))
                except AssertionError: negatives.append(dict(name=role + ' secondary enum ' + label, rejected=True))
                else: raise AssertionError('accepted corrupt secondary enum authentication')
        getter = programs['images'][0]['actualCompleteTagFunctions'][0]
        original_uh = Path(programs['images'][0]['original']['path']).read_bytes()
        sections = [section for segment in p.segments(original_uh) for section in segment['sections']]
        section = next(x for x in sections if x['address'] <= getter['originalCacheVA'] < x['address'] + x['size'])
        offset = section['fileoff'] + getter['originalCacheVA'] - section['address']
        getter_body = original_uh[offset:offset + getter['completeFunctionBytes']]
        assert len(getter_body) == 28 and hashlib.sha256(getter_body).hexdigest() == getter['codeSHA256']
        getter_path = out / 'original-uh-enum-tag-getter.bin'
        getter_path.write_bytes(getter_body)
        inputs.append(getter_path)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        for sub in subs: sub.close()
    report = dict(schema='Genuine observed HID CVW ownership dispatch and static registry ABI v2',
        source=p.pin(SOURCE), priorObservedPrograms=p.pin(PROGRAMS), priorOriginalCVW=p.pin(ORIGINAL),
        registry=p.pin(out / 'observed-registry.json'), actualCurrentStockDefinitions=definitions,
        originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalCoreUUID=core['UUID'],
        originalCacheReads=reads, tables=tables, actualSecondaryEnumHelpers=secondary, completeOwningAndDirectCalleeFunctions=list(functions.values()),
        originalAuthPage=p.pin(page_file), originalSlide5ValueAdd=slide.value_add, originalSlidePageStart=start,
        actualOriginalExternalAuthIslands=islands,
        soleOriginalEnumTagGetter=dict(body=p.pin(getter_path), originalVA=getter['originalCacheVA'],
            normalizedVA=getter['candidateVA'], instructions=h.decode_body(getter_body, getter['originalCacheVA'])),
        negativeControls=negatives, actualObservedDispatchIAMetadataCorrect=True,
        exactObservationOnly=True, allRecursiveHandlerSemanticsClosed=False, interpreterProvided=False,
        originalProcessGlobalRuntimeOverrideHooksPreserved=False, fullSwift27RuntimeEquivalent=False,
        candidateReadyForNativeLoading=False, originalHIDLoaded=False, deviceOperations=0, nativeIOSExecuted=False, full27Backend=False)
    p.save(out / 'audit.json', report)
    inputs += [out / 'observed-registry.json', out / 'audit.json']
    unique = {x['path']: x for x in current_pins + [p.pin(path) for path in inputs]}
    p.save(out / 'freeze.json', dict(files=list(unique.values()), deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), completedMetadata=65, originalPrograms=37,
        dispatchTables=3, observedEntries=18, secondaryEnumFunctions=3, completeFunctions=len(functions), rejectedControls=len(negatives))))


if __name__ == '__main__': main()
