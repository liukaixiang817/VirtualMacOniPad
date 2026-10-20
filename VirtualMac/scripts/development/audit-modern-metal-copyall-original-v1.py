#!/usr/bin/env python3
"""Read genuine macOS27 Metal collection code and the original VZ consumer only."""
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('metal_original_p', HERE/'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('metal_original_h', p.NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
METAL = '/System/Library/Frameworks/Metal.framework/Versions/A/Metal'
VZ = '/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization'


def branch(pc, word):
    assert word & 0x7c000000 == 0x14000000
    delta = (word & 0x3ffffff) << 2
    return pc + delta - (0x10000000 if delta & 0x8000000 else 0)


def page(pc, word):
    assert word & 0x9f000000 == 0x90000000
    delta = ((word >> 5 & 0x7ffff) << 2) | (word >> 29 & 3)
    if delta & 0x100000: delta -= 0x200000
    return (pc & ~4095) + (delta << 12)


def main():
    out = p.NODE/'metal-copyall-original-contract-readonly-v1'
    assert not out.exists()
    out.mkdir(mode=0o700)
    pins = [p.pin(Path(__file__)), p.pin(Path(p.__file__)), p.pin(Path(h.__file__))]
    reads, images, functions, pointers, pages = [], {}, {}, [], {}
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        try:
            genuine = p.GenuineCacheExports(cache)
            def read(va, length, name):
                assert 0 < length <= 2*1024*1024
                at, context = cache.convertAddr(va)
                raw = context.getBytes(at, length)
                assert len(raw) == length
                dest = out/(name+'.bin')
                assert not dest.exists()
                dest.write_bytes(raw)
                pin = p.pin(dest)
                reads.append(dict(address=va, bytes=length, actualSubcacheUUID=bytes(context.header.uuid).hex(), fileOffset=at, data=pin))
                pins.append(pin)
                return raw
            def image(path):
                if path not in images:
                    item = genuine.image(path)
                    prefix = read(item['base'], 32, 'original-'+Path(path).name+'-prefix')
                    raw = read(item['base'], 32+struct.unpack_from('<I', prefix, 20)[0], 'original-'+Path(path).name+'-commands')
                    header_pin = reads[-1]['data']
                    link = next(x for x in p.segments(raw) if x['name'] == '__LINKEDIT')
                    offset, length = next(struct.unpack_from('<II', raw, at+8) for cmd, at, size in p.commands(raw) if cmd == 0x26)
                    encoded = read(link['address']+offset-link['fileoff'], length, 'original-'+Path(path).name+'-function-starts')
                    starts, at, va = [], 0, item['base']
                    while at < len(encoded):
                        delta, at = h.uleb(encoded, at)
                        if not delta: break
                        va += delta; starts.append(va)
                    assert starts == sorted(set(starts)) and encoded[at:] == b'\0'*(len(encoded)-at)
                    images[path] = dict(item=item, header=raw, headerPin=header_pin, starts=starts, indexPin=reads[-1]['data'])
                return images[path]
            def capture(path, va):
                im = image(path)
                index = bisect.bisect_right(im['starts'], va)-1
                assert 0 <= index < len(im['starts'])-1
                begin, end = im['starts'][index:index+2]
                assert begin <= va < end and end-begin <= 65536
                if begin not in functions:
                    raw = read(begin, end-begin, 'original-function-'+hex(begin)[2:])
                    functions[begin] = dict(start=begin, end=end, owner=path, exactLC26Bounds=True,
                                           data=reads[-1]['data'], instructions=h.decode_body(raw, begin))
                return functions[begin]
            def pointer(slot):
                at, context = cache.convertAddr(slot)
                mapping = next(m for m, c in cache.mappings if c is context and m.address <= slot < m.address+m.size)
                index = context.mappings.index((mapping, context))
                expanded = h.dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset+index*h.dyld_cache_mapping_and_slide_info.SIZE)
                slide = h.dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
                assert slide.version == 5 and slide.page_size in (4096, 16384)
                page_index = (slot-expanded.address)//slide.page_size
                va = expanded.address+page_index*slide.page_size
                identity = (bytes(context.header.uuid).hex(), va)
                if identity not in pages:
                    start = context.readFormat('<H', expanded.slideInfoFileOffset+len(slide)+page_index*2)[0]
                    assert start != 0xffff
                    body = read(va, slide.page_size, 'original-slide5-page-'+hex(va)[2:])
                    rows, cursor = {}, start
                    for _ in range(slide.page_size//8):
                        assert 0 <= cursor <= len(body)-8
                        word = struct.unpack_from('<Q', body, cursor)[0]
                        target, auth, key, diversity, addr, delta = h.decodeV5Pointer(word, slide.value_add)
                        rows[va+cursor] = dict(slot=va+cursor, word=word, target=target, authenticated=bool(auth), key=key,
                            diversity=diversity, addressDiversity=bool(addr), nextBytes=delta, actualSlide5ChainMembership=True,
                            actualValueAdd=slide.value_add, actualPageStart=start, actualPage=reads[-1]['data'])
                        if not delta: break
                        assert delta > 0; cursor += delta
                    else: raise ValueError('unterminated real Slide5 chain')
                    pages[identity] = rows
                row = pages[identity][slot]
                if row not in pointers: pointers.append(row)
                return row
            def auth_island(va, expected_symbol, expected_owner):
                raw = read(va, 16, 'original-auth-island-'+hex(va)[2:])
                adrp, add, load, jump = struct.unpack('<4I', raw)
                assert adrp & 0x9f00001f == 0x90000011 and add & 0xffc003ff == 0x91000231
                assert load == 0xf9400230 and jump == 0xd71f0a11
                slot = page(va, adrp)+(add >> 10 & 4095)
                row = pointer(slot)
                definition = genuine.resolve(expected_owner, expected_symbol)
                assert definition and definition['exportFlags'] == 0 and row['target'] == definition['exportAddress']
                assert row['authenticated'] and row['key'] == 0 and row['diversity'] == 0 and row['addressDiversity']
                return dict(island=va, whole16B=reads[-2]['data'] if reads[-1]['data']==row['actualPage'] else p.pin(out/('original-auth-island-'+hex(va)[2:]+'.bin')),
                            actualGOT=row, actualOriginalDefinition=definition)
            def selector_island(va, selector):
                raw = read(va, 16, 'original-selector-island-'+hex(va)[2:])
                adrp, add, tail, trap = struct.unpack('<4I', raw)
                assert adrp & 0x9f00001f == 0x90000001 and add & 0xffc003ff == 0x91000021
                assert trap == 0xd4200020
                address = page(va, adrp)+(add >> 10 & 4095)
                name = read(address, len(selector)+1, 'original-selector-'+hex(address)[2:])
                assert name == selector.encode()+b'\0'
                return dict(island=va, data=p.pin(out/('original-selector-island-'+hex(va)[2:]+'.bin')),
                            selectorAddress=address, selector=name[:-1].decode(), actualTailTarget=branch(va+8, tail),
                            dispatcherCloneAddressMustBePreserved=True)
            metal = image(METAL)
            vz = image(VZ)
            assert metal['item']['UUID'] == 'b0bc74fe7080347d92ee38195058ccce'
            assert vz['item']['UUID'] == '418efc4809d93606918eb6f95baeffdc'
            definition = genuine.resolve(METAL, '_MTLCopyAllDevices')
            assert definition['exportFlags'] == 0 and definition['exportAddress'] == 0x18d543828
            collection = capture(METAL, definition['exportAddress'])
            assert collection['end']-collection['start'] == 212
            callback = capture(METAL, 0x18d549a2c)
            assert callback['end']-callback['start'] == 56
            setup = capture(METAL, 0x18d663274)
            capture(METAL, 0x18d6638d0); capture(METAL, 0x18d6638e0)
            original_default = genuine.resolve(METAL, '_MTLCreateSystemDefaultDevice')
            capture(METAL, original_default['exportAddress'])
            copy_island = auth_island(0x228084f60, '_MTLCopyAllDevices', METAL)
            assert copy_island['actualGOT']['slot'] == 0x2791fcd78
            section = next(x for z in p.segments(vz['header']) for x in z['sections'] if x['name'] == '__text')
            assert section['address'] == 0x225f38570 and section['size'] == 2510260
            text = b''
            for at in range(0, section['size'], 1048576):
                text += read(section['address']+at, min(1048576, section['size']-at), 'original-vz-text-chunk-'+str(at//1048576))
            refs = []
            for at in range(0, len(text), 4):
                word = struct.unpack_from('<I', text, at)[0]
                if word & 0x7c000000 == 0x14000000 and branch(section['address']+at, word) == copy_island['island']:
                    refs.append(dict(pc=section['address']+at, instruction=word, link=bool(word >> 31)))
            assert refs == [dict(pc=0x226197e04, instruction=0x947bb457, link=True)]
            consumer = capture(VZ, refs[0]['pc'])
            assert consumer['start'] == 0x226197dd0 and consumer['end']-consumer['start'] == 620
            objc = '/usr/lib/libobjc.A.dylib'
            ownership = [auth_island(va, symbol, objc) for va, symbol in
                [(0x22804ffd0, '_objc_retain'), (0x22804ffc0, '_objc_release'),
                 (0x22804fed0, '_objc_autoreleaseReturnValue'), (0x22804ff20, '_objc_enumerationMutation')]]
            selectors = [selector_island(va, name) for va, name in
                [(0x228001db0, 'countByEnumeratingWithState:objects:count:'),
                 (0x228038a70, 'isLowPower'), (0x228038ab0, 'isRemovable'), (0x190001540, 'copy')]]
            assert all(x['actualTailTarget'] == 0x228000800 for x in selectors[:3])
            assert selectors[3]['actualTailTarget'] == 0x190000800
            catalog = read(0x1e647a488, 24, 'original-metal-queue-catalog-once-state')
            direct = []
            for function in [collection, callback]:
                raw = Path(function['data']['path']).read_bytes()
                for at in range(0, len(raw), 4):
                    word = struct.unpack_from('<I', raw, at)[0]
                    if word & 0xfc000000 == 0x94000000:
                        direct.append(dict(owner=function['owner'], function=function['start'],
                                           pc=function['start']+at, target=branch(function['start']+at, word)))
            consumer_words = struct.unpack('<155I', Path(consumer['data']['path']).read_bytes())
            assert consumer_words[14] == 0xaa0003f3 and consumer_words[115] == 0xaa1303e0
            negatives = []
            for field, bad in [('authenticated', False), ('key', 2), ('diversity', 1), ('addressDiversity', False), ('target', 0x18d55755c)]:
                altered = dict(copy_island['actualGOT']); altered[field] = bad
                assert not (altered['authenticated'] and altered['key']==0 and altered['diversity']==0 and altered['addressDiversity'] and altered['target']==definition['exportAddress'])
                negatives.append(dict(name='wrong original Metal import '+field, rejected=True))
            p.save(out/'audit.json', dict(schema='Genuine macOS27 Metal owned collection and VZ consumer machine contract v1',
                originalMainCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalMetalUUID=metal['item']['UUID'],
                originalVZUUID=vz['item']['UUID'], originalDefinition=definition,
                originalCopyFunction=collection, originalCatalogCopyCallback=callback,
                originalCatalogInitializationFunction=setup, actualOriginalDefaultDefinition=original_default,
                originalVZTextScanBytes=len(text), completeDirectOriginalVZCallSites=refs,
                originalVZConsumer=consumer, exactOriginalMTLCopyImportIsland=copy_island,
                actualOriginalOwnershipIslands=ownership, actualSelectorIslands=selectors,
                actualDirectCollectionEdges=direct, actualCatalogDiskState=p.pin(out/'original-metal-queue-catalog-once-state.bin'),
                originalReturnsOwnedCopiedCollection=True, originalCallerFastEnumeratesWithBatch16=True,
                originalCallerSendsIsLowPowerAndIsRemovable=True,
                originalCallerRetainsChosenDeviceAndReleasesOwnedCollection=True,
                originalCatalogRuntimePopulationMustNotBeInferredFromDiskZeroes=True,
                originalEntireMultiGPUEnumerationSemanticsPreservedBySingleDefaultAdapter=False,
                nativeIOSSingleGPUCatalogNotYetProven=True, originalVZCallerExecuted=False,
                allReadSpans=reads, negativeControls=negatives, providerBuilt=False,
                deviceOperations=0, nativeCPUCalls=0, frameworkLoads=0, full27Backend=False))
        finally:
            for sub in subs: sub.close()
    pins.append(p.pin(out/'audit.json'))
    p.save(out/'freeze.json', dict(files=list({x['path']: x for x in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), freeze=p.pin(out/'freeze.json'),
                          completeFunctions=len(functions), originalPACSlots=len(pointers), VZDirectCalls=len(refs))))


if __name__ == '__main__':
    main()
