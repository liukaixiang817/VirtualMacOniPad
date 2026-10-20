#!/usr/bin/env python3
"""Read genuine typed throw/copy-box ABI without executing providers."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('typed_genuine', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('typed_helpers', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
spec = importlib.util.spec_from_file_location('typed_stock', HERE / 'audit-modern-universalhid-current-stock-exports-v1.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def target(pc, word):
    assert word & 0xfc000000 in (0x94000000, 0x14000000)
    delta = (word & 0x3ffffff) << 2
    return pc + delta - (0x10000000 if delta & 0x8000000 else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    inputs = [p.pin(Path(__file__)), p.pin(Path(h.__file__)), p.pin(Path(s.__file__)),
              p.pin(p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-RuntimeFunctions.def')]
    callers = {}
    for framework in ('UniversalHID', 'UniversalHIDKit'):
        path = h.ORIGINAL / 'raw' / framework
        memopath = h.ORIGINAL / (framework + '-symbols.a2s.batch.json')
        raw = path.read_bytes()
        memo = json.loads(memopath.read_bytes())['symbols']
        assert memo.get('0x2a00726e0') == ['_swift_willThrowTypedImpl', '/usr/lib/swift/libswiftCore.dylib'] if framework == 'UniversalHID' else True
        found = []
        for section in h.sections(raw):
            if section['name'] != '__text':
                continue
            for delta in range(0, section['bytes'], 4):
                word = struct.unpack_from('<I', raw, section['fileoff'] + delta)[0]
                if word & 0xfc000000 not in (0x94000000, 0x14000000):
                    continue
                pc = section['address'] + delta
                if target(pc, word) != 0x2a00726e0:
                    continue
                assert pc == 0x29fd638bc and word & 0xfc000000 == 0x14000000
                start = pc - 104
                body = raw[section['fileoff'] + delta - 104:section['fileoff'] + delta + 16]
                assert struct.unpack_from('<6I', body, 32) == (0x528001e0, 0xd2800001, 0xd2800002, 0x52800243, 0xd2800004, 0xd2800005)
                assert target(start + 56, struct.unpack_from('<I', body, 56)[0]) == 0x2a0071280
                assert struct.unpack_from('<3I', body, 64) == (0xaa1503e0, 0xaa1403e1, 0xaa1303e2)
                assert struct.unpack_from('<I', body, 100)[0] == 0xd4388e20
                found.append(dict(start=start, tailCall=pc, code=body.hex(), instructions=h.decode_body(body, start),
                                  availabilityArguments=[15, 0, 0, 18, 0, 0], originalGuardPreserved=True))
        assert len(found) == (1 if framework == 'UniversalHID' else 0)
        callers[framework] = found
        inputs += [p.pin(path), p.pin(memopath)]
    reads = []
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'
        subs = cache.addSubCaches(p.CACHE)
        def read(address, size, purpose):
            assert 0 < size <= 1024 * 1024
            off, context = cache.convertAddr(address)
            body = context.getBytes(off, size)
            assert len(body) == size
            reads.append(dict(address=address, bytes=size, offset=off, cacheUUID=bytes(context.header.uuid).hex(),
                              sha256=hashlib.sha256(body).hexdigest(), purpose=purpose))
            return body
        exports = p.GenuineCacheExports(cache)
        core = exports.image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0'
        header = read(core['base'], 32, 'Core header extent')
        header = read(core['base'], 32 + struct.unpack_from('<I', header, 20)[0], 'complete Core header')
        for command, at, size in h.commands(header):
            if command == 0x19 and header[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
                link, lfo = struct.unpack_from('<Q', header, at + 24)[0], struct.unpack_from('<Q', header, at + 40)[0]
            elif command == 0x26:
                off, length = struct.unpack_from('<II', header, at + 8)
        encoded = read(link + off - lfo, length, 'complete original Core function starts')
        starts, address, at = [], core['base'], 0
        while at < len(encoded):
            delta, at = h.uleb(encoded, at)
            if not delta:
                break
            address += delta
            starts.append(address)
        functions = []
        for name, expected_size in (('_swift_willThrowTypedImpl', 152), ('_swift_allocError', 296), ('_swift_errorRelease', 4), ('_swift_willThrow', 64)):
            export = core['exports'][name]
            assert export.flags == 0
            entry = core['base'] + export.address
            end = starts[starts.index(entry) + 1]
            assert end - entry == expected_size
            body = read(entry, end - entry, 'complete original ' + name)
            file = out / (name.removeprefix('_') + '.bin')
            file.write_bytes(body)
            functions.append(dict(symbol=name, entry=entry, nextStart=end, code=p.pin(file), instructions=h.decode_body(body, entry)))
            inputs.append(p.pin(file))
        typed, alloc, release, old = functions
        body = Path(typed['code']['path']).read_bytes()
        assert struct.unpack_from('<I', body, 24)[0] == 0xf8bfc103  # LDAR typed x3
        assert struct.unpack_from('<I', body, 40)[0] == 0xf8bfc114  # LDAR old x20
        assert struct.unpack_from('<I', body, 84)[0] == 0xd61f087f  # BRAAZ x3: IA, diversity zero
        assert struct.unpack_from('<5I', body, 88) == (0xaa0003e8, 0xaa0103e0, 0xaa0203e1, 0xaa0803e2, 0x52800003)
        assert target(typed['entry'] + 108, struct.unpack_from('<I', body, 108)[0]) == alloc['entry']
        assert struct.unpack_from('<I', body, 116)[0] == 0xd63f0a9f  # BLRAAZ x20
        assert target(typed['entry'] + 148, struct.unpack_from('<I', body, 148)[0]) == release['entry']
        allocbody = Path(alloc['code']['path']).read_bytes()
        assert struct.unpack_from('<2I', allocbody, 260) == (0xaa1803e0, 0xaa1603e1)  # BoxPair x0/x1
        oldbody = Path(old['code']['path']).read_bytes()
        assert struct.unpack_from('<I', oldbody, 44)[0] == 0xaa1503e0  # original untyped uses SwiftError x21
        globals = []
        for name, expected in (('__swift_willThrowTypedImpl', 0x1e480f540), ('__swift_willThrow', 0x1e480f508)):
            address = core['base'] + core['exports'][name].address
            assert address == expected
            data = read(address, 8, 'original real callback atomic slot ' + name)
            assert data == b'\0' * 8
            globals.append(dict(symbol=name, address=address, bytes=data.hex(), nativeSystemSlotModified=False))
        islands = []
        avname = '_$ss042_stdlib_isOSVersionAtLeastOrVariantVersiondE0yBi1_Bw_BwBwBwBwBwtF'
        for address, owner, name in ((0x2a00726e0, '/usr/lib/swift/libswiftCore.dylib', '_swift_willThrowTypedImpl'),
                                    (0x2a0071280, '/usr/lib/swift/libswiftCore.dylib', avname),
                                    (0x1980ee2e0, '/usr/lib/libobjc.A.dylib', '_objc_release')):
            definition = exports.resolve(owner, name)
            assert definition is not None
            code = read(address, 16, 'real original IA island ' + name)
            adrp, add, load, branch = struct.unpack('<4I', code)
            assert adrp & 0x9f00001f == 0x90000011
            assert add & 0xffc003ff == 0x91000231 and load == 0xf9400230 and branch == 0xd71f0a11
            immediate = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
            if immediate & 0x100000:
                immediate -= 0x200000
            slot = (address & ~0xfff) + (immediate << 12) + (add >> 10 & 0xfff)
            offset, context = cache.convertAddr(slot)
            mapping = next(m for m, c in cache.mappings if c is context and m.address <= slot < m.address + m.size)
            index = context.mappings.index((mapping, context))
            expanded = h.dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset + index * h.dyld_cache_mapping_and_slide_info.SIZE)
            slide = h.dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
            assert slide.version == 5
            page = (slot - expanded.address) // slide.page_size
            start = context.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page * 2)[0]
            assert start != 0xffff
            pageoff, cursor = expanded.fileOffset + page * slide.page_size, expanded.fileOffset + page * slide.page_size + start
            for _ in range(slide.page_size // 8):
                assert pageoff <= cursor <= pageoff + slide.page_size - 8
                word = context.readFormat('<Q', cursor)[0]
                result = h.decodeV5Pointer(word, slide.value_add)
                if cursor == offset:
                    break
                assert result[5] and cursor < offset
                cursor += result[5]
            else:
                raise AssertionError('real island slot missing from slide chain')
            resolved, auth, key, diversity, addressdiversity, delta = result
            assert resolved == definition['exportAddress'] and auth and key == 0 and addressdiversity
            islands.append(dict(address=address, code=code.hex(), slot=slot, pointerWord=word, target=resolved,
                                auth=auth, key=key, diversity=diversity, addressDiversity=addressdiversity,
                                exactChainMembershipVerified=True, exactDefinition=definition))
        assert target(release['entry'], struct.unpack('<I', Path(release['code']['path']).read_bytes())[0]) == 0x1980ee2e0
        for sub in subs:
            sub.close()
    images = s.captured_images()
    current = {name: s.resolve(images, '/usr/lib/swift/libswiftCore.dylib', name)
               for name in ('__swift_willThrow', '_swift_allocError', '_swift_errorRelease', '__swift_willThrowTypedImpl', '_swift_willThrowTypedImpl')}
    assert all(current[name]['status'] == 'actualDirectExport' for name in ('__swift_willThrow', '_swift_allocError', '_swift_errorRelease'))
    assert all(current[name]['status'] == 'actualExportAbsent' for name in ('__swift_willThrowTypedImpl', '_swift_willThrowTypedImpl'))
    report = dict(schema='Genuine typed-throw three-branch old-host ABI audit v1', inputs=inputs, reads=reads,
                  originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalSwiftCoreUUID=core['UUID'],
                  originalFunctions=functions, originalCallbackSlots=globals, authenticatedIslands=islands,
                  genuineCallerWindows=callers, currentNativeDefinitions=current,
                  ABI='SwiftCC x0=value,x1=metadata,x2=Error witness; normal C callback pointers IA diversity 0; swift_allocError SwiftCC BoxPair x0=box,x1=payload; isTake=false; errorRelease C_CC',
                  genuineThreeBranches=['typed callback priority', 'real native legacy callback with copied error box then release', 'return when both real callback slots empty'],
                  officialImplementationURL='https://github.com/swiftlang/swift/blob/main/stdlib/public/runtime/ErrorObjectCommon.cpp',
                  candidateScope='private typed callback slot plus existing native old-host callback slot read-only; genuine native boxing/copy/release',
                  fullSwift27RuntimeEquivalent=False, processGlobalTypedHookIdentityPreserved=False,
                  originalUHLoaded=False, nativeIOSExecuted=False, nativeSystemSlotModified=False,
                  fullCurrentLoadGraphProven=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    p.save(out / 'freeze.json', dict(files=inputs + [p.pin(out / 'audit.json')], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), originalCallerCount=1, actualNativeStrongDefinitions=3)))


if __name__ == '__main__':
    main()
