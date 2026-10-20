#!/usr/bin/env python3
"""Bounded genuine Core/UH allocation ABI inspection, without provider loading."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('coro_genuine', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('coro_abi_helpers', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
spec = importlib.util.spec_from_file_location('coro_current_stock', HERE / 'audit-modern-universalhid-current-stock-exports-v1.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def branch_target(pc, word):
    assert word & 0xfc000000 in (0x94000000, 0x14000000)
    delta = (word & 0x3ffffff) << 2
    if delta & 0x8000000:
        delta -= 0x10000000
    return pc + delta


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    inputs = [p.pin(Path(__file__)), p.pin(Path(h.__file__)), p.pin(Path(s.__file__)),
              p.pin(ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-RuntimeFunctions.def')]
    all_calls = {}
    islands = set()
    for framework in ('UniversalHID', 'UniversalHIDKit'):
        rawpath = h.ORIGINAL / 'raw' / framework
        memopath = h.ORIGINAL / (framework + '-symbols.a2s.batch.json')
        raw = rawpath.read_bytes()
        memo = json.loads(memopath.read_bytes())['symbols']
        targets = {int(a, 16) for a, v in memo.items() if v and v[0] == '_swift_coroFrameAlloc'}
        assert targets == {0x2a0078350}
        calls = []
        for section in h.sections(raw):
            if section['name'] != '__text':
                continue
            for delta in range(0, section['bytes'], 4):
                word = struct.unpack_from('<I', raw, section['fileoff'] + delta)[0]
                if word & 0xfc000000 != 0x94000000:
                    continue
                pc = section['address'] + delta
                if branch_target(pc, word) not in targets:
                    continue
                assert delta >= 64 and delta + 48 <= section['bytes']
                body = raw[section['fileoff'] + delta - 64:section['fileoff'] + delta + 48]
                # Every true caller writes a real 16-bit type ID to w1 directly
                # before BL, and uses the returned pointer immediately.
                typeword = struct.unpack_from('<I', body, 60)[0]
                assert typeword & 0xffe0001f == 0x52800001
                calls.append(dict(pc=pc, target=branch_target(pc, word), typeID=(typeword >> 5) & 65535,
                                  windowStart=pc - 64, window=body.hex(), instructions=h.decode_body(body, pc - 64)))
                islands.add(branch_target(pc, word))
        assert len(calls) == (52 if framework == 'UniversalHID' else 6)
        all_calls[framework] = calls
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
        exports = p.GenuineCacheExports(cache)
        core = exports.image('/usr/lib/swift/libswiftCore.dylib')
        assert core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0'
        extent = read(core['base'], 32, 'Core header extent')
        header = read(core['base'], 32 + struct.unpack_from('<I', extent, 20)[0], 'complete Core header')
        for command, at, size in h.commands(header):
            if command == 0x19 and header[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
                link = struct.unpack_from('<Q', header, at + 24)[0]
                lfo = struct.unpack_from('<Q', header, at + 40)[0]
            elif command == 0x26:
                off, starts_size = struct.unpack_from('<II', header, at + 8)
        encoded = read(link + off - lfo, starts_size, 'complete Core function starts')
        starts = []
        value = core['base']
        at = 0
        while at < len(encoded):
            delta, at = h.uleb(encoded, at)
            if not delta:
                break
            value += delta
            starts.append(value)
        functions = []
        for name, size_expected in (('_swift_coroFrameAlloc', 64), ('_swift_slowAlloc', 136)):
            export = core['exports'][name]
            assert export.flags == 0
            entry = core['base'] + export.address
            assert entry in starts
            end = starts[starts.index(entry) + 1]
            assert end - entry == size_expected
            body = read(entry, end - entry, 'complete original ' + name)
            path = out / (name.removeprefix('_') + '.bin')
            path.write_bytes(body)
            obj = out / (name.removeprefix('_') + '.inspection-only.macho-object')
            h.inspection_container(obj, entry, body)
            functions.append(dict(name=name, entry=entry, nextStart=end, code=p.pin(path),
                                  inspectionContainer=p.pin(obj), instructions=h.decode_body(body, entry)))
            inputs += [p.pin(path), p.pin(obj)]
        coro = functions[0]
        body = bytes.fromhex(''.join(x['bytes'] for x in coro['instructions']))
        assert list(struct.unpack_from('<4I', body, 16)) == [0x52800028, 0xf100001f, 0x9a881013, 0xaa1303e0]
        assert branch_target(coro['entry'] + 32, struct.unpack_from('<I', body, 32)[0]) == 0x1980ec150
        assert list(struct.unpack_from('<2I', body, 52)) == [0xaa1303e0, 0xd2800001]
        assert branch_target(coro['entry'] + 60, struct.unpack_from('<I', body, 60)[0]) == 0x194eb8e88
        # The following LC_FUNCTION_STARTS entry is a separate bzero thunk,
        # not a continuation of the noreturn allocation-failure call.
        adjacent_thunk = coro['nextStart']
        assert starts[starts.index(adjacent_thunk) + 1] - adjacent_thunk == 4
        thunk_body = read(adjacent_thunk, 4, 'unrelated following bzero thunk boundary')
        assert branch_target(adjacent_thunk, struct.unpack('<I', thunk_body)[0]) == 0x1980ec090
        # Exact common allocation-failure entry is shared with slowAlloc.
        slowbody = Path(functions[1]['code']['path']).read_bytes()
        assert branch_target(functions[1]['entry'] + 132, struct.unpack_from('<I', slowbody, 132)[0]) == 0x194eb8e88
        failure_entry = 0x194eb8e88
        assert failure_entry in starts
        failure_end = starts[starts.index(failure_entry) + 1]
        failure_body = read(failure_entry, failure_end - failure_entry, 'complete shared allocation-failure entry')
        failure_file = out / 'Core-shared-allocation-failure.bin'
        failure_file.write_bytes(failure_body)
        inputs.append(p.pin(failure_file))
        string = read(0x195297366, 128, 'genuine allocation-failure format').split(b'\0')[0]
        assert b'failed to allocate' in string
        authenticated = []
        for address, owner, name, expected in (
            (0x2a0078350, '/usr/lib/swift/libswiftCore.dylib', '_swift_coroFrameAlloc', coro['entry']),
            (0x1980ec150, '/usr/lib/libSystem.B.dylib', '_malloc_type_malloc', None),
            (0x1980ec090, '/usr/lib/system/libsystem_platform.dylib', '__platform_bzero', None),
        ):
            definition = exports.resolve(owner, name)
            assert definition is not None
            target_expected = definition['exportAddress']
            if expected is not None:
                assert target_expected == expected
            code = read(address, 16, 'exact original authenticated island ' + name)
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
            pageoff = expanded.fileOffset + page * slide.page_size
            cursor = pageoff + start
            for _ in range(slide.page_size // 8):
                assert pageoff <= cursor <= pageoff + slide.page_size - 8
                word = context.readFormat('<Q', cursor)[0]
                target, auth, key, diversity, addressdiversity, delta = h.decodeV5Pointer(word, slide.value_add)
                if cursor == offset:
                    break
                assert delta and cursor < offset
                cursor += delta
            else:
                raise AssertionError('island slot not in genuine slide chain')
            assert target == target_expected and auth and key == 0 and addressdiversity, (hex(address), name, hex(target), hex(target_expected), auth, key, addressdiversity)
            authenticated.append(dict(address=address, code=code.hex(), slot=slot, pointerWord=word,
                                      target=target, auth=auth, key=key, diversity=diversity, addressDiversity=addressdiversity,
                                      exactChainMembershipVerified=True, exactDefinition=definition))
        for sub in subs:
            sub.close()
    images = s.captured_images()
    current = s.resolve(images, '/usr/lib/swift/libswiftCore.dylib', '_swift_slowAlloc')
    assert current['status'] == 'actualDirectExport'
    report = dict(schema='Genuine coroutine frame allocation finite old-host ABI audit v1',
                  originalCacheUUID='c284a291b68b3d0da1a03f866f87efdc', originalSwiftCoreUUID=core['UUID'],
                  currentCacheUUID='1995ea169d0a33a0b78962cf99891168', inputs=inputs, reads=reads,
                  originalFunctions=functions, unrelatedFollowingBzeroThunk=dict(entry=adjacent_thunk, code=thunk_body.hex(), partOfCoroFunction=False),
                  sharedOriginalAllocationFailure=dict(entry=failure_entry,
                      code=p.pin(failure_file), format=string.decode(), instructions=h.decode_body(failure_body, failure_entry)),
                  authenticatedIslands=authenticated, genuineCallerWindows=all_calls,
                  currentNativeSlowAllocDefinition=current, officialImplementationURL='https://github.com/swiftlang/swift/blob/main/stdlib/public/runtime/Heap.cpp',
                  ABI='C_CC: x0=size_t, x1=uint64 typeID; x0=owned frame pointer',
                  candidateScope='finite old-host single genuine swift_slowAlloc(size,0), 16-byte alignment and fatal allocation failure; type-ID telemetry unavailable',
                  originalCallerCounts=dict(UniversalHID=52, UniversalHIDKit=6),
                  typedAllocatorTelemetryPreserved=False, allCoroutineLifecycleValidated=False,
                  fullSwift27RuntimeEquivalent=False, fullCurrentLoadGraphProven=False,
                  originalUHLoaded=False, originalVMMExecuted=False, nativeIOSExecuted=False,
                  deviceOperations=0, full27Backend=False)
    p.save(out / 'audit.json', report)
    inputs += [p.pin(out / 'audit.json')]
    p.save(out / 'freeze.json', dict(files=inputs, deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), originalCalls=58, currentSlowAllocPresent=True)))


if __name__ == '__main__':
    main()
