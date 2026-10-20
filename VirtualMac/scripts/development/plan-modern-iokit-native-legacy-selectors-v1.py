#!/usr/bin/env python3
"""Request the actual legacy ObjC selector base and initializer callee islands."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_legacy_ro', HERE/'plan-modern-iokit-native-class-ro-v1.py')
ro = importlib.util.module_from_spec(spec); spec.loader.exec_module(ro)
s, p = ro.s, ro.p
from current_hid_extra_three_capture_v1 import mapping


def branches(raw, va):
    result = []
    for offset in range(0, len(raw), 4):
        word = struct.unpack_from('<I', raw, offset)[0]
        if word & 0xfc000000 == 0x94000000:
            relative = word & 0x3ffffff
            if relative & 0x2000000: relative -= 0x4000000
            result.append(dict(pc=va+offset, target=va+offset+relative*4))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    heads_path = p.NODE/'ipad-current-cache-objc-linkedit-header-v1/headers.json'
    heads = json.loads(heads_path.read_bytes())
    captured = p.NODE/'ipad-current-iokit-objcopt-bounded-readonly-v1'
    request = p.NODE/'ipad-current-iokit-objcopt-bounded-read-plan-v1/request.json'
    receipt = s.checked_capture(captured, request, heads_path)
    assert receipt['readerSHA256'] == p.pin(captured/'reader-source.py')['sha256'] == 'ceca8607b86fb329aebc23ac48690a1abd3ef2adfb00432b854f25f25f717cd9'
    original = json.loads((p.NODE/'ipad-current-iokit-native-method-bodies-plan-v1/request.json').read_bytes())
    combined = json.loads(request.read_bytes())
    assert combined['ranges'][:-1] == original['ranges']
    raw = (captured/'objc-optimization-header.bin').read_bytes()
    assert len(raw) == 32 and struct.unpack('<II3Q', raw) == (1,7,32124928,1560444928,94814352)
    native = s.primary.captured_images()
    pins = s.join_capture(native, 'stock-extra', p.NODE/'ipad-current-cache-stock-extra-headers-v1/headers.json')
    image = native['/usr/lib/libobjc.A.dylib']
    sections = [section for segment in p.segments(Path(image['header']['path']).read_bytes()) for section in segment['sections']]
    opts = [section for section in sections if section['name'] == '__objc_opt_ro']
    assert len(opts) == 1 and opts[0]['address'] == 0x1800e9ab8 and opts[0]['size'] == 16384
    ranges = [dict(name='legacy-libobjc-optimization-header', **mapping(heads, opts[0]['address'], 48))]
    initializer = captured/'iokit-event-method-3-complete.bin'
    body = initializer.read_bytes()
    assert len(body) == 180
    calls = branches(body, 0x18ec7414c)
    assert [row['target'] for row in calls] == [0x193439650,0x18ed0ccf8,0x193438db0]
    # The method's real complete instructions first dispatch super init, then
    # require a non-nil receiver and size >=16. Type is only used for the mask
    # and raw header stores; selector identity remains pending the legacy base.
    assert struct.unpack_from('<5I', body, 0x48) == (0xf100001f,0xfa501a80,0x54000223,0xaa0003f6,0xaa1403e0)
    assert struct.unpack_from('<I', body, 0x60)[0] == 0xf90036c0
    # The other two actual callee islands are outside the current fixed
    # whitelist. Preserve that boundary instead of making an archive mapping
    # look like a current capture. The real allocator island is in guarded 05.
    ranges.append(dict(name='iokit-event-initializer-raw-allocation-island', **mapping(heads, calls[1]['target'], 16)))
    ranges.append(dict(name='iokit-event-super-init-selector', **mapping(heads, 0x1823f2883, 5)))
    # The already captured type encoding is bounded and truncated at 128 B.
    # Read its continuation rather than claim a complete struct type.
    ranges.append(dict(name='iokit-event-own-ivar-type-tail', **mapping(heads, 0x18ed2d6eb+128, 128)))
    assert len(ranges) == 4 and sum(row['length'] for row in ranges) == 197
    assert all(row['cache'] in {'main','01','03','05','07','11','13','17','21','25','27-data','28-linkedit','44-linkedit'} for row in ranges)
    out.mkdir()
    p.save(out/'request.json', dict(ranges=ranges))
    p.save(out/'derivation.json', dict(schema='Actual old HIDEvent legacy selector and initializer callee bounded request v1',
        actualReceipt=p.pin(captured/'receipt.json'), actualMergedManifest=p.pin(request),
        originalSevenRangesPreservedExactly=True, actualHeaders=p.pin(heads_path),
        actual32ByteObjCOptimizationHeader=p.pin(captured/'objc-optimization-header.bin'),
        actualVersion1HeaderHasNo48ByteSelectorBaseField=True,
        actualLegacyLibObjCCommands=image['header'], actualLegacyOptSection=opts[0],
        legacySchemaPrimarySources=[
            'https://raw.githubusercontent.com/llvm/llvm-project/main/lldb/source/Plugins/LanguageRuntime/ObjC/AppleObjCRuntime/AppleObjCRuntimeV2.cpp',
            'https://raw.githubusercontent.com/apple-oss-distributions/dyld/dyld-1042.1/include/objc-shared-cache.h'],
        legacyRelativeBaseInterpretationMustBeValidatedAgainstActualVersionAndBytes=True,
        actualCompleteInitializerShapedMethod=p.pin(initializer), actualDirectCallerEdges=calls,
        pendingUnguardedCalleeIslands=[calls[0],calls[2]],
        actualOwnIvarOffset=struct.unpack('<I',(captured/'iokit-event-own-ivar-offset.bin').read_bytes())[0],
        rawDataPointerObjectOffset=104, actualObservedSizeMinimum=16,
        methodSelectorIdentityStillUnproved=True, currentInitializerNewTypesExecutionUnproved=True,
        request=p.pin(out/'request.json'), requestedBytes=197, requestedRanges=4,
        nativeIOSExecuted=False, originalHIDLoaded=False, nativeHVCalls=0, deviceOperations=0, full27Backend=False))
    paths = [Path(__file__), heads_path, request, Path(image['header']['path']), initializer]
    paths += [captured/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py',
        'objc-optimization-header.bin','iokit-event-method-and-ivar-type-encodings.bin','iokit-event-own-ivar-offset.bin')]
    paths += [out/'request.json', out/'derivation.json']
    pins += [p.pin(path) for path in paths]
    p.save(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(request=p.pin(out/'request.json'), ranges=ranges)))


if __name__ == '__main__': main()
