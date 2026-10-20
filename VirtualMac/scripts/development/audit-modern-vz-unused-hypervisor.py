#!/usr/bin/env python3
"""Read genuine cache metadata for the VZ Hypervisor load edge; no image calls."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_structs import (
    dyld_cache_mapping_and_slide_info, dyld_cache_slide_info5)
from DyldExtractor.converter.slide_info import decodeV5Pointer

ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CACHE = Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')
RAW = ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw'


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def header(data):
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    count, size = struct.unpack_from('<II', data, 16)
    assert count < 256 and size < 65536 and 32 + size == len(data)
    at = 32
    commands, sections, segments, uuid = [], [], [], None
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, at)
        assert length >= 8 and length % 8 == 0 and at + length <= len(data)
        commands.append(dict(command=cmd, at=at, bytes=length, hex=data[at:at+length].hex()))
        if cmd == 0x1b:
            assert uuid is None and length == 24
            uuid = data[at+8:at+24].hex()
        if cmd == 0x19:
            segments.append(dict(name=data[at+8:at+24].split(b'\0')[0].decode(),
                address=struct.unpack_from('<Q',data,at+24)[0],
                bytes=struct.unpack_from('<Q',data,at+32)[0]))
            count = struct.unpack_from('<I', data, at+64)[0]
            assert length == 72 + count * 80
            for index in range(count):
                slot = at + 72 + index * 80
                sections.append(dict(name=data[slot:slot+16].split(b'\0')[0].decode(),
                    segment=data[slot+16:slot+32].split(b'\0')[0].decode(),
                    address=struct.unpack_from('<Q', data, slot+32)[0],
                    bytes=struct.unpack_from('<Q', data, slot+40)[0],
                    flags=struct.unpack_from('<I', data, slot+64)[0]))
        at += length
    assert at == len(data) and uuid
    return dict(uuid=uuid, commands=commands, sections=sections, segments=segments)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    assert output.is_relative_to(NODE) and not output.exists()
    assert pin(RAW/'Hypervisor')['sha256'] == '4d334d43c5628d134ef6b0f8ceef9a4c3c620467b284f92dc1c49b16bfc495a3'
    assert pin(RAW/'Virtualization')['sha256'] == 'ec4bbc11af44a0c04a56269397274c90265a51568fe50e4e94123dd5eaa82f04'
    reads, pointers = [], []
    with CACHE.open('rb') as stream:
        context = DyldContext(stream)
        context.addSubCaches(CACHE)
        cache_uuid = bytes(context.header.uuid).hex()
        assert cache_uuid == 'c284a291b68b3d0da1a03f866f87efdc'

        def read(address, count):
            assert 0 < count <= 1048576
            converted = context.convertAddr(address)
            assert converted is not None
            offset, owner = converted
            assert offset + count <= len(owner.file)
            data = owner.getBytes(offset, count)
            reads.append(dict(address=address, bytes=count, sha256=hashlib.sha256(data).hexdigest()))
            return data

        def image(path):
            matches = [x for x in context.images if context.readString(x.pathFileOffset).rstrip(b'\0').decode() == path]
            assert len(matches) == 1
            base = matches[0].address
            size = struct.unpack_from('<I', read(base, 32), 20)[0]
            assert size < 65536
            data = read(base, 32+size)
            return base, data, header(data)

        def pointer(slot):
            value = read(slot, 8)
            if value == bytes(8):
                return 0
            mapping, owner = next((m,o) for m,o in context.mappings if m.address <= slot < m.address+m.size)
            index = owner.mappings.index((mapping, owner))
            info = dyld_cache_mapping_and_slide_info(owner.file,
                owner.header.mappingWithSlideOffset + index * dyld_cache_mapping_and_slide_info.SIZE)
            slide = dyld_cache_slide_info5(owner.file, info.slideInfoFileOffset)
            assert slide.version == 5
            page = (slot-info.address)//slide.page_size
            start = owner.readFormat('<H', info.slideInfoFileOffset+len(slide)+page*2)[0]
            assert start != 65535
            pageoff = info.fileOffset+page*slide.page_size
            cursor, wanted = pageoff+start, info.fileOffset+slot-info.address
            for _ in range(slide.page_size//8):
                assert pageoff <= cursor <= pageoff+slide.page_size-8
                word = owner.readFormat('<Q', cursor)[0]
                target, auth, key, diversity, address_diversity, delta = decodeV5Pointer(word, slide.value_add)
                if cursor == wanted:
                    target &= 0x00ffffffffffffff
                    pointers.append(dict(slot=slot, word=word, target=target, auth=auth,
                        key=key, diversity=diversity, addressDiversity=address_diversity))
                    return target
                assert delta and cursor < wanted
                cursor += delta
            raise AssertionError('bounded pointer chain not found')

        def string(address):
            data = read(address, 512)
            assert b'\0' in data
            return data.split(b'\0')[0].decode()

        hv_base, hv_header, hv = image('/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor')
        vz_base, vz_header, vz = image('/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization')
        _, objc_header, objc = image('/usr/lib/libobjc.A.dylib')
        assert hv_base == 0x21e418000 and hv['uuid'] == '1b4f3a6a055836c6850d886311584afc'
        assert vz['uuid'] == '418efc4809d93606918eb6f95baeffdc'
        initializers = [s for s in hv['sections'] if s['bytes'] and
            (s['flags'] & 255 in (9, 10, 21) or s['name'] in ('__objc_nlclslist','__objc_nlcatlist'))]
        assert not initializers
        assert not any(c['command'] in (0x11, 0x1a, 0x16, 0x17, 0x8000001f) for c in hv['commands'])
        assert not any(s['bytes'] and s['name'] == '__objc_catlist' for s in hv['sections'])
        opt = next(s for s in objc['sections'] if s['name'] == '__objc_opt_ro')
        selector_base = opt['address'] + struct.unpack('<q', read(opt['address']+40, 8))[0]
        classes, methods = [], []
        owned = lambda address, count: any(s['address'] <= address and address+count <= s['address']+s['bytes'] for s in hv['sections'])

        def method_list(raw, name, meta):
            if not raw:
                return
            assert not raw & 1, 'unsupported list-of-lists requires explicit proof'
            address = raw & ~7
            assert owned(address, 8)
            flags, count = struct.unpack('<II', read(address, 8))
            stride = flags & 0xfffc
            assert count <= 4096 and owned(address, 8+stride*count)
            for index in range(count):
                slot = address+8+index*stride
                if flags & 0x80000000:
                    assert stride == 12
                    selector, _, imp = struct.unpack('<iii', read(slot, 12))
                    selector = selector_base+selector if flags & 0x40000000 else pointer(slot+selector)
                    target = slot+8+imp
                else:
                    assert stride == 24
                    selector, target = pointer(slot), pointer(slot+16)
                text = next(s for s in hv['sections'] if s['name'] == '__text')
                assert text['address'] <= target < text['address']+text['bytes']
                selector = string(selector)
                assert not meta or selector != 'load'
                methods.append(dict(className=name, classMethod=meta, selector=selector, target=target))

        classlist = next(s for s in hv['sections'] if s['name'] == '__objc_classlist')
        assert classlist['bytes'] == 40
        for index in range(5):
            cls = pointer(classlist['address']+index*8)
            assert owned(cls, 40)
            ro = pointer(cls+32) & ~7
            assert owned(ro, 72)
            name = string(pointer(ro+24))
            classes.append(dict(name=name, classAddress=cls))
            method_list(pointer(ro+32), name, False)
            meta = pointer(cls)
            assert owned(meta, 40)
            meta_ro = pointer(meta+32) & ~7
            assert owned(meta_ro, 72)
            assert string(pointer(meta_ro+24)) == name
            method_list(pointer(meta_ro+32), name, True)
        # Genuine original classref/superref slots never point into this provider.
        references = []
        for section in vz['sections']:
            if section['name'] not in ('__objc_classrefs', '__objc_superrefs'):
                continue
            assert section['bytes'] % 8 == 0
            for index in range(section['bytes']//8):
                slot = section['address']+index*8
                target = pointer(slot)
                assert not owned(target, 1)
                references.append(dict(slot=slot, target=target))
        cstrings = next(s for s in vz['sections'] if s['name'] == '__cstring')
        actual_strings = read(cstrings['address'], cstrings['bytes']).split(b'\0')
        assert not any(c['name'].encode() in actual_strings for c in classes)
        assert not any(b'Hypervisor.framework' in s or s.startswith(b'hv_') for s in actual_strings)
        # Inspect every original VZ slide-chain slot, including pointer data
        # outside ObjC sections. The two named HV imports use shared-cache
        # import islands; no raw VZ rebase may retain an HV code/data address.
        hv_contains = lambda address: any(s['name'] != '__LINKEDIT' and
            s['address'] <= address < s['address']+s['bytes'] for s in hv['segments'])
        original_vz_pointer_slots = 0
        original_vz_hv_targets = []
        for segment in vz['segments']:
            if segment['name'] in ('__TEXT','__LINKEDIT') or not segment['bytes']:
                continue
            begin, end = segment['address'], segment['address']+segment['bytes']
            mapping, owner = next((m,o) for m,o in context.mappings if m.address <= begin < m.address+m.size)
            assert end <= mapping.address+mapping.size
            index = owner.mappings.index((mapping,owner))
            info = dyld_cache_mapping_and_slide_info(owner.file,
                owner.header.mappingWithSlideOffset+index*dyld_cache_mapping_and_slide_info.SIZE)
            slide = dyld_cache_slide_info5(owner.file,info.slideInfoFileOffset)
            assert slide.version == 5
            first, last = (begin-info.address)//slide.page_size, (end-1-info.address)//slide.page_size
            for page in range(first,last+1):
                start = owner.readFormat('<H',info.slideInfoFileOffset+len(slide)+page*2)[0]
                if start == 65535:
                    continue
                pageoff = info.fileOffset+page*slide.page_size
                cursor = pageoff+start
                for _ in range(slide.page_size//8):
                    assert pageoff <= cursor <= pageoff+slide.page_size-8
                    word = owner.readFormat('<Q',cursor)[0]
                    target, _, _, _, _, delta = decodeV5Pointer(word,slide.value_add)
                    target &= 0x00ffffffffffffff
                    slot = info.address+cursor-info.fileOffset
                    if begin <= slot < end:
                        original_vz_pointer_slots += 1
                        if hv_contains(target):
                            original_vz_hv_targets.append(dict(slot=slot,target=target))
                    if not delta:
                        break
                    cursor += delta
                else:
                    raise AssertionError('nonterminating original pointer page')
        assert original_vz_pointer_slots == 17399 and not original_vz_hv_targets
        text = next(s for s in vz['sections'] if s['name'] == '__text')
        original_text = b''.join(read(text['address']+offset,min(65536,text['bytes']-offset))
            for offset in range(0,text['bytes'],65536))
        direct_edges = []
        for index,(word,) in enumerate(struct.iter_unpack('<I',original_text)):
            if word & 0x7c000000 != 0x14000000: # B/BL immediate only.
                continue
            immediate = word & 0x3ffffff
            if immediate & 0x2000000:
                immediate -= 0x4000000
            pc = text['address']+index*4
            target = pc+immediate*4
            if hv_contains(target):
                direct_edges.append(dict(pc=pc,target=target,word=word))
        assert not direct_edges

    output.mkdir(parents=True)
    for name, data in [('hypervisor-original-cache-header.bin',hv_header),
                       ('virtualization-original-cache-header.bin',vz_header),
                       ('libobjc-original-cache-header.bin',objc_header)]:
        (output/name).write_bytes(data)
    report = dict(schema='Original VZ unused Hypervisor edge genuine static audit v1',
        cacheUUID=cache_uuid, originalHypervisorUUID=hv['uuid'], originalVZUUID=vz['uuid'],
        originalHypervisorCommands=hv['commands'], originalHypervisorSections=hv['sections'],
        eagerInitializerSections=initializers, routinesCommands=0, reexportCommands=0,
        originalHypervisorClasses=classes, originalHypervisorMethods=methods,
        nonlazyObjCSections=0, ownClassLoadMethods=0, categories=0,
        originalVZClassReferences=references, originalVZClassRefTargetsOutsideHypervisor=True,
        originalVZCStringHVClassAndDynamicPathMatches=0,
        originalVZSlideChainSlotsChecked=original_vz_pointer_slots,
        originalVZSlideTargetsInHypervisor=original_vz_hv_targets,
        originalVZDirectBandBLTargetsInHypervisor=direct_edges,
        boundedCacheReadCount=len(reads), cacheReads=reads, exactPointerChainContracts=pointers,
        rawReferences=[pin(RAW/'Hypervisor'),pin(RAW/'Virtualization')],
        nativeExecuted=False, deviceOperations=0, CPUCalls=0, originalVZLoaded=False,
        noRuntimeLoaderSemanticsClaim=True, full27Backend=False)
    (output/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    records=[pin(p) for p in sorted(output.iterdir()) if p.is_file()]
    records.append(pin(Path(__file__)))
    (output/'freeze.json').write_text(json.dumps(dict(files=records),indent=2)+'\n')
    print(json.dumps(dict(audit=pin(output/'audit.json'),classes=classes,
        classMethods=[m for m in methods if m['classMethod']],cacheReadCount=len(reads),deviceOperations=0)))


if __name__ == '__main__':
    main()
