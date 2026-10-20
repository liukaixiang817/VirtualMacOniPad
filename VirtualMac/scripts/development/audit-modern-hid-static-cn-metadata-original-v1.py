#!/usr/bin/env python3
"""Read genuine StaticArray CN data, authenticated slots and complete methods.

This produces inspection data only. It does not load, sign, route, register,
instantiate or execute a class, and does not provide an alternate CN alias.
"""
from pathlib import Path
import argparse
import bisect
import hashlib
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('static_cn_contract', HERE / 'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('static_cn_tools', p.NODE / 'universalhid-array-reexport-abi-readonly-v1/audit.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

def require(value, reason):
    if not value:
        raise ValueError(reason)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    out = parser.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'new workspace output required')
    out.mkdir(mode=0o700)
    inputs = [p.pin(Path(__file__)), p.pin(Path(p.__file__)), p.pin(Path(h.__file__))]
    prior = p.NODE / 'universalhid-cvw-static-original-abi-readonly-v1/audit.json'
    caller = json.loads(prior.read_bytes())
    require(caller['actualStaticArrayISACount'] == 42, 'actual caller count')
    inputs.append(p.pin(prior))
    observed = p.NODE / 'static-array-base-descriptor-probe-build-v1/mac-native.stdout'
    require('classSize=176 classAddressPoint=24' in observed.read_text(), 'original runtime shape observation absent')
    inputs.append(p.pin(observed))
    reads, functions = [], []
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream)
        require(bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc', 'genuine cache drift')
        subs = cache.addSubCaches(p.CACHE)
        try:
            def read(address, size, label):
                require(0 < size <= 65536, 'bounded read')
                off, context = cache.convertAddr(address)
                data = context.getBytes(off, size)
                require(len(data) == size, 'short read')
                path = out / (label + '.bin')
                path.write_bytes(data)
                row = dict(address=address, bytes=size, offset=off, cacheUUID=bytes(context.header.uuid).hex(), data=p.pin(path))
                reads.append(row)
                inputs.append(row['data'])
                return data

            exports = p.GenuineCacheExports(cache)
            core = exports.image('/usr/lib/swift/libswiftCore.dylib')
            require(core['UUID'] == 'c9b36da7bb3435afbc5d91ecbcaa9ed0', 'genuine Core UUID drift')
            def definition(name):
                value = core['exports'][name]
                require(value.flags == 0, 'direct Core definition required')
                return core['base'] + value.address
            cn = definition('_$ss20__StaticArrayStorageCN')
            descriptor = definition('_$ss20__StaticArrayStorageCMn')
            base = definition('_$ss28__ContiguousArrayStorageBaseCN')
            base_descriptor = definition('_$ss28__ContiguousArrayStorageBaseCMn')
            body = read(cn - 24, 176, 'original-CN-complete-prefix-and-metadata')
            require(struct.unpack_from('<II', body, 24 + 56) == (176, 24), 'exact metadata extent')
            require(struct.unpack_from('<I', body, 24 + 40)[0] == 2, 'class flags')
            require(struct.unpack_from('<IHH', body, 24 + 48) == (32, 7, 0), 'instance size/alignment')
            desc = read(descriptor, 124, 'original-CMn-complete-descriptor')
            words = struct.unpack('<31I', desc)
            require(words[0] == 0xc0000050 and words[6:11] == (3, 19, 1, 0, 18), 'fixed non-generic class descriptor shape')
            require(words[11:13] == (18, 1) and words[15] == 5, 'vtable and override counts')
            base_desc = read(base_descriptor, 92, 'original-parent-CMn-complete-descriptor')
            require(struct.unpack_from('<I', base_desc)[0] == 0xc0000050, 'exact parent descriptor flags')

            chain_pages = {}
            def page_chain(address):
                offset, context = cache.convertAddr(address)
                mapping = next(m for m, c in cache.mappings if c is context and m.address <= address < m.address + m.size)
                index = context.mappings.index((mapping, context))
                expanded = h.dyld_cache_mapping_and_slide_info(context.file, context.header.mappingWithSlideOffset + index * h.dyld_cache_mapping_and_slide_info.SIZE)
                slide = h.dyld_cache_slide_info5(context.file, expanded.slideInfoFileOffset)
                require(slide.version == 5 and slide.page_size in (4096, 16384), 'actual slide5 shape')
                page = (address - expanded.address) // slide.page_size
                identity = (str(context.file.name), page)
                if identity not in chain_pages:
                    start = context.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page * 2)[0]
                    page_offset = expanded.fileOffset + page * slide.page_size
                    entries = {}
                    if start != 0xffff:
                        cursor = page_offset + start
                        for visits in range(slide.page_size // 8):
                            require(page_offset <= cursor <= page_offset + slide.page_size - 8, 'chain bounds')
                            word = context.readFormat('<Q', cursor)[0]
                            target, auth, key, diversity, address_diversity, delta = h.decodeV5Pointer(word, slide.value_add)
                            entries[expanded.address + page * slide.page_size + cursor - page_offset] = dict(slot=expanded.address + page * slide.page_size + cursor - page_offset, raw=word, target=target, auth=auth, key=key, diversity=diversity, addressDiversity=address_diversity, actualChainMembership=True)
                            if not delta:
                                break
                            require(delta > 0, 'forward chain required')
                            cursor += delta
                        else:
                            raise ValueError('chain did not terminate')
                    chain_pages[identity] = entries
                return chain_pages[identity]
            slots = [page_chain(cn).get(address) for address in range(cn - 24, cn + 152, 8)]
            slots = [row for row in slots if row]
            byslot = {row['slot']: row for row in slots}
            require(byslot[cn + 8]['target'] == base and byslot[cn + 64]['target'] == descriptor, 'actual superclass/descriptor pointers')
            require(byslot[cn + 64]['auth'] and byslot[cn + 64]['key'] == 2 and byslot[cn + 64]['diversity'] == 0xae86 and byslot[cn + 64]['addressDiversity'], 'descriptor PAC')
            inverse = {}
            for name, value in core['exports'].items():
                if value.flags == 0:
                    inverse.setdefault(core['base'] + value.address, []).append(name)
            for row in slots:
                row['CNByteOffset'] = row['slot'] - cn
                row['directCoreExportsAtTarget'] = inverse.get(row['target'], [])
            overrides = []
            for index in range(5):
                at = 64 + index * 12
                parent_rel, method_rel, function_rel = struct.unpack_from('<3i', desc, at)
                parent = descriptor + at + parent_rel
                method = descriptor + at + 4 + method_rel
                function = descriptor + at + 8 + function_rel
                require(parent == base_descriptor and 52 <= method - base_descriptor <= 84 and (method - base_descriptor - 52) % 8 == 0, 'exact direct override parent/method')
                entry_index = (method - base_descriptor - 52) // 8
                parent_vtable_offset = struct.unpack_from('<I', base_desc, 44)[0]
                slot = cn + (parent_vtable_offset + entry_index) * 8
                require(slot in byslot and byslot[slot]['target'] == function, 'descriptor override matches actual completed vtable')
                overrides.append(dict(descriptorOffset=at, parent=parent, parentMethod=method, function=function, completedVTableSlot=slot, exactMatch=True))

            hdr32 = read(core['base'], 32, 'original-Core-header-prefix')
            header = read(core['base'], 32 + struct.unpack_from('<I', hdr32, 20)[0], 'original-Core-header')
            for command, at, size in h.commands(header):
                if command == 0x19 and header[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
                    link, lfo = struct.unpack_from('<Q', header, at + 24)[0], struct.unpack_from('<Q', header, at + 40)[0]
                elif command == 0x26:
                    function_off, function_length = struct.unpack_from('<II', header, at + 8)
            encoded = read(link + function_off - lfo, function_length, 'original-Core-function-starts')
            starts, cursor, address = [], 0, core['base']
            while cursor < len(encoded):
                delta, cursor = h.uleb(encoded, cursor)
                if not delta:
                    break
                address += delta
                starts.append(address)
            require(starts == sorted(set(starts)), 'function starts ordering')
            for target in sorted({row['target'] for row in slots if row['auth'] and row['key'] == 0}):
                index = bisect.bisect_left(starts, target)
                require(index < len(starts) - 1 and starts[index] == target, 'actual function entry boundary')
                end = starts[index + 1]
                code = read(target, end - target, 'original-method-' + hex(target)[2:])
                edges = []
                for at in range(0, len(code), 4):
                    word = struct.unpack_from('<I', code, at)[0]
                    if word & 0xfc000000 in (0x94000000, 0x14000000):
                        delta = (word & 0x3ffffff) << 2
                        destination = target + at + delta - (0x10000000 if delta & 0x8000000 else 0)
                        if not target <= destination < end:
                            edges.append(dict(pc=target + at, target=destination, exactDirectCoreExports=inverse.get(destination, []), exactCoreFunctionStart=destination in starts))
                functions.append(dict(entry=target, end=end, exactDirectCoreExports=inverse.get(target, []), actualAuthenticatedCNOffsets=[row['CNByteOffset'] for row in slots if row['target'] == target], instructions=h.decode_body(code, target), outgoingDirectEdges=edges))
            report = dict(schema='Genuine original StaticArray CN metadata ABI read-only v1', originalCacheUUID=bytes(cache.header.uuid).hex(), originalCoreUUID=core['UUID'], CN=cn, CMn=descriptor, parentCN=base, parentCMn=base_descriptor, classSize=176, classAddressPoint=24, metadataPositiveWords=19, metadataNegativeWords=3, instanceBytes=32, instanceAlignmentMask=7, ownVTableOffsetWords=18, ownVTableCount=1, genuineOverrides=overrides, exactAuthenticatedAndRebasedCNSlots=slots, completeOriginalMethods=functions, genuineArrayCallerCount=42, actualCallerContract=p.pin(prior), boundedGenuineCacheReads=reads, inputs=inputs, originalMetadataBodyCopiedIntoProvider=False, actualSwiftClassRegistered=False, originalCNIdentityRetainedInCandidate=False, factoryMetadataIsNotCNData=True, wrongAliasAllowed=False, recursivePointerDependencyClosureComplete=False, actualClassMethodsExecuted=False, candidateReadyForNativeLoading=False, deviceOperations=0, nativeCPUCalls=0, nativeVMCalls=0, full27Backend=False)
            p.save(out / 'audit.json', report)
            p.save(out / 'freeze.json', dict(files=inputs + [p.pin(out / 'audit.json')], deviceOperations=0, nativeCPUCalls=0, nativeVMCalls=0))
            print(json.dumps(dict(audit=p.pin(out / 'audit.json'), actualCNSlots=len(slots), actualCompleteMethods=len(functions))))
        finally:
            for sub in subs:
                sub.close()

if __name__ == '__main__':
    main()
