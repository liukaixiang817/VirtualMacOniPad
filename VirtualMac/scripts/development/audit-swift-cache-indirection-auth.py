#!/usr/bin/env python3
"""Read original cache GOT auth contracts; never load libraries or write caches.

Input routes come from an independently pinned relative-metadata candidate.
Each slot must be an actual member of its original slide-info-v5 fixup chain.
Authentication is decoded per slot, never guessed from a mangled-name suffix.
"""
import argparse
import hashlib
import inspect
import json
import pathlib
import struct
from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info, dyld_cache_slide_info5
from DyldExtractor.converter.slide_info import decodeV5Pointer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--routes', type=pathlib.Path, required=True)
    parser.add_argument('--expected-routes-sha256', required=True)
    parser.add_argument('--cache', type=pathlib.Path, required=True)
    parser.add_argument('--expected-cache-uuid', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    raw = args.routes.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == args.expected_routes_sha256
    candidate = json.loads(raw)
    routes = candidate['newStrongDataImports'] if isinstance(candidate, dict) else candidate
    addresses = [row['originalSlotVA'] for row in routes]
    assert len(set(addresses)) == len(addresses) and len(routes) <= 1024
    args.output.mkdir(parents=True, exist_ok=False)
    rows, inputs = [], []
    with args.cache.open('rb') as main_file:
        context = DyldContext(main_file)
        assert bytes(context.header.uuid).hex() == args.expected_cache_uuid
        subs = context.addSubCaches(args.cache)
        assert len(context._subCaches) == len(subs)
        file_names = {id(context): str(args.cache.resolve())}
        for sub_context, sub_file in zip(context._subCaches, subs):
            file_names[id(sub_context)] = str(pathlib.Path(sub_file.name).resolve())
        try:
            for route in routes:
                address = route['originalSlotVA']
                assert address % 8 == 0
                converted = context.convertAddr(address)
                assert converted is not None
                offset, owner = converted
                matches = [(mapping, current) for mapping, current in context.mappings
                           if current is owner and mapping.address <= address < mapping.address + mapping.size]
                assert len(matches) == 1
                mapping, _ = matches[0]
                index = owner.mappings.index((mapping, owner))
                expanded = dyld_cache_mapping_and_slide_info(owner.file, owner.header.mappingWithSlideOffset + index * dyld_cache_mapping_and_slide_info.SIZE)
                assert expanded.address == mapping.address and expanded.slideInfoFileOffset
                slide = dyld_cache_slide_info5(owner.file, expanded.slideInfoFileOffset)
                assert slide.version == 5 and slide.page_size in (4096, 16384)
                page = (address - expanded.address) // slide.page_size
                assert page < slide.page_starts_count
                start = owner.readFormat('<H', expanded.slideInfoFileOffset + len(slide) + page * 2)[0]
                assert start != 0xffff
                page_offset = expanded.fileOffset + page * slide.page_size
                cursor, visits = page_offset + start, 0
                while True:
                    assert page_offset <= cursor <= page_offset + slide.page_size - 8 and (cursor - page_offset) % 8 == 0
                    word = owner.readFormat('<Q', cursor)[0]
                    target, auth, key, diversity, address_diversity, delta = decodeV5Pointer(word, slide.value_add)
                    visits += 1
                    assert visits <= slide.page_size // 8
                    if cursor == offset:
                        break
                    assert delta and cursor < offset
                    cursor += delta
                row = dict(route)
                row.update(rawCacheWord=hex(word), actualTarget=hex(target), auth=auth,
                           key=key, diversity=hex(diversity), addressDiversity=address_diversity,
                           slideInfoVersion=5, chainMembershipVerified=True,
                           cacheFile=file_names[id(owner)], cacheUUID=bytes(owner.header.uuid).hex(),
                           cacheFileOffset=offset, mappingVA=expanded.address,
                           slideInfoFileOffset=expanded.slideInfoFileOffset, slideValueAdd=slide.value_add)
                rows.append(row)
            unique = {file_names[id(owner)]: owner for _, owner in context.mappings}
            for name, owner in sorted(unique.items()):
                stat = pathlib.Path(name).stat()
                inputs.append({'path': name, 'uuid': bytes(owner.header.uuid).hex(), 'bytes': stat.st_size, 'mtime_ns': stat.st_mtime_ns})
        finally:
            for sub in subs:
                sub.close()
    for row in inputs:
        stat = pathlib.Path(row['path']).stat()
        assert stat.st_size == row['bytes'] and stat.st_mtime_ns == row['mtime_ns']
    assert hashlib.sha256(args.routes.read_bytes()).hexdigest() == args.expected_routes_sha256
    assert len(rows) == len(routes)
    decoder = pathlib.Path(inspect.getfile(decodeV5Pointer))
    result = {'sourceRoutes': str(args.routes.resolve()), 'sourceRoutesSHA256': args.expected_routes_sha256,
              'mainCacheUUID': args.expected_cache_uuid, 'cacheInputs': inputs,
              'decoder': str(decoder), 'decoderSHA256': hashlib.sha256(decoder.read_bytes()).hexdigest(),
              'contracts': rows, 'libraryLoaded': False, 'cacheModified': False,
              'symbolTargetsIndependentlyResolved': False}
    (args.output / 'contract.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'slots': len(rows), 'authPolicies': sorted(set((r['auth'], r['key'], r['diversity'], r['addressDiversity']) for r in rows)), 'libraryLoaded': False}))


if __name__ == '__main__':
    main()
