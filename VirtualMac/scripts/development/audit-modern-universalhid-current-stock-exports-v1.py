#!/usr/bin/env python3
"""Audit captured current iPad export tries against inert genuine27 images.

Only complete, UUID/header-pinned captures are accepted. A missing name in an
image with uncaptured reexport dependencies is not transitive absence proof.
This does not load any image, change a provider or contact the device.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hid_reader', HERE/'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
from compiler_image import commands, imports, segments

NODE = p.NODE
CAPTURE = NODE/'ipad-current-cache-exports-readonly-v1'
COMMANDS = NODE/'ipad-current-cache-commands-readonly-v1'
HEADERS = NODE/'ipad-current-cache-header-readonly-v2/headers.json'
MANIFEST = NODE/'ipad-current-cache-exports-manifest-v1.json'
SOURCE = NODE/'universalhid-genuine-type-metadata-data-v2/candidate.json'
FRONTEND = NODE/'universalhid-exact-owner-private-route-v5/candidate.json'


def checked_receipt(path, manifest):
    receipt = json.loads(path.read_text())
    assert receipt['mainCacheUUID'] == '1995ea169d0a33a0b78962cf99891168'
    assert receipt['allHeaderPinsMatchBeforeAndAfter'] and receipt['transportExit'] == 0
    assert receipt['headersSHA256'] == p.pin(HEADERS)['sha256']
    assert receipt['manifestSHA256'] == p.pin(manifest)['sha256']
    assert not any(receipt[k] for k in ('deviceWrites', 'nativeCPUCalls', 'newFrameworksLoaded'))
    for r in receipt['ranges']:
        assert p.pin(Path(r['path']))['sha256'] == r['sha256']
        assert Path(r['path']).stat().st_size == r['length']
    assert sum(r['length'] for r in receipt['ranges']) == receipt['requestedBytes']
    return receipt


def trie(blob):
    def uleb(at, limit):
        value = shift = 0
        while True:
            assert at < limit and shift < 64
            byte = blob[at]; at += 1
            value |= (byte & 127) << shift
            if not byte & 128: return value, at
            shift += 7
    result = {}; stack = [(0, '')]; seen = set()
    while stack:
        at, name = stack.pop()
        assert at not in seen and at < len(blob); seen.add(at)
        size, body = uleb(at, len(blob)); end = body + size
        assert end < len(blob)
        if size:
            flags, pos = uleb(body, end)
            value, pos = uleb(pos, end)
            row = dict(symbol=name, flags=flags)
            if flags & 8:
                stop = blob.find(b'\0', pos, end); assert stop >= 0
                row.update(ordinal=value, importedName=blob[pos:stop].decode()); pos = stop+1
            else:
                row['offsetOrAbsoluteAddress'] = value
                if flags & 16:
                    row['resolverOffset'], pos = uleb(pos, end)
            assert pos == end and name not in result; result[name] = row
        count = blob[end]; pos = end+1
        for _ in range(count):
            stop = blob.find(b'\0', pos); assert stop >= 0
            edge = blob[pos:stop].decode(); assert edge
            target, pos = uleb(stop+1, len(blob)); stack.append((target, name+edge))
    return result


def canonical_path(path):
    # iOS and macOS spell the same framework image's Versions/A component
    # differently. This is image-path matching only, never symbol aliasing.
    return re.sub(r'(?<=\.framework)/Versions/[^/]+/', '/', path)


def captured_images():
    checked_receipt(CAPTURE/'receipt.json', MANIFEST)
    command_manifest = NODE/'ipad-current-cache-commands-manifest-v1.json'
    checked_receipt(COMMANDS/'receipt.json', command_manifest)
    manifest = json.loads(MANIFEST.read_text())
    result = {}
    for row in manifest['mappedActualLoadCommands']:
        stem = row['name'].removesuffix('-exports')
        header = (COMMANDS/(stem+'-commands.bin')).read_bytes()
        assert len(header) == 32+struct.unpack_from('<I', header, 20)[0]
        imagepath = None; imageuuid = None; export = None
        for cmd, at, size in commands(header):
            if cmd == 13:
                no = struct.unpack_from('<I', header, at+8)[0]
                imagepath = header[at+no:at+size].split(b'\0')[0].decode()
            elif cmd == 27: imageuuid = header[at+8:at+24].hex()
            elif cmd == 0x80000033: export = struct.unpack_from('<II', header, at+8)
        assert imagepath and imageuuid
        if export is None:
            for cmd, at, size in commands(header):
                if cmd == 0x80000022: export = struct.unpack_from('<II', header, at+40)
        assert export == (row['originalImageExportOffset'], row['length'])
        link = next(s for s in segments(header) if s['name'] == '__LINKEDIT')
        assert row['exportVA'] == hex(link['address']+export[0]-link['fileoff'])
        assert link['address'] == row['linkedit']['vmaddr'] and link['fileoff'] == row['linkedit']['fileoff']
        blobpath = CAPTURE/(stem+'-exports.bin'); blob = blobpath.read_bytes()
        assert len(blob) == export[1]
        exports = trie(blob); deps = p.dependencies(header)
        for e in exports.values():
            if e['flags'] & 8: assert 1 <= e['ordinal'] <= len(deps)
        result[canonical_path(imagepath)] = dict(path=imagepath, UUID=imageuuid,
            header=p.pin(COMMANDS/(stem+'-commands.bin')), trie=p.pin(blobpath),
            exports=exports, dependencies=deps)
    assert len(result) == 5
    return result


def resolve(images, path, symbol, seen=()):
    key = canonical_path(path)
    if (key, symbol) in seen or len(seen) > 12: raise AssertionError('reexport cycle')
    if key not in images:
        return dict(status='uncapturedOwner', requestedPath=path, symbol=symbol)
    image = images[key]; entry = image['exports'].get(symbol)
    seen += ((key, symbol),)
    if entry and not entry['flags'] & 8:
        return dict(status='actualDirectExport', owner=image['path'], UUID=image['UUID'], export=entry)
    if entry:
        dep = image['dependencies'][entry['ordinal']-1]
        nested = resolve(images, dep['path'], entry['importedName'] or symbol, seen)
        return dict(status=nested['status'], namedReexport=entry, nested=nested)
    reexports = [d for d in image['dependencies'] if d['command'] == 0x8000001f]
    unknown = []
    for dep in reexports:
        nested = resolve(images, dep['path'], symbol, seen)
        if nested['status'] == 'actualDirectExport':
            return dict(status='actualDirectExport', reexportDependency=dep, nested=nested)
        if nested['status'] in ('uncapturedOwner', 'ownerHasNoDefinitionReexportsUnverified'): unknown.append(dep['path'])
    return dict(status='ownerHasNoDefinitionReexportsUnverified' if unknown else 'actualExportAbsent',
                owner=image['path'], UUID=image['UUID'], symbol=symbol, unverifiedReexportPaths=unknown)


def audit():
    images = captured_images(); source = json.loads(SOURCE.read_text())
    plans = [(r['name'], Path(r['candidate']['path']), False) for r in source['providers']]
    frontend = json.loads(FRONTEND.read_text())
    plans.append(('Virtualization', Path(frontend['frontendCandidate']['path']), True))
    results = []
    for name, path, vz in plans:
        raw = path.read_bytes()
        if vz:
            parsed = p.vz_reader.parse(raw); imp = parsed['imports']; deps = {d['ordinal']: d['name'] for d in parsed['deps']}
        else:
            imp = imports(raw)['imports']; deps = {d['ordinal']: d['path'] for d in p.dependencies(raw)}
        rows = []
        for r in imp:
            if r['weak']: continue
            assert r['ordinal'] > 0 and r['ordinal'] in deps
            owner = deps[r['ordinal']]
            proof = resolve(images, owner, r['name'])
            rows.append(dict(index=r['index'], symbol=r['name'], ordinal=r['ordinal'], dependency=owner, proof=proof))
        counts = {s: sum(r['proof']['status'] == s for r in rows) for s in
                  ('actualDirectExport', 'actualExportAbsent', 'ownerHasNoDefinitionReexportsUnverified', 'uncapturedOwner')}
        results.append(dict(name=name, image=p.pin(path), strongImports=len(rows), counts=counts, imports=rows))
    output = dict(schema='Current UUID-pinned stock export definition audit v1',
        currentCacheUUID='1995ea169d0a33a0b78962cf99891168', headers=p.pin(HEADERS),
        exportsReceipt=p.pin(CAPTURE/'receipt.json'), commandsReceipt=p.pin(COMMANDS/'receipt.json'),
        images=[{k:v for k,v in image.items() if k != 'exports'}|dict(exportCount=len(image['exports'])) for image in images.values()],
        auditedImages=results, completeCapturedTries=True, stockTransitiveClosureProven=False,
        fullMetadataSchema=False, nativeExecuted=False, deviceOperations=0, originalVZLoaded=False, full27Backend=False)
    # These counterexamples specifically exercise absence and the unresolved
    # reexport boundary. Neither may silently turn into an available symbol.
    assert resolve(images, '/usr/lib/swift/libswiftCore.dylib', '__VM27_not_a_real_export__')['status'] == 'actualExportAbsent'
    assert resolve(images, '/System/Library/Frameworks/Foundation.framework/Foundation', '__VM27_not_a_real_export__')['status'] == 'ownerHasNoDefinitionReexportsUnverified'
    assert resolve(images, '@loader_path/UniversalHID27.dylib', '_swift_getWitnessTable')['status'] == 'uncapturedOwner'
    return output


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True); args = ap.parse_args()
    out = args.output.resolve(); assert out.is_relative_to(NODE) and not out.exists(); out.mkdir()
    report = audit(); p.save(out/'audit.json', report)
    p.save(out/'freeze.json', dict(files=[p.pin(Path(__file__)), p.pin(out/'audit.json'), p.pin(SOURCE), p.pin(FRONTEND),
        p.pin(HEADERS), p.pin(MANIFEST), p.pin(CAPTURE/'receipt.json'), p.pin(COMMANDS/'receipt.json')]
        +[p.pin(Path(r['image']['path'])) for r in report['auditedImages']]
        +[image[k] for image in report['images'] for k in ('header','trie')],
        deviceOperations=0, nativeExecuted=False))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), images=[dict(name=r['name'], counts=r['counts']) for r in report['auditedImages']])))


if __name__ == '__main__': main()
