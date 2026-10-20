#!/usr/bin/env python3
"""Bounded real RawSpan references/callers before a separate old-host adaptation.

The historical declared provider set is reference scope, not a complete current
load graph. All code and cache inspections are local and non-executing.
"""
import argparse
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hid_reader', HERE/'prepare-modern-universalhid-provider-data-v1.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
from compiler_image import commands, segments, imports, chain_entries
from swift_relative_metadata import RelativeMetadata

NODE = p.NODE
SOURCE = NODE/'universalhid-genuine-type-metadata-data-v2/candidate.json'
METADATA = NODE/'universalhid-genuine-auth-relative-data-v1/candidate.json'
FRONTEND = NODE/'universalhid-exact-owner-private-route-v5/candidate.json'
STAGED = NODE/'vz-genuine-strong-closure-design-v2/build-v1/candidate.json'
STOCK = NODE/'universalhid-current-stock-exports-audit-v2/audit.json'
OLD_DESC = NODE/'ipad-current-cache-first-ranges-readonly-v1/foundation-contiguousbytes-protocol.bin'
OLD_RECEIPT = OLD_DESC.parent/'receipt.json'
PROTO = '_$s10Foundation15ContiguousBytesMp'
OLD = '_$s10Foundation15ContiguousBytesP010withUnsafeC0yqd__qd__SWKXEKlFTq'
NEW = '_$s10Foundation15ContiguousBytesP04withC0yqd__qd__s7RawSpanVqd_0_YKXEqd_0_YKs5ErrorRd_0_r0_lFTq'
OLD_DISPATCH = OLD[:-2]+'Tj'
NEW_DISPATCH = NEW[:-2]+'Tj'
CONFORMANCE = 0x29fd9b9d8


def function_starts(buf):
    base = next(g['address'] for g in segments(buf) if g['name'] == '__TEXT')
    for cmd, at, size in commands(buf):
        if cmd == 0x26: off, length = struct.unpack_from('<II', buf, at+8); break
    else: raise AssertionError('no function starts')
    blob = buf[off:off+length]; starts = []; at = 0; value = base
    while at < len(blob):
        delta = shift = 0
        while True:
            assert at < len(blob) and shift < 64
            byte = blob[at]; at += 1; delta |= (byte & 127) << shift; shift += 7
            if not byte & 128: break
        if not delta: break
        value += delta; starts.append(value)
    assert len(set(starts)) == len(starts)
    return starts


def branches(buf, target=None):
    rows = []
    for g in segments(buf):
        for s in g['sections']:
            if s['name'] not in ('__text', '__objc_stubs'): continue
            for q in range(0, s['size']-3, 4):
                word = struct.unpack_from('<I', buf, s['fileoff']+q)[0]
                if word & 0x7c000000 != 0x14000000: continue
                pc = s['address']+q; imm = word & 0x3ffffff
                if imm & 0x2000000: imm -= 0x4000000
                to = pc+(imm<<2)
                if target is None or to == target: rows.append(dict(PC=pc, target=to, word=word, call=bool(word>>31)))
    return rows


def relative_hits(buf, target):
    # Byte-by-byte overapprox includes aligned metadata and unaligned symbolic
    # mangling payloads. Hits are subsequently classified; no nearest-symbol
    # lookup or arbitrary data-as-pointer mutation follows from this scan.
    hits = []
    for g in segments(buf):
        for s in g['sections']:
            if not s['fileoff'] or s['flags'] & 255 in (1, 12): continue
            for q in range(max(0, s['size']-3)):
                word = struct.unpack_from('<i', buf, s['fileoff']+q)[0]; slot = s['address']+q
                if slot+word == target or slot+word-(word&1) == target:
                    hits.append(dict(slot=slot, segment=g['name'], section=s['name'], word=word))
    return hits


def image_names(buf):
    result = set()
    for cmd, at, size in commands(buf):
        if cmd == 0x80000034:
            data, length = struct.unpack_from('<II', buf, at+8)
            version, starts, imp, strings, count, fmt, compressed = struct.unpack_from('<7I', buf, data)
            assert version == compressed == 0 and fmt in (1, 2) and data+length <= len(buf)
            width = 4 if fmt == 1 else 8
            for i in range(count):
                word = struct.unpack_from('<I', buf, data+imp+i*width)[0]
                pos = data+strings+(word>>9); stop = buf.find(b'\0', pos, data+length); assert stop >= pos
                result.add(buf[pos:stop].decode())
        elif cmd == 2:
            off, count, stringoff, strings = struct.unpack_from('<4I', buf, at+8)
            assert off+count*16 <= len(buf) and stringoff+strings <= len(buf)
            for i in range(count):
                no, ty = struct.unpack_from('<IB', buf, off+i*16)
                if ty & 0x0e != 0 or ty & 0xe0: continue
                pos = stringoff+no; stop = buf.find(b'\0', pos, stringoff+strings); assert stop >= pos
                result.add(buf[pos:stop].decode())
    return sorted(result)


def checked_scope(names):
    found = [n for n in names if 'ContiguousBytes' in n or 'RawSpan' in n]
    assert NEW_DISPATCH not in names, 'new RawSpan protocol dispatch forbids deleting its requirement'
    assert not any('ContiguousBytes' in n and 'RawSpan' in n and n != NEW for n in names), found
    return found


def inspection_object(out, address, code):
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 1, 1, 152, 0, 0)
    segment = struct.pack('<II16sQQQQiiII', 0x19, 152, b'__TEXT', address, len(code), 184, len(code), 5, 5, 1, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', address, len(code), 184, 2, 0, 0, 0x80000400, 0, 0, 0)
    dest = out/(hex(address)+'.inspection-only.macho-object'); dest.write_bytes(header+segment+section+code)
    r = subprocess.run(['xcrun', 'llvm-objdump', '--disassemble', '--macho', str(dest)], capture_output=True, text=True)
    assert r.returncode == 0
    asm = out/(hex(address)+'.asm'); asm.write_text(r.stdout)
    return dict(container=p.pin(dest), assembly=p.pin(asm))


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True); args = ap.parse_args()
    out = args.output.resolve(); assert out.is_relative_to(NODE) and not out.exists(); out.mkdir()
    receipt = json.loads(OLD_RECEIPT.read_text()); assert receipt['mainCacheUUID'] == '1995ea169d0a33a0b78962cf99891168'
    assert receipt['allHeaderPinsMatchBeforeAndAfter'] and not any(receipt[k] for k in ('deviceWrites', 'nativeCPUCalls', 'newFrameworksLoaded'))
    assert any(Path(r['path']) == OLD_DESC and r['sha256'] == p.pin(OLD_DESC)['sha256'] for r in receipt['ranges'])
    old = OLD_DESC.read_bytes(); assert len(old) == 128
    flags, parent, name, signature, count, associated = struct.unpack_from('<6I', old)
    assert (flags, signature, count, associated) == (0x30043, 0, 1, 0)
    oldflags, default = struct.unpack_from('<Ii', old, 24); assert (oldflags, default) == (0x5cdf0011, 0)
    source = json.loads(SOURCE.read_text()); metadata = json.loads(METADATA.read_text())
    routes = metadata['providers'][0]['exactAuthRoutes']; route = next(r for r in routes if r['symbol'] == NEW)
    assert route['labels'] == ['resilientRequirement'] and route['importIndex'] == 533
    results = []
    for plan in source['providers']:
        raw = Path(plan['originalRaw']['path']).read_bytes(); candidate = Path(plan['candidate']['path']).read_bytes()
        a = RelativeMetadata(raw, candidate)
        names = image_names(candidate); related = checked_scope(names)
        originalhits = relative_hits(raw, route['originalSlotVA'])
        assert originalhits == ([dict(slot=CONFORMANCE+28,segment='__TEXT',section='__const',word=812632869)] if plan['name'] == 'UniversalHID' else [])
        row = dict(name=plan['name'], candidate=plan['candidate'], originalRaw=plan['originalRaw'],
            relatedImports=related, originalRawSpanTqRelativeReferences=originalhits)
        if plan['name'] == 'UniversalHID':
            candidatehits = relative_hits(candidate, route['newSlotVA'])
            assert [r['slot'] for r in candidatehits] == [a.mapped(CONFORMANCE+28)]
            bound = [r for r in chain_entries(candidate) if r['symbol'] == NEW]
            assert len(bound) == 1 and bound[0]['address'] == route['newSlotVA'] and bound[0]['auth']
            rawtail = raw[a.offset(CONFORMANCE):a.offset(CONFORMANCE)+48]
            assert struct.unpack_from('<II', rawtail, 12) == (0x30000, 2)
            assert struct.unpack_from('<HHi', rawtail, 36) == (0, 1, 0)
            private = CONFORMANCE+44+struct.unpack_from('<i', rawtail, 44)[0]
            assert private == 0x2cdaf1f00
            starts = function_starts(raw); funcs = []
            for address in (0x29fd61774, 0x29fd61794, 0x29fd61874):
                assert address in starts; end = starts[starts.index(address)+1]
                assert end-address <= 1024
                code = raw[a.offset(address):a.offset(address)+end-address]
                path = out/(hex(address)+'.original-code.bin'); path.write_bytes(code)
                calls = [r for r in branches(raw) if address <= r['PC'] < end]
                funcs.append(dict(address=address,end=end,code=p.pin(path),branches=calls,**inspection_object(out,address,code)))
            assert funcs[0]['branches'] == [dict(PC=0x29fd61788,target=0x29fd6033c,word=0x97fffaed,call=True)]
            assert funcs[1]['branches'] == [dict(PC=0x29fd61838,target=0x29fd61874,word=0x9400000f,call=True)]
            dispatch = [r for r in funcs[2]['branches'] if r['target'] == 0x2a00700d0]
            assert len(dispatch) == 1 and dispatch[0]['PC'] == 0x29fd618d0
            memo = NODE/'universalhid-original-contract-v1/UniversalHID-symbols.a2s.batch.json'
            assert json.loads(memo.read_text())['symbols']['0x2a00700d0'] == [OLD_DISPATCH, '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation']
            stock = json.loads(STOCK.read_text())
            proof = next(r for image in stock['auditedImages'] if image['name'] == 'UniversalHID'
                         for r in image['imports'] if r['symbol'] == OLD_DISPATCH)
            assert proof['proof']['status'] == 'actualDirectExport'
            assert OLD_DISPATCH in names and NEW_DISPATCH not in names
            row.update(candidateRawSpanTqRelativeReferences=candidatehits, soleRawSpanTqBinding=bound[0],
                rawConformanceWords=rawtail.hex(), genericPrivateDataOriginal=private,
                genericPrivateDataCandidate=a.mapped(private), actualCallerFunctions=funcs,
                actualOldProtocolDispatch=proof, originalExactBranchIslandSymbol=p.pin(memo))
        results.append(row)
    frontend = json.loads(FRONTEND.read_text())['frontendCandidate']; frontendrelated = checked_scope(image_names(Path(frontend['path']).read_bytes()))
    assert not frontendrelated
    declared = json.loads(STAGED.read_text())['stagedPrivateLibraries']; providerrows = []
    for plan in declared:
        path = Path(plan['path']); assert p.pin(path) == plan
        related = checked_scope(image_names(path.read_bytes())); assert NEW not in related
        providerrows.append(dict(provider=plan, relatedImports=related))
    # A concrete compiled/new-client dispatch requirement is a blocker even
    # if the metadata scanner found the expected lone resilient entry.
    rejected = False
    try: checked_scope([OLD_DISPATCH, NEW_DISPATCH])
    except AssertionError: rejected = True
    assert rejected
    report = dict(schema='Bounded genuine HID old host ContiguousBytes adaptation preconditions v1',
        currentOldProtocol=dict(source=p.pin(OLD_DESC),receipt=p.pin(OLD_RECEIPT),descriptorAddress=0x181812554,
            flags=flags, signatureRequirements=signature, requirements=count, oldRequirementFlags=oldflags,
            oldRequirementAddress=0x18181256c, defaultImplementation=None),
        source=p.pin(SOURCE), metadata=p.pin(METADATA), stockAudit=p.pin(STOCK), originalRawSpanRoute=route,
        providers=results, frontend=dict(image=frontend,relatedImports=frontendrelated),
        declaredProviderManifest=p.pin(STAGED), declaredProviderReferenceScope=providerrows,
        allCurrentProvidersDeclared=False, fullCurrentLoadGraphProven=False,
        RawSpanDispatchRequirementNegativeControlRejected=True,
        boundedListedImportsAndTqReferencesClosed=True, originalRawSpanImplementationUsesOldDispatch=True,
        adaptationApplied=False, completeOriginal27MetadataPreserved=True,
        nativeExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out/'audit.json', report)
    files = [Path(__file__), SOURCE, METADATA, FRONTEND, STAGED, STOCK, OLD_DESC, OLD_RECEIPT, out/'audit.json']
    files += [Path(r['candidate']['path']) for r in results] + [Path(r['originalRaw']['path']) for r in results]
    files += [Path(frontend['path'])] + [Path(r['path']) for r in declared]
    files += [x for x in out.iterdir() if x.name != 'audit.json']
    p.save(out/'freeze.json', dict(files=[p.pin(f) for f in files], nativeExecuted=False, deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'), declaredProviders=len(declared), RawSpanMetadataOnly=True)))


if __name__ == '__main__': main()
