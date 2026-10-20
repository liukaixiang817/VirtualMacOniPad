#!/usr/bin/env python3
"""Separate, explicit old-host HIDReport conformance adaptation; inert only.

This narrows one genuine27 resilient conformance to the current native old
protocol's sole requirement. It preserves real methods and witnesses. It is
not complete original27 metadata, a full load graph, or runtime evidence.
"""
import argparse
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
BASE = NODE/'universalhid-genuine-type-metadata-data-v2'
AUDIT = NODE/'universalhid-oldhost-contiguousbytes-audit-v2'
ORACLE = NODE/'universalhid-oldhost-dispatch-oracle-v1'
SOURCE_SHA = '6d3af1bafbe751d899a5c80c4a85adecbc1f8ea017e324e34082f0ef5d71de59'
AUDIT_SHA = '5327d2233c1ac75dca317df3c7dc40d2d7cde5295527020a97ac12f5db95693e'
ORACLE_SHA = 'cc7873a92924995392dc86ef35a398a3d4368fb305598e1e8a7a7951c2850838'
NEW = '_$s10Foundation15ContiguousBytesP04withC0yqd__qd__s7RawSpanVqd_0_YKXEqd_0_YKs5ErrorRd_0_r0_lFTq'
CONFORMANCE = 0x29fd9b9d8


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True); args = ap.parse_args()
    out = args.output.resolve(); assert out.is_relative_to(NODE) and not out.exists(); out.mkdir()
    for folder, name, sha in ((BASE, 'candidate.json', SOURCE_SHA), (AUDIT, 'audit.json', AUDIT_SHA), (ORACLE, 'audit.json', ORACLE_SHA)):
        assert p.pin(folder/name)['sha256'] == sha
        for row in json.loads((folder/'freeze.json').read_text())['files']: assert p.pin(Path(row['path'])) == row
    report = json.loads((AUDIT/'audit.json').read_text())
    assert report['boundedListedImportsAndTqReferencesClosed'] and report['originalRawSpanImplementationUsesOldDispatch']
    assert report['RawSpanDispatchRequirementNegativeControlRejected'] and not report['fullCurrentLoadGraphProven']
    source = json.loads((BASE/'candidate.json').read_text()); plan = source['providers'][0]
    assert plan['name'] == 'UniversalHID'
    before = Path(plan['candidate']['path']).read_bytes(); raw = Path(plan['originalRaw']['path']).read_bytes()
    a = RelativeMetadata(raw, before); info = imports(before); oldimports = info['imports']
    assert len(oldimports) == 714 and all(r['ordinal'] > 0 and not r['weak'] for r in oldimports)
    removed = [r for r in oldimports if r['name'] == NEW]; assert len(removed) == 1
    removed = removed[0]; assert removed['index'] == 533 and removed['ordinal'] == 3
    entries = list(chain_entries(before)); slots = [r for r in entries if r['import_index'] == 533]
    assert len(slots) == 1 and slots[0]['symbol'] == NEW and slots[0]['auth']
    slot = slots[0]; predecessor = next(r for r in entries if r['fileoff'] == slot['previous'])
    assert predecessor['page_field'] == slot['page_field']
    oldnext = (slot['word']>>51)&2047; assert oldnext == 1
    skip = (slot['fileoff']-predecessor['fileoff'])//8+oldnext; assert skip == 2
    descriptor = a.mapped(CONFORMANCE); offset = a.offset(descriptor, False)
    assert struct.unpack_from('<II', before, offset+12) == (0x30000, 2)
    assert struct.unpack_from('<HHi', before, offset+36) == (0, 1, 0)
    private = descriptor+44+struct.unpack_from('<i', before, offset+44)[0]
    assert private == report['providers'][0]['genericPrivateDataCandidate']
    data = bytearray(before)
    struct.pack_into('<I', data, offset+16, 1)
    # Move the real GenericWitnessTable control structure over the removed
    # entry. Its PrivateData is a non-NULL per-conformance runtime cache and
    # therefore needs a new relative displacement at its new field address.
    data[offset+28:offset+40] = before[offset+36:offset+48]
    struct.pack_into('<i', data, offset+36, private-(descriptor+36))
    struct.pack_into('<Q', data, predecessor['fileoff'],
                     (predecessor['word']&~(2047<<51))|(skip<<51))
    changed_indices = []
    for r in entries:
        if r['bind'] and r['import_index'] > removed['index']:
            word = struct.unpack_from('<Q', data, r['fileoff'])[0]
            struct.pack_into('<Q', data, r['fileoff'], (word&~65535)|(r['import_index']-1))
            changed_indices.append(dict(fileoff=r['fileoff'], before=r['import_index'], after=r['import_index']-1))
    # The former slot retains its source bytes as unreachable padding. No
    # relocation points at it and it is omitted from the loader's chain; it
    # is never a weak/nil import or replacement witness.
    assert bytes(data[slot['fileoff']:slot['fileoff']+8]) == before[slot['fileoff']:slot['fileoff']+8]
    blob = before[info['data']:info['data']+info['size']]
    version, starts, imp, strings, count, fmt, compressed = info['header']
    assert version == compressed == 0 and fmt == 1 and strings == imp+count*4
    prefix = bytearray(blob[:imp]); words = blob[imp:strings]; names = blob[strings:]
    words = words[:533*4]+words[534*4:]
    struct.pack_into('<7I', prefix, 0, version, starts, imp, strings-4, count-1, fmt, compressed)
    newblob = prefix+words+names
    newoff = (len(data)+7)&~7; data += bytes(newoff-len(data)); data += newblob
    for cmd, at, length in commands(data):
        if cmd == 0x80000034: struct.pack_into('<II', data, at+8, newoff, len(newblob))
        elif cmd == 0x19 and data[at+8:at+24].split(b'\0')[0] == b'__LINKEDIT':
            fileoff = struct.unpack_from('<Q', data, at+40)[0]
            struct.pack_into('<Q', data, at+32, (len(data)-fileoff+16383)&~16383)
            struct.pack_into('<Q', data, at+48, len(data)-fileoff)
    after = bytes(data); newimports = imports(after)['imports']; newentries = list(chain_entries(after))
    assert len(newimports) == 713 and all(r['name'] != NEW and not r['weak'] and r['ordinal'] > 0 for r in newimports)
    assert [dict(name=r['name'],ordinal=r['ordinal'],weak=r['weak']) for r in newimports] == [
        dict(name=r['name'],ordinal=r['ordinal'],weak=r['weak']) for r in oldimports if r['index'] != 533]
    assert len(newentries) == len(entries)-1 and all(r['fileoff'] != slot['fileoff'] for r in newentries)
    oldby = {r['fileoff']: r for r in entries}
    for r in newentries:
        old = oldby[r['fileoff']]
        assert (r['symbol'],r['bind'],r['auth']) == (old['symbol'],old['bind'],old['auth'])
        mask = (65535 if r['bind'] else 0)|(2047<<51 if r['fileoff'] == predecessor['fileoff'] else 0)
        assert r['word']&~mask == old['word']&~mask
    target = out/'UniversalHID27.oldhost-contiguousbytes-adapted.mac.inert.macho-data'; target.write_bytes(after)
    validation = subprocess.run(['xcrun','dyld_info','-validate_only',str(target)],capture_output=True,text=True)
    assert validation.returncode == 0, (validation.stdout, validation.stderr)
    kit = source['providers'][1]; assert kit['name'] == 'UniversalHIDKit' and p.pin(Path(kit['candidate']['path'])) == kit['candidate']
    result = dict(schema='Explicit genuine HID old-host ContiguousBytes conformance adaptation inert v1',
        sourceCandidate=p.pin(BASE/'candidate.json'), preconditionAudit=p.pin(AUDIT/'audit.json'),
        genuineDispatchOracle=p.pin(ORACLE/'audit.json'), providerSource=plan['candidate'], originalRaw=plan['originalRaw'],
        providerCandidate=p.pin(target), unchangedKit=kit['candidate'],
        oldNativeProtocol=report['currentOldProtocol'], conformanceOriginalVA=CONFORMANCE, conformanceCandidateVA=descriptor,
        conformanceFileoff=offset, oldResilientCount=2, adaptedResilientCount=1,
        genuineUnsafeBytesWitnessOriginalVA=0x29fd61774, genuineRawSpanFunctionOriginalVA=0x29fd61794,
        actualRawSpanFunctionCoreUsesOldUnsafeDispatch=True, genuineCodeAndWitnessFunctionsPreserved=True,
        genericControlOldOffset=36, genericControlNewOffset=28, privateDataTarget=private,
        removedImport=removed, removedUnreferencedChainSlot=slot, predecessor=predecessor,
        skippedStride=skip, remappedBindIndices=changed_indices,
        fixupBlob=dict(fileoff=newoff,bytes=len(newblob),oldImportCount=714,newImportCount=713),
        allRemainingImportSymbolsOrdinalsWeakBitsPreserved=True, allRemainingPACSemanticsPreserved=True,
        dyldValidationExit=validation.returncode, conformanceMetadataAdapted=True,
        completeOriginal27MetadataPreserved=False, allCurrentProvidersDeclared=False,
        fullMetadataSchema=False, stockTransitiveClosureProven=False, nativeExecuted=False,
        codeSigned=False, deviceOperations=0, originalVZLoaded=False, originalVMMExecuted=False, full27Backend=False)
    p.save(out/'candidate.json', result)
    files = [Path(__file__), BASE/'candidate.json', AUDIT/'audit.json', AUDIT/'freeze.json', ORACLE/'audit.json', ORACLE/'freeze.json',
             Path(plan['candidate']['path']),Path(plan['originalRaw']['path']),Path(kit['candidate']['path']),target,out/'candidate.json']
    p.save(out/'freeze.json',dict(files=[p.pin(f) for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'), provider=p.pin(target), imports=713,
                         conformanceMetadataAdapted=True, completeOriginal27MetadataPreserved=False)))


if __name__ == '__main__': main()
