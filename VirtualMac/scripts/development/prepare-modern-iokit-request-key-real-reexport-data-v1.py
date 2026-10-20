#!/usr/bin/env python3
"""Route one genuine CFString strong binding via an inert true AR reexport."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_key_frontier', HERE / 'audit-modern-genuine-hid-current-frontier-v12.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
s, p = f.s, f.p
BASE = p.NODE / 'universalhid-observed-cvw-real-reexport-data-v2/candidate.json'
BUILD = p.NODE / 'iokit-request-terminate-key-data-build-v3/candidate.json'
FRONTIER = p.NODE / 'universalhid-current-exact-frontier-audit-v14/audit.json'
SYMBOL = '_kIOHIDServiceRequestTerminateKey'


def checked(path):
    for row in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    return json.loads(path.read_bytes())


def contract(before, after, name):
    expected = bytearray(before)
    old = p.imports(before)['imports']
    if name == 'UniversalHID':
        row = old[527]
        assert row['index'] == 527 and row['name'] == SYMBOL and row['ordinal'] == 1 and not row['weak']
        assert p.dependencies(before)[0]['path'] == '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
        expected[row['command']] = 20
        assert p.dependencies(before)[19]['path'] == '@loader_path/AR'
    assert after == expected
    actual = p.imports(after)['imports']
    assert len(actual) == len(old)
    for a, b in zip(old, actual, strict=True):
        assert b == ({**a, 'ordinal':20} if name == 'UniversalHID' and a['index'] == 527 else a)
    return [] if name != 'UniversalHID' else [dict(index=527, symbol=SYMBOL, at=row['command'],
        oldOrdinal=1, newOrdinal=20, strong=True, importRecordBytesChanged=1)]


def ar_contract(before, after):
    count, size = struct.unpack_from('<II', before, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/IK\0'
    assert len(addition) == 40 and not any(before[32+size:32+size+40])
    expected = bytearray(before)
    struct.pack_into('<II', expected, 16, count+1, size+40)
    expected[32+size:32+size+40] = addition
    assert after == expected
    assert p.imports(after)['imports'] == p.imports(before)['imports']
    assert p.dependencies(after)[:-1] == p.dependencies(before)
    assert p.dependencies(after)[-1]['ordinal'] == 10


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    base, build, frontier = [checked(path) for path in (BASE, BUILD, FRONTIER)]
    assert build['originalCFStringTypeValueLifetimePreserved'] and not build['missingEventConstructorsImplemented']
    assert frontier['currentStockImages'] == 22 and not frontier['full27Backend']
    assert set(build['exactExports']) == {SYMBOL}
    out.mkdir()
    source_ik = build['iosProvider']
    ikpath = out / 'IK.unchanged-unsigned-ios-provider.inert.macho-data'
    ikpath.write_bytes(Path(source_ik['path']).read_bytes())
    assert p.pin(ikpath)['sha256'] == source_ik['sha256'] and p.pin(ikpath)['bytes'] == source_ik['bytes']
    source_ar = base['modifiedArrayReexportProvider']['candidate']
    before_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(before_ar)
    assert p.append_dependency(ar, '@loader_path/IK') == 10
    added = p.dependencies(ar)[-1]
    assert added['size'] == 40
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    ar_contract(before_ar, bytes(ar))
    arpath = out / 'AR.real-request-key-reexport.inert.macho-data'; arpath.write_bytes(ar)
    images = s.primary.captured_images(); pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    pins += f.join_kernel(s, images)
    extra_pins, _ = f.join_hid_extra(s, images); pins += extra_pins
    swift_pins, _ = f.join_swift_two(s, images); pins += swift_pins
    assert len(images) == 22
    for alias, path in (('AR', arpath), ('IK', ikpath)):
        images[s.primary.canonical_path('@loader_path/' + alias)] = f.image(p.pin(path), '@loader_path/' + alias)
    results, negatives = [], []
    for name in ('UniversalHID', 'UniversalHIDKit'):
        source = next(row['candidate'] for row in base['images'] if row['name'] == name)
        before = Path(source['path']).read_bytes(); after = bytearray(before)
        if name == 'UniversalHID': after[p.imports(before)['imports'][527]['command']] = 20
        routes = contract(before, bytes(after), name)
        path = out / (name + '27.request-key-real-reexport.mac.inert.macho-data'); path.write_bytes(after)
        results.append(dict(name=name, source=source, candidate=p.pin(path), routes=routes,
            wholeBytesPreserved=name == 'UniversalHIDKit', allInstructionMetadataWitnessPACBytesPreserved=True))
        for label, offset in [('old instruction', next(sec['fileoff'] for seg in p.segments(before) for sec in seg['sections'] if sec['name'] == '__text')),
                ('old PAC whole word', next(row['fileoff'] + 4 for row in p.chain_entries(before) if row['auth'])),
                ('old Swift metadata', next(sec['fileoff'] for seg in p.segments(before) for sec in seg['sections'] if sec['name'].startswith('__swift5')))]:
            changed = bytearray(after); changed[offset] ^= 1
            try: contract(before, bytes(changed), name)
            except (AssertionError, ValueError): negatives.append(dict(owner=name, name=label, rejected=True))
            else: raise AssertionError('accepted mutated request key route')
        if routes:
            route = routes[0]
            for label, offset in [('wrong ordinal',route['at']),('weak bit',route['at']+1),('name offset',route['at']+2)]:
                changed = bytearray(after); changed[offset] ^= 1
                try: contract(before, bytes(changed), name)
                except (AssertionError, ValueError): negatives.append(dict(owner=name,name=label,rejected=True))
                else: raise AssertionError('accepted mutated key import')
            proof = f.resolve(images, '@loader_path/AR', SYMBOL)
            leaf = proof
            while 'nested' in leaf: leaf = leaf['nested']
            assert proof['status'] == 'actualDirectExport' and leaf['owner'] == '@loader_path/IK'
            route['actualReexportDefinition'] = proof
    proof = f.resolve(images, build['actualCurrentNativeImport']['dependency'], build['actualCurrentNativeImport']['name'])
    assert proof == build['actualCurrentNativeImport']['proof']
    fixup = next(struct.unpack_from('<I', before_ar, at+8)[0] for cmd,at,size in p.commands(before_ar) if cmd == 0x80000034)
    for label, offset in [('wrong genuine reexport command', added['at']), ('wrong reexport path', added['at']+24),
        ('old AR chained fixups',fixup), ('old AR instruction',next(sec['fileoff'] for seg in p.segments(before_ar) for sec in seg['sections'] if sec['name']=='__text'))]:
        changed = bytearray(ar); changed[offset] ^= 1
        try: ar_contract(before_ar, bytes(changed))
        except (AssertionError, ValueError): negatives.append(dict(owner='AR',name=label,rejected=True))
        else: raise AssertionError('accepted mutated AR key reexport')
    validations = []
    for path in [arpath,ikpath] + [Path(row['candidate']['path']) for row in results]:
        result = subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True,timeout=30)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path),exit=0))
    report = dict(schema='Genuine RequestTerminate CFString one strong true reexport data v1',
        sources=[p.pin(path) for path in (Path(__file__),BASE,BUILD,FRONTIER)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR',intendedLoadPath='@loader_path/AR',source=source_ar,candidate=p.pin(arpath),
            addedGenuineReexport=dict(ordinal=10,path='@loader_path/IK',bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True,preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='IK',intendedLoadPath='@loader_path/IK',source=source_ik,candidate=p.pin(ikpath),
            currentPositiveStrongDefinitions=[build['actualCurrentNativeImport']]),
        preservedLeafProviders=base['preservedLeafProviders']+[base['unchangedRuntimeProvider']],
        currentStockImages=22,routedStrongImports=1,negativeControls=negatives,structuralValidations=validations,
        originalCFStringTypeValueLifetimePreserved=True,originalKeyCallersExecuted=False,
        remainingTwoEventConstructorsImplemented=False,oldIOKitDataPointerOffset=104,original27IOKitDataPointerOffset=96,
        candidateReadyForNativeLoading=False,productionHIDIdentityGatePassed=False,originalUHLoaded=False,
        nativeIOSExecuted=False,deviceOperations=0,codeSigned=False,full27Backend=False)
    p.save(out / 'candidate.json',report)
    paths=[Path(__file__),Path(f.__file__),BASE,BUILD,FRONTIER,Path(source_ar['path']),Path(source_ik['path']),arpath,ikpath,out/'candidate.json']
    paths += [Path(row[key]['path']) for row in results for key in ('source','candidate')]
    p.save(out/'freeze.json',dict(files=pins+[p.pin(path) for path in paths],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),strongImportsRouted=1,negativeControls=len(negatives),structuralValidations=len(validations))))


if __name__ == '__main__': main()
