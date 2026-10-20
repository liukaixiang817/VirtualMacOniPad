#!/usr/bin/env python3
"""Route two finite genuine native IOKit double constructors through inert AR."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iokit_key_frontier', HERE / 'audit-modern-genuine-hid-current-frontier-v13.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
s, p = f.s, f.p
BASE = p.NODE / 'universalhid-request-key-real-reexport-data-v2/candidate.json'
BUILD = p.NODE / 'iokit-double-events-data-build-v3/candidate.json'
FRONTIER = p.NODE / 'universalhid-current-exact-frontier-audit-v15/audit.json'
SYMBOLS = {257:'_IOHIDEventCreateForceStageEvent',265:'_IOHIDEventCreateTouchSensitiveButtonEventWithRadius'}


def checked(path):
    for row in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(row['path'])) == row
    return json.loads(path.read_bytes())


def contract(before, after, name):
    expected=bytearray(before);old=p.imports(before)['imports'];routes=[]
    if name=='UniversalHID':
        assert p.dependencies(before)[0]['path']=='/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
        assert p.dependencies(before)[19]['path']=='@loader_path/AR'
        for index,symbol in SYMBOLS.items():
            row=old[index]
            assert row['index']==index and row['name']==symbol and row['ordinal']==1 and not row['weak']
            expected[row['command']]=20
            routes.append(dict(index=index,symbol=symbol,at=row['command'],oldOrdinal=1,newOrdinal=20,strong=True,importRecordBytesChanged=1))
    assert after==expected
    actual=p.imports(after)['imports'];assert len(actual)==len(old)
    for a,b in zip(old,actual,strict=True):
        assert b==({**a,'ordinal':20}if name=='UniversalHID'and a['index']in SYMBOLS else a)
    return routes


def ar_contract(before, after):
    count, size = struct.unpack_from('<II', before, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/DE\0'
    assert len(addition) == 40 and not any(before[32+size:32+size+40])
    expected = bytearray(before)
    struct.pack_into('<II', expected, 16, count+1, size+40)
    expected[32+size:32+size+40] = addition
    assert after == expected
    assert p.imports(after)['imports'] == p.imports(before)['imports']
    assert p.dependencies(after)[:-1] == p.dependencies(before)
    assert p.dependencies(after)[-1]['ordinal'] == 11


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    base, build, frontier = [checked(path) for path in (BASE, BUILD, FRONTIER)]
    assert build['originalDoublePacketTypesSizesAndIEEEBitsPreserved'] and not build['nativeIOSExecuted']
    assert frontier['currentStockImages'] == 22 and not frontier['full27Backend']
    assert set(build['exactExports']) == set(SYMBOLS.values())
    out.mkdir()
    source_de = build['iosProvider']
    depath = out / 'DE.unchanged-unsigned-ios-provider.inert.macho-data'
    depath.write_bytes(Path(source_de['path']).read_bytes())
    assert p.pin(depath)['sha256'] == source_de['sha256'] and p.pin(depath)['bytes'] == source_de['bytes']
    source_ar = base['modifiedArrayReexportProvider']['candidate']
    before_ar = Path(source_ar['path']).read_bytes()
    ar = bytearray(before_ar)
    assert p.append_dependency(ar, '@loader_path/DE') == 11
    added = p.dependencies(ar)[-1]
    assert added['size'] == 40
    struct.pack_into('<I', ar, added['at'], 0x8000001f)
    ar_contract(before_ar, bytes(ar))
    arpath = out / 'AR.real-double-events-reexport.inert.macho-data'; arpath.write_bytes(ar)
    images = s.primary.captured_images(); pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf', 'dyld-leaf', 'xpc-leaf'):
        version = 2 if group in ('dyld-leaf', 'xpc-leaf') else 1
        pins += s.join_capture(images, group, p.NODE / ('ipad-current-cache-' + group + '-headers-v' + str(version) + '/headers.json'))
    pins += f.join_kernel(s, images)
    extra_pins, _ = f.join_hid_extra(s, images); pins += extra_pins
    swift_pins, _ = f.join_swift_two(s, images); pins += swift_pins
    assert len(images) == 22
    for alias, path in (('AR', arpath), ('DE', depath)):
        images[s.primary.canonical_path('@loader_path/' + alias)] = f.image(p.pin(path), '@loader_path/' + alias)
    results, negatives = [], []
    for name in ('UniversalHID', 'UniversalHIDKit'):
        source = next(row['candidate'] for row in base['images'] if row['name'] == name)
        before = Path(source['path']).read_bytes(); after = bytearray(before)
        if name == 'UniversalHID':
            for index in SYMBOLS:after[p.imports(before)['imports'][index]['command']]=20
        routes = contract(before, bytes(after), name)
        path = out / (name + '27.double-events-real-reexport.mac.inert.macho-data'); path.write_bytes(after)
        results.append(dict(name=name, source=source, candidate=p.pin(path), routes=routes,
            wholeBytesPreserved=name == 'UniversalHIDKit', allInstructionMetadataWitnessPACBytesPreserved=True))
        for label, offset in [('old instruction', next(sec['fileoff'] for seg in p.segments(before) for sec in seg['sections'] if sec['name'] == '__text')),
                ('old PAC whole word', next(row['fileoff'] + 4 for row in p.chain_entries(before) if row['auth'])),
                ('old Swift metadata', next(sec['fileoff'] for seg in p.segments(before) for sec in seg['sections'] if sec['name'].startswith('__swift5')))]:
            changed = bytearray(after); changed[offset] ^= 1
            try: contract(before, bytes(changed), name)
            except (AssertionError, ValueError): negatives.append(dict(owner=name, name=label, rejected=True))
            else: raise AssertionError('accepted mutated double event route')
        for route in routes:
            for label,offset in [('wrong ordinal',route['at']),('weak bit',route['at']+1),('name offset',route['at']+2)]:
                changed=bytearray(after);changed[offset]^=1
                try:contract(before,bytes(changed),name)
                except(AssertionError,ValueError):negatives.append(dict(owner=name,index=route['index'],name=label,rejected=True))
                else:raise AssertionError('accepted mutated double constructor import')
            proof=f.resolve(images,'@loader_path/AR',route['symbol']);leaf=proof
            while 'nested'in leaf:leaf=leaf['nested']
            assert proof['status']=='actualDirectExport'and leaf['owner']=='@loader_path/DE'
            route['actualReexportDefinition']=proof
    for imported in build['actualCurrentNativeImports']:
        assert s.primary.resolve(images,imported['dependency'],imported['name'])==imported['actualCurrentNativeResolution']
    fixup = next(struct.unpack_from('<I', before_ar, at+8)[0] for cmd,at,size in p.commands(before_ar) if cmd == 0x80000034)
    for label, offset in [('wrong genuine reexport command', added['at']), ('wrong reexport path', added['at']+24),
        ('old AR chained fixups',fixup), ('old AR instruction',next(sec['fileoff'] for seg in p.segments(before_ar) for sec in seg['sections'] if sec['name']=='__text'))]:
        changed = bytearray(ar); changed[offset] ^= 1
        try: ar_contract(before_ar, bytes(changed))
        except (AssertionError, ValueError): negatives.append(dict(owner='AR',name=label,rejected=True))
        else: raise AssertionError('accepted mutated AR double reexport')
    validations = []
    for path in [arpath,depath] + [Path(row['candidate']['path']) for row in results]:
        result = subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True,timeout=30)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path),exit=0))
    report = dict(schema='Finite native double IOKit constructors two strong true reexport data v1',
        sources=[p.pin(path) for path in (Path(__file__),BASE,BUILD,FRONTIER)], images=results,
        modifiedArrayReexportProvider=dict(alias='AR',intendedLoadPath='@loader_path/AR',source=source_ar,candidate=p.pin(arpath),
            addedGenuineReexport=dict(ordinal=11,path='@loader_path/DE',bytes=40),
            allOriginalSectionsImportsAndChainedPointerBytesPreserved=True,preexistingSignatureInvalidAfterHeaderMutation=True),
        unchangedRuntimeProvider=dict(alias='DE',intendedLoadPath='@loader_path/DE',source=source_de,candidate=p.pin(depath),
            currentPositiveStrongDefinitions=build['actualCurrentNativeImports']),
        preservedLeafProviders=base['preservedLeafProviders']+[base['unchangedRuntimeProvider']],
        currentStockImages=22,routedStrongImports=2,negativeControls=negatives,structuralValidations=validations,
        bothFiniteNativeConstructorsImplemented=True,originalCtorCallersExecuted=False,
        currentIOKitKernelNewTypeConsumerValidated=False,originalFullIOKitSemanticsPreserved=False,
        allPreexistingIKOWBTPLProvidersAndRoutesPreserved=True,completeOriginal27MetadataPreserved=False,oldIOKitDataPointerOffset=104,original27IOKitDataPointerOffset=96,
        candidateReadyForNativeLoading=False,productionHIDIdentityGatePassed=False,originalUHLoaded=False,
        nativeIOSExecuted=False,deviceOperations=0,codeSigned=False,full27Backend=False)
    p.save(out / 'candidate.json',report)
    paths=[Path(__file__),Path(f.__file__),BASE,BUILD,FRONTIER,Path(source_ar['path']),Path(source_de['path']),arpath,depath,out/'candidate.json']
    paths += [Path(row[key]['path']) for row in results for key in ('source','candidate')]
    p.save(out/'freeze.json',dict(files=pins+[p.pin(path) for path in paths],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),strongImportsRouted=2,negativeControls=len(negatives),structuralValidations=len(validations))))


if __name__ == '__main__': main()
