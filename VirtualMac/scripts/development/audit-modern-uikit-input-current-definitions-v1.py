#!/usr/bin/env python3
"""Small current-definition supplement for own UIKit/native-scroll products."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('input_frontier', HERE/'audit-modern-genuine-hid-current-frontier-v20.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
p, s, n = f.p, f.s, f.n
from macho_chained_import_records_v1 import read as import_records
from current_hid_extra_three_capture_v1 import mapping


def main():
    out = n/'uikit-input-current-definitions-readonly-v1'
    assert not out.exists()
    images = s.primary.captured_images(); pins = []
    for group in ('system', 'stock-extra', 'cxx-leaf'):
        pins += s.join_capture(images, group, n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'):
        pins += s.join_capture(images, group, n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    pins += f.f.join_kernel(s, images)
    for fn in (f.f.join_hid_extra, f.f.join_swift_two, f.f.join_eight, f.f.join_three,
               f.f.join_trace, f.f.join_unwind, f.f.join_compiler, f.f.join_crypto):
        added, _ = fn(s, images); pins += added
    assert len(images) == 36
    heads = n/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    headers = json.loads(heads.read_bytes())
    prefix = n/'ipad-current-uikit-own-input-command-prefix-readonly-v1'
    tail = n/'ipad-current-uikit-scroll-bounded-tail-readonly-v1'
    capture = n/'ipad-current-uikitcore-actual-exports-readonly-v1'
    stages = [(prefix, n/'ipad-current-uikit-own-input-command-prefix-plan-v1/request.json'),
              (tail, n/'ipad-current-uikit-scroll-bounded-tail-plan-v1/request.json'),
              (capture, n/'uikit-scroll-current-tables-readonly-v2/request.json')]
    for directory, manifest in stages:
        receipt = s.checked_capture(directory, manifest, heads)
        assert receipt['readerSHA256'] == p.pin(directory/'reader-source.py')['sha256']
        pins += [p.pin(manifest)] + [p.pin(directory/name) for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr')]
        pins += [p.pin(Path(row['path'])) for row in receipt['ranges']]
    uikit = (prefix/'uikit-command-prefix.bin').read_bytes()[:1464]
    core = (prefix/'uikitcore-command-prefix.bin').read_bytes()+(tail/'uikitcore-command-tail.bin').read_bytes()
    assert core == (n/'uikit-scroll-current-tables-readonly-v2/uikitcore-complete-commands.bin').read_bytes()
    assert len(core) == 11352 and len(uikit) == 1464
    for raw, trie_file, uuid in ((uikit, tail/'uikit-exports.bin','43985fb412b339f6971ddd896641da4a'),
                                 (core, capture/'uikitcore-exports.bin','179501b60fc2344ab969b4e3961ebe10')):
        assert [raw[at+8:at+24].hex() for cmd,at,size in p.commands(raw) if cmd==27] == [uuid]
        path = next(raw[at+struct.unpack_from('<I',raw,at+8)[0]:at+size].split(b'\0')[0].decode() for cmd,at,size in p.commands(raw) if cmd==13)
        off,length = next(struct.unpack_from('<II',raw,at+8) for cmd,at,size in p.commands(raw) if cmd==0x80000033)
        link = next(row for row in p.segments(raw) if row['name']=='__LINKEDIT')
        requested = mapping(headers,link['address']+off-link['fileoff'],length)
        actual = next(row for directory,manifest in stages for row in json.loads((directory/'receipt.json').read_bytes())['ranges'] if Path(row['path'])==trie_file)
        assert all(actual[key]==requested[key] for key in ('cache','offset','length'))
        tree = s.primary.trie(trie_file.read_bytes()); deps = p.dependencies(raw)
        assert len(trie_file.read_bytes())==length
        if raw is uikit: assert not tree
        key = s.primary.canonical_path(path); assert key not in images
        images[key] = dict(path=path,UUID=uuid,exports=tree,dependencies=deps,currentCapture=True)
    assert len(images)==38
    products = [('UIKitSource', n/'uikit-own-input-surface-data-build-v6/VM27UIKitInput.ios.unsigned.inert.dylib',86),
                ('NativeScrollProvider', n/'processed-scroll-native-data-build-v2/VM27ProcessedScroll.ios.unsigned.inert.dylib',30),
                ('NativeScrollOrdinary', n/'processed-scroll-native-data-build-v2/VM27ProcessedScroll.ios.ordinary.unsigned.inert',19)]
    # The first product's exact filename is taken from its frozen candidate.
    candidate = json.loads((n/'uikit-own-input-surface-data-build-v6/candidate.json').read_bytes())
    products[0] = ('UIKitSource', Path(candidate['provider']['path']),86)
    rows = []
    for label, file, count in products:
        raw = file.read_bytes(); deps = {row['ordinal']:row['path'] for row in p.dependencies(raw)}
        schema = import_records(raw,p.commands); assert len(schema['imports'])==count
        proofs = []
        for row in schema['imports']:
            assert not row['weak'] and row['ordinal']>0
            proof = s.primary.resolve(images,deps[row['ordinal']],row['name'])
            assert proof['status']=='actualDirectExport',(label,row,proof)
            proofs.append(dict(row,dependency=deps[row['ordinal']],proof=proof))
        rows.append(dict(name=label,image=p.pin(file),strongImports=count,imports=proofs))
        pins.append(p.pin(file))
    uikit_imports = [row for row in rows[0]['imports'] if row['dependency']=='/System/Library/Frameworks/UIKit.framework/UIKit']
    assert len(uikit_imports)==13
    assert all(row['proof']['reexportDependency']['command']==0x8000001f and row['proof']['nested']['owner']=='/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore' for row in uikit_imports)
    negatives = []
    uikitpath = '/System/Library/Frameworks/UIKit.framework/UIKit'; corepath='/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore'
    for name, action in [('ordinary dependency cannot reexport',lambda graph:[row.update(command=12) for row in graph[uikitpath]['dependencies'] if row['command']==0x8000001f]),
                         ('missing actual Core remains unknown',lambda graph:graph.pop(corepath)),
                         ('missing exact native name remains absent',lambda graph:graph[corepath]['exports'].pop(uikit_imports[0]['name']))]:
        damaged=copy.deepcopy(images); action(damaged)
        assert s.primary.resolve(damaged,uikitpath,uikit_imports[0]['name'])['status']!='actualDirectExport'
        negatives.append(dict(name=name,rejected=True))
    out.mkdir()
    p.save(out/'audit.json',dict(schema='Current own UIKit and native processed-scroll exact strong definitions v1',
        currentMainUUID='1995ea169d0a33a0b78962cf99891168',currentHeaders=p.pin(heads),capturedNativeTableCount=38,
        UIKitEmptyTrieTrueReexport=True,UIKitStrongDefinitions=13,products=rows,negativeControls=negatives,
        sourceStrongDefinitionEvidenceOnly=True,actualUIKitClassesOrSelectorsExecuted=False,
        actualUIKitTimestampOriginValidated=False,nativeScrollIOSFixtureExecuted=False,
        originalVZReceiverExecuted=False,completeTransitiveLoadGraph=False,full27Backend=False,
        deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0))
    pins += [p.pin(heads),p.pin(Path(__file__)),p.pin(out/'audit.json')]
    for directory in (n/'uikit-own-input-surface-data-build-v6',n/'processed-scroll-native-data-build-v2',n/'uikit-scroll-current-tables-readonly-v2'):
        for row in json.loads((directory/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path']))==row; pins.append(row)
        pins.append(p.pin(directory/'freeze.json'))
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),strongCounts=[row['strongImports'] for row in rows])))


if __name__=='__main__': main()
