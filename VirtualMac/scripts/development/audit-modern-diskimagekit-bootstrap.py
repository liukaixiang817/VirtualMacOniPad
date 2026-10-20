#!/usr/bin/env python3
"""Read-only audit of the exact DIKit27 two-phase bootstrap candidate input."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    compiler = root / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
    sys.path.insert(0, str(compiler))
    from compiler_image import chain_entries, commands, imports
    spec = importlib.util.spec_from_file_location('bounded_objc_reader', compiler / 'gpu-error-protocol-audit/read-protocol.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = root / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-scoped-cvw-image-v9'
    expected = {'ios': '89c62608fb78ef57e0fda03667b47ea7959ee81bea716e7b5c576d07ab34c33b',
                'mac': '057804feb243955c28e2832faab9d57e6e12c452063409b030692535894b734c'}
    # The Mac hash is read from the frozen manifest and also recorded in output.
    frozen = json.loads((source / 'manifest.json').read_text())
    expected['mac'] = next(row['sha256'] for row in frozen['files'] if row['role'] == 'mac')
    roles = []
    for role in ('ios', 'mac'):
        image = reader.Image(source / role / 'DiskImageKit27.dylib')
        digest = hashlib.sha256(image.b).hexdigest()
        assert digest == expected[role]
        sections = [s for g in image.segs for s in g['sections']]
        no_hooks = ('__mod_init_func', '__init_offsets', '__objc_nlclslist',
                    '__objc_nlcatlist', '__objc_catlist', '__objc_catlist2',
                    '__objc_stublist', '__swift5_replace', '__swift5_replac2',
                    '__swift5_ac_funcs', '__swift5_ac_p_funcs')
        assert not [s for s in sections if s['size'] and s['name'] in no_hooks]
        assert not [c for c, _, _ in commands(image.b) if c in (0x11, 0x1a)]
        assert len(image.classes) == 2 and not image.methods
        objc = []
        for klass, init_rva, accessor_rva, completion_rva in zip(
                image.classes, (0x5888, 0x9fb8), (0x5890, 0x9fc0), (0x58dc, 0xa00c)):
            address = int(klass['address'], 16)
            ro = image.ptr(address + 32) & ~7
            assert image.num(ro, '<I') == 0xc0
            assert image.ptr(ro + 32) == 0 and image.ptr(ro + 64) == 0
            assert image.ptr(ro + 72) == image.base + init_rva
            meta = image.ptr(address)
            meta_ro = image.ptr(meta + 32) & ~7
            assert not image.ptr(meta_ro + 32) and not image.ptr(meta_ro + 64)
            paths = [image.disasm(image.base + rv) for rv in (init_rva, accessor_rva, completion_rva)]
            assert '__StaticArrayStorage' not in ''.join(paths)
            assert '_swift_getSingletonMetadata' in paths[1]
            assert '_swift_updateClassMetadata2' in paths[2]
            (out / (role + '-' + klass['name'] + '.asm')).write_text(''.join(paths))
            objc.append({'name': klass['name'], 'classRVA': address-image.base,
                         'roFlags': '0xc0', 'hasLazySwiftMetadataInitializer': True,
                         'initializerRVA': init_rva, 'accessorRVA': accessor_rva,
                         'completionRVA': completion_rva,
                         'instanceMethods': 0, 'classMethods': 0,
                         'staticISAReferencesInThoseBodies': 0})
        static_imports = [x for x in imports(image.b)['imports'] if x['name'] == '_$ss20__StaticArrayStorageCN']
        assert len(static_imports) == 1 and static_imports[0]['ordinal'] == 5 and not static_imports[0]['weak']
        sites = [x for x in chain_entries(image.b) if x['symbol'] == '_$ss20__StaticArrayStorageCN']
        assert [x['address']-image.base for x in sites] == [0x181a0, 0x183f8, 0x18618]
        for site in sites:
            w = site['word']
            assert site['segment'] == '__AUTH_CONST' and site['section'] == '__const'
            assert site['auth'] and (w >> 32 & 65535) == 0x6ae1 and (w >> 48 & 1) and (w >> 49 & 3) == 2
        refs = []
        for function in image.starts:
            body = image.disasm(function)
            if '__StaticArrayStorageCN' in body:
                refs.append({'functionRVA': function-image.base, 'body': body})
        assert [x['functionRVA'] for x in refs] == [0x33ec, 0x3514, 0x7284]
        (out / (role + '-static-references.json')).write_text(json.dumps(refs, indent=2)+'\n')
        roles.append({'role': role, 'path': str(image.path), 'sha256': digest,
                      'uuid': '652b07a998be31d298d7ffcaf14aca5e',
                      'classes': objc, 'initializerCommands': 0,
                      'nonLazyLists': 0, 'categoryLists': 0,
                      'dynamicReplacementAndAccessibleFunctionSections': 0,
                      'staticSites': sites, 'staticReferenceFunctionRVAs': [x['functionRVA'] for x in refs]})
    report = {'roles': roles,
        'regularMapReadClassDoesNotCallLazySwiftInitializer': True,
        'upstreamObjCRuntimeReference': 'objc4-866.9/runtime/objc-runtime-new.mm:3385-3460,3821-3855,3951-3957',
        'notClaimingNoSwiftMetadataCallbacks': True,
        'runtimeRestrictions': ['fresh single-threaded CPU-only process',
            'reject OBJC_ and DYLD_ environment settings before loading',
            'no class enumeration, lookup or DIKit accessor/API before bootstrap',
            'only exact SHA-pinned audited image accepted'],
        'nativeLoadExecuted': False, 'completeOriginalClosure': False}
    (out / 'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'roles': [{'role': r['role'], 'sha256': r['sha256']} for r in roles],
                      'initializerCommands': 0, 'lazySwiftMetadataCallbacks': 2,
                      'staticSites': 3, 'bootstrapImplementationAllowedWithinRecordedRestrictions': True}, indent=2))


if __name__ == '__main__':
    main()
