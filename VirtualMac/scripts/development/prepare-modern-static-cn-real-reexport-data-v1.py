#!/usr/bin/env python3
"""Connect the two absent StaticCN definitions to the tested own class, inertly."""
from pathlib import Path
import hashlib, importlib.util, json, struct, subprocess, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
R = HERE.parents[2]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = N / 'universalhid-static-cn-real-reexport-data-v1'
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
m = module('static_cn_route_frontier', HERE / 'audit-modern-genuine-hid-current-frontier-v20.py')
p, s = m.p, m.s
mp = module('static_cn_route_macho', N / 'cpu-config-capability-query-independent-review-v1/independent_macho.py')
def checked(path, digest, files):
    row = p.pin(path); assert row['sha256'] == digest; files[row['path']] = row
    for entry in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        assert p.pin(Path(entry['path'])) == entry; files[entry['path']] = entry
    files[str(path.parent / 'freeze.json')] = p.pin(path.parent / 'freeze.json')
    return json.loads(path.read_bytes())
def main():
    assert not OUT.exists(); files = {}
    prior_path = N / 'universalhid-current-exact-frontier-audit-v25/audit.json'
    prior = checked(prior_path, 'ed4a8eb8f21547b5a0e61c110ff58d37e02d3fb21a913bf13e2bc7a4c4f3dc97', files)
    source = checked(N / 'static-cn-fixed-original-linked-provider-local-v2/candidate.json', '108db59aaa283b279ec8950d646a5ecd053c1d61e72ae353307b8eb731975503', files)
    actual = checked(N / 'ordinary-static-cn-original-device-result-v2/verdict.json', '9a50bd9bf8156972fb46f1885efe25dcc6a29e48500b601e2f1794ef67ae797e', files)
    peer = checked(N / 'static-cn-original-ios-actual-independent-review-v2/review.json', 'dae2566371e58623e391f4b054e8b688059b0bea746cdb6e69e6b412ba38ec95', files)
    assert actual['actualOriginalNamespaceLifetimePassed'] and not peer['findings']
    assert source['usesTrueOwn176ClassData'] and not source['oldFactoryAlias'] and not source['rawCachedInheritedMethodPointerBorrowed']
    # The DSO's three exact object inputs are the same objects linked into the
    # successful iPad executable. This does not claim the DSO itself was loaded.
    fixture_path = N / 'static-cn-original-identity-ios-fixture-local-v3/candidate.json'
    fixture = json.loads(fixture_path.read_bytes()); files[str(fixture_path)] = p.pin(fixture_path)
    dso_inputs = [row for row in source['objects'] if '/ios-inert/' in row['path']]
    assert len(dso_inputs) == 3
    for row in dso_inputs:
        copied = next(x for x in fixture['copiedObjects'] if Path(x['source']['path']).name == Path(row['path']).name)
        assert row == copied['source'] and p.pin(Path(row['path'])) == row
        assert Path(row['path']).read_bytes() == Path(copied['product']['path']).read_bytes()
    cn_pin = source['linkedProduct']; assert p.pin(Path(cn_pin['path'])) == cn_pin
    cn_raw = Path(cn_pin['path']).read_bytes(); cn = mp.MachO(cn_raw)
    symbol = '_$ss20__StaticArrayStorageCN'
    assert cn.exports[symbol]['flags'] == 0 and cn.exports[symbol]['address'] == cn.exports['_OBJC_CLASS_$_TtCs20__StaticArrayStorage']['address']
    assert len(cn.imports) == 18 and all(not row['weak'] and row['ordinal'] > 0 for row in cn.imports)
    ar_old = next(row for row in prior['privateDefinitions'] if row['path'] == '@loader_path/AR')
    ar_raw = Path(ar_old['image']['path']).read_bytes(); assert p.pin(Path(ar_old['image']['path'])) == ar_old['image']
    count, size = struct.unpack_from('<II', ar_raw, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/CN\0'
    assert len(addition) == 40 and not any(ar_raw[32+size:32+size+40])
    ar_new = bytearray(ar_raw); struct.pack_into('<II', ar_new, 16, count+1, size+40); ar_new[32+size:32+size+40] = addition
    assert p.dependencies(ar_new)[:-1] == p.dependencies(ar_raw)
    assert p.dependencies(ar_new)[-1] == dict(ordinal=12, command=0x8000001f, path='@loader_path/CN', at=32+size, size=40)
    assert p.imports(ar_new) == p.imports(ar_raw)
    # Native owners needed by this provider are joined from real receipts.
    # Other 47-owner frontier results are inherited, not re-audited here.
    images = s.primary.captured_images(); pins = []
    for group in ['system','stock-extra','cxx-leaf']:
        pins += s.join_capture(images, group, N / ('ipad-current-cache-' + group + '-headers-v1/headers.json'))
    for group in ['dyld-leaf','xpc-leaf']:
        pins += s.join_capture(images, group, N / ('ipad-current-cache-' + group + '-headers-v2/headers.json'))
    pins += m.f.join_kernel(s, images)
    for fn in [m.f.join_hid_extra,m.f.join_swift_two,m.f.join_eight,m.f.join_three,m.f.join_trace,m.f.join_unwind,m.f.join_compiler,m.f.join_crypto]:
        added, _ = fn(s, images); pins += added
    assert len(images) == 36
    for row in pins: files[row['path']] = row
    cn_proofs = []
    for row in cn.imports:
        dep = cn.loads[row['ordinal']-1]
        proof = m.f.resolve(images, dep['path'], row['name'])
        assert proof['status'] == 'actualDirectExport'
        cn_proofs.append(dict(row, dependency=dep['path'], definitionProof=proof))
    OUT.mkdir(mode=0o700)
    cn_path = OUT / 'CN.unchanged-unsigned-ios-provider.inert.macho-data'; cn_path.write_bytes(cn_raw)
    ar_path = OUT / 'AR.real-static-cn-reexport.inert.macho-data'; ar_path.write_bytes(ar_new)
    assert p.pin(cn_path)['sha256'] == cn_pin['sha256']
    images['@loader_path/CN'] = m.f.image(p.pin(cn_path), '@loader_path/CN')
    images['@loader_path/AR'] = m.f.image(p.pin(ar_path), '@loader_path/AR')
    results = []
    for name, index, ordinal in [('UniversalHID',14,20),('UniversalHIDKit',9,1)]:
        old = next(row for row in prior['auditedImages'] if row['name'] == name)
        before = Path(old['image']['path']).read_bytes(); assert p.pin(Path(old['image']['path'])) == old['image']
        imports = p.imports(before)['imports']; record = imports[index]
        assert record['name'] == symbol and record['ordinal'] == 8 and not record['weak']
        assert p.dependencies(before)[7]['path'] == '/usr/lib/swift/libswiftCore.dylib'
        target = p.dependencies(before)[ordinal-1]
        assert target['path'] == ('@loader_path/AR' if name == 'UniversalHID' else '@loader_path/UniversalHID27.dylib')
        after = bytearray(before); after[record['command']] = ordinal
        assert len(after) == len(before) and sum(a != b for a,b in zip(before,after,strict=True)) == 1
        wanted = [dict(row, ordinal=ordinal) if row['index'] == index else row for row in imports]
        assert p.imports(after)['imports'] == wanted
        assert p.dependencies(after) == p.dependencies(before)
        path = OUT / (name + '27.static-cn-real-reexport.mac.inert.macho-data'); path.write_bytes(after)
        images[old['path']] = m.f.image(p.pin(path), old['path'])
        results.append(dict(name=name, source=old['image'], candidate=p.pin(path), importIndex=index,
            symbol=symbol, oldOrdinal=8, newOrdinal=ordinal, actualDependency=target, importByteOffset=record['command'],
            wholeFileChangedBytes=1, allOtherWholeFileBytesPreserved=True, allInstructionMetadataWitnessPACBytesPreserved=True))
        files[old['image']['path']] = old['image']
    for result in results:
        definition = m.f.resolve(images, result['actualDependency']['path'], symbol, images['@loader_path/' + result['name'] + '27.dylib'])
        assert definition['status'] == 'actualDirectExport'
        leaf = definition
        while 'nested' in leaf: leaf = leaf['nested']
        assert leaf['owner'] == '@loader_path/CN' and leaf['export']['flags'] == 0
        result['actualReexportDefinition'] = definition
    # A regular LC_LOAD_DYLIB does not re-export the class. Verify that the
    # genuinely new AR command, not an invented symbol default, closes it.
    damaged = dict(images); damaged_ar = dict(images['@loader_path/AR'])
    damaged_ar['dependencies'] = [dict(row, command=12) if row['ordinal'] == 12 else row for row in damaged_ar['dependencies']]
    damaged['@loader_path/AR'] = damaged_ar
    assert m.f.resolve(damaged, '@loader_path/AR', symbol)['status'] != 'actualDirectExport'
    validations = []
    for path in [cn_path, ar_path, *[Path(row['candidate']['path']) for row in results]]:
        result = subprocess.run(['xcrun','dyld_info','-validate_only',str(path)], capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr
        validations.append(dict(image=p.pin(path), exit=0))
    report = dict(schema='Two real StaticCN strong imports through unchanged own class inert reexports v1',
        sourceFrontier=p.pin(prior_path), actualOriginalCNDeviceAudit=p.pin(N / 'ordinary-static-cn-original-device-result-v2/verdict.json'),
        independentActualCNPeer=p.pin(N / 'static-cn-original-ios-actual-independent-review-v2/review.json'),
        unchangedProvider=dict(alias='CN', intendedLoadPath='@loader_path/CN', source=cn_pin, candidate=p.pin(cn_path),
            executableFixtureObjectsWholeBytesSame=True, actualExport=cn.exports[symbol], imports=cn_proofs,
            strongDefinitionsClosed=18, chainedImportAddendsPreserved=True, classABI='176B/AP24/N3/P19; actual old Core Base N2',
            providerDSOActuallyLoaded=False, originalGenericMethodCallersExecuted=False),
        modifiedArrayReexportProvider=dict(alias='AR', source=ar_old['image'], candidate=p.pin(ar_path),
            genuineNewReexportOrdinal=12, genuineNewReexportPath='@loader_path/CN', addedCommandBytes=40,
            allPreexistingSectionsImportsChainedPointerBytesPreserved=True, preexistingSignatureInvalidAfterHeaderMutation=True),
        images=results, routedStrongImports=2, onlyTwoConsumerWholeFileBytesChanged=True, allOther51PrivatePlacementsInherited=True,
        nativeCurrentOwnersUsedForProviderClosure=36, declaredPrivateImagesAfterAddingCN=52,
        twoFormerActualAbsentCNDefinitionsNowRouted=True, definitionEvidenceOnly=True,
        structuralValidations=validations, trueReexportCommandNegativeControlPassed=True,
        providerClassIdentityAndLifetimeEstablishedOnlyByExecutable=True, providerDSOIdentityOrLifetimeExecuted=False,
        originalUHKRemainingAppKitSkyLightImportsClosed=False, candidateReadyForNativeLoading=False,
        currentCompleteProviderDependencyGraphValidated=False, originalUHLoaded=False, originalUHKLoaded=False,
        originalVZLoaded=False, nativeIOSExecuted=False, deviceOperations=0, productionPackageModified=False, full27Backend=False)
    p.save(OUT / 'candidate.json', report)
    for path in [Path(__file__).resolve(), Path(mp.__file__).resolve(), ar_path, cn_path, OUT / 'candidate.json', *[Path(row['candidate']['path']) for row in results]]:
        files[str(path)] = p.pin(path)
    for row in files.values(): assert p.pin(Path(row['path'])) == row
    p.save(OUT / 'freeze.json', dict(files=list(files.values()), deviceOperations=0, candidateLoaded=False, full27Backend=False))
    print(json.dumps(dict(candidate=p.pin(OUT / 'candidate.json'), freeze=p.pin(OUT / 'freeze.json'), routedStrongImports=2, nativeProviderStrongDefinitions=18)))
if __name__ == '__main__': main()
