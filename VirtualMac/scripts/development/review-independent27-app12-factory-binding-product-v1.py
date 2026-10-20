#!/usr/bin/env python3
"""Finite independent actual App12 two-unit/signature/native import peer."""
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import struct
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = R / 'VirtualMac/scripts/development'
S = R / 'VirtualMac/vz/host'

def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def exact(row):
    assert pin(row['path']) == {key: row[key] for key in ('path', 'bytes', 'sha256')}, row['path']
    return pathlib.Path(row['path'])

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def main():
    cp = N / 'independent27-signed-app-vm-class-binding-v12-attempt1/candidate.json'
    c = json.loads(cp.read_bytes())
    lp = exact(c['sourceCandidate']); linked = json.loads(lp.read_bytes())
    oldcp = N / 'independent27-signed-app-uikit-basic-input-product-v11-attempt1/candidate.json'
    old = json.loads(oldcp.read_bytes()); oldlinked = json.loads(exact(old['sourceCandidate']).read_bytes())
    priorpeer = N / 'independent27-app11-basic-input-stage14-final-independent-peer-v1-attempt1/review.json'
    prior = json.loads(priorpeer.read_bytes())
    assert prior['signedCandidate'] == pin(oldcp) and prior['findings'] == []
    sourcepeer = N / 'independent27-runtime5-factory-attestation-independent-peer-v1-attempt1/review.json'
    source = json.loads(sourcepeer.read_bytes())
    assert source['findings'] == [] and source['finiteLocalScopePassed']
    for freeze in (cp.parent / 'freeze.json', lp.parent / 'freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']:
            exact(row)
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    macho = module(reader, 'actual_app12_independent_macho')
    signatures = module(B / 'review-independent27-signed-runtime-product-v1.py', 'actual_app12_signature')
    der = module(B / 'review-independent27-app8-signed-main-v1.py', 'actual_app12_der')
    signed_bytes = exact(c['binary']).read_bytes(); unsigned_bytes = exact(linked['binary']).read_bytes()
    signed = macho.MachO(signed_bytes); unsigned = macho.MachO(unsigned_bytes)
    previous = macho.MachO(exact(old['binary']).read_bytes())
    assert signed.uuid == unsigned.uuid == '4af2420e502c3db4bbff92ef4b5bdd1c'
    assert signed.sections == unsigned.sections and signed.binds == unsigned.binds
    assert signed.imports == unsigned.imports and signed.exports == unsigned.exports
    for section in unsigned.sections:
        at, size = section['fileoff'], section['size']
        if at and size and section['flags'] & 255 not in (1, 12, 18):
            assert signed_bytes[at:at + size] == unsigned_bytes[at:at + size]
    app = pathlib.Path(c['app']); info = (app / 'Info.plist').read_bytes()
    resources = (app / '_CodeSignature/CodeResources').read_bytes()
    signature = signatures.signed_image(exact(c['binary']), c['actualSignature'], {1: info, 3: resources})
    assert json.loads(json.dumps(signature)) == c['actualSignature']
    assert signature['cdhash'] == '8657b9da3b665cee6d5ead283254cf2e92e6481e'
    assert signature['actualCodePages'] == 55 and len(signed_bytes) == 894448 <= 2097152
    slots = der.signature_slots(signed_bytes); oldslots = der.signature_slots(previous.data)
    entitlements = plistlib.loads(slots[5][8:])
    assert entitlements == der.der_entitlements(slots[7]) == plistlib.loads((S / 'VirtualMac.entitlements').read_bytes())
    assert slots[5] == oldslots[5] and slots[7] == oldslots[7]

    assert len(linked['objects']) == len(linked['sourceFiles']) == len(oldlinked['objects']) == 35
    changed = [i for i, (new, prior) in enumerate(zip(linked['objects'], oldlinked['objects'])) if new['sha256'] != prior['sha256']]
    assert changed == [16, 32]
    assert [i for i, (new, prior) in enumerate(zip(linked['sourceFiles'], oldlinked['sourceFiles'])) if new['sha256'] != prior['sha256']] == changed
    assert linked['sourceFiles'][16] == source['sources'][2] and linked['sourceFiles'][32] == source['sources'][0]
    assert all(row['exit'] == 0 for row in linked['commands'])
    for index in changed:
        command = next(row['argv'] for row in linked['commands'] if row['label'] == 'compile-' + str(index))
        assert '-fobjc-arc' in command and linked['sourceFiles'][index]['path'] in command
    link = next(row['argv'] for row in linked['commands'] if row['label'] == 'link-app')
    assert all(row['path'] in link for row in linked['objects'])
    assert '-Wl,-no_adhoc_codesign' in link and '-Wl,-export_dynamic' in link
    assert not any(token in link for token in ('dynamic_lookup', '-flat_namespace', '-undefined'))
    assert not any(row['name'] == '_VM27UIKitActualVirtualMachineAttestedV2' for row in signed.imports)

    oldfiles = {str(pathlib.Path(row['path']).relative_to(old['app'])): row for row in old['appFiles']}
    newfiles = {str(pathlib.Path(row['path']).relative_to(c['app'])): row for row in c['appFiles']}
    assert set(oldfiles) == set(newfiles) and len(newfiles) == 103
    changed_files = [name for name in newfiles if newfiles[name]['sha256'] != oldfiles[name]['sha256']]
    assert changed_files == ['VirtualMacIndependent27']
    for row in newfiles.values(): exact(row)
    assert c['runtimeCandidate'] == old['runtimeCandidate'] == prior['runtimeCandidate']
    runtime = json.loads(exact(c['runtimeCandidate']).read_bytes())
    manifest = exact(runtime['manifest']).read_bytes()
    assert c['realCompiledManifestAnchor'] == old['realCompiledManifestAnchor'] == runtime['anchorSource']
    assert linked['sourceFiles'][34] == oldlinked['sourceFiles'][34] == runtime['anchorSource']
    digest_at = signed.file(signed.base + signed.exports['_VM27IndependentRuntimeManifestSHA256V1']['address'])
    size_at = signed.file(signed.base + signed.exports['_VM27IndependentRuntimeManifestBytesV1']['address'])
    assert signed_bytes[digest_at:digest_at + 32] == hashlib.sha256(manifest).digest()
    assert struct.unpack_from('<Q', signed_bytes, size_at)[0] == len(manifest) == 43345

    builder = exact(linked['builder']).read_text()
    old_builder = (B / 'build-independent27-copied-app-v11-uikit-filter.py').read_text()
    expected = old_builder.replace(" ap.add_argument('--basic-input-surface-source',type=pathlib.Path,required=True)\n", " ap.add_argument('--basic-input-surface-source',type=pathlib.Path,required=True)\n ap.add_argument('--uikit-guest-display-source',type=pathlib.Path,required=True)\n")
    expected = expected.replace(" sourceOverrides={'vm27_own_uikit_ingress_profile_v1.m':profileSource,'modern_uikit_input_surface_v2.m':surfaceSource}", " displaySource=a.uikit_guest_display_source.resolve()\n assert displaySource==S/'vm27_uikit_guest_display_v2.mm' and displaySource.is_file()\n assert 'VM27UIKitCreateActualVirtualMachineV1' in displaySource.read_text()\n sourceOverrides={'vm27_own_uikit_ingress_profile_v1.m':profileSource,'modern_uikit_input_surface_v2.m':surfaceSource,'vm27_uikit_guest_display_v1.mm':displaySource}")
    expected = expected.replace('Copied independent27 App11 actual UIKit input profile', 'Copied independent27 App12 actual genuine factory attestation')
    assert builder == expected
    signerpath = B / 'sign-independent27-actual-app-product-v3.py'
    oldsigner = (B / 'sign-independent27-actual-app-product-v2.py').read_text()
    assert signerpath.read_text() == oldsigner.replace('vm27_independent_app_runtime_v4.m', 'vm27_independent_app_runtime_v5.m').replace('actual Runtime4 compiled into main', 'actual Runtime5 compiled into main').replace('Actual strong linked and signed independent27 App main identity product v2', 'Actual strong linked and signed independent27 App factory class binding product v3')

    prior_routes_path = exact(prior['actualNativeRoutes'])
    inherited = json.loads(prior_routes_path.read_bytes())
    def key(row): return (row['name'], row['ordinal'], row['weak'], row['addend'])
    old_routes = {key(row['actualNewImport']): row for row in inherited['actualRows']}
    assert len(old_routes) == 481
    assert [{k: v for k, v in row.items() if k != 'at'} for row in signed.loads] == [{k: v for k, v in row.items() if k != 'at'} for row in previous.loads]
    assert len(signed.imports) == 482 and sum(not row['weak'] for row in signed.imports) == 481
    added = [row for row in signed.imports if key(row) not in old_routes]
    assert len(added) == 1 and added[0]['name'] == '_class_getName' and added[0]['ordinal'] == 16 and not added[0]['weak']
    assert set(old_routes) == {key(row) for row in signed.imports if key(row) in old_routes}
    original_proof = json.loads(exact(inherited['inheritedNativeProof']).read_bytes())
    index_path = exact(original_proof['originalIndex']); index = json.loads(index_path.read_bytes())
    objc = index['images']['/usr/lib/libobjc.A.dylib']
    assert len(index['images']) == 67 and objc['UUID'] == 'ab79707faf643ba588993b711c6cff5c'
    export_path = exact(objc['actualCompleteExportSource']['rangePin'])
    exports, _ = macho.trie(export_path.read_bytes())
    actual_definition = exports['_class_getName']
    assert actual_definition == dict(flags=0, address=25132)
    assert objc['definitions']['_class_getName'] == dict(flags=0, offset=25132)
    routes = []
    for row in signed.imports:
        if key(row) in old_routes:
            inherited_row = old_routes[key(row)]
            routes.append(dict(actualNewImport=row, requiredLoad=inherited_row['requiredLoad'], route=inherited_row['route']))
        else:
            routes.append(dict(actualNewImport=row, requiredLoad='/usr/lib/libobjc.A.dylib', route=[dict(path='/usr/lib/libobjc.A.dylib', symbol='_class_getName', definition=objc['definitions']['_class_getName'], UUID=objc['UUID'])]))
    out = N / 'independent27-app12-factory-binding-signed-independent-peer-v1-attempt1'
    out.mkdir(mode=0o700)
    (out / 'actual-app12-native-routes.json').write_text(json.dumps(dict(actualImports=482, strong=481, weak=1,
        inherited481Proof=pin(prior_routes_path), originalNative67Index=pin(index_path),
        actualAdditionalExportCapture=pin(export_path), additionalNativeImports=added,
        actualRows=routes, unresolved=[], deviceOperations=0), indent=2) + '\n')
    report = dict(schema='Actual App12 factory binding finite signed product independent peer v1',
        signedCandidate=pin(cp), unsignedCandidate=pin(lp), actualSignature=signature,
        sourcePeer=pin(sourcepeer), actualChangedObjectIndices=changed, other33ObjectsWholeBytesSame=True,
        actualAppFiles=103, allOther102AppFilesWholeBytesSame=True, onlyUpdatedAppFile='VirtualMacIndependent27',
        builderDeltaOnlyNewFactoryARCOverrideAndSchema=True, signerDeltaOnlyRuntime5SourceAndSchema=True,
        actualCompiledRuntime10AnchorWholeUnchanged=True, manifestDigestAndExtentVerified=True,
        Runtime10SignedImagesRepeated=False, signature55PrimaryPagesAndAll7SlotsVerified=True,
        XMLDER14EntitlementsWholeBytesSameAsApp11=True, signingPreservesActualCompiledCodeDataAndPointerAuthMetadata=True,
        actualNativeImports=482, strongNativeImports=481, weakNativeImports=1,
        inherited481ImportNamespacesWholeSame=True, additionalNativeImport='_class_getName',
        additionalNativeDefinitionUUID=objc['UUID'], additionalNativeDefinitionRVA=25132,
        actualNativeRoutes=pin(out / 'actual-app12-native-routes.json'), nativeImportClosureComplete=True,
        newDeviceNativeCaptures=0, guestStartupActuallyExecuted=False, actualDynamicISAObserved=False,
        actualGuestDisplay=False, actualGuestInput=False, actualGuestSSHAuthenticated=False,
        freshAppSingleVMLimit=True, repeatStartWithinSameAppImplemented=False,
        deviceOperations=0, codeSigningOperations=0, findings=[], finiteLocalScopePassed=True)
    (out / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(__file__), pin(cp), pin(cp.parent / 'freeze.json'), pin(lp), pin(lp.parent / 'freeze.json'),
        pin(oldcp), old['sourceCandidate'], pin(priorpeer), pin(sourcepeer), c['binary'], linked['binary'],
        linked['builder'], pin(signerpath), pin(B / 'build-independent27-copied-app-v11-uikit-filter.py'),
        pin(B / 'sign-independent27-actual-app-product-v2.py'), runtime['manifest'], runtime['anchorSource'],
        pin(reader), pin(prior_routes_path), pin(index_path), pin(export_path)] + linked['sourceFiles'] + linked['objects'] + [
        pin(app / 'Info.plist'), pin(app / '_CodeSignature/CodeResources'), pin(out / 'review.json'),
        pin(out / 'actual-app12-native-routes.json')]
    (out / 'freeze.json').write_text(json.dumps(dict(files=list({row['path']: row for row in rows}.values()), deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'), findings=[])))

if __name__ == '__main__':
    main()
