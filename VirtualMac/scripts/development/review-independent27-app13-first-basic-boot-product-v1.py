#!/usr/bin/env python3
"""Finite App13 product, signing and builder peer; Main semantics use a separate peer."""
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
    cp = N / 'independent27-signed-app-first-basic-boot-v13-attempt1/candidate.json'
    assert pin(cp)['sha256'] == 'ab7b676205bcf972c047430582c9e7b425e1513c676fb150a0f0d555835c9c28'
    c = json.loads(cp.read_bytes())
    lp = exact(c['sourceCandidate']); linked = json.loads(lp.read_bytes())
    oldcp = N / 'independent27-signed-app-vm-class-binding-v12-attempt1/candidate.json'
    old = json.loads(oldcp.read_bytes()); oldlinked = json.loads(exact(old['sourceCandidate']).read_bytes())
    priorpeer = N / 'independent27-app12-factory-binding-peer-finalization-v1-attempt1/review.json'
    prior = json.loads(priorpeer.read_bytes())
    assert prior['signedCandidate'] == pin(oldcp) and prior['finiteLocalScopePassed'] and prior['findings'] == []
    sourcepeer = N / 'independent27-app13-first-basic-boot-source-independent-peer-v1-attempt1/review.json'
    source = json.loads(sourcepeer.read_bytes())
    assert source['passed'] and source['findings'] == [] and source['sourceCandidate'] == linked['sourceCandidate']
    sourcecandidate = json.loads(exact(linked['sourceCandidate']).read_bytes())
    for freeze in (cp.parent / 'freeze.json', lp.parent / 'freeze.json', sourcepeer.parent / 'freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']:
            exact(row)
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    macho = module(reader, 'actual_app13_independent_macho')
    signatures = module(B / 'review-independent27-signed-runtime-product-v1.py', 'actual_app13_signature')
    der = module(B / 'review-independent27-app8-signed-main-v1.py', 'actual_app13_der')
    signed_bytes = exact(c['binary']).read_bytes(); unsigned_bytes = exact(linked['binary']).read_bytes()
    signed = macho.MachO(signed_bytes); unsigned = macho.MachO(unsigned_bytes)
    previous = macho.MachO(exact(old['binary']).read_bytes())
    assert signed.uuid == unsigned.uuid == '907e3c6f22a43a688de5fcdeada0169e'
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
    assert signature['cdhash'] == 'afeccdbc7e89a0fed56261bc2de9c586eae16ffa'
    assert signature['actualCodePages'] == 55 and len(signed_bytes) == 893872 <= 2097152
    slots = der.signature_slots(signed_bytes); oldslots = der.signature_slots(previous.data)
    entitlements = plistlib.loads(slots[5][8:])
    assert entitlements == der.der_entitlements(slots[7]) == plistlib.loads((S / 'VirtualMac.entitlements').read_bytes())
    assert slots[5] == oldslots[5] and slots[7] == oldslots[7]

    assert len(linked['objects']) == len(linked['sourceFiles']) == len(oldlinked['objects']) == 35
    changed = [i for i, (new, oldrow) in enumerate(zip(linked['objects'], oldlinked['objects'])) if new['sha256'] != oldrow['sha256']]
    assert changed == [0]
    assert [i for i, (new, oldrow) in enumerate(zip(linked['sourceFiles'], oldlinked['sourceFiles'])) if new['sha256'] != oldrow['sha256']] == changed
    assert linked['sourceFiles'][0] == sourcecandidate['source']
    assert len(linked['commands']) == 80 and all(row['exit'] == 0 for row in linked['commands'])
    link = next(row['argv'] for row in linked['commands'] if row['label'] == 'link-app')
    assert all(row['path'] in link for row in linked['objects'])
    assert '-Wl,-no_adhoc_codesign' in link and '-Wl,-export_dynamic' in link
    assert not any(token in link for token in ('dynamic_lookup', '-flat_namespace', '-undefined'))
    oldfiles = {str(pathlib.Path(row['path']).relative_to(old['app'])): row for row in old['appFiles']}
    newfiles = {str(pathlib.Path(row['path']).relative_to(c['app'])): row for row in c['appFiles']}
    assert set(oldfiles) == set(newfiles) and len(newfiles) == 103
    assert [name for name in newfiles if newfiles[name]['sha256'] != oldfiles[name]['sha256']] == ['VirtualMacIndependent27']
    for row in newfiles.values(): exact(row)
    assert c['runtimeCandidate'] == old['runtimeCandidate'] == prior['runtimeCandidate']
    runtime = json.loads(exact(c['runtimeCandidate']).read_bytes()); manifest = exact(runtime['manifest']).read_bytes()
    assert c['realCompiledManifestAnchor'] == old['realCompiledManifestAnchor'] == runtime['anchorSource']
    assert linked['sourceFiles'][34] == oldlinked['sourceFiles'][34] == runtime['anchorSource']
    digest_at = signed.file(signed.base + signed.exports['_VM27IndependentRuntimeManifestSHA256V1']['address'])
    size_at = signed.file(signed.base + signed.exports['_VM27IndependentRuntimeManifestBytesV1']['address'])
    assert signed_bytes[digest_at:digest_at + 32] == hashlib.sha256(manifest).digest()
    assert struct.unpack_from('<Q', signed_bytes, size_at)[0] == len(manifest) == 43345

    builder = exact(linked['builder']).read_text(); oldbuilderpath = exact(oldlinked['builder'])
    oldbuilder = oldbuilderpath.read_text()
    admission = """ assert manifest['trueSSHRegistrationAfterRuntimeBindBeforeStart'] is False
 assert manifest['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True
 assert manifest['selectedIndependent27FirstDisplaySSHDeferred'] is True
 assert manifest['runtimeGuestStartedActualStateAdmissionPreserved'] is True
 assert manifest['actualRuntimeBindQueueAndFactoryCallsWholeUnchanged'] is True
 assert manifest['actualCPUDisplayInputAndGuestConfigurationWholeUnchanged'] is True
 assert manifest['existingSSHOwnerDrainAndFailureRetentionWholeUnchanged'] is True
 assert manifest['genuineSSHBridgeIncludedAsDormantFutureCode'] is True
 assert manifest['finalNetworkAndSSHStillRequired'] is True
 assert manifest['fakeProtocolOrClassAdded'] is False and manifest['fakeHELLOOrSSHReadyAdded'] is False
 assert manifest['guestSSHAvailable'] is False and manifest['actualSSHVerified'] is False
 priorApp12=N/'independent27-actual-app-vm-class-binding-v12-attempt1/candidate.json'
 assert manifest['priorActualApp12Candidate']==pin(priorApp12)
"""
    expected = oldbuilder.replace(" assert manifest['trueSSHRegistrationAfterRuntimeBindBeforeStart']\n", admission)
    expected = expected.replace('Copied independent27 App12 actual genuine factory attestation', 'Copied independent27 App13 actual first basic boot with SSH explicitly deferred')
    expected = expected.replace('genuineSSHBridgeIncluded=True,guestHelperInstalled=False,', 'genuineSSHBridgeIncluded=True,genuineSSHBridgeDormantForFirstBoot=True,sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,guestHelperInstalled=False,')
    assert builder == expected
    signerpath = B / 'sign-independent27-actual-app-product-v3.py'
    assert pin(signerpath)['sha256'] == '5d3a08e035dfcd9a503c42433e9efc8b02cc40bc8a6cbd029bf3e80ae937ae65'
    routespath = exact(prior['actualNativeRoutes']); inherited = json.loads(routespath.read_bytes())
    def key(row): return (row['name'], row['ordinal'], row['weak'], row['addend'])
    oldroutes = {key(row['actualNewImport']): row for row in inherited['actualRows']}
    assert len(oldroutes) == 482
    semantic = lambda rows: [{k: v for k, v in row.items() if k != 'at'} for row in rows]
    assert semantic(signed.imports) == semantic(previous.imports) and semantic(signed.loads) == semantic(previous.loads)
    assert len(signed.imports) == 482 and sum(not row['weak'] for row in signed.imports) == 481
    indexpath = exact(inherited['originalNative67Index'])
    assert len(json.loads(indexpath.read_bytes())['images']) == 67
    out = N / 'independent27-app13-first-basic-boot-signed-independent-peer-v1-attempt1'
    out.mkdir(mode=0o700)
    routefile = out / 'actual-app13-native-routes.json'
    routefile.write_text(json.dumps(dict(actualImports=482, strong=481, weak=1,
        inherited482Proof=pin(routespath), originalNative67Index=pin(indexpath), actualRows=[dict(
        actualNewImport=row, requiredLoad=oldroutes[key(row)]['requiredLoad'], route=oldroutes[key(row)]['route']) for row in signed.imports],
        unresolved=[], deviceOperations=0), indent=2) + '\n')
    report = dict(schema='Actual App13 first basic boot finite signed product independent peer v1',
        signedCandidate=pin(cp), unsignedCandidate=pin(lp), runtimeCandidate=c['runtimeCandidate'], actualSignature=signature,
        independentMainSemanticPeer=pin(sourcepeer), mainSourceAuthorIsProductReviewer=True,
        mainSemanticsIndependentlyReviewedBySeparatePeer=True, priorActualSignedProductPeer=pin(priorpeer),
        actualChangedObjectIndices=changed, other34ObjectsWholeBytesSame=True, actualAppFiles=103,
        allOther102AppFilesWholeBytesSame=True, onlyUpdatedAppFile='VirtualMacIndependent27',
        builderDeltaOnlyExplicitSSHDeferredAdmissionAndMetadata=True, compileLinkImplementationWholeUnchanged=True,
        signerV3WholeBytesUnchanged=True, actualCompiledRuntime10AnchorWholeUnchanged=True,
        manifestDigestAndExtentVerified=True, Runtime10SignedImagesRepeated=False,
        signature55PrimaryPagesAndAll7SlotsVerified=True, XMLDER14EntitlementsWholeBytesSameAsApp12=True,
        signingPreservesActualCompiledCodeDataAndPointerAuthMetadata=True,
        actualNativeImports=482, strongNativeImports=481, weakNativeImports=1,
        all482ImportSemanticsAnd16NamespacesWholeSameAsApp12=True, additionalNativeImports=[],
        actualNativeRoutes=pin(routefile), nativeImportClosureComplete=True, newDeviceNativeCaptures=0,
        genuineSSHBridgeDormantForFirstBasicGuestBoot=True, guestSSHAvailable=False, actualSSHVerified=False,
        finalNetworkAndSSHStillRequired=True, guestStartupActuallyExecuted=False,
        actualGuestDisplay=False, actualGuestInput=False, deviceOperations=0, codeSigningOperations=0,
        findings=[], finiteLocalScopePassed=True)
    review = out / 'review.json'; review.write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(__file__), pin(cp), pin(cp.parent/'freeze.json'), pin(lp), pin(lp.parent/'freeze.json'),
        pin(oldcp), old['sourceCandidate'], pin(priorpeer), pin(sourcepeer), pin(sourcepeer.parent/'freeze.json'),
        linked['sourceCandidate'], c['binary'], linked['binary'], linked['builder'], pin(oldbuilderpath), pin(signerpath),
        runtime['manifest'], runtime['anchorSource'], pin(reader), pin(routespath), pin(indexpath),
        pin(B/'review-independent27-signed-runtime-product-v1.py'), pin(B/'review-independent27-app8-signed-main-v1.py')]
    rows += linked['sourceFiles'] + linked['objects'] + [pin(app/'Info.plist'), pin(app/'_CodeSignature/CodeResources'), pin(review), pin(routefile)]
    freeze = out/'freeze.json'; freeze.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()), deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(review=pin(review), freeze=pin(freeze), findings=[])))

if __name__ == '__main__':
    main()
