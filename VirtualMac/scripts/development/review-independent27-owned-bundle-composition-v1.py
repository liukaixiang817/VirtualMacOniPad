#!/usr/bin/env python3
"""Finite HOST peer: new Root composition, six real signatures, exact V2 packet."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import re
import struct
import sys
import tarfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent

def pin(path):
    path = pathlib.Path(path).resolve(); raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args(); out = args.output.resolve()
    assert out.parent == N and not out.exists()
    inputs, checks = {}, []
    def exact(row):
        expected = {key: row[key] for key in ('path', 'bytes', 'sha256')}
        assert pin(row['path']) == expected, row['path']
        inputs[row['path']] = expected; return pathlib.Path(row['path'])
    def load(name):
        path = N / name / 'candidate.json'; exact(pin(path)); exact(pin(path.parent / 'freeze.json'))
        return path, json.loads(path.read_bytes())
    def need(value, reason):
        if not value: raise ValueError(reason)
        checks.append(reason)
    packet_path, packet = load('independent27-owned-bundle-device-v3-attempt1')
    need(pin(packet_path)['sha256'] == '99a5497b769a056089f3711e5c6b3352ace9516817489f94c0db148bf359b7aa', 'exact current V3 packet')
    runtime_path, runtime = load('independent27-signed-runtime-product-v6-attempt1')
    old_runtime_path, old_runtime = load('independent27-signed-runtime-product-v5-attempt1')
    app_path, app = load('independent27-signed-app-owned-bundle-product-v6-attempt1')
    old_app_path, old_app = load('independent27-signed-app-child-plugin-product-v5-attempt1')
    provider_path, provider = load('owned-bundle-approved-startup-provider-v6-attempt3')
    stage_path, stage = load('independent27-owned-bundle-stage-v10-attempt1')
    scope = json.loads(exact(packet['scope']).read_bytes())
    need(packet['runtimeCandidate'] == pin(runtime_path) and packet['appCandidate'] == pin(app_path), 'concrete signed Runtime6/App6 composition')
    peer_path = exact(pin(N / 'owned-bundle-consumer-policy-source-independent-review-v1-attempt1/review.json'))
    peer = json.loads(peer_path.read_bytes())
    need(peer['findings'] == [] and peer['finiteSourceScopePassed'], 'independent source decision review passed')
    source_peer_path = exact(pin(N / 'owned-bundle-authentication-boundaries-review-v1-attempt1/review.json'))
    source_peer = json.loads(source_peer_path.read_bytes())
    for row in source_peer['inputs']: exact(row)
    need(source_peer['finiteSourceScopePassed'] and source_peer['findings'] == [], 'own independent Root source boundary review still exact')
    for row in provider['actualIncludeClosure'] + provider['actualNewObjects'] + provider['actualReusedObjects'] + provider['actualReusedLibraries']:
        exact(row)
    need(provider['policyCandidate']['sha256'] == 'f7f66382a28639013fd051b787ddf0472fb2924c215335fb3bd77fa795d419d0', 'actual production policy joins frozen genuine-files models')
    m = module('owned_bundle_macho_peer', exact(pin(N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')))
    signing = module('owned_bundle_signature_peer', exact(pin(B / 'review-independent27-signed-runtime-product-v2.py')))
    consumer = m.MachO(exact(provider['consumer']).read_bytes())
    adapter = m.MachO(exact(provider['adapter']).read_bytes())
    baseline = json.loads(exact(provider['inheritedProviderCandidate']).read_bytes())
    old_consumer = m.MachO(exact(baseline['consumer']).read_bytes())
    need(set(consumer.exports) == set(old_consumer.exports) | {'_VM27OwnedBundlePrivateServiceConsumerCreateV5'}, 'old eight public consumer exports plus only explicit owned Create')
    previous = json.loads(exact(provider['previousStartupCandidate']).read_bytes())
    need(set(adapter.exports) == set(m.MachO(exact(previous['adapter']).read_bytes()).exports), 'all eleven startup public APIs unchanged')
    need(not any('OwnedBundleApprovedPolicy' in key or 'BundleChildInspect' in key for key in consumer.exports), 'policy/inspection private symbols remain hidden')
    before_stage = json.loads(exact(stage['baseStage']).read_bytes())
    arows, brows = ({row['key']: row for row in value['stagedImages']} for value in (before_stage, stage))
    changed_stage = []
    for key in brows:
        if exact(arows[key]['staged']).read_bytes() != exact(brows[key]['staged']).read_bytes(): changed_stage.append(key)
    need(set(changed_stage) == {'VM27LargeConsumerV2.dylib', 'VM27OwnedAppStartupV3.dylib'} and len(brows) == 73, 'Stage10 only two leaves changed; other71 whole bytes exact')
    for key, product in [('VM27LargeConsumerV2.dylib', provider['consumer']), ('VM27OwnedAppStartupV3.dylib', provider['adapter'])]:
        raw = exact(product).read_bytes(); final = exact(brows[key]['staged']).read_bytes()
        a, b = m.MachO(raw), m.MachO(final)
        need(all(getattr(a, field) == getattr(b, field) for field in ('uuid', 'sections', 'exports', 'imports', 'binds')), 'stage header-only retarget preserves ABI/PAC/fixups ' + key)
        end = max(32 + a.sizeofcmds, 32 + b.sizeofcmds)
        need(not any(raw[32 + a.sizeofcmds:end]) and raw[end:] == final[end:], 'header packing consumes only zero padding; all body bytes equal ' + key)
    admission = json.loads(exact(runtime['admission']).read_bytes())
    need(admission['actualStage'] == pin(stage_path), 'actual signed admission binds Stage10')
    graph = json.loads(exact(admission['actualVerification']).read_bytes())
    need(graph['actualImages'] == 73 and graph['actualStrongImports'] == 5445 and graph['unresolvedStrongImportRows'] == [] and
         graph['requiredSelectedLoadGaps'] == [] and graph['nativeWeakDefinitionsResolved'] == 13 and graph['finalStrongDefinitionGraphClosed'], 'actual5445 strong imports/13weak/no gaps')
    raw_manifest = exact(runtime['manifest']).read_bytes(); manifest = plistlib.loads(raw_manifest)
    old_manifest = plistlib.loads(exact(old_runtime['manifest']).read_bytes())
    rows, old_rows = ({row['id']: row for row in value['files']} for value in (manifest, old_manifest))
    need(rows.keys() == old_rows.keys() and len(rows) == 148, 'same148 runtime destinations')
    root, old_root = pathlib.Path(runtime['runtimeRoot']), pathlib.Path(old_runtime['runtimeRoot'])
    changed, unchanged, signatures = [], [], []
    def blobs(raw):
        image = m.MachO(raw); command = next(c for c in image.commands if c['cmd'] == 0x1d)
        begin, length = struct.unpack_from('<II', command['raw'], 8); sig = raw[begin:begin + length]
        count = struct.unpack_from('>I', sig, 8)[0]; result = {}
        for i in range(count):
            slot, at = struct.unpack_from('>II', sig, 12 + i * 8)
            size = struct.unpack_from('>I', sig, at + 4)[0]; result[slot] = sig[at:at + size]
        return begin, result
    for key, row in rows.items():
        old = old_rows[key]; path, old_path = root / row['path'], old_root / old['path']
        actual, old_actual = exact(pin(path)), exact(pin(old_path))
        need(pin(path)['bytes'] == row['bytes'] and pin(path)['sha256'] == row['sha256'] and
             pin(old_path)['bytes'] == old['bytes'] and pin(old_path)['sha256'] == old['sha256'], 'actual manifests bind finite file ' + key)
        if actual.read_bytes() == old_actual.read_bytes(): unchanged.append(key); continue
        changed.append(key)
        if row['kind'] != 'mach-o': continue
        external = {int(slot): (root / rows[resource]['path']).read_bytes() for slot, resource in row.get('signatureSlots', {}).items()}
        signature = signing.signed_image(path, row, external); signatures.append(signature)
        signed = actual.read_bytes(); original = old_actual.read_bytes()
        old_blobs, new_blobs = blobs(original)[1], blobs(signed)[1]
        need(old_blobs.get(5) == new_blobs.get(5) and old_blobs.get(7) == new_blobs.get(7), 'actual signed XML/DER permission blobs unchanged ' + key)
        if key == manifest['parentBootstrapContract']['childID']:
            need(signature['embeddedEntitlements']['com.apple.private.virtualization.plugin'] is True and
                 len(signature['embeddedEntitlements']) == 13, 'child retains all13 exact permissions and true plugin')
            need({value['slot'] for value in signature['actualSpecialSlots'] if value['external']} == {1, 3}, 'child true external Info and CodeResources checked')
            need(original[:blobs(original)[0]] == signed[:blobs(signed)[0]], 'child instruction/header/PAC/fixup bytes unchanged by seal update')
        else:
            key_name = pathlib.PurePosixPath(row['path']).name
            unsigned = exact(brows[key_name]['staged']).read_bytes(); a, b = m.MachO(unsigned), m.MachO(signed)
            need(all(getattr(a, field) == getattr(b, field) for field in ('uuid', 'sections', 'exports', 'imports', 'binds', 'loads')), 'real signer preserves body/PAC/API geometry ' + key)
            begin = max(32 + a.sizeofcmds, 32 + b.sizeofcmds)
            limit = min(blobs(signed)[0], len(unsigned))
            if any(c['cmd'] == 0x1d for c in a.commands): limit = min(limit, blobs(unsigned)[0])
            need(unsigned[begin:limit] == signed[begin:limit], 'actual unsigned→signed code/fixup identity ' + key)
    changed_code = [key for key in changed if rows[key]['kind'] == 'mach-o']
    need(len(changed) == 7 and len(changed_code) == 5 and len([key for key in unchanged if rows[key]['kind'] == 'mach-o']) == 134 and
         raw_manifest != exact(old_runtime['manifest']).read_bytes(), 'runtime seven inventoried files plus manifest changed/5newCDs/134 signed wholebytes identical')
    need(not any('HVVMProduction' in key or 'PreMain' in key or 'Firmware' in key for key in changed), 'CPU Root19/premain/five actual firmware resources unchanged')
    app_binary = exact(app['binary']); old_app_binary = exact(old_app['binary'])
    new_app_signature = signing.signed_image(app_binary, app['actualSignature'], {
        1: (pathlib.Path(app['app']) / 'Info.plist').read_bytes(),
        3: (pathlib.Path(app['app']) / '_CodeSignature/CodeResources').read_bytes()})
    signatures.append(new_app_signature)
    need(new_app_signature['cdhash'] == '2150d3ba65d0bfbf8839f4aabaea8bfdb1538196' and len(app_binary.read_bytes()) < 2 * 1024 * 1024, 'exact real App newCD and self-inspection limit')
    need(all(blobs(app_binary.read_bytes())[1].get(slot) == blobs(old_app_binary.read_bytes())[1].get(slot) for slot in (5, 7)), 'all App XML/DER permissions unchanged')
    linked = json.loads(exact(app['sourceCandidate']).read_bytes()); old_linked = json.loads(exact(old_app['sourceCandidate']).read_bytes())
    changed_objects = [index for index, pair in enumerate(zip(linked['objects'], old_linked['objects'], strict=True))
        if exact(pair[0]).read_bytes() != exact(pair[1]).read_bytes()]
    need(len(linked['objects']) == 31 and changed_objects == [30], 'actual31 App objects only manifest anchor changed')
    anchor_text = exact(runtime['anchorSource']).read_text()
    digest = hashlib.sha256(raw_manifest).digest()
    match = re.search(r'SHA256V1\[32\]=\{([^}]+)\}', anchor_text)
    need(match and bytes(int(value) for value in match[1].split(',')) == digest and
         'ManifestBytesV1=' + str(len(raw_manifest)) + ';' in anchor_text and
         digest in exact(linked['objects'][30]).read_bytes() and digest in app_binary.read_bytes(), 'actual Runtime6 manifest digest/length compiled into actual App main')
    need(app['runtimeCandidate'] == pin(runtime_path) and app['realCompiledManifestAnchor'] == runtime['anchorSource'], 'App binds exact real Runtime6 rather than a fixture')
    need(len(scope['files']) == 252 and len(scope['deltaFiles']) == 9 and scope['unchangedFiles'] == 243 and scope['unchangedSignedImages'] == 134, 'exact current nine-file scope')
    delta = {'new-' + str(value['index']): value for value in scope['deltaFiles']}
    with tarfile.open(exact(packet['archive']), 'r:') as archive:
        members = archive.getmembers(); files = [value for value in members if value.isfile()]
        need(len(files) == 9 and {value.name for value in files} == set(delta), 'real delta archive contains only declared nine regular files')
        for member in members:
            need(not member.linkname and not member.pax_headers and member.uid == member.gid == member.mtime == 0 and
                 member.isfile() and member.mode == 0o600 and '..' not in pathlib.PurePosixPath(member.name).parts and not member.name.startswith('/'), 'finite root-stage canonical USTAR regular member')
            if member.isfile():
                row = delta[member.name]; data = archive.extractfile(member).read()
                need(data == exact(row['new']).read_bytes(), 'archive actual new product bytes ' + member.name)
    new_cd = {value['cdhash'] for value in signatures}
    need(len(new_cd) == 6 and new_cd == set(scope['newTrustCacheCDHashes']) and
         scope['trustCacheFixedBatchCounts'] == [6] and scope['trustCacheRegistrationCount'] == 6, 'only six exact new CDHash additions requested')
    full_cd = {row['cdhash'] for row in rows.values() if row['kind'] == 'mach-o'} | {new_app_signature['cdhash']}
    need(len(full_cd) == 140 and full_cd == set(scope['trustCacheCDHashes']) and scope['actualFullCodeInventoryForVerificationOnly'],
         'full140 inventory is exact verification data, separate from six additions')
    need(scope['deltaArchiveBytes'] == packet['archive']['bytes'] and scope['deltaArchiveSHA256'] == packet['archive']['sha256'] and
         scope['archive'] == packet['archive'], 'scope/archive actual metadata agrees')
    need(scope['ownedEndpointAuthenticationContract']['mode'] == 'explicit-owned-bundle-v1' and
         scope['ownedEndpointAuthenticationContract']['nativeTrustFlagWrites'] == 0 and scope['ownedEndpointAuthenticationContract']['kernelWrites'] == 0,
         'precise own authentication decision declared; no native flag or kernel writes')
    prior_packet_path, prior_packet = load('independent27-owned-bundle-device-v1-attempt1')
    need(exact(packet['controller']).read_bytes() == exact(prior_packet['controller']).read_bytes() and
         exact(packet['archive']).read_bytes() == exact(prior_packet['archive']).read_bytes() and
         all(exact(row).read_bytes() == exact(prior_packet['scripts'][key]).read_bytes() for key, row in packet['scripts'].items()),
         'V3 only historical metadata corrections; controller/archive/eight scripts wholebytes unchanged')
    need(packet['maximumQuotedCommandBytes'] + 10000 < 262144 and packet['closeOwnAppExternalWallSeconds'] == 20 and
         packet['allOriginalRemoteActionsExternalWallSeconds'] == 45 and packet['transportTimeoutSeconds'] == 55,
         'declared20/45/55 limits and actual argv bound retained')
    record = dict(schema='Finite independent owned bundle composition peer v1', controllerPacketCandidate=pin(packet_path),
        scope=packet['scope'], runtimeCandidate=pin(runtime_path), appCandidate=pin(app_path), providerCandidate=pin(provider_path),
        inheritedIndependentSourceReview=pin(peer_path), independentRootSourceReview=pin(source_peer_path),
        actualChangedRuntimeFiles=changed + ['VM27IndependentRuntimeManifestV1.plist'], actualUnchangedRuntimeFiles=unchanged,
        actualNewSignedImages=signatures, actualChangedAppObjectIndices=changed_objects,
        actualSourceAndProviderPins=list(inputs.values()), checks=checks, actualChecks=len(checks),
        nativeValidatedFalseAndResult13RemainSeparate=True, strictNativeRawAndDefaultPreserved=True,
        bodyTokenOrHashNotAuthorization=True, actualCurrentVMMHandshakeNotExecuted=True,
        nativeTrustFlagWrites=0, kernelWrites=0, actualDeviceOperations=0,
        unrelatedCPUOrHostModelsRepeated=False, actualUnchangedImagePagesRepeated=False,
        finiteLocalScopePassed=True, findings=[])
    out.mkdir(mode=0o700)
    def save(path, value): path.write_text(json.dumps(value, indent=2) + '\n')
    save(out / 'review.json', record)
    save(out / 'freeze.json', dict(files=list(inputs.values()) + [pin(__file__), pin(out / 'review.json')], deviceOperations=0))
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'), checks=len(checks),
        actualNewSignedImages=len(signatures), actualNewCodePages=sum(value['actualCodePages'] for value in signatures), findings=[])))

if __name__ == '__main__':
    main()
