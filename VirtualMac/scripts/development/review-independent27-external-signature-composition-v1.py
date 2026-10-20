#!/usr/bin/env python3
"""Finite read-only peer: external-slot repair, six signatures, exact packet."""
import ast
import hashlib
import importlib.util
import io
import json
import pathlib
import plistlib
import re
import shlex
import struct
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load(name):
    path = N/name/'candidate.json'
    return path, json.loads(path.read_bytes())


def main():
    out = N/'independent27-external-signature-composition-peer-v1-attempt1'
    assert not out.exists()
    pins, checks = {}, []

    def exact(row):
        core = {key: row[key] for key in ('path', 'bytes', 'sha256')}
        assert pin(row['path']) == core, row['path']
        pins[row['path']] = core
        return pathlib.Path(row['path'])

    def check(value, label):
        assert value, label
        checks.append(label)

    packet_path, packet = load('independent27-external-signature-device-v1-attempt1')
    check(pin(packet_path)['sha256'] == '02789e228e8ce5b0a151f6f32cd0512002bd316402afd9e500c60ef39e4d8e1d', 'exact new packet candidate')
    scope = json.loads(exact(packet['scope']).read_bytes())
    runtime_path, runtime = load('independent27-signed-runtime-product-v4-attempt1')
    old_runtime_path, old_runtime = load('independent27-signed-runtime-product-v3-attempt1')
    app_path, app = load('independent27-signed-app-external-signature-product-v3-attempt1')
    stage_path, stage = load('independent27-external-signature-stage-v8-attempt1')
    old_stage = json.loads(exact(stage['baseStage']).read_bytes())
    provider_path = exact(stage['externalSignatureProviderCandidate'])
    provider = json.loads(provider_path.read_bytes())
    check(packet['runtimeCandidate'] == pin(runtime_path) and packet['appCandidate'] == pin(app_path), 'packet joins actual Runtime4 and signed App')
    for path in [packet_path, runtime_path, old_runtime_path, app_path, stage_path, provider_path]:
        exact(pin(path))
        exact(pin(path.parent/'freeze.json'))
    for key in ('builder', 'sourceCandidate', 'sourceFreeze', 'consumer', 'adapter'):
        exact(provider[key])
    for row in provider['actualNewObjects']+provider['actualIncludeClosure']+provider['actualReusedLibraries']:
        exact(row)
    source = json.loads(exact(provider['sourceCandidate']).read_bytes())
    for row in json.loads(exact(provider['sourceFreeze']).read_bytes())['files']:
        exact(row)
    check(provider['nativeAuditAndKernelCodeGatesUnchanged'] and provider['singleNativeStrictIdentity'], 'actual frozen original identity and native gates retained')
    m = module('finite_external_macho', exact(stage['reader']))
    signing = module('finite_signature_reader', B/'review-independent27-signed-runtime-product-v2.py')
    base = module('finite_original_controller', N/'independent27-device-bootstrap-controller-v3-attempt1/control.py')
    fast = module('finite_batch_verifier', B/'independent27_device_product_verify_fast_v1.py')
    replacements = {'VM27LargeConsumerV2.dylib': provider['consumer'], 'VM27OwnedAppStartupV3.dylib': provider['adapter']}
    old_rows = {row['key']: row for row in old_stage['stagedImages']}
    stage_rows = {row['key']: row for row in stage['stagedImages']}
    check(len(stage_rows) == len(old_rows) == 73 and stage_rows.keys() == old_rows.keys(), 'same actual73 stage members')
    for key, row in stage_rows.items():
        actual = exact(row['staged']).read_bytes()
        if key not in replacements:
            check(actual == exact(old_rows[key]['staged']).read_bytes(), 'unchanged inherited stage image '+key)
            continue
        original = m.MachO(exact(replacements[key]).read_bytes())
        commands = []
        for command in original.commands:
            raw = command['raw']
            if command['cmd'] in (12, 0x80000018, 0x8000001f, 0x80000023):
                offset = struct.unpack_from('<I', raw, 8)[0]
                name = raw[offset:].split(b'\0', 1)[0]
                if name.startswith(b'@rpath/'):
                    dependency = name[7:].decode()
                    check(dependency in stage_rows and not any(raw[offset+len(name)+1:]), 'real dependency and zero command padding '+dependency)
                    payload = b'@loader_path/'+name[7:]+b'\0'
                    length = (offset+len(payload)+7)&~7
                    changed = bytearray(raw[:offset]+payload+bytes(length-offset-len(payload)))
                    struct.pack_into('<I', changed, 4, length)
                    raw = bytes(changed)
            commands.append(raw)
        body = b''.join(commands)
        end = max(32+original.sizeofcmds, 32+len(body))
        check(not any(original.data[32+original.sizeofcmds:end]), 'only existing zero header padding consumed '+key)
        reconstructed = bytearray(original.data)
        reconstructed[32:end] = body+bytes(end-32-len(body))
        struct.pack_into('<II', reconstructed, 16, len(commands), len(body))
        check(bytes(reconstructed) == actual, 'independent exact header-only reconstruction '+key)
        changed = m.MachO(actual)
        check(all(getattr(changed, k) == getattr(original, k) for k in ('uuid', 'sections', 'segments', 'exports', 'imports', 'binds')), 'code geometry exports and PAC/fixups identical '+key)
        expected_exports = provider['exactConsumerV2Exports' if key.startswith('VM27Large') else 'exactAdapterV3Exports']
        check(sorted(changed.exports) == expected_exports, 'exact prior public ABI '+key)
    graph_path = N/'independent27-external-signature-definition-graph-v4-attempt1/verification.json'
    graph = json.loads(graph_path.read_bytes())
    exact(pin(graph_path))
    check(graph['actualImages'] == 73 and graph['actualStrongImports'] == 5437 and graph['nativeWeakDefinitionsResolved'] == 13 and
          graph['unresolvedStrongImportRows'] == [] and graph['requiredSelectedLoadGaps'] == [] and graph['finalStrongDefinitionGraphClosed'], 'actual5437 strong graph and thirteen weak routes have no gaps')
    root, old_root = pathlib.Path(runtime['runtimeRoot']), pathlib.Path(old_runtime['runtimeRoot'])
    manifest_raw = exact(runtime['manifest']).read_bytes()
    manifest = plistlib.loads(manifest_raw)
    previous = plistlib.loads(exact(old_runtime['manifest']).read_bytes())
    rows, old_files = ({row['id']: row for row in x['files']} for x in (manifest, previous))
    check(rows.keys() == old_files.keys() and len(rows) == 148, 'same148 runtime files including five genuine firmware resources')
    signatures, changed_ids, unchanged = [], [], []

    def blobs(data):
        image = m.MachO(data)
        command = next(c for c in image.commands if c['cmd'] == 0x1d)
        start, size = struct.unpack_from('<II', command['raw'], 8)
        raw = data[start:start+size]
        count = struct.unpack_from('>I', raw, 8)[0]
        result = {}
        for i in range(count):
            slot, offset = struct.unpack_from('>II', raw, 12+8*i)
            length = struct.unpack_from('>I', raw, offset+4)[0]
            result[slot] = raw[offset:offset+length]
        return start, result

    def code_preserved(unsigned, signed, label):
        a, b = m.MachO(unsigned), m.MachO(signed)
        check(all(getattr(a, k) == getattr(b, k) for k in ('uuid', 'sections', 'exports', 'imports', 'binds')), 'signing preserves actual code/PAC geometry '+label)
        ac = [c for c in a.commands if c['cmd'] != 0x1d]
        bc = [c for c in b.commands if c['cmd'] != 0x1d]
        check(len(ac) == len(bc), 'no added non-signature commands '+label)
        for x, y in zip(ac, bc):
            if x['cmd'] == 0x19 and x['raw'][8:24].rstrip(b'\0') == b'__LINKEDIT':
                ax, by = bytearray(x['raw']), bytearray(y['raw'])
                ax[32:40] = by[32:40] = bytes(8)
                ax[48:56] = by[48:56] = bytes(8)
                check(ax == by, 'only LINKEDIT signature sizes change '+label)
            else:
                check(x['raw'] == y['raw'], 'unchanged non-signature command '+label)
        boundary = max(32+a.sizeofcmds, 32+b.sizeofcmds)
        limit = min(blobs(signed)[0], len(unsigned))
        if any(c['cmd'] == 0x1d for c in a.commands):
            limit = min(limit, blobs(unsigned)[0])
        check(unsigned[boundary:limit] == signed[boundary:limit], 'every original body and fixup byte preserved '+label)

    for file_id, row in rows.items():
        new_data, old_data = (root/row['path']).read_bytes(), (old_root/old_files[file_id]['path']).read_bytes()
        check(len(new_data) == row['bytes'] and hashlib.sha256(new_data).hexdigest() == row['sha256'], 'actual manifest file '+file_id)
        if row['kind'] != 'mach-o':
            if file_id not in ('dependency-proof', 'child-coderesources'):
                check(new_data == old_data, 'unchanged genuine resource '+file_id)
            continue
        if new_data == old_data:
            unchanged.append(file_id)
            check(row['cdhash'] == old_files[file_id]['cdhash'], 'unchanged code hash '+file_id)
            continue
        changed_ids.append(file_id)
        external = {int(k): (root/rows[v]['path']).read_bytes() for k, v in row.get('signatureSlots', {}).items()}
        signatures.append(signing.signed_image(root/row['path'], row, external))
        old_blobs, new_blobs = blobs(old_data)[1], blobs(new_data)[1]
        check(all(new_blobs.get(k) == old_blobs.get(k) for k in (2, 5, 7)), 'embedded requirements/XML/DER privileges unchanged '+file_id)
        key = file_id.split(':', 1)[1]
        code_preserved((pathlib.Path(stage_rows[key]['staged']['path']).read_bytes() if key in replacements else old_data), new_data, file_id)
    expected_ids = {role+':'+key for role in ('parent', 'child') for key in replacements}|{'child:com.apple.Virtualization.VirtualMachine'}
    check(set(changed_ids) == expected_ids and len(unchanged) == 134, 'only five runtime signed images changed; other134 whole bytes identical')
    check(manifest['loadOrder'] == previous['loadOrder'] and not any('PreMain' in x for x in manifest['loadOrder']), 'premain remains child-only and parent load order unchanged')
    for entry in manifest['entries']:
        image = m.MachO((root/rows[entry['fileID']]['path']).read_bytes())
        check(image.exports['_'+entry['symbol']]['address'] == entry['rva'], 'real manifest entry '+entry['symbol'])
    check(manifest['entries'][0]['rva'] == 70404, 'Root19 config entry unchanged')
    anchor = exact(runtime['anchorSource']).read_text()
    match = re.search(r'SHA256V1\[32\]=\{([^}]+)\}', anchor)
    check(bytes(int(x) for x in match[1].split(',')) == hashlib.sha256(manifest_raw).digest() and 'ManifestBytesV1=42432;' in anchor, 'actual fresh manifest source anchor')
    linked = json.loads(exact(app['sourceCandidate']).read_bytes())
    old_linked = json.loads((N/'independent27-actual-app-main-identity-linked-v9-attempt1/candidate.json').read_bytes())
    check(len(linked['objects']) == len(old_linked['objects']) == 31, 'same31 App compiled objects')
    check(all(exact(a).read_bytes() == pathlib.Path(b['path']).read_bytes() for a,b in zip(linked['objects'][:-1], old_linked['objects'][:-1])), 'thirty App objects including Runtime4/finder unchanged; only product anchor differs')
    check(exact(linked['objects'][-1]).read_bytes() == exact(runtime['anchorIOSObject']).read_bytes(), 'actual strong compiled fresh manifest anchor object')
    app_main = exact(app['binary'])
    app_image = m.MachO(app_main.read_bytes())
    for symbol, value in [('VM27IndependentRuntimeManifestSHA256V1', hashlib.sha256(manifest_raw).digest()),
                          ('VM27IndependentRuntimeManifestBytesV1', struct.pack('<Q', len(manifest_raw)))]:
        offset = app_image.file(app_image.base+app_image.exports['_'+symbol]['address'])
        check(app_image.data[offset:offset+len(value)] == value, 'actual signed App anchor '+symbol)
    signatures.append(signing.signed_image(app_main, app['actualSignature'], {1: (pathlib.Path(app['app'])/'Info.plist').read_bytes(), 3: (pathlib.Path(app['app'])/'_CodeSignature/CodeResources').read_bytes()}))
    old_app = json.loads((N/'independent27-signed-app-main-identity-product-v2-attempt1/candidate.json').read_bytes())
    check(all(blobs(app_main.read_bytes())[1].get(k) == blobs(pathlib.Path(old_app['binary']['path']).read_bytes())[1].get(k) for k in (2,5,7)), 'App XML/DER privileges and embedded requirements unchanged')
    code_preserved(exact(linked['binary']).read_bytes(), app_main.read_bytes(), 'actual App signing')
    check(len(signatures) == 6 and sorted(x['cdhash'] for x in signatures) == scope['newTrustCacheCDHashes'], 'six rehashed CodeDirectories exactly equal authorized-to-be-reviewed set')
    old_scope = json.loads(exact(scope['oldScope']).read_bytes())
    changes = []
    for new, old in zip(scope['files'], old_scope['files'], strict=True):
        check(new['archivePath'] == old['archivePath'] and new['devicePath'] == old['devicePath'], 'same exact owned destination '+new['archivePath'])
        exact(new['local']); exact(old['local'])
        if new['local']['sha256'] != old['local']['sha256']:
            changes.append(new['devicePath'])
    check(len(changes) == 9 and set(changes) == {r['devicePath'] for r in scope['deltaFiles']} and scope['unchangedFiles'] == 243, 'actual nine changed252 product paths and243 unchanged')
    raw = exact(packet['archive']).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        check(len(members) == 9, 'exact finite nine-member archive')
        for i, (item, row) in enumerate(zip(members, scope['deltaFiles'], strict=True)):
            check(item.name == 'new-'+str(i) and item.isreg() and not item.linkname and not item.pax_headers and item.uid == item.gid == item.mtime == 0 and item.mode == 0o600 and item.size == row['new']['bytes'] and hashlib.sha256(archive.extractfile(item).read()).hexdigest() == row['new']['sha256'], 'actual canonical ordinary delta archive '+str(i))
    controller = exact(packet['controller']).read_text()
    old_controller = exact(packet['priorController']).read_text()
    trees = [ast.parse(x) for x in (controller, old_controller)]
    for name in ('run_remote', 'prior_receipt'):
        nodes = [next(x for x in t.body if isinstance(x, ast.FunctionDef) and x.name == name) for t in trees]
        check(ast.dump(nodes[0], include_attributes=False) == ast.dump(nodes[1], include_attributes=False), 'exact frozen transport/receipt AST '+name)
    process = [next(x.value.value for x in t.body if isinstance(x, ast.Assign) and any(isinstance(y,ast.Name) and y.id=='PROCESS_FUNCTIONS' for y in x.targets)) for t in trees]
    check(process[0] == process[1] == base.PROCESS_FUNCTIONS, 'exact captured PID UID path PPID start-time TERM/KILL functions')
    for value in ('auth[\'scope\'] == pin(packet/\'scope.json\')', "auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']", "auth['trustCacheRegistrationCount'] == 6", "auth['initializationExternalWallSeconds'] == 45", 'os.O_EXCL', "need(not output.exists(), 'serial action never repeated')"):
        check(value in controller, 'actual ready and once gate '+value)
    scripts = {action: exact(row).read_text() for action,row in packet['scripts'].items()}
    for action,text in scripts.items():
        subprocess.run(['/bin/sh','-n'], input=text.encode(), check=True)
        check('timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c ' in text and len((('sudo -k -S -p "" ' if action!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(text)).encode())+10000 < 262144, 'actual bounded shell/ARG_MAX '+action)
    base.DEVICE_STAGE = scope['deviceStage']
    original = base.make_scripts(scope, base.HEALTH.read_text())
    inside = lambda text: text.replace("'", "'\"'\"'")
    check(scripts['launch'] == original['launch'].replace(inside(base.verify_products(scope)), inside(fast.batch_check(scope)), 1), 'launch unchanged except finite fast252 verification')
    for action in ('register', 'post'):
        inner = shlex.split(scripts[action])[-1]
        check(inner == original[action].replace(base.verify_products(scope, include_cd=True), fast.batch_check(scope), 1), 'exact prior cleanup/health body '+action)
    stage_body = shlex.split(scripts['stage'])[-1]
    first_move = stage_body.index('mv -f ')
    check(all(stage_body.index('backup-'+str(i)) < first_move for i in range(9)) and stage_body.index('backup-app-log') < first_move, 'all nine old SHA backups and exact751 log backup precede first replacement')
    check('f3a4328f1791518149bd06c7f9086d1b06d0ce6f648f8665bdd35fd97395caf0' in stage_body and stage_body.count('mv -f ') == 9 and all('.VM27-external-signature-v1-'+str(i)+'.pending' in stage_body for i in range(9)), 'exact old log and same-parent9 atomic replacements')
    trust_body = shlex.split(scripts['trust'])[-1]
    actual_tc = re.findall(r'^jbctl trustcache add ([a-f0-9]{40})$', trust_body, re.M)
    check(actual_tc == scope['newTrustCacheCDHashes'] and trust_body.index('trust-dispatched') < trust_body.index('jbctl trustcache add'), 'only six once-marked actual trust additions after finalSHA/CD checks')
    post_path = exact(packet['priorActualPost'])
    post = json.loads(post_path.read_bytes())
    check(post['transportExit'] == 0 and b'INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in exact(post['stdout']).read_bytes(), 'actual prior clean health/post0 preserved')
    check(scope['guestBootRequested'] is False and scope['deviceReboot'] is False and scope['perPIDKernelPrivilegeModification'] is False, 'finite original authorized-to-be-reviewed initializer scope without reboot/kernel modifications')
    for row in (packet['preparer'], pin(__file__), pin(B/'review-independent27-signed-runtime-product-v2.py'), pin(B/'independent27_device_product_verify_fast_v1.py')):
        exact(row)
    out.mkdir(mode=0o700)
    review = dict(schema='Finite independent external child signature product and packet peer v1', controllerPacketCandidate=pin(packet_path),
        scope=packet['scope'], runtimeCandidate=pin(runtime_path), appCandidate=pin(app_path), providerCandidate=pin(provider_path), stageCandidate=pin(stage_path),
        graph=pin(graph_path), actualSignedImagesReparsed=signatures, actualOnlyChangedRuntimeCodeIDs=sorted(changed_ids),
        actualUnchangedSignedRuntimeWholeBytes=134, actualChangedOwnedFiles=9, actualNewCodeDirectoryHashes=scope['newTrustCacheCDHashes'],
        originalRoot19PreMainAndFirmwareWholeBytesUnchanged=True, genuineExternalInfoAndCodeResourcesSlotsChecked=True,
        frozenSourceAndActualCompiledObjectsJoined=True, processCleanupAndTransportUnchanged=True, allOldBackupsBeforeFirstReplacement=True,
        finiteLocalScopePassed=True, findings=[], actualDeviceOperations=0, nativeOperations=0, trustCacheOperations=0, modelsRepeated=False,
        actualNewIOSCodeExecuted=False, actualGuestBoot=False, actualGuestDisplay=False, actualNetworking=False,
        boundaries=['This is a host peer of the exact next six-entry/9-file initialization packet; it does not grant human authorization.',
          'External slots and registered-child-port host evidence do not prove the next original child completes startup.',
          'No repeated CPU models or old134 signature page parsing; whole bytes/CD values preserved.',
          'Actual initializer failure must retain receipts and run the exact post cleanup; no blind retries.'], checks=checks, verifiedPins=list(pins.values()))
    (out/'review.json').write_text(json.dumps(review,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps({'files': list(pins.values())+[pin(out/'review.json')]},indent=2)+'\n')
    print(json.dumps({'review':pin(out/'review.json'),'freeze':pin(out/'freeze.json'),'actualNewSignatures':6,'unchangedSignedImages':134,'findings':[]}))


if __name__ == '__main__':
    main()
