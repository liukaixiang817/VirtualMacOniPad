#!/usr/bin/env python3
"""Finite HOST-only peer of Startup5, the exact child plugin and four new CDs."""
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import struct
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    out = N/'independent27-child-plugin-composition-peer-v1-attempt1'
    assert not out.exists()
    pins, checks = {}, []
    def exact(row):
        core = {k: row[k] for k in ('path', 'bytes', 'sha256')}
        assert pin(row['path']) == core, row['path']
        pins[row['path']] = core
        return pathlib.Path(row['path'])
    def load(name):
        path = N/name/'candidate.json'
        exact(pin(path)); exact(pin(path.parent/'freeze.json'))
        return path, json.loads(path.read_bytes())
    def check(value, label):
        assert value, label
        checks.append(label)
    packet_path, packet = load('independent27-child-plugin-device-v1-attempt1')
    check(pin(packet_path)['sha256'] == '9a4f6557599b19635c7840c63a502875621a5001ff2f889c497ea76c42674280', 'concrete current packet')
    runtime_path, runtime = load('independent27-signed-runtime-product-v5-attempt1')
    old_runtime_path, old_runtime = load('independent27-signed-runtime-product-v4-attempt1')
    app_path, app = load('independent27-signed-app-child-plugin-product-v5-attempt1')
    old_app_path, old_app = load('independent27-signed-app-unbuffered-log-product-v4-attempt1')
    stage_path, stage = load('independent27-postspawn-diagnostic-stage-v9-attempt2')
    provider_path, provider = load('owned-app-postspawn-diagnostic-provider-v5-attempt4')
    scope = json.loads(exact(packet['scope']).read_bytes())
    check(packet['runtimeCandidate'] == pin(runtime_path) and packet['appCandidate'] == pin(app_path), 'concrete actual Runtime5 and App5 joins')
    peer = exact(pin(N/'owned-startup-v5-source-independent-short-review-v1/review.json'))
    source_peer = json.loads(peer.read_bytes())
    check(source_peer['findings'] == [] and source_peer['finiteLocalScopePassed'], 'existing independent typed once-only Startup5 source review')
    source = exact(pin(R/'VirtualMac/vz/host/vm27_owned_app_child_startup_v5.c')).read_text()
    check(source.count('#include "vm27_owned_app_child_startup_v4.c"') == 1 and source.count('nativeDetailsAvailable=0') == 1, 'frozen V4 lifecycle retained; external hello detail not invented')
    builder = exact(runtime['builder']).read_text()
    previous_builder = exact(pin(B/'build-independent27-signed-runtime-product-v3.py')).read_text()
    added = '''    # The unchanged received-message LWCR requires this exact Boolean on
    # the owned child before its first configuration request. Preserve the
    # parent App contract and every other copied child entitlement.
    need('com.apple.private.virtualization.plugin' not in child_ent,
         'the prior genuine child contract lacks the required plugin key')
    child_ent['com.apple.private.virtualization.plugin'] = True
'''
    expected = previous_builder.replace("    for k in ('platform-application'", added+"    for k in ('platform-application'", 1)
    expected = expected.replace("              'com.apple.security.virtualization','com.apple.private.virtualization'):", "              'com.apple.security.virtualization','com.apple.private.virtualization',\n              'com.apple.private.virtualization.plugin'):", 1)
    expected = expected.replace('Actual signed independent27 Runtime4 main identity product v3', 'Actual signed independent27 Runtime5 child plugin product v4', 1)
    check(expected == builder, 'signer source delta only exact child Boolean, required-key validation and schema')
    check(exact(pin(R/'VirtualMac/vz/host/modern_xpc_lwcr_policy.h')).read_text().count('"com.apple.private.virtualization.plugin"') == 1, 'key exactly names unchanged real LWCR requirement')
    exact(pin(R/'VirtualMac/vz/host/modern_xpc_lwcr_policy.c'))
    m = module('plugin_macho', exact(pin(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')))
    signing = module('plugin_signature', exact(pin(B/'review-independent27-signed-runtime-product-v2.py')))
    base = json.loads(exact(stage['baseStage']).read_bytes())
    before_stage = {row['key']: row for row in base['stagedImages']}
    stage_rows = {row['key']: row for row in stage['stagedImages']}
    changed_stage = []
    for key, row in stage_rows.items():
        new = exact(row['staged']).read_bytes()
        old = exact(before_stage[key]['staged']).read_bytes()
        if new != old:
            changed_stage.append(key)
    check(changed_stage == ['VM27OwnedAppStartupV3.dylib'] and len(stage_rows) == 73, 'only true Startup5 leaf replaces Stage8; other72 whole bytes exact')
    raw = pathlib.Path(provider['adapter']['path']).read_bytes() if 'adapter' in provider else None
    if raw is None:
        raw = (provider_path.parent/'VM27OwnedAppStartupV3.unsigned.dylib').read_bytes()
    exact(pin(provider_path.parent/'VM27OwnedAppStartupV3.unsigned.dylib'))
    staged = exact(stage_rows[changed_stage[0]]['staged']).read_bytes()
    a, b = m.MachO(raw), m.MachO(staged)
    check(all(getattr(a,k) == getattr(b,k) for k in ('uuid','sections','exports','imports','binds')), 'header retarget preserves real Startup5 ABI/PAC/sections/fixups')
    boundary = max(32+a.sizeofcmds,32+b.sizeofcmds)
    check(b.sizeofcmds >= a.sizeofcmds and not any(raw[32+a.sizeofcmds:boundary]) and raw[boundary:] == staged[boundary:], 'stage header expansion only consumes zero padding; every body and fixup byte equal')
    for ac, bc in zip(a.commands, b.commands, strict=True):
        check(ac['cmd'] == bc['cmd'], 'same command order and kind')
        if ac['cmd'] in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            check(ac['raw'][8:24] == bc['raw'][8:24], 'retarget retains dylib versions, timestamp and name offset')
        else:
            check(ac['raw'] == bc['raw'], 'non-load command unchanged')
    admission = json.loads(exact(runtime['admission']).read_bytes())
    check(admission['actualStage'] == pin(stage_path), 'signed product inherits actual Stage9')
    graph = json.loads(exact(admission['actualVerification']).read_bytes())
    check(graph['actualImages'] == 73 and graph['actualStrongImports'] == 5440 and graph['nativeWeakDefinitionsResolved'] == 13 and graph['unresolvedStrongImportRows'] == [] and graph['requiredSelectedLoadGaps'] == [] and graph['finalStrongDefinitionGraphClosed'], 'actual5440 strong imports, thirteen weak routes and no definition/load gaps')
    manifest_raw = exact(runtime['manifest']).read_bytes()
    manifest = plistlib.loads(manifest_raw)
    previous = plistlib.loads(exact(old_runtime['manifest']).read_bytes())
    rows, old_rows = ({row['id']: row for row in x['files']} for x in (manifest, previous))
    check(rows.keys() == old_rows.keys() and len(rows) == 148, 'same actual148 runtime destinations')
    root, old_root = pathlib.Path(runtime['runtimeRoot']), pathlib.Path(old_runtime['runtimeRoot'])
    signatures, changed_ids, unchanged_ids = [], [], []
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
    def preserved(unsigned, signed, label):
        a, b = m.MachO(unsigned), m.MachO(signed)
        check(all(getattr(a,k) == getattr(b,k) for k in ('uuid','sections','exports','imports','binds','loads')), 'real signing geometry/PAC/imports/exports preserved '+label)
        boundary = max(32+a.sizeofcmds, 32+b.sizeofcmds)
        limit = min(blobs(signed)[0],len(unsigned))
        if any(c['cmd'] == 0x1d for c in a.commands): limit = min(limit,blobs(unsigned)[0])
        check(unsigned[boundary:limit] == signed[boundary:limit], 'all original bodies and fixup bytes preserved '+label)
    def der_value(data):
        def one(at, end):
            assert at+2 <= end
            tag, first = data[at:at+2]; at += 2
            if first & 128:
                count = first & 127
                assert 0 < count <= 4 and at+count <= end
                length = int.from_bytes(data[at:at+count], 'big'); at += count
            else: length = first
            stop = at+length; assert stop <= end
            if tag & 32:
                values=[]
                while at < stop:
                    value, at = one(at,stop); values.append(value)
                return (tag,values),stop
            return (tag,data[at:stop]),stop
        tree,end=one(8,len(data)); assert end == len(data) and tree[0] == 0x70
        version, mapping=tree[1]; assert version == (2,b'\x01') and mapping[0] == 0xb0
        result={}
        for tag,entry in mapping[1]:
            assert tag == 0x30 and len(entry) == 2 and entry[0][0] == 0x0c
            key=entry[0][1].decode('utf8'); assert key not in result
            value=entry[1]
            if value[0] == 1:
                assert value[1] in (b'\xff',b'\0'); value=value[1] == b'\xff'
            else:
                assert value[0] == 0x30 and all(x[0] == 0x0c for x in value[1])
                value=[x[1].decode('utf8') for x in value[1]]
            result[key]=value
        return result
    for file_id,row in rows.items():
        data=(root/row['path']).read_bytes(); old=(old_root/old_rows[file_id]['path']).read_bytes()
        check(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'], 'actual manifest file '+file_id)
        if row['kind'] != 'mach-o':
            if file_id not in ('dependency-proof','child-coderesources'): check(data == old, 'unchanged runtime resource '+file_id)
            continue
        if data == old:
            unchanged_ids.append(file_id); check(row['cdhash'] == old_rows[file_id]['cdhash'], 'whole unchanged signed image '+file_id); continue
        changed_ids.append(file_id)
        ext={int(k):(root/rows[v]['path']).read_bytes() for k,v in row.get('signatureSlots',{}).items()}
        sig=signing.signed_image(root/row['path'],row,ext); signatures.append(sig)
        old_blob,new_blob=blobs(old)[1],blobs(data)[1]
        check(new_blob[2] == old_blob[2], 'native designated requirements unchanged '+file_id)
        check((der_value(new_blob[7]) if 7 in new_blob else None) == sig['embeddedEntitlements'], 'actual DER and XML entitlement values identical '+file_id)
        if file_id == 'child:com.apple.Virtualization.VirtualMachine':
            old_ent=plistlib.loads(old_blob[5][8:]); new_ent=sig['embeddedEntitlements']
            check(len(old_ent) == 12 and len(new_ent) == 13 and 'com.apple.private.virtualization.plugin' not in old_ent and new_ent == dict(old_ent, **{'com.apple.private.virtualization.plugin':True}), 'child actual sole entitlement delta plugin=true; original12 key values preserved')
            preserved(old,data,file_id)
        else:
            check(all(old_blob.get(k) == new_blob.get(k) for k in (5,7)), 'Startup XML/DER privilege bytes unchanged '+file_id)
            preserved(staged,data,file_id)
    check(set(changed_ids) == {'parent:VM27OwnedAppStartupV3.dylib','child:VM27OwnedAppStartupV3.dylib','child:com.apple.Virtualization.VirtualMachine'} and len(unchanged_ids) == 136, 'exact three changed signed runtime images; all136 remaining whole bytes identical')
    check(manifest['loadOrder'] == previous['loadOrder'] and not any('PreMain' in x for x in manifest['loadOrder']), 'parent loadOrder unchanged and premain remains child-only')
    for entry in manifest['entries']:
        image=m.MachO((root/rows[entry['fileID']]['path']).read_bytes())
        check(image.exports['_'+entry['symbol']]['address'] == entry['rva'], 'real manifest function RVA '+entry['symbol'])
    linked=json.loads(exact(app['sourceCandidate']).read_bytes()); old_linked=json.loads(exact(old_app['sourceCandidate']).read_bytes())
    changed_objects=[]
    for i,(new,old) in enumerate(zip(linked['objects'],old_linked['objects'],strict=True)):
        if exact(new).read_bytes() != exact(old).read_bytes(): changed_objects.append(i)
    check(len(linked['objects']) == 31 and changed_objects == [30], 'only App object30 compiled manifest anchor changes; original30 objects incl App9/Runtime4/finder unchanged')
    check(exact(linked['objects'][-1]).read_bytes() == exact(runtime['anchorIOSObject']).read_bytes(), 'real fresh strong-linked anchor object')
    app_main=exact(app['binary']); app_data=app_main.read_bytes(); image=m.MachO(app_data)
    for symbol,value in [('VM27IndependentRuntimeManifestSHA256V1',hashlib.sha256(manifest_raw).digest()),('VM27IndependentRuntimeManifestBytesV1',struct.pack('<Q',len(manifest_raw)))]:
        at=image.file(image.base+image.exports['_'+symbol]['address']); check(app_data[at:at+len(value)] == value,'actual App manifest anchor '+symbol)
    sig=signing.signed_image(app_main,app['actualSignature'],{1:(pathlib.Path(app['app'])/'Info.plist').read_bytes(),3:(pathlib.Path(app['app'])/'_CodeSignature/CodeResources').read_bytes()});signatures.append(sig)
    old_app_blob,new_app_blob=blobs(exact(old_app['binary']).read_bytes())[1],blobs(app_data)[1]
    check(all(old_app_blob[k] == new_app_blob[k] for k in (2,5,7)) and der_value(new_app_blob[7]) == sig['embeddedEntitlements'], 'App native requirements/XML/DER/privileges unchanged')
    preserved(exact(linked['binary']).read_bytes(),app_data,'App')
    check(len(signatures) == 4 and sorted(x['cdhash'] for x in signatures) == scope['newTrustCacheCDHashes'], 'only four actual rehashed CodeDirectories exactly match proposed TC4')
    old_scope=json.loads(exact(scope['oldScope']).read_bytes()); changed_files=[]
    for new,old in zip(scope['files'],old_scope['files'],strict=True):
        check((new['archivePath'],new['devicePath']) == (old['archivePath'],old['devicePath']), 'same exact owned product destination '+new['archivePath'])
        if exact(new['local']).read_bytes() != exact(old['local']).read_bytes(): changed_files.append(new['devicePath'])
    check(len(scope['files']) == 252 and len(changed_files) == 7 and set(changed_files) == {row['devicePath'] for row in scope['deltaFiles']}, 'actual7-file update and other245 whole bytes equal')
    old_cds,new_cds=set(old_scope['trustCacheCDHashes']),set(scope['trustCacheCDHashes'])
    check(len(old_cds) == len(new_cds) == 140 and len(old_cds & new_cds) == 136 and sorted(new_cds-old_cds) == scope['newTrustCacheCDHashes'], 'four real new CD identities;136 retained; no re-registration of old152 entries')
    report=dict(schema='Finite Startup5 true plugin Runtime5/App5 product composition independent peer v1',controllerPacketCandidate=pin(packet_path),finiteProductCompositionScopePassed=True,findings=[],runtimeCandidate=pin(runtime_path),appCandidate=pin(app_path),actualStage=pin(stage_path),actualSourcePeer=pin(peer),actualNewSignatures=signatures,actualChangedRuntimeSignedIDs=changed_ids,actualUnchangedRuntimeSignedImages=len(unchanged_ids),checks=checks,deviceOperations=0,trustCacheOperations=0,actualGuestBoot=False,boundaries=['Product inspection proves the exact required plugin Boolean is signed; native validated-entitlement/audit/code/file gates remain unchanged and actual success still requires device execution.','The hello native gate resides in an unchanged external TU and is not repeated for diagnostics; only its true typed return is reported.','Previous actual post77 is preserved; the packet takes its predecessor evidence from a real read-only current-product receipt rather than claiming processes are off.','Controller finite cleanup/once/bounds review is separately joined before final ready; no139 page-signature or CPU model repetition.'])
    out.mkdir(mode=0o700)
    (out/'product-review.json').write_text(json.dumps(report,indent=2)+'\n')
    exact(pin(out/'product-review.json'));exact(pin(__file__))
    (out/'freeze.json').write_text(json.dumps(dict(files=list(pins.values()),deviceOperations=0,trustCacheOperations=0,findings=[]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'product-review.json'),freeze=pin(out/'freeze.json'),actualChecks=len(checks))))


if __name__ == '__main__':main()
