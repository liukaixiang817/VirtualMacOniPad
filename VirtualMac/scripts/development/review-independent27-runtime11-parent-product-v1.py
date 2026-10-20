#!/usr/bin/env python3
"""Read-only finite review of two actual Runtime11 parent signatures.

The Runtime11 builder author reviews Root's concrete signed output here. Source
semantics and primary/PAC composition are inherited from separately frozen peers.
No signing, dyld execution, device access or full baseline graph resolution occurs.
"""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import re
import stat
import struct
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def exact(row):
    require(pin(row['path']) == {k: row[k] for k in ('path', 'bytes', 'sha256')}, 'exact input pin ' + row['path'])
    return pathlib.Path(row['path'])


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def frozen(path):
    f = pathlib.Path(path).parent / 'freeze.json'
    rows = {r['path']: r for r in json.loads(f.read_bytes())['files']}
    require(rows[str(pathlib.Path(path).resolve())] == pin(path), 'candidate itself frozen')
    return rows, pin(f)


def semantic(row):
    return {k: v for k, v in row.items() if k != 'at'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.parent == N and not output.exists(), 'fresh diagnostic directory only')
    cpin = pin(args.candidate)
    require(cpin['sha256'] == 'ca82fb5fa1fb3120b45a4711268bb6ca002a3ebabf859ba3efea4e1f432f51ab', 'Root actual Runtime11 candidate')
    c = json.loads(args.candidate.read_bytes())
    newf, newfreeze = frozen(args.candidate)
    oldpath = exact(c['baselineRuntimeCandidate'])
    old = json.loads(oldpath.read_bytes())
    oldf, oldfreeze = frozen(oldpath)
    portpath = exact(c['parentPortCandidate'])
    port = json.loads(portpath.read_bytes())
    portf, portfreeze = frozen(portpath)
    for field in ('manifest', 'signatureVerification', 'anchorSource', 'anchorIOSObject', 'runtime10DeltaVerification', 'admission', 'builder'):
        exact(c[field])
        require(newf.get(c[field]['path']) == c[field], 'actual result field frozen ' + field)
    for field in ('manifest', 'signatureVerification'):
        exact(old[field])
        require(oldf.get(old[field]['path']) == old[field], 'actual baseline proof frozen')
    for field in ('patchedParentVZ', 'newProvider', 'recipe', 'graph'):
        exact(port[field])
        require(portf.get(port[field]['path']) == port[field], 'actual port input frozen')
    require(c['cacheAdapterContract'] == port['cacheAdapterContract'] and c['localizerContract'] == port['localizerContract'], 'production contracts preserved')
    manifest_raw = exact(c['manifest']).read_bytes()
    manifest = plistlib.loads(manifest_raw)
    prior = plistlib.loads(exact(old['manifest']).read_bytes())
    rows = {r['id']: r for r in manifest['files']}
    before = {r['id']: r for r in prior['files']}
    helper_id = 'parent:VM27OwnedVZStartCompat.dylib'
    changed = {'parent:VZ27.dylib', manifest['dependencyProofID']}
    require(len(rows) == len(manifest['files']) == 152 and len(before) == 151, '152 actual unique manifest rows')
    require(set(rows) - set(before) == {helper_id} and set(before) - set(rows) == set(), 'only one added named parent leaf')
    require({k: v for k, v in manifest.items() if k != 'files'} == {k: v for k, v in prior.items() if k != 'files'}, 'entry/load/bootstrap contracts whole unchanged')
    root, oldroot = pathlib.Path(c['runtimeRoot']), pathlib.Path(old['runtimeRoot'])
    unchanged = []
    for identity, row in rows.items():
        rel = pathlib.PurePosixPath(row['path'])
        require(not rel.is_absolute() and all(p not in ('', '.', '..') for p in rel.parts), 'bounded relative runtime path')
        path = root / row['path']
        require(stat.S_ISREG(path.lstat().st_mode), 'regular real runtime file')
        filepin = pin(path)
        require((filepin['bytes'], filepin['sha256']) == (row['bytes'], row['sha256']), 'actual manifest/file join ' + identity)
        require(newf.get(filepin['path']) == filepin, 'actual product file frozen')
        if identity in before and identity not in changed:
            require(row == before[identity] and path.read_bytes() == (oldroot / row['path']).read_bytes(), 'entire unchanged signed/resource file ' + identity)
            require(oldf.get(str((oldroot / row['path']).resolve())) == pin(oldroot / row['path']), 'old unchanged file frozen')
            unchanged.append(dict(id=identity, file=filepin, signed=row['kind'] == 'mach-o'))
    require(sum(r['signed'] for r in unchanged) == 140, '140 unchanged signed whole files')
    actual_paths = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual_paths == {r['path'] for r in rows.values()} | {pathlib.Path(c['manifest']['path']).name}, 'no omitted or extra product file')
    require(sum(r['kind'] == 'mach-o' for r in rows.values()) == 142, '142 distinct real signed Mach-O rows')
    require(len({r['cdhash'] for r in rows.values() if r['kind'] == 'mach-o'}) == 142, '142 unique actual CD set')
    sigreader = load_module('runtime11_independent_signatures', R / 'VirtualMac/scripts/development/review-independent27-signed-runtime-product-v1.py')
    macho_path = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    macho = load_module('runtime11_independent_macho', macho_path)
    new_signatures = []
    for identity, unsignedpin in [('parent:VZ27.dylib', port['patchedParentVZ']), (helper_id, port['newProvider'])]:
        row = rows[identity]
        signedpath = root / row['path']
        signeddata, unsigneddata = signedpath.read_bytes(), exact(unsignedpin).read_bytes()
        a, b = macho.MachO(signeddata), macho.MachO(unsigneddata)
        require(a.uuid == b.uuid == row['uuid'], 'signed image genuine UUID')
        require(a.sections == b.sections and a.imports == b.imports and a.binds == b.binds and a.exports == b.exports and a.loads == b.loads, 'signing preserves all actual section/import/chain/export/load semantics')
        for section in a.sections:
            at, size = section['fileoff'], section['size']
            if at and size and section['flags'] & 255 not in (1, 12, 18):
                require(signeddata[at:at + size] == unsigneddata[at:at + size], 'all actual backed section bytes preserved by signing')
        new_signatures.append(sigreader.signed_image(signedpath, row, {}))
    parent = macho.MachO((root / rows['parent:VZ27.dylib']['path']).read_bytes())
    parent_before = macho.MachO((oldroot / before['parent:VZ27.dylib']['path']).read_bytes())
    helper = macho.MachO((root / rows[helper_id]['path']).read_bytes())
    recipe = json.loads(exact(port['recipe']).read_bytes())
    require(parent.uuid == parent_before.uuid and parent.exports == parent_before.exports and parent.sections == parent_before.sections, 'genuine parent class/export and section geometry unchanged')
    require([semantic(x) for x in parent.loads[:-1]] == [semantic(x) for x in parent_before.loads], 'all old required namespaces unchanged')
    require(parent.loads[-1]['ordinal'] == 64 and parent.loads[-1]['path'] == '@loader_path/VM27OwnedVZStartCompat.dylib' and parent.loads[-1]['cmd'] == 12, 'one actual required named parent provider')
    require(len(parent.imports) == len(parent_before.imports) + 1 == 1058, 'one added localizer import')
    require(parent.imports[504]['name'] == '_VM27OwnedVZCacheConfstrV1' and parent.imports[504]['ordinal'] == 64, 'selected504 actual named cache API')
    require(parent.imports[1057]['name'] == '_VM27OwnedVZLocalizedStringOrEnglishKeyV1' and parent.imports[1057]['ordinal'] == 64, 'appended1057 actual named localization API')
    for current, previous in zip(parent.imports, parent_before.imports):
        if current['index'] != 504:
            require(semantic(current) == semantic(previous), 'all other original import semantics preserved')
    for section in parent.sections:
        at, size = section['fileoff'], section['size']
        if not at or not size or section['flags'] & 255 in (1, 12, 18):
            continue
        expected = bytearray(parent_before.data[at:at + size])
        for change in recipe['explicitChanges']:
            off, priorbytes, newbytes = change['fileOffset'], bytes.fromhex(change['before']), bytes.fromhex(change['after'])
            if at <= off < at + size:
                require(off + len(newbytes) <= at + size and expected[off - at:off - at + len(priorbytes)] == priorbytes, 'declared patch bounds and original bytes')
                expected[off - at:off - at + len(newbytes)] = newbytes
        require(parent.data[at:at + size] == expected, 'only five declared actual backed-section changes')
    oldbinds = {r['fileoff']: r for r in parent_before.binds}
    newbinds = {r['fileoff']: r for r in parent.binds}
    require(set(newbinds) - set(oldbinds) == {0x3197d0} and set(oldbinds) - set(newbinds) == set(), 'one added true authenticated localizer slot')
    require({off for off in oldbinds if oldbinds[off]['word'] != newbinds[off]['word']} == {0x3197c8}, 'only old terminal chain next field changes')
    require(oldbinds[0x3197c8]['word'] ^ newbinds[0x3197c8]['word'] == 1 << 51, 'exact next1 stride8 without changing old PAC/auth/target fields')
    slot = newbinds[0x3197d0]
    require(slot['index'] == 1057 and slot['auth'] == 1 and slot['key'] == 0 and slot['addrdiv'] == 1 and slot['diversity'] == 0, 'actual appended IA address-diversified localizer ABI')
    require(set(helper.exports) == {'_VM27OwnedVZCacheConfstrV1', '_VM27OwnedVZLocalizedStringOrEnglishKeyV1'} and all(x['flags'] == 0 for x in helper.exports.values()), 'exact two genuine named strong exports')
    graph = json.loads(exact(port['graph']).read_bytes())
    proofpin = pin(root / rows[manifest['dependencyProofID']]['path'])
    proof = json.loads(pathlib.Path(proofpin['path']).read_bytes())
    oldproofpath = oldroot / before[prior['dependencyProofID']]['path']
    require(proof['baselineDependencyProof'] == pin(oldproofpath) and proof['inheritedBaselineDefinitionGraph'] == json.loads(oldproofpath.read_bytes()), 'old actual full graph inherited without rerun')
    require(proof['actualParentIncrementalGraph'] == graph and proof['parentPortCandidate'] == pin(portpath), 'actual frozen role-aware incremental graph')
    require([r['actualImport'] for r in graph['actualProviderNativeRows']] == helper.imports and len(helper.imports) == 36 and graph['newProviderStrongImportsClosed'], 'actual signed helper36 imports join existing genuine Native67 proof')
    require([r['actualImport'] for r in proof['actualStrongParentImportRows']] == [r for r in parent.imports if not r['weak']], 'all real current parent strong imports joined by index including selected2')
    for row in proof['actualStrongParentImportRows']:
        if row['actualImport']['index'] in (504, 1057):
            route = row['resolution']['route']
            require(len(route) == 1 and route[0]['path'] == rows[helper_id]['path'] and route[0]['UUID'] == helper.uuid and route[0]['actualExport'] == helper.exports[row['actualImport']['name']], 'selected actual own helper export resolution')
    require(proof['finalStrongDefinitionGraphClosed'] and proof['unresolvedStrongImportRows'] == [] and proof['oldGraphRerun'] is False, 'truthful incremental closure boundary')
    anchor = exact(c['anchorSource']).read_text()
    match = re.search(r'SHA256V1\[32\]=\{([^}]+)\}', anchor)
    require(match is not None and bytes(int(x) for x in match[1].split(',')) == hashlib.sha256(manifest_raw).digest() and 'ManifestBytesV1=' + str(len(manifest_raw)) + ';' in anchor, 'actual new manifest SHA and length anchor')
    oldsig = json.loads(exact(old['signatureVerification']).read_bytes())
    signatures = json.loads(exact(c['signatureVerification']).read_bytes())
    inherited = {r['relativePath']: r for r in oldsig['actualSignedFiles']}
    for item in signatures['actualSignedFiles']:
        if item['relativePath'] == 'parent-flat/VZ27.dylib' or item['relativePath'] == rows[helper_id]['path']:
            continue
        original = dict(inherited[item['relativePath']])
        original['actualSignedFile'] = pin(root / item['relativePath'])
        require(item == original, 'unchanged140 signature proof whole joined without code page rerun')
    commands = json.loads((args.candidate.parent / 'commands.json').read_bytes())
    require(all(r['exit'] == 0 for r in commands) and sum(r['argv'][0] == 'codesign' and '--sign' in r['argv'] for r in commands) == 2, 'Root actual two signing commands and strict verifies/preflight completed')
    peers = [N / name / 'review.json' for name in ('owned-vz-cache-source-independent-peer-v1-attempt1', 'owned-vz-localization-source-independent-peer-v1-attempt2', 'owned-vz-start-compat-primary-pac-independent-peer-v1-attempt1')]
    for peer in peers:
        record = json.loads(peer.read_bytes())
        require(record['findings'] == [], 'separate inherited actual source/PAC peer')
        frozen(peer)
    output.mkdir(mode=0o700)
    report = dict(schema='Finite actual signed Runtime11 parent-only product peer v1', runtimeCandidate=cpin, inputFreeze=newfreeze, baselineRuntimeCandidate=pin(oldpath), baselineFreeze=oldfreeze, parentPortCandidate=pin(portpath), parentPortFreeze=portfreeze, passed=True, finiteLocalScopePassed=True, findings=[], actualManifest=c['manifest'], actualAnchor=c['anchorSource'], actualSignature=new_signatures, actualNewSignedPrimaryPages=sum(r['actualCodePages'] for r in new_signatures), actualSignedImages=142, actualManifestRows=152, unchangedSignedWholeFiles=140, inherited140PrimaryPagesNotRerun=True, actualDependencyProof=proofpin, selectedActualImports=[parent.imports[504], parent.imports[1057]], newRequiredLoad=parent.loads[-1], unchangedOldAuthWordsExceptSingleTerminalNext=True, oldTerminalNextChangeOnlyBit51=True, appendedActualAuthSlot=slot, cacheAdapterContract=c['cacheAdapterContract'], localizerContract=c['localizerContract'], inheritedSourceAndPACPeers=[pin(p) for p in peers], authorBoundary='Runtime11 builder author; concrete signing by Root; source/PAC peers separately inherited, not self-approved here', cacheDirectoriesMustBeProvisionedByDeployment=True, actualCacheFallbackExecuted=False, actualIOSImagesExecuted=False, deviceOperations=0, trustCacheOperations=0, actualVMStarted=False, guestBoot=False, physicalDisplayVerified=False)
    reportpath = output / 'review.json'
    reportpath.write_text(json.dumps(report, indent=2) + '\n')
    locked = [pin(__file__), pin(macho_path), pin(R / 'VirtualMac/scripts/development/review-independent27-signed-runtime-product-v1.py'), pin(reportpath), cpin, newfreeze, pin(oldpath), oldfreeze, pin(portpath), portfreeze, c['manifest'], c['anchorSource'], c['anchorIOSObject'], c['signatureVerification'], c['runtime10DeltaVerification'], proofpin, port['patchedParentVZ'], port['newProvider'], port['recipe'], port['graph']] + [pin(p) for p in peers] + [pin(root / rows[i]['path']) for i in ('parent:VZ27.dylib', helper_id)]
    (output / 'freeze.json').write_text(json.dumps(dict(files=list({r['path']: r for r in locked}.values()), hostOnly=True), indent=2) + '\n')
    print(json.dumps(dict(review=pin(reportpath), freeze=pin(output / 'freeze.json'), passed=True, findings=[], actualNewCodePages=report['actualNewSignedPrimaryPages'])))


if __name__ == '__main__':
    main()
