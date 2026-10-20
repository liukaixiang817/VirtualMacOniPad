#!/usr/bin/env python3
"""HOST compose genuine Stage14 from Stage13 and a frozen named filter port.

Only one shared VZ image is replaced and one real provider image is added.
Existing graph rows are inherited after actual record joins; only the new
class import and provider imports are resolved against the captured native67.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'independent27-owned-platform-launch-stage-v13-attempt1'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
NATIVE = N / 'current-native-header-export-index-v3/index.json'
KEY = 'VM27OwnedUIKitMacEventFilter.dylib'
VZ = 'VZ27.dylib'
CLASS = '_OBJC_CLASS_$_VM27OwnedUIKitMacEventFilterV1'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(path):
    path = Path(path).resolve(); data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def exact(row):
    need(pin(row['path']) == row, 'same actual input pin ' + row['path'])
    return Path(row['path']).read_bytes()


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2); f.write('\n')


def frozen(directory):
    path = directory / 'freeze.json'
    for row in json.loads(path.read_bytes())['files']:
        exact({k: row[k] for k in ('path', 'bytes', 'sha256')})
    return pin(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider-candidate', type=Path, required=True)
    parser.add_argument('--provider-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh Stage14 output')
    provider_path = args.provider_candidate.resolve()
    need(pin(provider_path)['sha256'] == args.provider_sha256 ==
         '6e82235d3687db04c6eae99be985b1f2e012fc41af85206f819459542fa3151b',
         'real corrected V2 source artifact; rejected raw18 layout source forbidden')
    need(pin(BASE / 'candidate.json')['sha256'] == 'a68cd0e7e86df85955f0c1a57ccc8524511a29df36aba33940551ce62431730a' and
         pin(BASE / 'verification.json')['sha256'] == '552815f5b7042890a6d61ffc8f1dbad4cbccfeb9e9d3cc4db409a9d228d0577e',
         'actual frozen Stage13 and full joined graph')
    freezes = [frozen(BASE), frozen(provider_path.parent)]
    provider = json.loads(provider_path.read_bytes())
    stage = json.loads((BASE / 'candidate.json').read_bytes())
    graph = json.loads((BASE / 'verification.json').read_bytes())
    contract = provider['ownMacEventFilterContract']
    need(provider['baseStage'] == pin(BASE / 'candidate.json') and provider['providerKey'] == KEY and
         provider['deviceOperations'] == 0 and provider['trustCacheOperations'] == 0 and
         provider['fakeNSEventClass'] is False and provider['fakeSwiftMetadata'] is False,
         'exact actual named source/provider, no fake Mac metadata')
    expected = dict(providerKey=KEY, ownClass='VM27OwnedUIKitMacEventFilterV1', classSymbol=CLASS,
        VZUUID='418efc4809d93606918eb6f95baeffdc', classrefRVA=0x318d68,
        isEnabled=False, hasEventTranslators=False, macMethodsReturnFakeReports=False,
        realOwnerPIDAndVZImageEpochRequired=True, originalMonitorAndVMConstructorPreserved=True,
        ordinaryUIKitKeyboardRVA=0x58aa8, ordinaryUIKitCoordinateRVA=0x6460c,
        parentBundleIdentifier='com.mac.virtual.independent27', ownerUID=501,
        childClassDefinitionLoadPermittedWithoutConstruction=True)
    for k, value in expected.items():
        need(type(contract.get(k)) is type(value) and contract[k] == value, 'true contract ' + k)
    need(contract.get('actualAlignedMonitorInstanceSize') == 24 and
         contract.get('actualMonitorIvarOffsets') == [8, 16, 17],
         'actual word-aligned Objective-C monitor instance size24')
    need(provider['patchedVZ'] == contract['patchedVZ'] and provider['originalVZ'] == contract['originalVZ'],
         'same genuine source port inputs')
    sp = importlib.util.spec_from_file_location('stage14_actual_macho', READER)
    m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
    native = json.loads(NATIVE.read_bytes())['images']
    old_rows = {row['key']: row for row in stage['stagedImages']}
    need(len(old_rows) == 73 and KEY not in old_rows and provider['originalVZ'] == old_rows[VZ]['staged'],
         'real sole shared VZ source replaced and one new provider')
    old_vz = m.MachO(exact(provider['originalVZ']))
    new_vz = m.MachO(exact(provider['patchedVZ']))
    owned = m.MachO(exact(provider['provider']))
    need(owned.imports == provider['actualNativeImports'] and owned.exports == provider['actualExports'] and
         CLASS in owned.exports and owned.exports[CLASS]['flags'] == 0 and
         'address' in owned.exports[CLASS], 'real class direct strong export and native imports')
    slot = new_vz.file(new_vz.base + contract['classrefRVA'])
    selected = new_vz.imports[contract['newActualImportIndex']]
    need(slot == contract['classrefFileOffset'] and
         struct.unpack_from('<Q', new_vz.data, slot)[0] == contract['newBindraw'] and
         struct.unpack_from('<Q', old_vz.data, slot)[0] == contract['oldRebase'] and
         selected['name'] == CLASS and selected['ordinal'] == contract['newRequiredOrdinal'] and
         selected['weak'] == 0 and selected['addend'] == 0,
         'actual one classref rebase to required class bind')
    normal = lambda rows: [{k: v for k, v in row.items() if k != 'at'} for row in rows]
    need(normal(new_vz.imports[:-1]) == normal(old_vz.imports) and len(new_vz.imports) == len(old_vz.imports) + 1 and
         new_vz.uuid == old_vz.uuid and new_vz.exports == old_vz.exports and new_vz.sections == old_vz.sections,
         'all old imports and original VZ UUID/exports/section geometry preserved')
    need(new_vz.loads[:-1] == old_vz.loads and new_vz.loads[-1]['cmd'] == 12 and
         new_vz.loads[-1]['path'] == '@loader_path/' + KEY,
         'one actual new required provider dependency')
    need([r for r in new_vz.binds if r['fileoff'] != slot] == old_vz.binds,
         'every other VZ chained bind/PAC field unchanged')
    for section in old_vz.sections:
        at, size = section['fileoff'], section['size']
        if at and size and section['flags'] & 255 not in (1, 12, 18):
            value = bytearray(new_vz.data[at:at + size])
            if at <= slot < at + size:
                value[slot - at:slot - at + 8] = old_vz.data[slot:slot + 8]
            need(bytes(value) == old_vz.data[at:at + size], 'all original VZ backed bytes except selected classref')
    out.mkdir(mode=0o700); flat = out / 'flat'; flat.mkdir(mode=0o700)
    rows = []; images = {VZ: new_vz, KEY: owned}; changed = []; sources = []
    for key, row in sorted(old_rows.items()):
        old = exact(row['staged']); value = new_vz.data if key == VZ else old
        p = flat / key; p.write_bytes(value); p.chmod(0o600)
        new_row = copy.deepcopy(row); new_row.update(staged=pin(p), source=provider['patchedVZ'] if key == VZ else row['staged'])
        rows.append(new_row); sources.append(row['staged'])
        if key == VZ: changed.append(key)
    p = flat / KEY; p.write_bytes(owned.data); p.chmod(0o600)
    rows.append(dict(key=KEY, staged=pin(p), source=provider['provider'], UUID=owned.uuid,
                     loadPathChanges=[], codeSignatureStaleUntilFinalSigning=True))
    actual_rows = {row['key']: row for row in rows}
    def image(key):
        if key not in images: images[key] = m.MachO(exact(actual_rows[key]['staged']))
        return images[key]
    def target(path):
        if path in native: return 'native', path
        if path.startswith('@loader_path/') and path[13:] in actual_rows: return 'own', path[13:]
        return 'missing', path
    def deps(kind, key):
        return native[key]['dependencies'] if kind == 'native' else [dict(ordinal=r['ordinal'], command=r['cmd'], path=r['path']) for r in image(key).loads]
    def definition(kind, key, name, seen=()):
        need(kind != 'missing' and (kind, key, name) not in seen, 'real definition with no reexport cycle')
        seen += ((kind, key, name),); value = native[key] if kind == 'native' else image(key)
        exports = value['definitions'] if kind == 'native' else value.exports
        entry = exports.get(name); step = dict(kind=kind, path=key, symbol=name)
        if entry:
            step['actualExport'] = entry
            if entry['flags'] & 8:
                dep = next(r for r in deps(kind, key) if r['ordinal'] == entry['ordinal'])
                rest = definition(*target(dep['path']), entry.get('alias', entry.get('importedName', '')) or name, seen)
                rest['route'] = [step] + rest['route']; return rest
            step['UUID'] = value['UUID'] if kind == 'native' else value.uuid
            return dict(resolved=True, route=[step])
        for dep in deps(kind, key):
            if dep['command'] == 0x8000001f and target(dep['path'])[0] != 'missing':
                try: rest = definition(*target(dep['path']), name, seen)
                except KeyError: continue
                rest['route'] = [step] + rest['route']; return rest
        raise KeyError((kind, key, name))
    increment = []
    for key, imports in [(VZ, [selected]), (KEY, owned.imports)]:
        for imp in imports:
            need(imp['ordinal'] > 0 and not imp['weak'], 'actual strong two-level new import')
            dep = next(r for r in deps('own', key) if r['ordinal'] == imp['ordinal'])
            increment.append(dict(importer=key, actualImport=imp, resolution=definition(*target(dep['path']), imp['name'])))
    strong, weak = copy.deepcopy(graph['actualStrongImportRows']), copy.deepcopy(graph['actualNativeWeakDefinitionRows'])
    for row in strong + weak:
        actual = image(row['importer']).imports[row['actualImport']['index']]
        need(dict(row['actualImport'], at=actual['at']) == actual, 'same inherited actual import record semantics')
        row['actualImport'] = actual
        for step in row.get('resolution', row.get('actualDefinition', {})).get('route', []):
            if step['kind'] == 'own' and step['path'] == VZ and 'actualExport' in step:
                need(new_vz.exports.get(step['symbol']) == step['actualExport'], 'inherited VZ export terminal preserved')
    strong += increment
    loads = copy.deepcopy(graph['actualLoadRows'])
    for key in (VZ, KEY):
        old_ordinals = {r['ordinal'] for r in loads if r['importer'] == key}
        for dep in deps('own', key):
            if dep['ordinal'] in old_ordinals: continue
            kind, to = target(dep['path']); need(kind != 'missing', 'new actual required first load')
            loads.append(dict(importer=key, **dep, targetKind=kind, target=to, required=True,
                 strongImportCount=sum(not r['weak'] and r['ordinal'] == dep['ordinal'] for r in image(key).imports)))
    joined = strong + weak
    need(len({(r['importer'], r['actualImport']['index']) for r in joined}) == len(joined) and
         {(r['importer'], r['actualImport']['index']) for r in joined} ==
         {(k, r['index']) for k in actual_rows for r in image(k).imports if not r['weak']},
         'complete joined graph exact actual strong and original native weak rows')
    steps = []
    for key in (VZ, KEY):
        argv = ['xcrun', 'dyld_info', '-validate_only', str(flat / key)]
        result = subprocess.run(argv, capture_output=True, timeout=30)
        (out / (key + '.validate.stdout')).write_bytes(result.stdout)
        (out / (key + '.validate.stderr')).write_bytes(result.stderr)
        need(result.returncode == 0, 'real staged image validation ' + key)
        steps.append(dict(argv=argv, exit=result.returncode))
    stage.update(schema='HOST Stage14 genuine named UIKit Mac filter and exact classref source port',
        builder=pin(__file__), baseStage=pin(BASE / 'candidate.json'), prior=pin(BASE / 'candidate.json'),
        stagedImages=rows, actualImages=len(rows), actualOnlyReplacedImages=[VZ], actualAddedImages=[KEY],
        actualUnchangedOtherImages=len(old_rows) - 1, actualOther72ImagesByteIdentical=True,
        ownMacEventFilterProviderCandidate=pin(provider_path), sourceArtifactContract=contract,
        ownMacEventFilterContract=contract, actualIncrementalResolvedImportRows=len(increment),
        actualJoinedStrongImportRowsIncludingExistingWeakDefinitions=len(joined),
        finalStrongDefinitionGraphClosed=True, definitionGraphOutputPath=str(out / 'verification.json'),
        codeSigned=False, actualCodeSigned=False, readyForDeviceExecution=False, deviceOperations=0,
        loaderExecuted=False, trustCacheOperations=0, guestBoot=False,
        readiness='HOST source port only; actual VM construction, boot and UIKit input unverified')
    stage.pop('actualOther71ImagesByteIdentical', None)
    save(out / 'candidate.json', stage)
    proof = copy.deepcopy(graph)
    proof.update(schema='Actual Stage14 incremental named Mac filter graph joined to immutable Stage13',
        actualStrongImportRows=strong, actualNativeWeakDefinitionRows=weak, actualLoadRows=loads,
        actualImages=len(rows), actualStrongImports=len(joined),
        actualNormalStrongImports=len(strong), actualWeakLookupStrongImports=len(weak),
        nativeWeakDefinitionsResolved=len(weak),
        actualWeakImports=sum(bool(r['weak']) for key in actual_rows for r in image(key).imports),
        actualChainedBindSlots=sum(len(image(key).binds) for key in actual_rows),
        actualRequiredNativeLibCxxLoadRows=[r for r in loads if r['required'] and
            r['targetKind']=='native' and r['target']=='/usr/lib/libc++.1.dylib'],
        inheritedExactPreviousVerification=pin(BASE / 'verification.json'),
        sources=[pin(out / 'candidate.json'), pin(NATIVE), pin(READER), pin(__file__), pin(provider_path),
                 pin(BASE / 'verification.json')] + [r['staged'] for r in rows],
        incrementallyResolvedActualStrongRows=len(increment), unresolvedStrongImportRows=[],
        requiredSelectedLoadGaps=[], remainingActualStrongSymbols=0, finalStrongDefinitionGraphClosed=True,
        deviceOperations=0, loaderExecuted=False, guestBoot=False)
    save(out / 'verification.json', proof)
    save(out / 'incremental-filter-definition-rows.json', increment)
    save(out / 'validation-steps.json', steps)
    files = [pin(p) for p in sorted(out.rglob('*')) if p.is_file()] + sources + freezes
    files += [pin(__file__), pin(BASE / 'candidate.json'), pin(BASE / 'verification.json'), pin(provider_path),
              provider['source'], provider['header'], provider['provider'], provider['patchedVZ'], provider['recipe'],
              pin(READER), pin(NATIVE)]
    files += [r['local'] for r in stage['firmwareResources']] + [r['local'] for r in stage['genuineSandboxResources']]
    save(out / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0, codeSigned=False))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), verification=pin(out / 'verification.json'),
                          freeze=pin(out / 'freeze.json'), images=len(rows), increment=len(increment))))


if __name__ == '__main__':
    main()
