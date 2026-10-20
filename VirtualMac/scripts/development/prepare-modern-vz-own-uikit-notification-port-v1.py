#!/usr/bin/env python3
"""Reject mac host notification capability; preserve genuine task cleanup."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('note_q', HERE/'prepare-modern-vz-own-uikit-packet-port-v2.py')
q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
f, p, s, n = q.f, q.p, q.s, q.n
BASE = 0x225f36000
SELECTED = {314: ('_SLSIsScreenWatcherPresent', '_VM27NoWatcherV1'),
            316: ('_SLSRegisterNotifyProc', '_VM27NoRegisterV1'),
            317: ('_SLSRemoveNotifyProc', '_VM27NoRemoveV1')}
PROVIDER = '@loader_path/VM27NoMacNotificationPort.dylib'
QUERY_BRANCH = 0x226165ad4-BASE
QUERY_EPILOGUE = 0x226166118-BASE
REGISTER_FLAG = 0x22616b288-BASE
CODE_PATCHES = {QUERY_BRANCH: (0x36000080, 0x14000000 | ((QUERY_EPILOGUE-QUERY_BRANCH)//4)),
                REGISTER_FLAG: (0x39006288, 0x3900629f)}
CALLS = {0x226165ad0: 314, 0x22616b2a4: 316, 0x22616b2c0: 316,
         0x22616b37c: 317, 0x22616b398: 317, 0x22616b454: 317, 0x22616b470: 317}

def transform(before):
    after = bytearray(before); rows = q.q.q.import_records(before, p.commands); strings = q.q.q.strings(before)
    for ix, (old, new) in SELECTED.items():
        row = rows['imports'][ix]; assert row['name'] == old and row['ordinal'] == 52 and not row['weak'] and row['addend'] == 0
        off, length = strings[ix]; assert len(new)+1 <= length
        assert all(other == ix or address+count <= off or off+length <= address for other, (address, count) in strings.items())
        after[off:off+length] = new.encode()+bytes(length-len(new))
    dep = next(row for row in p.dependencies(before) if row['ordinal'] == 52)
    assert dep['command'] == 12 and dep['path'] == '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'
    start = dep['at']+struct.unpack_from('<I', before, dep['at']+8)[0]; room = dep['at']+dep['size']-start
    assert before[start:start+len(dep['path'])+1] == dep['path'].encode()+b'\0' and len(PROVIDER)+1 <= room
    after[start:start+room] = PROVIDER.encode()+bytes(room-len(PROVIDER))
    for at, (old, new) in CODE_PATCHES.items():
        assert struct.unpack_from('<I', before, at)[0] == old; struct.pack_into('<I', after, at, new)
    return bytes(after)

def validate(before, after):
    assert after == transform(before)
    a, b = p.vz_reader.parse(before), p.vz_reader.parse(after)
    assert a['words'] == b['words'] and a['nlists'] == b['nlists'] and a['segments'] == b['segments'] and a['header'] == b['header']
    old, new = p.dependencies(before), p.dependencies(after)
    assert new == [dict(row, path=PROVIDER) if row['ordinal'] == 52 else row for row in old]
    ai, bi = q.q.q.import_records(before, p.commands), q.q.q.import_records(after, p.commands)
    assert bi == dict(ai, imports=[dict(row, name=SELECTED[row['index']][1]) if row['index'] in SELECTED else row for row in ai['imports']])
    assert len(bi['imports']) == 1056 and sum(not row['weak'] for row in bi['imports']) == 1011
    assert {row['name'] for row in bi['imports'] if row['ordinal'] == 52} == {name for old, name in SELECTED.values()}
    assert not any(row['path'] == old[51]['path'] for row in new)
    assert not any(row['name'] in [v[0] for v in SELECTED.values()] for row in b['nlists'])
    for seg in p.segments(before):
        for sec in seg['sections']:
            if not sec['fileoff'] or not sec['size'] or sec['flags'] & 255 in (1, 12, 18): continue
            start, end = sec['fileoff'], sec['fileoff']+sec['size']; expected = bytearray(before[start:end])
            for at in CODE_PATCHES:
                if start <= at < at+4 <= end: expected[at-start:at-start+4] = after[at:at+4]
            assert bytes(expected) == after[start:end]
    return dict(totalImports=1056, strongImports=1011, remainingOriginalSkyLightImports=0,
        originalSkyLightStrongLoadCommandReplacedByActualPrivateProvider=True, allDependencyOrdinalsPreserved=True,
        changedBytes=sum(a != b for a, b in zip(before, after)), onlyTwoOriginalInstructionWordsChanged=list(CODE_PATCHES),
        chainedWholePACWordsPreserved=len(a['words']), allOriginalMetadataNlistsAndUnwindBytesPreserved=True,
        hostWatcherResultNotFabricated=True, failedNotificationRegistrationFlagRemainsClear=True,
        originalTaskAndStackCookieCleanupPreserved=True)

def original_proof(before, out):
    contract = n/'vz-skylight-consumer-contract-v1/build-v3/contract.json'; j = json.loads(contract.read_bytes())
    assert p.pin(contract)['sha256'] == 'f1fcabba053f2e1331b8750883170b939fed06dc5c026cd9393abfe7d134d86d'
    parsed = p.vz_reader.parse(before); text = next(sec for seg in parsed['segments'] for sec in seg['sections'] if sec['name'] == '__text')
    routes = {q.q.q.stub_for(before, ix)['PC']: ix for ix in SELECTED}; calls = []
    for off in range(text['at'], text['at']+text['bytes'], 4):
        word = struct.unpack_from('<I', before, off)[0]
        if word & 0xfc000000 not in (0x14000000, 0x94000000): continue
        target = q.q.q.branch_target(0x100000000+off, word)
        if target in routes:
            assert BASE+off in CALLS and CALLS[BASE+off] == routes[target]
            calls.append(dict(originalPC=BASE+off, importIndex=routes[target], fileoff=off))
    assert len(calls) == 7
    # The watcher makes no local retain/CF allocation before query. Its only
    # earlier call is the genuine context-owned map insertion/lookup; its
    # returned node stays in that original map. No transient owner is skipped.
    watcher_start = 0x226165a74-BASE
    assert struct.unpack_from('<I', before, 0x226165ac8-BASE)[0] & 0xfc000000 == 0x94000000
    prefix_calls = [off for off in range(watcher_start, QUERY_BRANCH, 4) if struct.unpack_from('<I', before, off)[0] & 0xfc000000 == 0x94000000]
    assert prefix_calls == [0x226165ac8-BASE, 0x226165ad0-BASE]
    epilogue = before[QUERY_EPILOGUE:QUERY_EPILOGUE+56]
    assert struct.unpack_from('<I', epilogue, 0)[0] == 0xf85983a8 and struct.unpack_from('<I', epilogue, 52)[0] == 0xd65f0fff
    for pc in (0x22616b2a4, 0x22616b2c0, 0x22616b37c, 0x22616b398, 0x22616b454, 0x22616b470):
        at = pc-BASE
        assert struct.unpack_from('<3I', before, at-12) == (0xaa1003e0, 0x5280bbc1 if pc in (0x22616b2a4, 0x22616b37c, 0x22616b454) else 0x5280bbe1, 0xaa1403e2)
    # Original callback signing words and borrowed context are untouched. No
    # private API records or invokes that callback; the original captured
    # strong object/task release and tail deletion still run normally.
    assert struct.unpack_from('<I', before, REGISTER_FLAG-4)[0] == 0x52800028
    materials = []
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream); assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'; subs = cache.addSubCaches(p.CACHE)
        def read(va, length):
            assert 0 < length <= 65536; off, owner = cache.convertAddr(va); return owner.getBytes(off, length)
        try:
            for address in (0x226165a74, 0x22616b240, 0x22616b318, 0x22616b3f0, 0x22616bd54):
                original = next(row for row in j['originalBoundedConsumerHelperBodies'] if row['functionStart'] == address)
                file = out/(hex(address)+'.original.bin'); file.write_bytes(read(address, original['bytes'])); assert p.pin(file)['sha256'] == original['sha256']
                materials.append(dict(functionStart=address, functionEnd=original['functionEnd'], originalWholeBody=p.pin(file), unmatchedObjCMethodNotGuessed=not bool(original['exactObjCIMPMatches'])))
            off, owner = cache.convertAddr(BASE); header = owner.getBytes(off, 32); header = owner.getBytes(off, 32+struct.unpack_from('<I', header, 20)[0])
            lc = next(at for command, at, size in p.commands(header) if command == 0x26); dataoff, length = struct.unpack_from('<II', header, lc+8)
            linkedit = next(seg for seg in p.segments(header) if seg['name'] == '__LINKEDIT'); encoded = read(linkedit['address']+dataoff-linkedit['fileoff'], length)
            function_index = out/'original-function-starts.bin'; function_index.write_bytes(encoded)
            at = delta = 0; starts = []
            while at < len(encoded):
                value, at = q.uleb(encoded, at)
                if not value: assert not any(encoded[at:]); break
                delta += value; starts.append(BASE+delta)
            ix = starts.index(0x22616b564); assert starts[ix+1] == 0x22616b9c4
            map_body = read(starts[ix], starts[ix+1]-starts[ix]); file = out/'original-context-owned-map-lookup-complete.bin'; file.write_bytes(map_body)
            # New nodes zero their own observation bytes and are linked into
            # the original owner's table before returning, not an RAII local.
            assert struct.unpack_from('<I', map_body, 0x22616b690-starts[ix])[0] == 0x3c818000
            map_pin = p.pin(file)
        finally:
            for sub in subs: sub.close()
    return dict(originalContract=p.pin(contract), genuineCompleteFunctions=materials, allAffectedDirectCallers=calls,
        genuineContextOwnedMapHelper=map_pin, watcherErrorBranchesToOriginalCookieAndPACEpilogue=True,
        originalWatcherStateNotUpdated=True, registrationFlagStoreZeroBeforeErrors=True,
        originalCallbackPACWordsAndRetainReleaseDeletePreserved=True, noCallbackCaptureRetained=True,
        originalFunctionsExecuted=False, indirectInteriorEntrypointsExhaustivelyProven=False)

def main():
    out = n/'vz-own-uikit-notification-source-port-data-v1'; assert not out.exists(); out.mkdir(mode=0o700)
    previous = n/'vz-own-uikit-packet-source-port-data-v2/candidate.json'; manifest = json.loads(previous.read_bytes()); pins = []
    for freeze in (previous.parent/'freeze.json', n/'uikit-input-current-definitions-readonly-v1/freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']: assert p.pin(Path(row['path'])) == row; pins.append(row)
        pins.append(p.pin(freeze))
    base = manifest['frontendCandidate']; assert p.pin(Path(base['path'])) == base; before = Path(base['path']).read_bytes()
    proof = original_proof(before, out); p.save(out/'original-caller-proof.json', proof)
    sources = [p.ROOT/'VirtualMac/vz/host'/name for name in ('vm27_no_mac_notification_port_v1.h', 'vm27_no_mac_notification_port_v1.c', 'test-vm27-no-mac-notification-port-v1.c')]
    runs = []
    def run(label, args):
        args = list(map(str, args)); r = subprocess.run(args, capture_output=True, timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout); (out/(label+'.stderr')).write_bytes(r.stderr); runs.append(dict(label=label, argv=args, exit=r.returncode)); p.save(out/'processes.json', runs)
        assert r.returncode == 0, (label, r.stderr.decode()); return r
    for mode, flags in (('normal', []), ('san', ['-fsanitize=address,undefined'])):
        exe = out/('fixture-mac-'+mode); run('build-'+mode, ['xcrun', 'clang', '-O2', '-Wall', '-Wextra', '-Werror', *flags, sources[1], sources[2], '-o', exe])
        result = json.loads(run('run-'+mode, [exe]).stdout); assert result == dict(checks=3202, failures=0, contextsFreed=128, callbacks=0, registrations=0, VZCalls=0)
    directory = out/'private'; directory.mkdir(); copies = []
    for source in sorted((previous.parent/'private').iterdir()):
        dest = directory/source.name; dest.write_bytes(source.read_bytes()); copies.append(dict(source=p.pin(source), candidate=p.pin(dest), wholeBytesIdentical=True))
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip(); provider = directory/'VM27NoMacNotificationPort.dylib'
    flags = ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-O2', '-Wall', '-Wextra', '-Werror']
    run('build-ios-provider', flags+['-dynamiclib', sources[1], '-Wl,-install_name,@rpath/'+provider.name, '-Wl,-no_adhoc_codesign', '-o', provider])
    graph = {'@loader_path/'+file.name: f.image(p.pin(file), '@loader_path/'+file.name) for file in directory.iterdir()}; port = graph[PROVIDER]
    assert set(port['exports']) == {new for old, new in SELECTED.values()} | {'_VM27CopyHostNoteErrorsV1'}
    definitions = []
    for ix, (old, new) in SELECTED.items():
        found = f.resolve(graph, PROVIDER, new, port); assert found['status'] == 'actualDirectExport'; definitions.append(dict(importIndex=ix, name=new, definition=found))
    native = s.primary.captured_images()
    for group in ('system', 'stock-extra', 'cxx-leaf'): s.join_capture(native, group, n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'): s.join_capture(native, group, n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    f.join_kernel(s, native)
    for fn in (f.join_hid_extra, f.join_swift_two, f.join_eight, f.join_three, f.join_trace, f.join_unwind, f.join_compiler, f.join_crypto): fn(s, native)
    assert len(native) == 36; native_defs = []; raw = provider.read_bytes(); deps = {row['ordinal']: row['path'] for row in p.dependencies(raw)}
    for row in q.q.q.import_records(raw, p.commands)['imports']:
        assert row['ordinal'] > 0 and not row['weak']; found = s.primary.resolve(native, deps[row['ordinal']], row['name']); assert found['status'] == 'actualDirectExport'; native_defs.append(dict(row, owner=deps[row['ordinal']], definition=found))
    after = transform(before); verification = validate(before, after); candidate = out/'VZ27.own-uikit-no-mac-notification.mac.inert.macho-data'; candidate.write_bytes(after); candidate.chmod(0o600)
    negatives = []
    for label, off in (('watcher bool-consumer branch', QUERY_BRANCH), ('failed registration flag', REGISTER_FLAG), ('watcher cookie cleanup', QUERY_EPILOGUE), ('original task delete', 0x22616b2fc-BASE),
        ('original callback PAC', 0x22616b294-BASE), ('original metadata', 0x2f0600), ('genuine sender', 0x5c770), ('genuine six-parameter constructor', 0x6494c),
        ('original notification PAC', q.q.q.stub_for(before, 316)['chain']['at']+7), ('new actual dependency path', next(row for row in p.dependencies(before) if row['ordinal'] == 52)['at']+24), ('new private refusal name', q.q.q.strings(before)[316][0])):
        bad = bytearray(after); bad[off] ^= 1
        try: validate(before, bytes(bad))
        except (AssertionError, ValueError): negatives.append(dict(name=label, rejected=True))
        else: raise AssertionError('damaged exact notification port accepted')
    bad = copy.deepcopy(graph); bad.pop(PROVIDER); assert f.resolve(bad, PROVIDER, '_VM27NoWatcherV1', port)['status'] != 'actualDirectExport'; negatives.append(dict(name='missing actual notification provider', rejected=True))
    for file in (candidate, provider): run('validate-'+file.name, ['xcrun', 'dyld_info', '-validate_only', file])
    p.save(out/'candidate.json', dict(schema='Independent own UIKit no mac host-notification source port v1', sourceFrontend=base,
        frontendCandidate=p.pin(candidate), frontendAggregate=p.pin(directory/'XF'), hostNotificationProvider=p.pin(provider), sourceFiles=[p.pin(file) for file in sources],
        wholeCopiedPreviousProviders=copies, originalCallerProof=p.pin(out/'original-caller-proof.json'), verification=verification,
        explicitHostCapabilityDefinitions=definitions, providerCurrentStrongImports=native_defs, negativeControls=negatives,
        originalMacArtifactPreserved=True, noFakeSLSCGSNSEventExportsOrClasses=True, macScreenWatcherAndNotificationsExplicitlyUnsupported=True,
        originalVZSenderFramesAndVMExecutorPreserved=True, ownUIKitInputAndSixParameterInitializerPreserved=True,
        allTwelveOriginalSkyLightStrongImportsHaveOwnUIKitSourcePortDefinitions=True, macWindowServerFunctionalEquivalenceClaimed=False,
        originalHostTasksExecuted=False, actualIOSNotificationProviderExecuted=False, originalVZLoaded=False, completeCurrentStrongLoadGraph=False,
        originalOuterAsyncExceptionPolicyVerified=False, providerSigningCalls=0, deviceOperations=0, nativeCPUCalls=0, guestInstructions=0, full27Backend=False))
    pins += [p.pin(Path(__file__))]+[p.pin(file) for file in sources]+[p.pin(file) for file in out.rglob('*') if file.is_file()]
    p.save(out/'freeze.json', dict(files=list({row['path']: row for row in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'), freeze=p.pin(out/'freeze.json'), verification=verification, provider=p.pin(provider), currentStrongImports=len(native_defs))))

if __name__ == '__main__':
    try: main()
    except Exception as exc:
        out = n/'vz-own-uikit-notification-source-port-data-v1'
        if out.exists(): p.save(out/'failure.json', dict(error=repr(exc), candidateWritten=(out/'candidate.json').exists(), deviceOperations=0)); (out/'failed-builder.py').write_bytes(Path(__file__).read_bytes())
        raise
