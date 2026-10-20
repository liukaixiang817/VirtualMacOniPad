#!/usr/bin/env python3
"""Private mac packet refusal contracts, preserving genuine C++ cleanup/PAC."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('packet_q', HERE/'prepare-modern-vz-own-uikit-haptic-port-v2.py')
q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
f, p, s, n = q.f, q.p, q.s, q.n
SELECTED = {308: ('_SLEventCreateFromData', '_VM27RejectPacketV1'),
            309: ('_SLEventCreateKeyboardEvent', '_VM27RejectMacKeyV1'),
            310: ('_SLEventGetIntegerValueField', '_VM27RejectFieldV1')}
ORIGINAL_BASE = 0x225f36000
CALLS = {0x22607cb84: (308, 0x22607cb30, 0x22607d270),
         0x22607c3ac: (309, 0x22607c334, 0x22607c4a0),
         0x22607cbe4: (310, 0x22607cb30, 0x22607d25c),
         0x22607cc2c: (310, 0x22607cb30, 0x22607d240)}

def transform(before):
    after = bytearray(before)
    schema = q.q.import_records(before, p.commands); ranges = q.q.strings(before)
    for ix, (old, new) in SELECTED.items():
        row = schema['imports'][ix]
        assert row['name'] == old and row['ordinal'] == 52 and not row['weak'] and row['addend'] == 0
        off, length = ranges[ix]; assert len(new)+1 <= length
        assert all(other == ix or address+count <= off or off+length <= address for other, (address, count) in ranges.items())
        after[off:off+length] = new.encode()+bytes(length-len(new))
        after[row['command']] = 29
    return bytes(after)

def validate(before, after):
    assert after == transform(before)
    old, new = p.vz_reader.parse(before), p.vz_reader.parse(after)
    for key in ('words', 'nlists', 'segments', 'header', 'commands'): assert old[key] == new[key]
    a, b = q.q.import_records(before, p.commands), q.q.import_records(after, p.commands)
    assert b == dict(a, imports=[dict(row, name=SELECTED[row['index']][1], ordinal=29) if row['index'] in SELECTED else row for row in a['imports']])
    assert len(b['imports']) == 1056 and sum(not row['weak'] for row in b['imports']) == 1011
    for seg in p.segments(before):
        for sec in seg['sections']:
            if sec['fileoff'] and sec['size'] and sec['flags'] & 255 not in (1, 12, 18):
                off, length = sec['fileoff'], sec['size']; assert before[off:off+length] == after[off:off+length]
    assert not any(row['name'] in [v[0] for v in SELECTED.values()] for row in new['nlists'])
    remaining = [row for row in b['imports'] if row['ordinal'] == 52 and not row['weak']]
    assert len(remaining) == 3
    return dict(totalImports=1056, strongImports=1011, changedBytes=sum(a != b for a, b in zip(before, after)),
        allOriginalInstructionSectionsMetadataNlistsAndDependencyCommandsPreserved=True,
        allOriginalUnwindAndExceptionCleanupBytesPreserved=True, chainedWholePACWordsPreserved=len(old['words']),
        remainingSkyLightStrongImports=remaining)

def uleb(raw, at):
    value = shift = 0
    for _ in range(10):
        assert at < len(raw); byte = raw[at]; at += 1; value |= (byte & 127) << shift
        if not byte & 128: return value, at
        shift += 7
    raise ValueError('unbounded ULEB')

def cleanup_proof(before, out):
    contract = n/'vz-skylight-consumer-contract-v1/build-v3/contract.json'; j = json.loads(contract.read_bytes())
    assert p.pin(contract)['sha256'] == 'f1fcabba053f2e1331b8750883170b939fed06dc5c026cd9393abfe7d134d86d'
    sections = [sec for seg in p.segments(before) for sec in seg['sections']]
    unwind = next(sec for sec in sections if sec['name'] == '__unwind_info'); u = unwind['fileoff']
    header = struct.unpack_from('<7I', before, u); assert header[0] == 1 and header[4] == 1
    indices = [struct.unpack_from('<III', before, u+header[5]+ix*12) for ix in range(header[6])]
    lsdas = {}
    for ix in range(len(indices)-1):
        assert indices[ix][2] <= indices[ix+1][2] <= unwind['size']
        for at in range(indices[ix][2], indices[ix+1][2], 8):
            fn, lsda = struct.unpack_from('<II', before, u+at); assert fn not in lsdas; lsdas[fn] = lsda
    personality_slot = struct.unpack_from('<I', before, u+header[3])[0]
    parsed = p.vz_reader.parse(before); word = next(row for row in parsed['words'] if row['at'] == personality_slot)
    assert word['auth'] and word['bind']
    personality = q.q.import_records(before, p.commands)['imports'][word['index']]
    assert personality['name'] == '___gxx_personality_v0' and personality['ordinal'] == 18 and not personality['weak']
    all_calls = []; selected_ranges = []; tables = []
    routes = {q.q.stub_for(before, ix)['PC']: ix for ix in SELECTED}
    text = next(sec for seg in parsed['segments'] for sec in seg['sections'] if sec['name'] == '__text')
    for off in range(text['at'], text['at']+text['bytes'], 4):
        word = struct.unpack_from('<I', before, off)[0]
        if word & 0xfc000000 not in (0x14000000, 0x94000000): continue
        target = q.q.branch_target(0x100000000+off, word)
        if target in routes:
            assert ORIGINAL_BASE+off in CALLS and CALLS[ORIGINAL_BASE+off][0] == routes[target]
            all_calls.append(dict(fileoff=off, originalPC=ORIGINAL_BASE+off, importIndex=routes[target]))
    assert len(all_calls) == 4
    with p.CACHE.open('rb') as stream:
        cache = p.DyldContext(stream); assert bytes(cache.header.uuid).hex() == 'c284a291b68b3d0da1a03f866f87efdc'; subs = cache.addSubCaches(p.CACHE)
        def read(va, length):
            assert 0 < length <= 4096; off, owner = cache.convertAddr(va); return owner.getBytes(off, length)
        try:
            for original_start in sorted({row[1] for row in CALLS.values()}):
                original = next(row for row in j['originalBoundedConsumerHelperBodies'] if row['functionStart'] == original_start)
                body = read(original_start, original['bytes']); file = out/(hex(original_start)+'.original.bin'); file.write_bytes(body)
                assert p.pin(file)['sha256'] == original['sha256']
                fn = original_start-ORIGINAL_BASE; at = lsdas[fn]; start = at
                assert before[at] == 255; at += 1
                type_encoding = before[at]; at += 1
                assert type_encoding == 0x9b; _, at = uleb(before, at)
                encoding = before[at]; at += 1; assert encoding == 1
                length, at = uleb(before, at); end = at+length; rows = []
                while at < end:
                    call, at = uleb(before, at); size, at = uleb(before, at); landing, at = uleb(before, at); action, at = uleb(before, at)
                    rows.append(dict(start=fn+call, end=fn+call+size, landing=fn+landing if landing else 0, action=action))
                assert at == end and end-start <= 4096
                # Genuine cache LSDA headers and complete call-site table, not
                # a synthetic cleanup model or a presumed API throwing rule.
                genuine = read(ORIGINAL_BASE+start, end-start); assert genuine == before[start:end]
                table = out/(hex(original_start)+'.genuine-lsda-call-sites.bin'); table.write_bytes(genuine)
                tables.append(dict(function=original_start, completeOriginalBody=p.pin(file), genuineCallSiteTable=p.pin(table), lsdaRVA=start, rows=rows))
                for pc, (ix, owner, target) in CALLS.items():
                    if owner != original_start: continue
                    call_rva = pc-ORIGINAL_BASE
                    matched = [row for row in rows if row['start'] <= call_rva < row['end']]
                    assert len(matched) == 1 and matched[0]['landing'] == target-ORIGINAL_BASE and matched[0]['action'] == 0
                    selected_ranges.append(dict(originalCallPC=pc, importIndex=ix, originalLandingPad=target, cleanupOnlyAction=True, table=matched[0]))
                # Verify the actual register-width preparation. These are not
                # guessed C signatures from similarly named platform APIs.
                if original_start == 0x22607c334:
                    rva = 0x22607c3a0-ORIGINAL_BASE
                    assert struct.unpack_from('<3I', before, rva) == (0x79402301, 0xd2800000, 0x52800002)
                else:
                    assert struct.unpack_from('<2I', before, 0x22607cb7c-ORIGINAL_BASE) == (0xaa1503e0, 0xaa1303e1)
                    for pc in (0x22607cbe0, 0x22607cc28): assert struct.unpack_from('<I', before, pc-ORIGINAL_BASE)[0] == 0x52800121
        finally:
            for sub in subs: sub.close()
    assert len(selected_ranges) == 4
    return dict(exactOriginalContract=p.pin(contract), allAffectedDirectCallers=all_calls, tables=tables, cleanupRanges=selected_ranges,
        authenticatedGXXPersonalityImport=personality, personalityWholeChain=word if isinstance(word, dict) else next(row for row in parsed['words'] if row['at'] == personality_slot),
        borrowedArgumentsNotConsumed=True, packetFactoryReturnNeverFabricated=True, integerFieldValueNeverFabricated=True,
        originalCallersExecuted=False, originalOuterAsyncExceptionPolicyVerified=False)

def main():
    out = n/'vz-own-uikit-packet-source-port-data-v2'; assert not out.exists(); out.mkdir(mode=0o700)
    previous = n/'vz-own-uikit-haptic-source-port-data-v2/candidate.json'; manifest = json.loads(previous.read_bytes()); pins = []
    for freeze in (previous.parent/'freeze.json', n/'uikit-input-current-definitions-readonly-v1/freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']: assert p.pin(Path(row['path'])) == row; pins.append(row)
        pins.append(p.pin(freeze))
    base = manifest['frontendCandidate']; assert p.pin(Path(base['path'])) == base; before = Path(base['path']).read_bytes()
    proof = cleanup_proof(before, out); p.save(out/'original-cleanup-proof.json', proof)
    sources = [p.ROOT/'VirtualMac/vz/host'/name for name in ('vm27_no_mac_packet_port_v1.h', 'vm27_no_mac_packet_port_v1.mm', 'test-vm27-no-mac-packet-port-v1.mm', 'vm27_frontend_owned_xpc_aggregate_v1.c')]
    runs = []
    def run(label, args):
        args = list(map(str, args)); r = subprocess.run(args, capture_output=True, timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout); (out/(label+'.stderr')).write_bytes(r.stderr)
        runs.append(dict(label=label, argv=args, exit=r.returncode)); p.save(out/'processes.json', runs)
        assert r.returncode == 0, (label, r.stderr.decode()); return r
    for mode, flags in (('normal', []), ('san', ['-fsanitize=address,undefined'])):
        exe = out/('fixture-mac-'+mode)
        run('build-'+mode, ['xcrun', 'clang++', '-O2', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', *flags, sources[1], sources[2], '-framework', 'Foundation', '-framework', 'CoreGraphics', '-o', exe])
        result = json.loads(run('run-'+mode, [exe]).stdout)
        assert result == dict(checks=1282, failures=0, rejected=192, scopedCFReleases=192, globalDispatches=0, VZCalls=0)
    directory = out/'private'; directory.mkdir(); copies = []
    for source in sorted((previous.parent/'private').iterdir()):
        if source.name == 'XF': continue
        dest = directory/source.name; dest.write_bytes(source.read_bytes()); copies.append(dict(source=p.pin(source), candidate=p.pin(dest), wholeBytesIdentical=True))
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
    flags = ['xcrun', 'clang++', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-O2', '-fobjc-arc', '-Wall', '-Wextra', '-Werror']
    provider = directory/'VM27NoMacPacketPort.dylib'
    run('build-ios-provider', flags+['-dynamiclib', sources[1], '-framework', 'Foundation', '-Wl,-install_name,@rpath/VM27NoMacPacketPort.dylib', '-Wl,-no_adhoc_codesign', '-o', provider])
    run('compile-ios-abi', flags+['-S', '-emit-llvm', sources[1], '-o', out/'provider-ios.ll'])
    ir = (out/'provider-ios.ll').read_text()
    assert 'define void @VM27RejectPacketV1(ptr' in ir and 'define void @VM27RejectMacKeyV1(ptr' in ir and 'define void @VM27RejectFieldV1(ptr' in ir
    aggregate = directory/'XF'
    link = ['xcrun', 'clang']+flags[2:]+['-dynamiclib', '-nostdlib', sources[3], '-Wl,-install_name,@loader_path/XF', '-Wl,-rpath,@loader_path']
    for name in ('VM27VMNetUnavailable.dylib', 'VM27OriginalV10Transport.dylib', 'VM27NoMacCursorPort.dylib', 'VM27NoMacEventInitPort.dylib', 'VM27NoMacHapticPort.dylib', 'VM27NoMacPacketPort.dylib'):
        link.append('-Wl,-reexport_library,'+str(directory/name))
    run('build-ios-aggregate', link+['-Wl,-no_adhoc_codesign', '-o', aggregate])
    graph = {'@loader_path/'+file.name: f.image(p.pin(file), '@loader_path/'+file.name) for file in directory.iterdir()}
    agg = graph['@loader_path/XF']; port = graph['@loader_path/'+provider.name]
    assert not agg['exports'] and len(agg['dependencies']) == 6 and all(row['command'] == 0x8000001f for row in agg['dependencies'])
    assert set(port['exports']) == {new for old, new in SELECTED.values()}
    retained = []
    for old in manifest['previousTwentySixReexportDefinitionsPreserved']+manifest['explicitHapticDefinitions']:
        symbol = old['name']; found = f.resolve(graph, '@loader_path/XF', symbol, agg); assert found['status'] == 'actualDirectExport'; retained.append(dict(name=symbol, proof=found))
    newdefs = []
    for symbol in sorted(port['exports']):
        found = f.resolve(graph, '@loader_path/XF', symbol, agg); assert found['status'] == 'actualDirectExport'; newdefs.append(dict(name=symbol, proof=found))
    native = s.primary.captured_images()
    for group in ('system', 'stock-extra', 'cxx-leaf'): s.join_capture(native, group, n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf', 'xpc-leaf'): s.join_capture(native, group, n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    f.join_kernel(s, native)
    for fn in (f.join_hid_extra, f.join_swift_two, f.join_eight, f.join_three, f.join_trace, f.join_unwind, f.join_compiler, f.join_crypto): fn(s, native)
    assert len(native) == 36
    native_defs = []; raw = provider.read_bytes(); deps = {row['ordinal']: row['path'] for row in p.dependencies(raw)}
    for row in q.q.import_records(raw, p.commands)['imports']:
        assert row['ordinal'] > 0 and not row['weak']; found = s.primary.resolve(native, deps[row['ordinal']], row['name']); assert found['status'] == 'actualDirectExport'
        native_defs.append(dict(row, owner=deps[row['ordinal']], definition=found))
    personality_owner = {row['ordinal']: row['path'] for row in p.dependencies(before)}[18]
    personality_def = s.primary.resolve(native, personality_owner, '___gxx_personality_v0'); assert personality_def['status'] == 'actualDirectExport'
    after = transform(before); verification = validate(before, after)
    candidate = out/'VZ27.own-uikit-no-mac-packet.mac.inert.macho-data'; candidate.write_bytes(after); candidate.chmod(0o600)
    negatives = []
    for label, off in (('original CG callback cleanup', 0x22607d270-ORIGINAL_BASE), ('original packet code', 0x22607cb30-ORIGINAL_BASE), ('original LSDA', proof['tables'][0]['lsdaRVA']+7),
        ('genuine sender', 0x5c770), ('genuine six-argument initializer', 0x6494c), ('original metadata', 0x2f0600),
        ('original packet PAC', q.q.stub_for(before, 308)['chain']['at']+7), ('packet strong ordinal', q.q.import_records(after, p.commands)['imports'][308]['command']), ('packet refusal name', q.q.strings(before)[308][0])):
        bad = bytearray(after); bad[off] ^= 1
        try: validate(before, bytes(bad))
        except (AssertionError, ValueError): negatives.append(dict(name=label, rejected=True))
        else: raise AssertionError('damaged packet port accepted')
    for label, op in (('missing packet provider', lambda g: g.pop('@loader_path/'+provider.name)), ('ordinary load cannot reexport errors', lambda g: g['@loader_path/XF']['dependencies'][5].update(command=12))):
        bad = copy.deepcopy(graph); op(bad); assert f.resolve(bad, '@loader_path/XF', '_VM27RejectPacketV1', bad['@loader_path/XF'])['status'] != 'actualDirectExport'; negatives.append(dict(name=label, rejected=True))
    for file in (candidate, provider, aggregate): run('validate-'+file.name, ['xcrun', 'dyld_info', '-validate_only', file])
    p.save(out/'candidate.json', dict(schema='Independent own UIKit explicit mac CG packet refusal source port v1',
        sourceFrontend=base, frontendCandidate=p.pin(candidate), frontendAggregate=p.pin(aggregate), explicitPacketProvider=p.pin(provider),
        sourceFiles=[p.pin(file) for file in sources], wholeCopiedPreviousProviders=copies, originalCleanupProof=p.pin(out/'original-cleanup-proof.json'),
        verification=verification, previousTwentyNineReexportDefinitionsPreserved=retained, explicitPacketDefinitions=newdefs,
        providerCurrentStrongImports=native_defs, originalPersonalityCurrentDefinition=personality_def, negativeControls=negatives,
        originalMacArtifactPreserved=True, borrowedArgumentsNotConsumed=True, fakeCGPacketsIntegerFieldsNSEventsOrSLSExportsProvided=False,
        originalVZSenderFramesAndVMExecutorPreserved=True, ownUIKitInputAndSixParameterInitializerPreserved=True,
        originalCPPCallersExecuted=False, originalOuterAsyncExceptionPolicyVerified=False, actualIOSPacketProviderExecuted=False,
        originalVZLoaded=False, completeCurrentStrongLoadGraph=False, providerSigningCalls=0, deviceOperations=0, nativeCPUCalls=0, guestInstructions=0, full27Backend=False))
    pins += [p.pin(Path(__file__))]+[p.pin(file) for file in sources]+[p.pin(file) for file in out.rglob('*') if file.is_file()]
    pins += [p.pin(HERE/'prepare-modern-vz-own-uikit-packet-port-v1.py')]+[p.pin(file) for file in (n/'vz-own-uikit-packet-source-port-data-v1').rglob('*') if file.is_file()]
    p.save(out/'freeze.json', dict(files=list({row['path']: row for row in pins}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'), freeze=p.pin(out/'freeze.json'), verification=verification, provider=p.pin(provider), currentStrongImports=len(native_defs))))

if __name__ == '__main__':
    try: main()
    except Exception as exc:
        out = n/'vz-own-uikit-packet-source-port-data-v2'
        if out.exists(): p.save(out/'failure.json', dict(error=repr(exc), candidateWritten=(out/'candidate.json').exists(), deviceOperations=0)); (out/'failed-builder.py').write_bytes(Path(__file__).read_bytes())
        raise
