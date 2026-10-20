#!/usr/bin/env python3
"""Scoped genuine DI2 HPKE closure; no framework/API/device execution.

Restore original import contracts, five RTTI vtables+16, and exact private
providers. Fourteen missing HPKE imports are strongly routed to the separately validated
private natural provider; seven existing P256 imports remain native CryptoKit.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, segments, cstring
spec = importlib.util.spec_from_file_location('rtti', Path(__file__).with_name('prepare-modern-diskimages2-rtti-data.py'))
rtti = importlib.util.module_from_spec(spec); spec.loader.exec_module(rtti)
SHA = lambda b: hashlib.sha256(b).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}

def flatten(path):
    if '/Versions/' in path:
        a, b = path.split('/Versions/'); path = a + '/' + b.split('/', 1)[1]
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', default='/var/root/VirtualMac2/testing/diskimages227-hpke-loadonly-v1')
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    ios = out / 'ios'; ios.mkdir(); source = out / 'source'; source.mkdir()
    input_path = N / 'di2-rtti-data-build-v2/DiskImages2.rtti-data.ios.dylib'
    original = input_path.read_bytes()
    assert SHA(original) == 'f393dd2ec3c3933bfb06d1d744da05f94c52cd1bfa56c746872040e88eaf8714'
    plan_path = N / 'diskimages2-reconstruct-root-v1/positive-routing-plan.json'
    plans = json.loads(plan_path.read_text())['plans']; assert len(plans) == 818
    ledger_path = N / 'di2-native-import-ledger-root-v2/ledger.json'
    ledger = json.loads(ledger_path.read_text()); native = {r['original']['name']: r for r in ledger['rows']}
    assert len(native) == 724
    private_rows = {name: r for name, r in native.items() if not r['native']['found']}
    assert len(private_rows) == 45
    deps = [dict(command=c, path=cstring(original, a + struct.unpack_from('<I', original, a + 8)[0]))
            for c, a, _ in commands(original) if c in (0xc, 0x80000018, 0x8000001f, 0x80000023)]
    assert len(deps) == 31 and deps[30]['path'] == '/usr/lib/libc++abi.dylib'
    provider_files = []
    cxx_plan = N / 'vmm-runtime-aggregate-v1/build-v4/consumer-plan.json'
    provider_files.extend(r for r in json.loads(cxx_plan.read_text())['files'] if r['path'].endswith('.dylib'))
    assert len(provider_files) == 4
    for name in ('di2-typed-allocator-probe-build-v1', 'di2-constants-probe-build-v1'):
        provider_files.extend(r for r in json.loads((N / name / 'manifest.json').read_text())['files'] if r['path'].endswith('.dylib'))
    sec = next(r for r in json.loads((N / 'di2-security-unavailable-build-v1/candidate.json').read_text())['candidates'] if r['role'] == 'ios')['provider']
    provider_files.append(sec)
    qtn = next(r for r in json.loads((N / 'libquarantine-loadonly-build-v3/candidate.json').read_text())['candidates'] if r['role'] == 'ios')['library']
    provider_files.append(qtn)
    lookup = next(r for r in json.loads((N / 'diskimagekit-static-bootstrap-build-v12/manifest.json').read_text())['files'] if r['path'].endswith('/VM27SwiftLookup.dylib'))
    provider_files.append(lookup)
    assert len(provider_files) == 9
    hpke_plan_path = N / 'hpke-original-sdk-fixture-build-v5/consumer-plan.json'
    assert SHA(hpke_plan_path.read_bytes()) == 'ff3cc5257a5fa8f394ee79e7a07d48f40c1dd155cf34f3444ac7e8dc5aac1854'
    hpke_plan = json.loads(hpke_plan_path.read_bytes())
    hpke = next(r for r in hpke_plan['files'] if r['name'] == 'VM27HPKECompat.dylib')
    provider_files.append(hpke)
    hpke_aliases_path = N / 'hpke-compat-build-v6/aliases.json'
    hpke_aliases = json.loads(hpke_aliases_path.read_bytes())['aliases']
    hpke_names = {r['originalSymbol'] for r in hpke_aliases if not r['originalSymbol'].endswith('Mc')}
    assert len(hpke_names) == 14 and not hpke_names.intersection(private_rows)
    pins = []
    for row in provider_files:
        p = Path(row['path']); data = p.read_bytes()
        assert len(data) == row['bytes'] and SHA(data) == row['sha256']
        uuid = next(data[a + 8:a + 24].hex() for c, a, _ in commands(data) if c == 0x1b)
        assert uuid == row.get('UUID', row.get('uuid', uuid))
        destination = ios / p.name; destination.write_bytes(data)
        pins.append(dict(name=p.name, path=str(destination), bytes=len(data), sha256=SHA(data), UUID=uuid,
                         CDHash=row.get('CDHash', row.get('cdhash')), unchangedFromFrozenProvider=True))
    log = []
    def run(label, argv):
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout); (out / (label + '.stderr')).write_bytes(stderr)
        log.append(dict(label=label, argv=argv, PID=child.pid, wait=child.returncode, reaped=True))
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-3000:]
        return stdout, stderr
    def sign(label, path, rights=None):
        argv = ['codesign', '--force', '--sign', '-', '--timestamp=none']
        if rights:
            p = out / (label + '.entitlements.plist'); p.write_bytes(plistlib.dumps(rights)); argv += ['--entitlements', str(p)]
        run(label + '-sign', argv + [str(path)])
        run(label + '-strict', ['codesign', '--verify', '--strict', str(path)])
        run(label + '-dyld', ['xcrun', 'dyld_info', '-validate_only', str(path)])
        _, s = run(label + '-signature', ['codesign', '-d', '--verbose=4', str(path)])
        actual, _ = run(label + '-rights', ['codesign', '-d', '--entitlements', ':-', str(path)])
        assert (plistlib.loads(actual) if actual else {}) == (rights or {})
        b = path.read_bytes()
        return dict(name=path.name, path=str(path), bytes=len(b), sha256=SHA(b),
                    UUID=next(b[a + 8:a + 24].hex() for c, a, _ in commands(b) if c == 0x1b),
                    CDHash=re.search(rb'CDHash=([0-9a-f]{40})', s)[1].decode(), entitlements=rights or {})
    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'])[0].decode().strip()
    umbrella_source = source / 'di2-compat.c'
    umbrella_source.write_text('const char VM27DI2CompatibilityContract[] = "genuine27 exact private providers; no emulated success";\n')
    umbrella = ios / 'VM27DI2Compat.dylib'
    reexports = ['VM27CxxABICompat.dylib', 'VM27DiskAllocatorProvider.dylib', 'VM27DiskImageConstants.dylib',
                 'VM27DI2SecurityUnavailable.dylib', 'Libquarantine27.dylib', 'VM27SwiftLookup.dylib', 'VM27HPKECompat.dylib']
    argv = ['xcrun', 'clang', '-dynamiclib', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
            '-fptrauth-abi-version=0', '-fno-typed-memory-operations-experimental', '-Wall', '-Wextra', '-Werror',
            str(umbrella_source), '-Wl,-no_adhoc_codesign', '-Wl,-install_name,@rpath/VM27DI2Compat.dylib', '-Wl,-rpath,@loader_path']
    for name in reexports: argv += ['-Wl,-reexport_library,' + str(ios / name)]
    argv += ['-o', str(umbrella)]; run('umbrella-build', argv)
    umbrella_data = bytearray(umbrella.read_bytes()); at = next(a for c, a, _ in commands(umbrella_data) if c == 0x32)
    struct.pack_into('<III', umbrella_data, at + 8, 2, 0x100100, 0x100100)
    # The frozen lookup provider retains its original standalone diagnostic
    # install ID. Change only this new consumer's re-export route; retain the
    # provider bytes/UUID and require its actual private canonical identity.
    lookup_id = '/var/root/VirtualMac2/testing/modern-swift-lookup-wrapper-native-v1/lookup_wrapper.ios.dylib'
    repaired = 0
    for c, a, size in commands(umbrella_data):
        if c != 0x8000001f: continue
        offset = struct.unpack_from('<I', umbrella_data, a + 8)[0]
        if cstring(umbrella_data, a + offset) == lookup_id:
            replacement = b'@loader_path/VM27SwiftLookup.dylib\0'
            assert offset + len(replacement) <= size
            umbrella_data[a + offset:a + size] = replacement + bytes(size - offset - len(replacement))
            repaired += 1
    assert repaired == 1
    umbrella.write_bytes(umbrella_data)
    pins.append(sign('umbrella', umbrella))
    actual_reexports = [cstring(umbrella.read_bytes(), a + struct.unpack_from('<I', umbrella.read_bytes(), a + 8)[0])
                       for c, a, _ in commands(umbrella.read_bytes()) if c == 0x8000001f]
    assert actual_reexports == ['@rpath/' + name for name in reexports[:5]] + ['@loader_path/VM27SwiftLookup.dylib', '@rpath/VM27HPKECompat.dylib']
    data = bytearray(original); packed = bytearray(); lc_changes = []
    for c, a, size in commands(original):
        if c in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0xd):
            old = cstring(original, a + struct.unpack_from('<I', original, a + 8)[0])
            new = '@rpath/DiskImages227.dylib' if c == 0xd else flatten(old)
            length = (24 + len(new.encode()) + 1 + 7) & ~7
            cmd = bytearray(original[a:a + 24]); struct.pack_into('<II', cmd, 4, length, 24)
            cmd += new.encode() + b'\0' + bytes(length - 24 - len(new.encode()) - 1)
            packed += cmd
            lc_changes.append(dict(command=hex(c), before=old, after=new, beforeBytes=size, afterBytes=length))
        else: packed += original[a:a + size]
    path = b'@loader_path/VM27DI2Compat.dylib\0'; length = (24 + len(path) + 7) & ~7
    packed += struct.pack('<6I', 0xc, length, 24, 2, 0x10000, 0x10000) + path + bytes(length - 24 - len(path))
    first = min(s['fileoff'] for g in segments(original) if g['name'] != '__LINKEDIT' for s in g['sections'] if s['size'] and s['fileoff'])
    assert 32 + len(packed) <= first
    old_end = 32 + struct.unpack_from('<I', original, 20)[0]
    data[32:old_end] = packed + bytes(old_end - 32 - len(packed))
    struct.pack_into('<II', data, 16, struct.unpack_from('<I', original, 16)[0] + 1, len(packed))
    imports = rtti.output_imports(original); assert len(imports) == 818
    fixup = next(a for c, a, _ in commands(data) if c == 0x80000034)
    base = struct.unpack_from('<I', data, fixup + 8)[0]; entries = struct.unpack_from('<I', data, base + 8)[0]
    routes = []; provider_roles = {}
    for name, row in private_rows.items():
        status = row['status']
        if status.startswith('private-Cxx'): owner = 'VM27CxxABICompat.dylib'
        elif status.startswith('private-typed-allocator'): owner = 'VM27DiskAllocatorProvider.dylib'
        elif status.startswith('private-CFString'): owner = 'VM27DiskImageConstants.dylib'
        elif status.startswith('desktop-authorization'): owner = 'VM27DI2SecurityUnavailable.dylib'
        elif status.startswith('quarantine-'): owner = 'Libquarantine27.dylib'
        elif status.startswith('private-swift-lookup'): owner = 'VM27SwiftLookup.dylib'
        else: raise AssertionError(status)
        provider_roles[name] = owner
    assert len(provider_roles) == 45
    provider_roles.update({name:'VM27HPKECompat.dylib' for name in hpke_names})
    assert len(provider_roles) == 59
    for i, (row, plan) in enumerate(zip(imports, plans)):
        assert plan['index'] == i
        if plan['policy'] == 'unproven-converter-named-RTTI-D1-route':
            assert row['name'].startswith('__ZTVN10__cxxabiv1') and row['ordinal'] == 31 and row['addend'] == 16 and not row['weak']
            ordinal, weak, policy = 31, False, 'original-cache-vtable-address-point+16-DA0'
        else:
            assert row['name'] == plan['symbol'] and row['addend'] == 0
            if row['name'] in provider_roles:
                ordinal, weak, policy = 32, False, 'strong-exact-private-provider-reexport'
            else:
                ordinal = plan['proposedOrdinal']
                weak = plan['proposedWeak'] if plan['policy'] == 'restore-exact-original-nlist-contract' else False
                policy = plan['policy']
        cell = base + entries + i * 8; word = struct.unpack_from('<I', data, cell)[0]
        struct.pack_into('<I', data, cell, (word & ~511) | ordinal | (int(weak) << 8))
        routes.append(dict(index=i, name=row['name'], ordinal=ordinal, weak=weak, addend=row['addend'], policy=policy,
                           exactPrivateOwner=provider_roles.get(row['name']), ABIProven=False if ordinal != 32 else 'provider-scoped-only'))
    for section in [s for g in segments(original) for s in g['sections'] if s['size'] and s['fileoff']]:
        a, b = section['fileoff'], section['fileoff'] + section['size']; assert data[a:b] == original[a:b]
    library = ios / 'DiskImages227.dylib'; library.write_bytes(data); pins.append(sign('di2', library))
    actual = rtti.output_imports(library.read_bytes())
    assert actual == [{k:r[k] for k in ('name', 'ordinal', 'weak', 'addend')} for r in routes]
    assert pins[-1]['UUID'] == 'a456d4a4d6ab3549965d0400f3552de3'
    assert all(r['ordinal'] > 0 for r in actual)
    runtime = args.native_directory.rstrip('/')
    def literal(b): return '{' + ','.join(str(v) for v in b) + '}'
    header = 'struct ImagePin {const char *path; size_t bytes; unsigned char sha[32]; const char *uuid;};\nstatic const struct ImagePin Images[]={\n'
    for pin in pins:
        header += '{' + json.dumps(runtime + '/' + pin['name']) + ',' + str(pin['bytes']) + ',' + literal(bytes.fromhex(pin['sha256'])) + ',' + json.dumps(pin['UUID']) + '},\n'
    header += '};\nstatic const unsigned ImageCount=' + str(len(pins)) + ', CompatIndex=10, DI2Index=11;\n'
    assert pins[9]['name'] == 'VM27HPKECompat.dylib' and pins[10]['name'] == 'VM27DI2Compat.dylib' and pins[11]['name'] == 'DiskImages227.dylib'
    name_index = {p['name']:i for i,p in enumerate(pins)}
    header += 'struct ProviderSymbol {const char *name; unsigned image; int data;};\nstatic const struct ProviderSymbol ProviderSymbols[]={\n'
    for name, owner in sorted(provider_roles.items()):
        header += '{' + json.dumps(name) + ',' + str(name_index[owner]) + ',' + str(int(owner == 'VM27DiskImageConstants.dylib' or (owner == 'VM27HPKECompat.dylib' and name.endswith(('N','Mn','WP'))))) + '},\n'
    header += '};\nstatic const unsigned ProviderSymbolCount=59;\n'
    header += 'static const char *ClassNames[5]={"DIOpenParams","DIImageHandle","DIDiskImageBridge","DICreateParams","DIAttachParams"};\n'
    methods_path = N / 'di2-desktop-services-static-contract-v1/selected-original-objc-methods.json'
    methods = [r for r in json.loads(methods_path.read_text())['rows'] if r['role']=='instance' and r['class'] in ('DIOpenParams','DIImageHandle') and r['selector'] in ('initWithURL:openMode:error:','openWithError:','UIOOpenMode','fileDescriptor','openMode','blockSize','blockCount','imageFormat')]
    assert len(methods) == 8
    header += 'struct MethodPin {const char *className; const char *selector; const char *encoding; uintptr_t rva;};\nstatic const struct MethodPin Methods[]={\n'
    for row in methods:
        header += '{' + ','.join(json.dumps(row[k]) for k in ('class','selector','encoding')) + ',' + hex(row['rawIMP']-0x23fd3e000) + '},\n'
    header += '};\nstatic const unsigned MethodCount=8;\n'
    (ios / 'diskimages227-pins.h').write_text(header)
    probe_source = ROOT / 'VirtualMac/vz/host/modern_diskimages2_hpke_loadonly_probe.c'
    (source / probe_source.name).write_bytes(probe_source.read_bytes())
    probe = ios / 'diskimages227-loadonly-probe'
    run('probe-build', ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-O2','-fptrauth-abi-version=0',
                       '-fno-typed-memory-operations-experimental','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',
                       '-I'+str(ios),str(source / probe_source.name),'-lobjc','-Wl,-no_adhoc_codesign','-o',str(probe)])
    image=bytearray(probe.read_bytes()); at=next(a for c,a,_ in commands(image) if c==0x32)
    struct.pack_into('<III',image,at+8,2,0x100100,0x100100); probe.write_bytes(image)
    probe_pin=sign('probe',probe,RIGHTS)
    for path in (Path(__file__), input_path, plan_path, ledger_path, cxx_plan, methods_path, hpke_plan_path, hpke_aliases_path):
        if path==input_path: continue
        (source / path.name).write_bytes(path.read_bytes())
    (out / 'binding-routes.json').write_text(json.dumps(routes,indent=2)+'\n')
    result=dict(nativeDirectory=runtime, files=pins+[probe_pin], inputSHA256=SHA(original), importsFormat=2, imports=818,
                strongImports=sum(not r['weak'] for r in routes), originalWeakContractsRestored=sum(r['weak'] for r in routes),
                exactPrivateRoutes=59, optimizedCryptoKit21RemainStrong=True, privateHPKEMissing14StronglyRouted=True, existingP2567RemainNative=True, HPKEPrivateNominalContext=True, originalCryptoKit27BinaryClaimed=False, LCChanges=lc_changes, originalDependenciesRemoved=0,
                extraStrongCompatibilityOwnerOrdinal=32, compatibilityReexports=actual_reexports, allSectionPayloadBytesUnchanged=True,
                originalRTTIVptrAuthWordsUnchanged=True, genuineDI2UUID=pins[-1]['UUID'], native679PresenceOnly=True,
                allNative679ABIsProven=False, additionalOptimizedImportNativeABIProven=False, sourceProbeMethods=methods,
                frameworkLoaded=False, DI2APICalls=0, RAWReadWriteVerified=False, deviceOperations=False, productionModified=False,
                full27Backend=False, commands=log)
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(candidate=str(out/'candidate.json'),files=[{k:p[k] for k in ('name','bytes','sha256','UUID')} for p in result['files']],strongImports=result['strongImports']),indent=2))

if __name__=='__main__': main()
