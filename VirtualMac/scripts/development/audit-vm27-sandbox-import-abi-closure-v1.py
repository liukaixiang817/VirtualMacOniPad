"""Freeze actual missing-import ABI, native routes and new bridge evidence."""
from pathlib import Path
import bisect
import collections
import datetime
import hashlib
import json
import plistlib
import re
import struct

ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
RAW = NODE / 'mac27-native-sandbox-compiler-readonly-v1-attempt1'
ABI = NODE / 'mac27-sandbox-remaining-import-abi-host-v1-attempt1'
PRODUCT = NODE / 'sandbox-compiler-imports-compat-unsigned-local-v3-attempt1'
OUT = NODE / 'mac27-sandbox-import-abi-closure-host-v1-attempt1'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def macho(path):
    data = Path(path).read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    offset = 32
    commands = []
    segments = []
    uuid = None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, offset)
        commands.append((command, offset, size))
        if command == 0x19:
            name = data[offset+8:offset+24].split(b'\0')[0].decode()
            address, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, offset+24)
            segments.append(dict(name=name, VA=address, VMSize=vmsize, fileoff=fileoff, filesize=filesize))
        if command == 0x1b:
            uuid = data[offset+8:offset+24].hex()
        offset += size
    symbol_command = next(x for x in commands if x[0] == 2)
    symoff, symcount, stroff, strsize = struct.unpack_from('<IIII', data, symbol_command[1]+8)
    strings = data[stroff:stroff+strsize]
    symbols = {}
    for index in range(symcount):
        string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', data, symoff+index*16)
        name = strings[string:strings.index(0, string)].decode()
        symbols[name] = dict(kind=kind, section=section, descriptor=descriptor, value=value)
    return dict(data=data, uuid=uuid, commands=commands, segments=segments,
                symbols=symbols, symoff=symoff, symcount=symcount)


def at(image, address, size):
    for segment in image['segments']:
        if segment['VA'] <= address and address+size <= segment['VA']+segment['filesize']:
            offset = segment['fileoff'] + address-segment['VA']
            return image['data'][offset:offset+size]
    raise ValueError('VA outside genuine captured image ' + hex(address))


def main():
    OUT.mkdir(exist_ok=False)
    product = json.loads((PRODUCT / 'candidate.json').read_bytes())
    assert pin(PRODUCT / 'candidate.json')['sha256'] == 'a9d47acc6eb45beab16067c5af67a2c0b7af487abc060809fcdad521079cf536'
    for row in json.loads((PRODUCT / 'freeze.json').read_bytes())['files']:
        assert pin(row['path']) == row, ('changed frozen product', row['path'])
    native_index = NODE / 'current-native-header-export-index-v3/index.json'
    assert pin(native_index)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    images = json.loads(native_index.read_bytes())['images']

    def resolve(path, symbol, seen=()):
        if (path, symbol) in seen or path not in images:
            return []
        image = images[path]
        definition = image['definitions'].get(symbol)
        found = []
        seen += ((path, symbol),)
        if definition:
            if definition['flags'] & 8:
                dependency = next(d for d in image['dependencies'] if d['ordinal'] == definition['ordinal'])
                for child in resolve(dependency['path'], definition.get('alias') or symbol, seen):
                    found.append({**child, 'route': [path] + child['route']})
            else:
                found.append(dict(route=[path], provider=path, UUID=image['UUID'],
                                  resolvedSymbol=symbol, definition=definition))
        for dependency in image['dependencies']:
            if dependency['command'] == 0x8000001f:
                for child in resolve(dependency['path'], symbol, seen):
                    found.append({**child, 'route': [path] + child['route']})
        return found

    compiler = macho(RAW / 'libsandbox.1.dylib')
    system = macho(ABI / 'libsystem_sandbox.dylib')
    darwin = macho(ABI / 'libsystem_darwin.dylib')
    bridge = macho(product['binary']['path'])
    assert compiler['uuid'] == '648b6ec9b80a3673ac47f6f7806bb158'
    assert system['uuid'] == '1e892b56092e3832bde3dce356d7a4fa'
    assert len(system['data']) == 114128
    assert len(darwin['data']) == 123384
    constants = []
    for symbol, address, expected in [('_SANDBOX_STORAGE_CLASS_GROUP_ANY', 0x18eb41b38, 0),
            ('_SANDBOX_STORAGE_CLASS_PROPERTY_WRITE_RESTRICTED', 0x18eb41b48, 2)]:
        assert system['symbols'][symbol]['value'] == address
        genuine = at(system, address, 8)
        assert struct.unpack('<Q', genuine)[0] == expected
        new = at(bridge, bridge['symbols'][symbol]['value'], 8)
        assert new == genuine
        constants.append(dict(symbol=symbol, genuineVA=hex(address), widthBytes=8,
                              genuineRawHex=genuine.hex(), value=expected,
                              actualUnsignedBridgeWholeDataBytesEqual=True))
    base_entry = darwin['symbols']['_os_variant_is_basesystem']['value']
    recovery_entry = darwin['symbols']['_os_variant_is_recovery']['value']
    assert base_entry == 0x1849f7ebc and recovery_entry == 0x1849f72c8
    shared = 0x1849f72cc
    for address in [base_entry, recovery_entry]:
        word = struct.unpack('<I', at(darwin, address, 4))[0]
        assert word & 0xfc000000 == 0x14000000
        immediate = word & 0x3ffffff
        if immediate & (1 << 25):
            immediate -= 1 << 26
        assert address + immediate * 4 == shared
    darwin_native = images['/usr/lib/system/libsystem_darwin.dylib']
    assert darwin_native['UUID'] == '2f7e2d4e1ed3311699e28132b208bbd3'
    assert darwin_native['definitions']['_os_variant_is_recovery'] == dict(flags=0, offset=0x27c4)
    source = (ABI / 'apple-Libc-variant.c').read_text()
    assert '#define BASE_SYSTEM_CONTENT_PATH "/System/Library/BaseSystem"' in source
    assert 'base_system_content = (access(path, F_OK) == 0)' in source
    assert 'recovery_release_type = (strstr(release_type, "Recovery") != NULL)' in source
    assert '#if TARGET_OS_OSX\nbool\nos_variant_is_basesystem' in source
    sdk = ROOT / 'VirtualMac/vendor/libmalloc-typed-backport/upstream/SDK27.1-_malloc.h'
    assert 'malloc_type_free_backdeploy(void * __unsafe_indexable ptr, malloc_type_id_t type_id)' in sdk.read_text()
    graph = json.loads((ABI / 'compiler-direct-call-graph.json').read_bytes())
    assert graph['LCFunctionStartsCount'] == 725 and graph['reachableFunctionCount'] == 117
    refs = graph['externalReferencesToMissingAPIs']
    assert refs['variant'][0]['reachableByDirectEdgesFromCompileParameterAndFreeAPIs']
    assert all(len(refs[k]) == 1 and not refs[k][0]['reachableByDirectEdgesFromCompileParameterAndFreeAPIs']
               for k in ['notify', 'rootless', 'storage'])
    pointer_matches = graph['actualFullRawFilePointerMatchesForSuspectFunctionStarts']
    for row in pointer_matches:
        offset = int(row['fileOffset'], 16)
        assert compiler['symoff'] <= offset < compiler['symoff'] + compiler['symcount']*16
        assert (offset - compiler['symoff']) % 16 == 8
    actual_map = json.loads((NODE / 'mac27-sandbox-compiler-reconstructed-host-v3-attempt1/symbols.a2s.batch.json').read_bytes())['symbols']
    assert actual_map['0x1880f9bd0'][0] == '__sandbox_enter_notify_libxpc'
    assert actual_map['0x1880f9ce0'][0] == '_rootless_protected_volume_fd'
    assert actual_map['0x1880f9cf0'][0] == '_sandbox_check_storage_class'
    assert actual_map['0x1880e5ed0'][0] == '_os_variant_is_basesystem'
    ranges = []
    text_lines = (RAW / 'libsandbox.text.llvm.txt').read_text().splitlines()
    for name, start, end in [('compile-real-variant-and-root-translation', 0x184e62eac, 0x184e62eec),
            ('Mac-apply-notify-after-real-kernel-return-zero', 0x184e81028, 0x184e810dc),
            ('bundle-rootless-fd-and-negative-error-route', 0x184e82624, 0x184e82640),
            ('bundle-scan-local-storage-callback', 0x184e83510, 0x184e83564),
            ('storage-fd-uint64-values-and-negative-error-route', 0x184e837a8, 0x184e837f4)]:
        code = at(compiler, start, end-start)
        lines = [line for line in text_lines if re.match(r'[0-9a-f]+:', line)
                 and start <= int(line.split(':')[0], 16) < end]
        assert len(lines) == (end-start)//4
        ranges.append(dict(name=name, genuineStartVA=hex(start), genuineEndVAExclusive=hex(end),
                           wholeCodeBytesSHA256=hashlib.sha256(code).hexdigest(), actualLLVMDisassembly=lines))
    save('focused-real-code.json', ranges)
    imports = json.loads((RAW / 'captured-current-libsystem-import-routes.json').read_bytes())
    assert imports['importEntries'] == 184
    runtime_candidate_path = NODE / 'independent27-signed-runtime-product-v7-attempt1/candidate.json'
    runtime = json.loads(runtime_candidate_path.read_bytes())
    manifest = plistlib.loads(Path(runtime['manifest']['path']).read_bytes())
    allocator_row = next(row for row in manifest['files'] if row['id'] == 'child:VM27AllocatorProvider.dylib')
    allocator_path = Path(runtime['runtimeRoot']) / allocator_row['path']
    assert pin(allocator_path)['bytes'] == allocator_row['bytes']
    assert pin(allocator_path)['sha256'] == allocator_row['sha256']
    allocator = macho(allocator_path)
    reuse_symbols = ['_malloc_type_malloc', '_malloc_type_calloc', '_malloc_type_realloc']
    for symbol in reuse_symbols:
        assert allocator['symbols'][symbol]['kind'] & 14 == 14
    closed = []
    for entry in imports['entries']:
        if entry['mac27MatchOrdinal']:
            closed.append(dict(image=entry['image'], symbol=entry['symbol'], binding='genuine Mac27 Match ordinal'))
        else:
            routes = resolve('/usr/lib/libSystem.B.dylib', entry['symbol'])
            if routes:
                closed.append(dict(image=entry['image'], symbol=entry['symbol'], binding='captured native LibSystem routes', routes=routes))
            elif entry['symbol'] in reuse_symbols:
                closed.append(dict(image=entry['image'], symbol=entry['symbol'], binding='reuse actual signed allocator', provider=pin(allocator_path)))
            else:
                assert entry['symbol'] in product['exactExports']
                closed.append(dict(image=entry['image'], symbol=entry['symbol'], binding='new explicit typed import bridge', provider=product['binary']))
    assert len(closed) == 184
    counts = collections.Counter(row['binding'] for row in closed)
    assert counts == {'captured native LibSystem routes': 167, 'genuine Mac27 Match ordinal': 6,
                      'reuse actual signed allocator': 4, 'new explicit typed import bridge': 7}
    bridge_imports = re.findall(r'^\s+0x[0-9a-fA-F]+\s+(\S+)\s+\(from libSystem\)',
                               (PRODUCT / 'ios-imports.stdout').read_text(), re.M)
    assert len(bridge_imports) == 13
    bridge_routes = []
    for symbol in bridge_imports:
        routes = resolve('/usr/lib/libSystem.B.dylib', symbol)
        assert routes, symbol
        bridge_routes.append(dict(symbol=symbol, actualNativeLibSystemRoutes=routes))
    save('all-184-import-symbol-routes.json', closed)
    save('all-13-new-bridge-native-import-routes.json', bridge_routes)
    required_native = {'/usr/lib/system/libsystem_darwin.dylib'}
    for row in closed + bridge_routes:
        for route in row.get('routes', row.get('actualNativeLibSystemRoutes', [])):
            required_native.update(route['route'])
    actual_native_ranges = []
    for path in sorted(required_native):
        image = images[path]
        for row in image.get('actualCommandSourceRanges', []):
            actual_native_ranges.append(row['rangePin'])
        actual_native_ranges.append(image['actualCompleteExportSource']['rangePin'])
    for row in actual_native_ranges:
        assert pin(row['path']) == row, ('native capture changed', row['path'])
    report = dict(schema='Actual genuine Mac27 compiler missing import ABI and explicit closure HOST audit v1',
        recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope=dict(deviceOperations=0, sandboxApplyCalls=0, nativeRecoveryCalls=0,
                   nativeMainAndFlagsModified=False, actualIPadCompilerRun=False,
                   actualIPadBytecodePolicyCompatibilityVerified=False),
        genuineImages=dict(compiler=pin(RAW / 'libsandbox.1.dylib'),
            systemSandbox=dict(**pin(ABI / 'libsystem_sandbox.dylib'), UUID=system['uuid']),
            systemDarwin=dict(**pin(ABI / 'libsystem_darwin.dylib'), UUID=darwin['uuid'])),
        actualNativeIndex=pin(native_index), actualCapturedNativeProviders=len(required_native),
        originalMissing=dict(importEntries=11, uniqueSymbols=10, exactEntries=imports['unresolvedCapturedTreeEntries']),
        twoRealStorageConstants=constants,
        typedFree=dict(ABI='void(void *, uint64_t)', source=pin(sdk), sourceLines='91-99',
            behavior='Apple backdeployment uses real legacy free(pointer) when typed free is unavailable; type_id does not replace allocator ownership.',
            actualBridgeCallsRealLegacyFree=True, actualHostNormalAndSanitizerAllocationReleasePassed=True),
        reuseAllocator=dict(provider=pin(allocator_path), UUID=allocator_row['uuid'],
            symbols=reuse_symbols, source=pin(ROOT / 'VirtualMac/vz/host/modern_typed_allocator_compat.c')),
        variant=dict(ABI='bool(const char *)', actualMacBaseSystemEntryVA=hex(base_entry),
            actualMacRecoveryEntryVA=hex(recovery_entry), actualSharedCoreVA=hex(shared),
            actualBothEntriesAreFourByteDirectBranchesIntoSameCore=True,
            actualNativeIPadRecovery=dict(path='/usr/lib/system/libsystem_darwin.dylib', UUID=darwin_native['UUID'], RVA=0x27c4,
                exactExport=darwin_native['definitions']['_os_variant_is_recovery']),
            explicitAdaptation='Delegate to guarded current native iOS Recovery boot-role bool; do not supply a fixed answer.',
            actualIPadRoleNotObserved=True, platformDifference='Apple Mac reads BaseSystem content; iOS Recovery derives from actual SystemVersion ReleaseType.',
            primaryURL='https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/libdarwin/variant.c',
            capturedPrimarySource=pin(ABI / 'apple-Libc-variant.c'), relevantPrimaryLines='90,326-339,426-443,718-732',
            compileCallsite='0x184e62eb4', subsystem='com.apple.sandbox',
            realConditionalSysctl='security.mac.sandbox.root_translation_enabled',
            nativeGuardFailure='Diagnostic then trap; it cannot become false.'),
        unusedAPIABIs=[dict(symbol='_rootless_protected_volume_fd', ABI='int(int fd)',
            genuineEntryVA='0x18eb409f0', actualCodeBytes=84, genuineSandboxKernelOperation=260,
            genuineResult='native success -> 0/1 using uint64 output; failure -> -1',
            onlyCompilerCallsite='0x184e82628', callerExport='_bundle_hardlink_verifier_set_bundle_root_fd',
            directCompileReachable=False, bridge='errno ENOTSUP and -1'),
            dict(symbol='_sandbox_check_storage_class', ABI='int(int fd, uint64_t properties, uint64_t group)',
                genuineEntryVA='0x18eb3fb10', actualCodeBytes=84, genuineSandboxKernelOperation=87,
                genuineResult='native success -> inverted byte result; failure -> -1',
                onlyCompilerCallsite='0x184e837d4', genuineCallbackVA='0x184e83754',
                callbackIsMaterializedInBundleScanHelperAtVA='0x184e8353c',
                callerAPI='_bundle_integrity_scan_fd', directCompileReachable=False,
                bridge='errno ENOTSUP and -1'),
            dict(symbol='__sandbox_enter_notify_libxpc', ABI='void(void)',
                genuineEntryVA='0x18eb3e090', actualFunctionCodeBytes=60,
                trueDlsymName='_xpc_runtime_process_has_entered_sandbox',
                genuineMissingCallbackIsFatal=True, onlyCompilerCallsite='0x184e810c4',
                callerExport='_sandbox_apply_container', genuineOnlyAfterKernelApplyReturnsZero=True,
                directCompileReachable=False, bridge='Diagnostic then trap; never a no-op')],
        actualDirectTransferGraph=dict(evidence=pin(ABI / 'compiler-direct-call-graph.json'),
            actualLCFunctionStartsCount=725, actualDirectReachableFunctions=117,
            roots=['sandbox_compile_file', 'sandbox_create_params', 'sandbox_set_param', 'sandbox_free_params', 'sandbox_free_profile'],
            variantReachable=True, otherThreeAPIsDirectReachable=False,
            rawPointerMatchesAreOnlyNListSymbolValueRecords=True,
            boundary='This proves the complete direct-transfer graph. The storage callback is indirect in a bundle-scan helper; TinyScheme callbacks and future arguments still require actual bounded compile evidence. It does not prove universal semantic unreachability.'),
        exactSymbolClosure=dict(originalEntries=184, actualNativeEntries=167, actualGenuineMatchEntries=6,
            actualReusedAllocatorEntries=4, actualNewBridgeEntries=7, uniqueMissingCovered=10,
            exact184Routes=pin(OUT / 'all-184-import-symbol-routes.json'),
            actualNewBridgeImports=13, all13ResolvedThroughCapturedNativeLibSystem=True,
            exact13Routes=pin(OUT / 'all-13-new-bridge-native-import-routes.json'),
            uncapturedNativeLibSystemReexportPaths=imports['uncapturedReexportPaths'],
            extraNativeExportCapturesRequiredForTheseRequestedBindings=[],
            boundary='Named routes close these actual symbol imports; presence does not prove ABI or behavior of every Mac LibSystem call on iOS. Reconstructed iOS library binding and actual compile remain required.'),
        actualUnsignedBridgeCandidate=pin(PRODUCT / 'candidate.json'),
        actualUnsignedBridgeFreeze=pin(PRODUCT / 'freeze.json'),
        realReconstructedHostCompile=pin(NODE / 'mac27-reconstructed-sandbox-compile-only-host-v3-attempt1/report.json'),
        remainingRequiredWork=['Independent source and unsigned product review.',
            'Retarget the two genuine reconstructed libraries to explicit native/allocator/new-bridge routes without changing their code semantics.',
            'Use the compiler-owned opaque profile and original producer free in production; the diagnostic 24-byte wrapper remains probe-only.',
            'The production adapter must call current iPad native apply, never the exported Mac apply routine.',
            'Bounded owned iPad compile with real resources must record actual native role and complete genuine output; never assume its bytes match HOST.',
            'Successful compilation or symbol closure alone does not establish kernel policy or all-operation compatibility.'],
        findings=[])
    save('report.json', report)
    files = [Path(__file__).resolve(), native_index, sdk, runtime_candidate_path, Path(runtime['manifest']['path']), allocator_path]
    files += [Path(row['path']) for row in actual_native_ranges]
    files += [RAW / 'libsandbox.1.dylib', RAW / 'libsandbox.text.llvm.txt', RAW / 'captured-current-libsystem-import-routes.json',
              NODE / 'mac27-sandbox-compiler-reconstructed-host-v3-attempt1/symbols.a2s.batch.json',
              NODE / 'mac27-reconstructed-sandbox-compile-only-host-v3-attempt1/report.json']
    files += [Path(row['path']) for row in json.loads((PRODUCT / 'freeze.json').read_bytes())['files']]
    files += [PRODUCT / 'freeze.json']
    for directory in [ABI, OUT]:
        files.extend(path for path in directory.iterdir() if path.is_file())
    save('freeze.json', dict(schema='Actual Mac27 missing import ABI closure HOST freeze v1',
                             deviceOperations=0, sandboxApplyCalls=0,
                             files=[pin(path) for path in sorted(set(files))]))
    print(json.dumps(dict(report=pin(OUT / 'report.json'), freeze=pin(OUT / 'freeze.json'))))


if __name__ == '__main__':
    main()
