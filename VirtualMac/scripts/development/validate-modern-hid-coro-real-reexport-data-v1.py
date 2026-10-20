#!/usr/bin/env python3
"""Independently rederive finite coroutine routes and reject changed contracts."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('coro_review_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
CANDIDATE = p.NODE / 'universalhid-coro-real-reexport-data-v2/candidate.json'
ARRAY = p.NODE / 'universalhid-real-array-reexports-data-v1/candidate.json'
BUILD = p.NODE / 'swift-coro-frame-data-build-v2/candidate.json'
ABI = p.NODE / 'swift-coro-allocation-original-abi-v4/audit.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked(path):
    for row in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        require(p.pin(Path(row['path'])) == row, 'immutable input pin')
    return json.loads(path.read_bytes())


def section_ranges(raw):
    return [section for segment in p.segments(raw) for section in segment['sections'] if section['fileoff'] and section['size']]


def validate_ar(old, new):
    count, size = struct.unpack_from('<II', old, 16)
    expected = bytearray(old)
    command = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/CR\0'
    require(len(command) == 40, 'exact new command extent')
    require(not any(old[32 + size:32 + size + 40]), 'unused header padding')
    struct.pack_into('<II', expected, 16, count + 1, size + 40)
    expected[32 + size:32 + size + 40] = command
    require(new == expected, 'only exact AR reexport header changed')
    olddeps, newdeps = p.dependencies(old), p.dependencies(new)
    require(len(olddeps) == 2 and len(newdeps) == 3, 'AR dependency count')
    require(newdeps[:2] == olddeps, 'old AR dependencies')
    require(newdeps[2]['ordinal'] == 3 and newdeps[2]['command'] == 0x8000001f and newdeps[2]['path'] == '@loader_path/CR', 'strong real reexport')
    require(p.imports(new)['imports'] == p.imports(old)['imports'], 'unchanged actual AR imports')


def validate_hid(old, new, index, ordinal):
    oldrows, newrows = p.imports(old)['imports'], p.imports(new)['imports']
    selected = next(x for x in oldrows if x['name'] == '_swift_coroFrameAlloc')
    require(selected['index'] == index and selected['ordinal'] == 8 and not selected['weak'], 'original strong exact import')
    offset = selected['command']
    expected = bytearray(old)
    expected[offset] = ordinal
    require(new == expected, 'one exact strong ordinal byte only')
    for a, b in zip(oldrows, newrows, strict=True):
        require(b == ({**a, 'ordinal': ordinal} if a['index'] == index else a), 'unchanged other import records')
    require(len(old) == len(new), 'no image extent change')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'fresh local output')
    out.mkdir()
    candidate, array, build, abi = [checked(x) for x in (CANDIDATE, ARRAY, BUILD, ABI)]
    require(not any(candidate[k] for k in ('typedAllocatorTelemetryPreserved', 'allCoroutineLifecycleValidated',
        'fullSwift27RuntimeEquivalent', 'currentCompleteProviderDependencyGraphValidated', 'metadataCompatibilityProven',
        'originalUHLoaded', 'originalVZLoaded', 'nativeIOSExecuted', 'deviceOperations', 'codeSigned', 'full27Backend')), 'finite inert boundary')
    arsource = next(x for x in array['unchangedRuntimeProviders'] if x['alias'] == 'AR')['candidate']
    require(arsource == candidate['modifiedArrayReexportProvider']['source'], 'actual AR base')
    old_ar = Path(arsource['path']).read_bytes()
    arfile = Path(candidate['modifiedArrayReexportProvider']['candidate']['path'])
    new_ar = arfile.read_bytes()
    validate_ar(old_ar, new_ar)
    require(candidate['modifiedArrayReexportProvider']['preexistingSignatureInvalidAfterHeaderMutation'], 'stale original signature explicit')
    negatives = []
    def reject(label, validator, original, at, mask):
        damaged = bytearray(original)
        damaged[at] ^= mask
        try:
            validator(bytes(damaged))
        except (ValueError, AssertionError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise ValueError('negative accepted: ' + label)
    headerend = 32 + struct.unpack_from('<I', old_ar, 20)[0]
    artest = lambda body: validate_ar(old_ar, body)
    reject('normal load instead of required AR reexport', artest, new_ar, headerend, 0x13)
    reject('weak AR dependency', artest, new_ar, headerend, 7)
    reject('wrong CR owner path', artest, new_ar, headerend + 37, 1)
    reject('wrong AR dependency ordinal count', artest, new_ar, 16, 1)
    reject('wrong AR command timestamp', artest, new_ar, headerend + 12, 1)
    reject('genuine AR instruction', artest, new_ar, next(x['fileoff'] for x in section_ranges(old_ar) if x['name'] == '__text'), 1)
    reject('original AR linkedit/signature bytes', artest, new_ar, len(new_ar) - 1, 1)
    destinations = []
    for name, index, ordinal in (('UniversalHID', 347, 20), ('UniversalHIDKit', 123, 1)):
        source = next(x for x in array['images'] if x['name'] == name)['candidate']
        plan = next(x for x in candidate['images'] if x['name'] == name)
        require(plan['source'] == source, 'actual provider base')
        old = Path(source['path']).read_bytes()
        new = Path(plan['candidate']['path']).read_bytes()
        validator = lambda body, old=old, index=index, ordinal=ordinal: validate_hid(old, body, index, ordinal)
        validator(new)
        offset = next(x for x in p.imports(old)['imports'] if x['index'] == index)['command']
        reject(name + ' wrong import ordinal', validator, new, offset, 1)
        reject(name + ' weak import bit', validator, new, offset + 1, 1)
        reject(name + ' changed symbol name offset', validator, new, offset + 2, 1)
        reject(name + ' genuine instruction', validator, new, next(x['fileoff'] for x in section_ranges(old) if x['name'] == '__text'), 1)
        reject(name + ' original metadata', validator, new, next(x['fileoff'] for x in section_ranges(old) if x['name'].startswith('__swift5')), 1)
        chains = list(p.chain_entries(old))
        require(chains, 'actual chained pointer records')
        authenticated = next(x for x in chains if x['auth'])
        reject(name + ' actual PAC pointer word', validator, new, authenticated['fileoff'] + 4, 1)
        destinations.append(Path(plan['candidate']['path']))
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    crfile = Path(candidate['unchangedRuntimeProvider']['candidate']['path'])
    cr = crfile.read_bytes()
    require(cr == Path(ios['provider']['path']).read_bytes(), 'full true CR bytes preserved')
    require(not any(c == 0x1d for c, at, size in p.commands(cr)), 'CR unsigned inert')
    imports = p.imports(cr)['imports']
    require(len(imports) == 1 and imports[0]['name'] == '_swift_slowAlloc' and imports[0]['ordinal'] > 0 and not imports[0]['weak'], 'single actual native allocation')
    deps = p.dependencies(cr)
    native = s.primary.captured_images()
    s.join_capture(native, 'system', p.NODE / 'ipad-current-cache-system-headers-v1/headers.json')
    definition = s.primary.resolve(native, deps[imports[0]['ordinal'] - 1]['path'], '_swift_slowAlloc')
    require(definition['status'] == 'actualDirectExport', 'current true native allocation definition')
    actual_mac = next(x for x in build['roles'] if x['role'] == 'mac')
    require(actual_mac['actualOrdinaryMac'] == dict(allocations=6048, freedFrames=6048, checks=36288, failures=0, workers=4), 'real ordinary Mac fixture')
    require(actual_mac['genuineImpossibleAllocationRejected']['exit'] == -6, 'real native fatal failure')
    require(abi['originalCallerCounts'] == dict(UniversalHID=52, UniversalHIDKit=6), 'complete direct original caller scan')
    commands = json.loads((BUILD.parent / 'commands.json').read_bytes())
    failure = next(x for x in commands if x['label'] == 'mac-allocation-failure')
    err = (BUILD.parent / 'mac-allocation-failure.stderr').read_bytes()
    require(failure['exit'] == -6 and b'failed to allocate' in err and hashlib.sha256(err).hexdigest() == failure['stderrSHA256'], 'fatal receipt actual stderr')
    fixed = lambda body: require(body == cr, 'immutable source CR bytes')
    reject('CR real instruction changed', fixed, cr, next(x['fileoff'] for x in section_ranges(cr) if x['name'] == '__text'), 1)
    reject('CR strong allocation ordinal changed', fixed, cr, imports[0]['command'], 1)
    rejects = len(negatives)
    require(rejects == 21, 'negative count')
    checks = []
    for path in [arfile, crfile] + destinations:
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, text=True)
        require(result.returncode == 0, 'dyld structural validation')
        checks.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Independent finite coroutine strong route regression v1',
        inputs=[p.pin(x) for x in (CANDIDATE, ARRAY, BUILD, ABI)],
        independentlyRederivedHeaderAndStrongOrdinals=True, originalCodeMetadataPACPreserved=True,
        actualMacAllocationAndFatalReceiptsReviewed=True, currentNativeAllocationDefinition=definition,
        negativeControls=negatives, structuralValidations=checks,
        oldHostAllocationAdapted=True, typedAllocatorTelemetryPreserved=False, allCoroutineLifecycleValidated=False,
        fullSwift27RuntimeEquivalent=False, fullCurrentLoadGraphProven=False,
        signatureValidityEstablished=False, nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'review.json', report)
    files = [Path(__file__), CANDIDATE, ARRAY, BUILD, ABI, out / 'review.json', arfile, crfile] + destinations
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(review=p.pin(out / 'review.json'), negativeControls=rejects, structuralValidations=4)))


if __name__ == '__main__':
    main()
