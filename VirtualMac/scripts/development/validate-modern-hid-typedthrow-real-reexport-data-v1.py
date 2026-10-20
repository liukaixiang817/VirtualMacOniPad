#!/usr/bin/env python3
"""Rederive exact typed-throw bytes, real callback ABI and fixture receipts."""
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
spec = importlib.util.spec_from_file_location('typed_review_stock', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
p = s.p
BASE = p.NODE / 'universalhid-lookup-oldhost-entry-data-v1/candidate.json'
CANDIDATE = p.NODE / 'universalhid-typedthrow-real-reexport-data-v1/candidate.json'
BUILD = p.NODE / 'swift-typedthrow-data-build-v3/candidate.json'
ABI = p.NODE / 'swift-typedthrow-original-abi-readonly-v1/audit.json'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def checked(path):
    for row in json.loads((path.parent / 'freeze.json').read_bytes())['files']:
        require(p.pin(Path(row['path'])) == row, 'immutable actual input')
    return json.loads(path.read_bytes())


def validate_ar(old, new):
    count, size = struct.unpack_from('<II', old, 16)
    command = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/TT\0'
    require(len(command) == 40 and not any(old[32 + size:32 + size + 40]), 'exact zero-padding command')
    expected = bytearray(old)
    struct.pack_into('<II', expected, 16, count + 1, size + 40)
    expected[32 + size:32 + size + 40] = command
    require(new == expected, 'only explicit AR reexport header added')
    require(p.dependencies(new)[:5] == p.dependencies(old), 'all five prior true owners retained')
    dep = p.dependencies(new)[-1]
    require(dep['ordinal'] == 6 and dep['command'] == 0x8000001f and dep['path'] == '@loader_path/TT', 'exact strong ordinal6 reexport')
    require(p.imports(new)['imports'] == p.imports(old)['imports'], 'all16 AR active imports unchanged')


def validate_uh(old, new):
    item = next(x for x in p.imports(old)['imports'] if x['name'] == '_swift_willThrowTypedImpl')
    require(item['index'] == 393 and item['ordinal'] == 8 and not item['weak'], 'true original strong UH393')
    expected = bytearray(old)
    expected[item['command']] = 20
    require(new == expected, 'one exact ordinal byte changed')
    for a, b in zip(p.imports(old)['imports'], p.imports(new)['imports'], strict=True):
        require(b == ({**a, 'ordinal': 20} if a['index'] == 393 else a), 'all other imports preserved')


def sections(raw):
    return [section for segment in p.segments(raw) for section in segment['sections']]


def validate_ir(ir):
    require('define swiftcc void @swift_willThrowTypedImpl(ptr' in ir, 'three pointer SwiftCC input')
    require(ir.count('load atomic i64') == 2 and ir.count('acquire, align 8') == 2, 'two acquire callback loads')
    require(ir.count('[ "ptrauth"(i32 0, i64 0) ]') == 2, 'two original IA0 normal C callbacks')
    require('call swiftcc { ptr, ptr } @swift_allocError' in ir and 'i1 noundef false' in ir, 'actual copied native BoxPair')
    require('call void @swift_errorRelease' in ir, 'real native box released')
    require('store atomic' not in ir, 'production system atomic never written')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'fresh local review')
    out.mkdir()
    base, candidate, build, abi = [checked(path) for path in (BASE, CANDIDATE, BUILD, ABI)]
    require(not any(candidate[key] for key in ('productionNativeCallbackSlotWritten', 'processGlobalTypedHookIdentityPreserved',
        'fullSwift27RuntimeEquivalent', 'fullSwift27ParserEquivalent', 'allOriginalHIDTypesProvenResolvable',
        'currentCompleteProviderDependencyGraphValidated', 'metadataCompatibilityProven', 'originalUHLoaded',
        'originalVZLoaded', 'nativeIOSExecuted', 'deviceOperations', 'codeSigned', 'full27Backend')), 'finite inert boundary')
    arsource = base['modifiedArrayReexportProvider']['candidate']
    arpath = Path(candidate['modifiedArrayReexportProvider']['candidate']['path'])
    old_ar, new_ar = Path(arsource['path']).read_bytes(), arpath.read_bytes()
    validate_ar(old_ar, new_ar)
    require(candidate['modifiedArrayReexportProvider']['preexistingSignatureInvalidAfterHeaderMutation'], 'signature failure retained')
    source_uh = next(x for x in base['images'] if x['name'] == 'UniversalHID')['candidate']
    uhpath = Path(next(x for x in candidate['images'] if x['name'] == 'UniversalHID')['candidate']['path'])
    old_uh, new_uh = Path(source_uh['path']).read_bytes(), uhpath.read_bytes()
    validate_uh(old_uh, new_uh)
    uhkpath = Path(next(x for x in candidate['images'] if x['name'] == 'UniversalHIDKit')['candidate']['path'])
    old_uhk = Path(next(x for x in base['images'] if x['name'] == 'UniversalHIDKit')['candidate']['path']).read_bytes()
    require(uhkpath.read_bytes() == old_uhk, 'whole UHK untouched')
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    ttpath = Path(candidate['unchangedRuntimeProvider']['candidate']['path'])
    tt = ttpath.read_bytes()
    require(tt == Path(ios['provider']['path']).read_bytes(), 'whole unsigned true TT copied')
    require(not any(command == 0x1d for command, at, size in p.commands(tt)), 'no inert TT signature')
    text = next(x for x in sections(tt) if x['name'] == '__text')
    code = tt[text['fileoff']:text['fileoff'] + text['size']]
    require(text['size'] == 152, 'actual complete three-branch entry')
    require(struct.unpack_from('<I', code, 24)[0] == 0xf8bfc103 and struct.unpack_from('<I', code, 68)[0] == 0xf8bfc114, 'actual LDAR typed and legacy')
    require(struct.unpack_from('<I', code, 56)[0] == 0xd61f087f and struct.unpack_from('<I', code, 104)[0] == 0xd63f0a9f, 'actual BRAAZ and BLRAAZ C callbacks IA0')
    require(struct.unpack_from('<I', code, 92)[0] == 0x52800003, 'actual copy isTake=false')
    require(abi['originalFunctions'][0]['nextStart'] - abi['originalFunctions'][0]['entry'] == 152, 'genuine Core full entry extent')
    ir = Path(ios['entryIR']['path']).read_text()
    validate_ir(ir)
    native = s.primary.captured_images()
    deps = {x['ordinal']: x['path'] for x in p.dependencies(tt)}
    imports = p.imports(tt)['imports']
    require(len(imports) == 3 and {x['name'] for x in imports} == {'__swift_willThrow', '_swift_allocError', '_swift_errorRelease'}, 'three exact native imports')
    definitions = []
    for item in imports:
        require(item['ordinal'] > 0 and not item['weak'] and item.get('addend', 0) == 0, 'real native strong import')
        proof = s.primary.resolve(native, deps[item['ordinal']], item['name'])
        require(proof['status'] == 'actualDirectExport', 'actual current native Core definition')
        definitions.append(dict(item, proof=proof))
    receipts = json.loads((BUILD.parent / 'commands.json').read_bytes())
    for receipt in receipts:
        for stream in ('stdout', 'stderr'):
            raw = (BUILD.parent / (receipt['label'] + '.' + stream)).read_bytes()
            require(hashlib.sha256(raw).hexdigest() == receipt[stream + 'SHA256'], 'actual command receipt content')
        require(receipt['exit'] == 0, 'actual build/fixture success')
    mac = []
    for role in ('mac', 'mac-sanitized'):
        row = next(x for x in build['roles'] if x['role'] == role)
        require(p.pin(Path(row['fixture']['path'])) == row['fixture'], 'actual ordinary Mac executable pin')
        stdout = (BUILD.parent / (role + '-actual-callback-ownership.stdout')).read_bytes()
        require(json.loads(stdout) == row['actualOrdinaryMac'] and not (BUILD.parent / (role + '-actual-callback-ownership.stderr')).read_bytes(), 'actual callback/ARC receipt')
        require(row['actualOrdinaryMac']['realCopiedBoxes'] == 1536 and row['actualOrdinaryMac']['retainedARCValueCases'] == 256, 'real copied box retention and release')
        mac.append(dict(role=role, fixture=row['fixture'], result=row['actualOrdinaryMac']))
    negatives = []
    def reject(label, validator, original, at, mask=1):
        bad = bytearray(original)
        bad[at] ^= mask
        try:
            validator(bytes(bad))
        except (ValueError, AssertionError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise ValueError('negative accepted ' + label)
    end = 32 + struct.unpack_from('<I', old_ar, 20)[0]
    for name, at, mask in (('AR load instead of reexport', end, 0x13), ('AR weak dependency', end, 7),
        ('AR wrong owner', end + 37, 1), ('AR original instruction', next(x['fileoff'] for x in sections(old_ar) if x['name'] == '__text'), 1),
        ('AR original signature bytes', len(new_ar) - 1, 1)):
        reject(name, lambda body: validate_ar(old_ar, body), new_ar, at, mask)
    at = next(x for x in p.imports(old_uh)['imports'] if x['index'] == 393)['command']
    for name, offset in (('UH wrong ordinal', at), ('UH weak bit', at + 1), ('UH name offset', at + 2),
        ('UH original instruction', next(x['fileoff'] for x in sections(old_uh) if x['name'] == '__text')),
        ('UH original metadata', next(x['fileoff'] for x in sections(old_uh) if x['name'].startswith('__swift5'))),
        ('UH actual PAC', next(x['fileoff'] for x in p.chain_entries(old_uh) if x['auth']) + 4)):
        reject(name, lambda body: validate_uh(old_uh, body), new_uh, offset)
    for name, at in (('TT isTake changed', text['fileoff'] + 92), ('TT acquire changed', text['fileoff'] + 24),
                     ('TT callback PAC changed', text['fileoff'] + 104), ('TT native owner changed', imports[0]['command'])):
        reject(name, lambda body: require(body == tt, 'whole true source TT'), tt, at)
    reject('UHK changed', lambda body: require(body == old_uhk, 'whole UHK'), old_uhk, 16)
    for label, old, new in (('copy becomes take', 'i1 noundef false', 'i1 noundef true'),
                            ('typed acquire relaxed', 'acquire, align 8', 'monotonic, align 8'),
                            ('callback authentication removed', '[ "ptrauth"(i32 0, i64 0) ]', ''),
                            ('native release omitted', 'call void @swift_errorRelease', 'call void @__omitted_release'),
                            ('native atomic write added', 'ret void', 'store atomic i64 0, ptr @_swift_willThrow release, align 8\n  ret void')):
        damaged = ir.replace(old, new, 1)
        require(damaged != ir, 'true IR negative')
        try:
            validate_ir(damaged)
        except ValueError:
            negatives.append(dict(name=label, rejected=True))
        else:
            raise ValueError('IR negative accepted')
    require(len(negatives) == 21, 'complete independent regressions')
    validations = []
    for path in (arpath, ttpath, uhpath, uhkpath):
        result = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, text=True)
        require(result.returncode == 0, 'structural validation')
        validations.append(dict(image=p.pin(path), exit=result.returncode))
    report = dict(schema='Independent exact finite typed-throw route and real Mac receipt review v1',
        inputs=[p.pin(path) for path in (BASE, CANDIDATE, BUILD, ABI)], negativeControls=negatives,
        structuralValidations=validations, currentActualNativeDefinitions=definitions, actualMacResults=mac,
        actualMachineAcquireAndCABIAuthenticationReviewed=True, oneUHStrongOrdinalOnly=True,
        originalInstructionsMetadataWitnessPACAndAvailabilityGuardPreserved=True,
        productionNativeCallbackSlotWritten=False, providerPrivateTypedCallbackSlot=True,
        processGlobalTypedHookIdentityPreserved=False, originalUHErrorWitnessCompatibilityProven=False,
        allOriginalHIDErrorTypesBoxableOnOldHost=False, fullSwift27RuntimeEquivalent=False,
        fullCurrentLoadGraphProven=False, signatureValidityEstablished=False,
        nativeIOSExecuted=False, deviceOperations=0, full27Backend=False)
    p.save(out / 'review.json', report)
    files = [Path(__file__), BASE, CANDIDATE, BUILD, ABI, out / 'review.json', arpath, ttpath, uhpath, uhkpath]
    files += [Path(row['fixture']['path']) for row in mac]
    files += [BUILD.parent / (receipt['label'] + '.' + stream) for receipt in receipts for stream in ('stdout', 'stderr')]
    p.save(out / 'freeze.json', dict(files=[p.pin(path) for path in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(review=p.pin(out / 'review.json'), rejectedControls=len(negatives), structuralValidations=4)))


if __name__ == '__main__':
    main()
