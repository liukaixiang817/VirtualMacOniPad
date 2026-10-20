#!/usr/bin/env python3
"""Recompute the finite POD route, signed layout-pointer ABI and real receipts."""
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
spec = importlib.util.spec_from_file_location('pod_validate', HERE / 'prepare-modern-hid-pod-layout-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p = r.p
CANDIDATE = p.NODE / 'universalhid-pod-layout-real-reexport-data-v2/candidate.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def ar_contract(old, new):
    count, size = struct.unpack_from('<II', old, 16)
    addition = struct.pack('<6I', 0x8000001f, 40, 24, 0, 0x10000, 0x10000) + b'@loader_path/PL\0'
    require(len(addition) == 40 and not any(old[32 + size:32 + size + 40]), 'real unused header bytes')
    expected = bytearray(old)
    struct.pack_into('<II', expected, 16, count + 1, size + 40)
    expected[32 + size:32 + size + 40] = addition
    require(new == expected, 'only true PL reexport header changed')
    require(p.dependencies(new)[:-1] == p.dependencies(old), 'all six preceding owners preserved')
    require(p.dependencies(new)[-1]['ordinal'] == 7, 'exact PL ordinal7')
    require(p.imports(new)['imports'] == p.imports(old)['imports'], 'all AR imports preserved')


def ir_contract(text):
    require('define void @swift_cvw_initStructMetadataWithLayoutString(ptr noundef %0, i64 noundef %1, i64 noundef %2, ptr noundef %3, ptr noundef %4, ptr noundef %5)' in text, 'true six ordinary C arguments')
    require('call void @swift_initStructMetadata(ptr noundef %0, i64 noundef 256, i64 noundef 2, ptr noundef nonnull %1, ptr noundef %2)' in text, 'true native five ordinary C arguments')
    require('or disjoint i64 ptrtoint (ptr @_ZN16VM27HIDPODLayoutL7ProgramE to i64), 1' in text, 'real resolved-pointer low bit')
    require('i64 35685)' in text and 'call i64 @llvm.ptrauth.sign(i64 %46, i32 2, i64 %49)' in text, 'DA2 address plus8b65 authentication')
    require('and i32 %92, 33554432' in text, 'documented dependency addressability bit')
    require('tail call zeroext i1 @_ZN16VM27HIDPODLayout18ProductionMetadataEPvPj' in text, 'finite original HID production identity')
    require('call void @llvm.trap()' in text, 'unsupported ABI must reject')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'fresh local review')
    out.mkdir()
    base, build, abi, candidate = [r.checked(path) for path in (r.BASE, r.BUILD, r.ABI, CANDIDATE)]
    require(not any(candidate[k] for k in ('productionHIDIdentityGatePassed', 'actualCurrentIOSUUIDAndUInt64TypeLayoutsRead',
        'generalCVWInterpreterProvided', 'fullOriginal27RuntimeOverrideHookIdentity', 'fullSwift27RuntimeEquivalent',
        'fullSwift27ParserEquivalent', 'allOriginalHIDTypesProvenResolvable', 'currentCompleteProviderDependencyGraphValidated',
        'metadataCompatibilityProven', 'candidateReadyForNativeLoading', 'originalUHLoaded', 'originalVZLoaded',
        'nativeIOSExecuted', 'deviceOperations', 'codeSigned', 'full27Backend')), 'inert finite boundary')
    ar_source = base['modifiedArrayReexportProvider']['candidate']
    ar_path = Path(candidate['modifiedArrayReexportProvider']['candidate']['path'])
    old_ar, new_ar = Path(ar_source['path']).read_bytes(), ar_path.read_bytes()
    ar_contract(old_ar, new_ar)
    require(candidate['modifiedArrayReexportProvider']['preexistingSignatureInvalidAfterHeaderMutation'], 'original AR signature not valid')
    paths, source_bytes = {}, {}
    for name in ('UniversalHID', 'UniversalHIDKit'):
        row = next(x for x in candidate['images'] if x['name'] == name)
        paths[name] = Path(row['candidate']['path'])
        original = next(x for x in base['images'] if x['name'] == name)['candidate']
        source_bytes[name] = Path(original['path']).read_bytes()
    uh = paths['UniversalHID'].read_bytes()
    r.validate_uh(source_bytes['UniversalHID'], uh)
    require(paths['UniversalHIDKit'].read_bytes() == source_bytes['UniversalHIDKit'], 'whole UHK preserved')
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    pl_path = Path(candidate['unchangedRuntimeProvider']['candidate']['path'])
    pl = pl_path.read_bytes()
    require(pl == Path(ios['provider']['path']).read_bytes(), 'whole true unsigned PL provider')
    require(not any(cmd == 0x1d for cmd, at, size in p.commands(pl)), 'PL has no signature')
    imports = p.imports(pl)['imports']
    require(len(imports) == 8 and all(x['ordinal'] > 0 and not x['weak'] and not x.get('addend', 0) for x in imports), 'eight ordinary positive strong imports')
    definitions = ios['currentExactNativeImports']
    require(sum(x['proof']['status'] == 'actualDirectExport' for x in definitions) == 6, 'only six actual current named definitions')
    require({x['name'] for x in definitions if x['proof']['status'] != 'actualDirectExport'} ==
            {'_vm_read_overwrite', '_mach_task_self_'}, 'kernel reexports still explicitly uncaptured')
    ir_path = Path(ios['entryIR']['path'])
    ir = ir_path.read_text()
    ir_contract(ir)
    commands = json.loads((r.BUILD.parent / 'commands.json').read_bytes())
    for command in commands:
        require(command['exit'] == 0, 'real build/fixture command exit0')
        for suffix in ('stdout', 'stderr'):
            require(hashlib.sha256((r.BUILD.parent / (command['label'] + '.' + suffix)).read_bytes()).hexdigest() ==
                    command[suffix + 'SHA256'], 'actual command stdout/stderr unchanged')
    for role in ('mac', 'mac-sanitized'):
        record = next(x for x in build['roles'] if x['role'] == role)
        actual = json.loads((r.BUILD.parent / (role + '-real-runtime-compare.stdout')).read_bytes())
        require(actual == record['actualOrdinaryMac'] and actual['nativeComparedCases'] == 1024 and
                actual['checks'] == 21586 and not actual['productionHIDEntryExecuted'], 'actual finite Mac native CVW comparison')
        require(not (r.BUILD.parent / (role + '-real-runtime-compare.stderr')).read_bytes(), 'no actual sanitizer/fixture stderr')
    negatives = []
    def bad_byte(label, raw, at, validator, mask=1):
        damaged = bytearray(raw)
        damaged[at] ^= mask
        try:
            validator(bytes(damaged))
        except (AssertionError, ValueError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise ValueError('accepted invalid byte contract: ' + label)
    end = 32 + struct.unpack_from('<I', old_ar, 20)[0]
    for name, at in (('AR load instead of real reexport', end), ('AR wrong true provider', end + 37),
                     ('AR native code', next(x['fileoff'] for seg in p.segments(old_ar) for x in seg['sections'] if x['name'] == '__text')),
                     ('AR previous signature bytes', len(new_ar) - 1)):
        bad_byte(name, new_ar, at, lambda data: ar_contract(old_ar, data))
    item = next(x for x in p.imports(uh)['imports'] if x['index'] == 348)
    for name, at in (('UH ordinal', item['command']), ('UH weak bit', item['command'] + 1), ('UH symbol', item['command'] + 2),
                     ('UH instruction', next(x['fileoff'] for seg in p.segments(uh) for x in seg['sections'] if x['name'] == '__text')),
                     ('UH metadata', next(x['fileoff'] for seg in p.segments(uh) for x in seg['sections'] if x['name'].startswith('__swift5'))),
                     ('UH true PAC', next(x['fileoff'] for x in p.chain_entries(uh) if x['auth']) + 4)):
        bad_byte(name, uh, at, lambda data: r.validate_uh(source_bytes['UniversalHID'], data))
    bad_byte('UHK preserved whole', paths['UniversalHIDKit'].read_bytes(), 16,
        lambda data: require(data == source_bytes['UniversalHIDKit'], 'whole UHK'))
    for item in imports:
        bad_byte('PL native strong owner ' + item['name'], pl, item['command'], lambda data: require(data == pl, 'whole real PL'))
    for name, old, new in (
        ('six C ABI changed', 'i64 noundef %2, ptr noundef %3, ptr noundef %4, ptr noundef %5)', 'i64 noundef %2, ptr noundef %3, ptr noundef %4)'),
        ('native field count changed', 'i64 noundef 256, i64 noundef 2', 'i64 noundef 256, i64 noundef 1'),
        ('resolved-pointer tag lost', 'to i64), 1', 'to i64), 0'),
        ('layout-pointer key changed', 'sign(i64 %46, i32 2,', 'sign(i64 %46, i32 0,'),
        ('layout-pointer discriminator changed', 'i64 35685)', 'i64 35684)'),
        ('dependency flag lost', 'and i32 %92, 33554432', 'and i32 %92, 0'),
        ('identity check removed', 'tail call zeroext i1 @_ZN16VM27HIDPODLayout18ProductionMetadataEPvPj', 'tail call zeroext i1 @__omitted_identity'),
        ('unsupported ABI accepted', 'call void @llvm.trap()', 'call void @__ignored_trap()')):
        damaged = ir.replace(old, new)
        require(damaged != ir, 'true IR negative: ' + name)
        try:
            ir_contract(damaged)
        except ValueError:
            negatives.append(dict(name=name, rejected=True))
        else:
            raise ValueError('accepted invalid IR: ' + name)
    validations = []
    for path in (ar_path, pl_path, paths['UniversalHID'], paths['UniversalHIDKit']):
        command = subprocess.run(['xcrun', 'dyld_info', '-validate_only', str(path)], capture_output=True, timeout=30)
        require(command.returncode == 0, 'actual dyld structural validation')
        validations.append(dict(image=p.pin(path), exit=command.returncode))
    report = dict(schema='Finite original HID POD initializer exact local route validation v1',
        inputs=[p.pin(path) for path in (r.BASE, r.BUILD, r.ABI, CANDIDATE)], negativeControls=negatives,
        structuralValidations=validations, actualCurrentNativeImports=definitions,
        oneUHStrongImportOrdinalByteChanged=True, allGenuineInstructionsMetadataWitnessPACBytesPreserved=True,
        realSixCABIToNativeFiveCABIAndTaggedDA8b65Layout=True, actualMacNativeCVWCompared1024CasesPerRole=True,
        actualCurrentIOSFieldTypeLayoutsVerified=False, generalCVWInterpreterProvided=False,
        originalRuntimeOverrideHookIdentityEquivalent=False, fullCurrentLoadGraphProven=False,
        candidateReadyForNativeLoading=False, originalHIDLoaded=False, deviceOperations=0, nativeIOSExecuted=False,
        full27Backend=False)
    p.save(out / 'review.json', report)
    files = [Path(__file__), Path(r.__file__), r.BASE, r.BUILD, r.ABI, CANDIDATE, ir_path,
             ar_path, pl_path, paths['UniversalHID'], paths['UniversalHIDKit'], out / 'review.json']
    files.extend(r.BUILD.parent / (c['label'] + '.' + suffix) for c in commands for suffix in ('stdout', 'stderr'))
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(review=p.pin(out / 'review.json'), counterexamplesRejected=len(negatives))))


if __name__ == '__main__':
    main()
