#!/usr/bin/env python3
"""Validate exact finite take routing, ownership evidence and current definitions."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('take_validate_route', HERE / 'prepare-modern-hid-bitwise-take-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p = r.p
CANDIDATE = p.NODE / 'universalhid-bitwise-take-real-reexport-data-v1/candidate.json'
FRONTIER = p.NODE / 'universalhid-current-exact-frontier-audit-v10/audit.json'


def require(value, message):
    if not value: raise ValueError(message)


def ir_contract(text):
    match = re.search(r'^define ([^\n]*)@swift_cvw_initWithTake\(([^\n]*)\)', text, re.M)
    require(match and 'ptr' in match[1] and 'swiftcc' not in match[1] and match[2].count('ptr noundef') == 3, 'ordinary three-pointer C ABI')
    require('call zeroext i1 @_ZN18VM27HIDBitwiseTake18ProductionMetadataEPKvRNS_6LayoutE' in text, 'true finite owner gate')
    require('call void @llvm.trap()' in text, 'reject unsupported production metadata')
    require('call void @llvm.memcpy.p0.p0.i64(ptr nonnull align 1 %0, ptr nonnull readonly align 1 %1, i64 %11, i1 false)' in text, 'metadata size ownership transfer')
    require('and i32 %16, 5242880' in text, 'non-bitwise and incomplete masks')
    require('call i64 @llvm.ptrauth.blend(i64 %10, i64 11839)' in text, 'actual VWT address-diverse 2e3f')
    require('call ptr @_ZN18VM27HIDBitwiseTake11DataPointerEPKvlt(ptr noundef nonnull %0, i64 noundef -16, i16 noundef zeroext -29851)' in text, 'actual resolved program address-diverse 8b65')
    require('and i64 %221, 1' in text and 'and i64 %221, -2' in text, 'real resolved-pointer tag')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'fresh inert local review')
    out.mkdir()
    base, build, abi, candidate, frontier = [r.r.checked(x) for x in (r.BASE, r.BUILD, r.ABI, CANDIDATE, FRONTIER)]
    require(frontier['currentStockImages'] == 17 and frontier['declaredPrivateImages'] == 15, 'actual finite captured/declaration counts')
    require(not any(candidate[k] for k in ('productionHIDIdentityGatePassed', 'generalNonBitwiseInterpreterProvided',
        'remainingFiveCVWBindingsClosed', 'fullOriginal27RuntimeOverrideHookIdentity', 'fullSwift27RuntimeEquivalent',
        'fullSwift27ParserEquivalent', 'allOriginalHIDTypesProvenResolvable', 'allCurrentProvidersDeclared',
        'currentCompleteProviderDependencyGraphValidated', 'metadataCompatibilityProven', 'originalHIDInitializerExecuted',
        'originalUHLoaded', 'originalVZLoaded', 'nativeIOSExecuted', 'deviceOperations', 'codeSigned',
        'candidateReadyForNativeLoading', 'full27Backend')), 'finite proof does not weaken native/full-runtime gates')
    ar_before = Path(base['modifiedArrayReexportProvider']['candidate']['path']).read_bytes()
    ar_after = Path(candidate['modifiedArrayReexportProvider']['candidate']['path']).read_bytes()
    r.ar_contract(ar_before, ar_after)
    uh_row = next(x for x in candidate['images'] if x['name'] == 'UniversalHID')
    uh_before = Path(uh_row['source']['path']).read_bytes()
    uh_after = Path(uh_row['candidate']['path']).read_bytes()
    r.validate_uh(uh_before, uh_after)
    uhk = next(x for x in candidate['images'] if x['name'] == 'UniversalHIDKit')
    require(Path(uhk['source']['path']).read_bytes() == Path(uhk['candidate']['path']).read_bytes(), 'whole unchanged genuine UHK')
    bt_path = Path(candidate['unchangedRuntimeProvider']['candidate']['path'])
    bt = bt_path.read_bytes()
    require(bt == Path(candidate['unchangedRuntimeProvider']['source']['path']).read_bytes(), 'whole unchanged true compiled BT')
    imports = p.imports(bt)['imports']
    require(len(imports) == 6 and all(x['ordinal'] > 0 and not x['weak'] for x in imports), 'six ordinary positive strong bindings')
    bt_result = next(x for x in frontier['auditedImages'] if x['name'] == 'BT')
    pl_result = next(x for x in frontier['auditedImages'] if x['name'] == 'PL')
    require(bt_result['counts'] == dict(actualDirectExport=6) and pl_result['counts'] == dict(actualDirectExport=8), 'all fourteen actual named leaf definitions')
    ios = next(x for x in build['roles'] if x['role'] == 'ios')
    ir_path = Path(ios['entryIR']['path'])
    ir = ir_path.read_text()
    ir_contract(ir)
    commands = json.loads((r.BUILD.parent / 'commands.json').read_bytes())
    for row in commands:
        require(row['exit'] == 0, 'real successful build/ordinary fixture command')
        for suffix in ('stdout', 'stderr'):
            require(hashlib.sha256((r.BUILD.parent / (row['label'] + '.' + suffix)).read_bytes()).hexdigest() == row[suffix + 'SHA256'], 'actual command bytes intact')
    for role in ('mac', 'mac-sanitized'):
        actual = json.loads((r.BUILD.parent / (role + '-real-runtime-compare.stdout')).read_bytes())
        require(actual == next(x for x in build['roles'] if x['role'] == role)['actualOrdinaryMac'], 'real ordinary callback fixture receipt')
        require(actual['nativeComparedCases'] == 3072 and actual['checks'] == 26876 and actual['genuineRetainCountChecks'] == 8192,
                'true default move and retain-count comparisons')
        require(actual['realObjectsCreated'] == actual['realObjectsDestroyed'] == 8 and actual['nativeNonBitwiseMetadataRejected'] == 8,
                'real ARC lifetime and unsupported weak storage')
        require(not (r.BUILD.parent / (role + '-real-runtime-compare.stderr')).read_bytes(), 'actual sanitizer/runtime stderr empty')
    negatives = []
    def bad(label, raw, at, validator):
        corrupted = bytearray(raw)
        corrupted[at] ^= 1
        try: validator(bytes(corrupted))
        except (ValueError, AssertionError): negatives.append(dict(name=label, rejected=True))
        else: raise ValueError('accepted corruption: ' + label)
    import_record = next(x for x in p.imports(uh_after)['imports'] if x['index'] == 11)
    for label, at in (('UH ordinal', import_record['command']), ('UH weakbit', import_record['command'] + 1),
        ('UH symbol', import_record['command'] + 2), ('UH code', next(y['fileoff'] for x in p.segments(uh_after) for y in x['sections'] if y['name'] == '__text')),
        ('UH PAC', next(x['fileoff'] for x in p.chain_entries(uh_after) if x['auth']) + 4)):
        bad(label, uh_after, at, lambda x: r.validate_uh(uh_before, x))
    reexport = p.dependencies(ar_after)[-1]
    for label, at in (('AR load vs reexport', reexport['at']), ('AR actual BT path', reexport['at'] + 37), ('AR original code', next(y['fileoff'] for x in p.segments(ar_after) for y in x['sections'] if y['name'] == '__text'))):
        bad(label, ar_after, at, lambda x: r.ar_contract(ar_before, x))
    for x in imports:
        bad('BT genuine strong ' + x['name'], bt, x['command'], lambda raw: require(raw == bt, 'whole true BT'))
    for label, before, after in (
        ('C ABI changed', 'ptr noundef %2)', 'i64 noundef %2)'),
        ('owner gate removed', 'call zeroext i1 @_ZN18VM27HIDBitwiseTake18ProductionMetadataEPKvRNS_6LayoutE', 'call zeroext i1 @removed_owner'),
        ('unsupported accepted', 'call void @llvm.trap()', 'call void @ignored_trap()'),
        ('ownership transfer omitted', 'ptr nonnull readonly align 1 %1, i64 %11', 'ptr nonnull readonly align 1 %1, i64 0'),
        ('non-bitwise accepted', 'and i32 %16, 5242880', 'and i32 %16, 0'),
        ('VWT authentication wrong', 'i64 11839)', 'i64 11838)'),
        ('program authentication wrong', 'i16 noundef zeroext -29851)', 'i16 noundef zeroext -29850)'),
        ('program lowbit omitted', 'and i64 %221, 1', 'and i64 %221, 0')):
        changed = ir.replace(before, after)
        require(changed != ir, 'actual IR mutation: ' + label)
        try: ir_contract(changed)
        except ValueError: negatives.append(dict(name=label, rejected=True))
        else: raise ValueError('accepted invalid IR: ' + label)
    report = dict(schema='Finite genuine HID POD take exact local ABI/route/ownership review v1',
        candidate=p.pin(CANDIDATE), originalABI=p.pin(r.ABI), build=p.pin(r.BUILD), actualCurrentStockFrontier=p.pin(FRONTIER),
        negativeControls=negatives, actualAllSixBTAndEightPLNamedDefinitions=bt_result['imports'] + pl_result['imports'],
        originalThreeCABIAndVWTDA2Address2e3fAndTakeIA0Address48d8Preserved=True,
        soleUHOrdinalByteChanged=True, allOriginalInstructionsMetadataWitnessPACBytesPreserved=True,
        actualOrdinaryMac3072NativeCasesAnd8192RetainCountChecksPerRole=True, realObjectsCreatedAndDestroyed=8,
        actualCurrentIOSFieldLayoutsRead=True, productionHIDIdentityGatePassed=False, originalHIDInitializerExecuted=False,
        remainingFiveCVWBindingsClosed=False, generalNonBitwiseInterpreterProvided=False,
        originalProcessGlobalRuntimeOverrideHookIdentityPreserved=False, fullCurrentLoadGraphProven=False,
        candidateReadyForNativeLoading=False, deviceOperations=0, nativeIOSExecuted=False, full27Backend=False)
    p.save(out / 'review.json', report)
    files = [Path(__file__), Path(r.__file__), r.BASE, r.BUILD, r.ABI, CANDIDATE, FRONTIER, ir_path,
        Path(candidate['modifiedArrayReexportProvider']['candidate']['path']), Path(uh_row['candidate']['path']), Path(uhk['candidate']['path']), bt_path, out / 'review.json']
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(review=p.pin(out / 'review.json'), negativeControls=len(negatives))))


if __name__ == '__main__': main()
