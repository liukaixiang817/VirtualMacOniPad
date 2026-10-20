#!/usr/bin/env python3
"""Prove the exact HID take binding and genuine default bitwise path."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('take_pod_route', HERE / 'prepare-modern-hid-pod-layout-real-reexport-data-v1.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p = r.p
BASE = p.NODE / 'universalhid-pod-layout-real-reexport-data-v2/candidate.json'
ORIGINAL = p.NODE / 'universalhid-cvw-static-original-abi-readonly-v1/audit.json'
CURRENT = p.NODE / 'universalhid-pod-current-native-layout-readonly-v1/audit.json'
SYMBOL = '_swift_cvw_initWithTake'


def require(value, message):
    if not value:
        raise ValueError(message)


def machine(raw):
    require(len(raw) == 776, 'whole original default take helper')
    words = {32: 0xaa0203f1, 36: 0xf85f8e30, 40: 0xf2e5c7f1, 44: 0xdac11a30,
             52: 0xdac147f1, 60: 0x54000040, 64: 0xd4388e40,
             68: 0x39414a08, 72: 0x372001a8, 76: 0xf9402202, 120: 0x14ca838f}
    for offset, word in words.items():
        require(struct.unpack_from('<I', raw, offset)[0] == word, 'actual take ABI/PAC/bitwise instruction')
    return [dict(offset=at, word=hex(word)) for at, word in words.items()]


def bind_contract(raw):
    imports = {x['index']: x for x in p.imports(raw)['imports']}
    entries = list(p.chain_entries(raw))
    targets = [x for x in entries if x['bind'] and imports[x['import_index']]['name'] == SYMBOL]
    require(len(targets) == 1, 'sole actual UH initWithTake bind')
    row = targets[0]
    item = imports[row['import_index']]
    require(item['index'] == 11 and item['ordinal'] == 8 and not item['weak'] and row['auth'], 'true strong original Core import 11')
    require(row['address'] == 0x1000ccac0 and row['word'] == 0xc00948d80000000b, 'original EventReportSenderID take VWT slot')
    require((row['word'] >> 49 & 3) == 0 and (row['word'] >> 48 & 1) == 1 and
            (row['word'] >> 32 & 0xffff) == 0x48d8, 'original IA0 address-diverse 48d8')
    vwt = row['fileoff'] - 32
    require(struct.unpack_from('<QQII', raw, vwt + 64) == (0, 0, 0x400000, 0), 'initial unresolved original POD VWT')
    counts = collections.Counter(imports[x['import_index']]['name'] for x in entries if x['bind'] and imports[x['import_index']]['name'].startswith('_swift_cvw_'))
    require(counts['_swift_cvw_initializeBufferWithCopyOfBuffer'] == 65 and counts['_swift_cvw_destroy'] == 64 and
            counts['_swift_cvw_initWithCopy'] == 64 and counts['_swift_cvw_assignWithCopy'] == 63 and
            counts['_swift_cvw_assignWithTake'] == 64, 'other five CVWs remain separate genuine bindings')
    return dict(importRecord=item, authenticatedBind=row, originalVWTFileOffset=vwt,
                originalVWTNormalizedVA=0x1000ccaa0, otherCVWBindCounts=dict(counts))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    require(out.is_relative_to(p.NODE) and not out.exists(), 'fresh ordinary local audit')
    out.mkdir()
    base, original, current = [r.checked(path) for path in (BASE, ORIGINAL, CURRENT)]
    require(current['actualCurrentIOSUUIDAndUInt64TypeLayoutsRead'] and not current['originalHIDInitializerExecuted'], 'current native fields, no fabricated HID execution')
    uh = next(x['candidate'] for x in base['images'] if x['name'] == 'UniversalHID')
    uhk = next(x['candidate'] for x in base['images'] if x['name'] == 'UniversalHIDKit')
    raw = Path(uh['path']).read_bytes()
    bind = bind_contract(raw)
    other = Path(uhk['path']).read_bytes()
    other_imports = {x['index']: x for x in p.imports(other)['imports']}
    require(not any(x['bind'] and other_imports[x['import_index']]['name'] == SYMBOL for x in list(p.chain_entries(other))), 'UHK has no imported take binding')
    fn = next(x for x in original['completeOriginalCVWEntriesAndFirstHelperBodies'] if x['entry'] == 0x194e4b2cc)
    body_path = Path(fn['code']['path'])
    body = body_path.read_bytes()
    words = machine(body)
    public = next(x for x in original['completeOriginalCVWEntriesAndFirstHelperBodies'] if x['role'] == SYMBOL)
    hook = next(x for x in original['actualOriginalRuntimeHookControls'] if x['symbol'] == SYMBOL)
    require(hook['slotValue'] == 0 and public['code']['bytes'] == 48, 'actual lazy original runtime hook starts unresolved')
    source = p.ROOT / 'VirtualMac/vendor/swift-bytecode-enum-tag/Swift-BytecodeLayouts.cpp'
    code = source.read_text()
    require('if (SWIFT_LIKELY(metadata->getValueWitnesses()->isBitwiseTakable())) {\n    size_t size = metadata->vw_size();\n    memcpy(_dest, _src, size);\n    return _dest;' in code,
            'real default bitwise transfer source')
    negatives = []
    for word in words:
        bad = bytearray(body)
        bad[word['offset']] ^= 1
        try:
            machine(bytes(bad))
        except ValueError:
            negatives.append(dict(name='original take machine ' + str(word['offset']), rejected=True))
        else:
            raise ValueError('accepted corrupt original machine')
    for label, at in [('strong owner', bind['importRecord']['command']), ('bind IA discriminator', bind['authenticatedBind']['fileoff'] + 4),
                      ('initial VWT flags', bind['originalVWTFileOffset'] + 80)]:
        bad = bytearray(raw)
        bad[at] ^= 1
        try:
            bind_contract(bytes(bad))
        except (ValueError, AssertionError):
            negatives.append(dict(name=label, rejected=True))
        else:
            raise ValueError('accepted corrupt original binding')
    report = dict(schema='Original HID sole POD take binding and genuine default fast-path ABI v1',
        originalProviderSource=p.pin(BASE), currentNativeFieldLayout=p.pin(CURRENT), originalCVWAudit=p.pin(ORIGINAL),
        originalUH=uh, originalUHK=uhk, exactBinding=bind, originalDefaultHelper=fn['code'],
        originalDefaultHelperVA=fn['entry'], machineContracts=words, originalPublicEntry=public['code'],
        originalLazyRuntimeHook=hook, defaultFastPathSource=p.pin(source), negativeControls=negatives,
        originalThreeOrdinaryCPointerABI=True, originalVWTDA2Address2e3fAndTakeIA0Address48d8=True,
        originalDefaultUsesMetadataSizeAndNonBitwiseTakableFlag=True, onlyOneOriginalUHBindingIsInitialPODType=True,
        originalPODInitializerMustCompleteBeforeTakeUse=True, currentActualNativeFieldLayoutsVerified=True,
        finiteCompletedPODDefaultTakeSemanticsImplementable=True, generalCVWInterpreterProvided=False,
        originalProcessGlobalRuntimeOverrideHookIdentityPreserved=False, remainingFiveCVWBindingsClosed=False,
        productionHIDIdentityGatePassed=False, originalHIDInitializerExecuted=False,
        candidateReadyForNativeLoading=False, deviceOperations=0, nativeIOSExecuted=False, full27Backend=False)
    p.save(out / 'audit.json', report)
    files = [Path(__file__), Path(r.__file__), BASE, ORIGINAL, CURRENT, Path(uh['path']), Path(uhk['path']), body_path,
             Path(public['code']['path']), source, out / 'audit.json']
    p.save(out / 'freeze.json', dict(files=[p.pin(x) for x in files], deviceOperations=0, nativeIOSExecuted=False))
    print(json.dumps(dict(audit=p.pin(out / 'audit.json'), actualTakeBindings=1, rejectedControls=len(negatives))))


if __name__ == '__main__':
    main()
