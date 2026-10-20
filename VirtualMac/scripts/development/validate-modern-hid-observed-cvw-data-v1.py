#!/usr/bin/env python3
"""Verify actual finite ownership candidate bytes; no native framework load."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ownership_data_review', HERE / 'build-modern-hid-observed-cvw-production-data-v1.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
p = b.p
ROUTE = p.NODE / 'universalhid-observed-cvw-real-reexport-data-v2/candidate.json'
BUILD = p.NODE / 'hid-observed-cvw-production-data-build-v2/candidate.json'
COMPONENT = p.NODE / 'hid-observed-cvw-component-build-v5/candidate.json'
PARSER = p.NODE / 'hid-observed-cvw-registry-local-review-v2/review.json'
WHITELIST = p.NODE / 'hid-observed-cvw-production-whitelist-readonly-v1/audit.json'
FRONTIER = p.NODE / 'universalhid-current-exact-frontier-audit-v11/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output',type=Path,required=True)
    out = ap.parse_args().output.resolve(); assert out.is_relative_to(p.NODE) and not out.exists(); out.mkdir()
    paths = (ROUTE,BUILD,COMPONENT,PARSER,WHITELIST,FRONTIER)
    all_pins = {}
    for path in paths:
        freeze = json.loads((path.parent/'freeze.json').read_text())
        for pin in freeze['files']:
            assert p.pin(Path(pin['path'])) == pin; all_pins[pin['path']] = pin
    route, build, component, parser, whitelist, frontier = [json.loads(x.read_text()) for x in paths]
    checks = 0; negatives = []; chain_counts = []
    def accepted(before, after, name):
        expected = bytearray(before)
        count = 5 if name == 'UniversalHID' else 1
        indices = (7,8,9,10,12) if count == 5 else (5,)
        rows = p.imports(before)['imports']
        names = {'_swift_cvw_initializeBufferWithCopyOfBuffer','_swift_cvw_destroy','_swift_cvw_initWithCopy',
                 '_swift_cvw_assignWithCopy','_swift_cvw_assignWithTake'}
        assert set(rows[i]['name'] for i in indices) == (names if count == 5 else {'_swift_cvw_initializeBufferWithCopyOfBuffer'})
        for index in indices:
            row = rows[index]; assert row['ordinal'] == 8 and not row['weak']
            expected[row['command']] = 20 if count == 5 else 1
        assert after == expected
        actual = p.imports(after)['imports']; assert len(actual) == len(rows)
        for a, z in zip(rows,actual,strict=True):
            assert z == (dict(a,ordinal=20 if count == 5 else 1) if a['index'] in indices else a)
        assert p.dependencies(before) == p.dependencies(after)
        assert list(p.chain_entries(before)) == list(p.chain_entries(after))
        return len(list(p.chain_entries(before)))
    for image in route['images']:
        before = Path(image['source']['path']).read_bytes(); after = Path(image['candidate']['path']).read_bytes()
        count = accepted(before,after,image['name']); checks += count
        chain_counts.append(dict(owner=image['name'],originalChainedEntriesWholeWordPreserved=count))
        indices = (7,8,9,10,12) if image['name'] == 'UniversalHID' else (5,)
        rows = p.imports(before)['imports']
        offsets = [(f'strong import {index}',rows[index]['command']) for index in indices]
        offsets += [('weak bit',rows[indices[0]]['command']+1),('wrong name',rows[indices[0]]['command']+2)]
        for segment in p.segments(before):
            for section in segment['sections']:
                if section['name'] == '__text' or section['name'] == '__swift5_fieldmd':
                    offsets.append((section['name'],section['fileoff']))
        offsets += [('original authenticated word',next(x['fileoff'] for x in p.chain_entries(before) if x['auth']))]
        for label,offset in offsets:
            changed = bytearray(after); changed[offset] ^= 1
            try: accepted(before,bytes(changed),image['name'])
            except (AssertionError,ValueError): negatives.append(dict(owner=image['name'],name=label,rejected=True))
            else: raise AssertionError('mutated original candidate accepted')
    ar = route['modifiedArrayReexportProvider']; before = Path(ar['source']['path']).read_bytes(); after = Path(ar['candidate']['path']).read_bytes()
    count,size = struct.unpack_from('<II',before,16); expected = bytearray(before)
    struct.pack_into('<II',expected,16,count+1,size+40)
    expected[32+size:32+size+40] = struct.pack('<6I',0x8000001f,40,24,0,0x10000,0x10000) + b'@loader_path/OW\0'
    assert after == expected and p.dependencies(after)[-1]['ordinal'] == 9
    assert p.imports(after) == p.imports(before); checks += 1
    ow = route['unchangedRuntimeProvider']; ios = next(x for x in build['roles'] if x['role']=='ios')
    assert Path(ow['candidate']['path']).read_bytes() == Path(ios['provider']['path']).read_bytes()
    assert ios['provider']['bytes'] == 71112 and len(ios['currentExactNativeImports']) == 16
    assert all(x['ordinal'] > 0 and not x['weak'] and x['actualCurrentDefinition']['status']=='actualDirectExport'
        for x in ios['currentExactNativeImports']); checks += 16
    raw = Path(ios['provider']['path']).read_bytes(); assert not any(cmd == 0x1d for cmd,at,size in p.commands(raw))
    ir = Path(ios['IR']['path']).read_text()
    for symbol in b.SYMBOLS:
        pattern = r'^define ([^\n]*)@' + symbol[1:] + r'\(([^\n]*)\)'
        entry = re.search(pattern,ir,re.M); assert entry and 'swiftcc' not in entry[1]
        assert entry[2].count('ptr noundef') == (2 if symbol=='_swift_cvw_destroy' else 3); checks += 1
    assert 'llvm.ptrauth.auth' in ir and 'i64 11839' in ir and 'Identity' in ir and 'llvm.trap' in ir
    assert set(ios['exports']) == set(b.SYMBOLS)
    for role in component['roles'][:2]:
        actual=role['actualOrdinaryMac']; assert actual['nativeComparedCases']==19840 and actual['checks']==90963
        assert actual['genuineRetainCountChecks']==36160 and actual['operations']==[3968]*5
        assert actual['enumTagPairs']==200 and actual['nativeBoxCases']==384
        assert actual['realObjectsCreated']==actual['realObjectsDestroyed']==16; checks += actual['checks']
    for role in parser['roles']:
        actual=role['actualOrdinaryMac']; assert actual['completedOriginalMetadataSchemasValidated']==65
        assert actual['counterexamplesRejected']==507; checks += actual['checks']
    for role in build['roles'][:2]:
        actual=role['actualOrdinaryMacIdentity']; assert actual['syntheticExactOriginalMetadataCases']==65
        assert actual['counterexamplesRejected']==446 and actual['realProductionOwnerRejections']==65
        checks += actual['checks']
    assert len(whitelist['rows'])==65 and whitelist['originalRelativeFNUsesUntaggedMetadataProgram']
    assert frontier['currentStockImages']==17 and frontier['declaredPrivateImages']==16
    for result in frontier['auditedImages'][:2]:
        absent=[x for x in result['imports'] if x['proof']['status']=='actualExportAbsent']
        assert len(absent)==1 and absent[0]['symbol']=='_$ss20__StaticArrayStorageCN'
    assert len(frontier['finiteObservedHIDOwnership']['sixStrongRoutes'])==6
    for report in (route,build,frontier):
        assert not report['full27Backend'] and not report['currentCompleteProviderDependencyGraphValidated']
        assert not report['nativeIOSExecuted'] and report['deviceOperations']==0
    pins=list(all_pins.values())+[p.pin(Path(__file__))]
    report=dict(schema='Own byte-contract review of finite six-strong HID ownership candidate v1',
        sources=list(map(p.pin,paths)),checkedPins=len(all_pins),checks=checks,originalChainedEntryCounts=chain_counts,
        negativeControls=negatives,actualSixStrongNamedDefinitionsClosed=True,currentActualProviderStrongDefinitions=16,
        ordinaryMacRealCoreFiveOwnershipOperationsCompared=True,originalProgramLowTagsAndPACPreserved=True,
        independentlyReviewedByAnotherAgent=False,originalEnumGetterRuntimeExecuted=False,
        productionHIDIdentityGatePassed=False,fullSwiftBytecodeInterpreterImplemented=False,
        processGlobalRuntimeOverrideHookIdentityPreserved=False,currentCompleteProviderDependencyGraphValidated=False,
        originalHIDLoaded=False,originalVZLoaded=False,deviceOperations=0,nativeIOSExecuted=False,full27Backend=False)
    p.save(out/'review.json',report); pins.append(p.pin(out/'review.json'))
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(review=p.pin(out/'review.json'),checkedPins=len(all_pins),checks=checks,rejectedControls=len(negatives))))


if __name__=='__main__': main()
