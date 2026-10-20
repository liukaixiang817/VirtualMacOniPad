#!/usr/bin/env python3
"""Strict saved genuine DIKit/DI2 load-only receipt, with no device or API operations."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-genuine-metadata-field-build-v4'
DI2 = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait in (0, 83)
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    di2_manifest = json.loads((DI2 / 'candidate.json').read_bytes())
    pins = manifest['files'][:13]; assert len(manifest['files']) == 20
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = di2_manifest['sourceProbeMethods']; assert len(symbols) == 60 and len(methods) == 8
    lines = Path(path).read_bytes().splitlines()
    failure = lines[-1].decode() if lines[-1].startswith(b'FAIL ') else None
    rows = [json.loads(line) for line in (lines[:-1] if failure else lines)]
    assert len(rows) >= 123
    same(rows[0], dict(record='DIKitClosureStart', PID=pid, DIKitAPICalls=0, DI2APICalls=0))
    original = rows[1:89]
    same(original[0], dict(record='start', PID=pid, DI2APICalls=0))
    runtime = '/private' + manifest['nativeDirectory']
    def identity(row, pin, record='identity', rva=None):
        assert set(row) == {'record', 'UUID', 'path', 'RVA'}
        assert type(row['RVA']) is str and re.fullmatch(r'0x[0-9a-f]+', row['RVA']) and int(row['RVA'], 16) > 0
        same(row, dict(record=record, UUID=pin['UUID'], path=runtime + '/' + pin['name'],
                       RVA=row['RVA'] if rva is None else hex(rva)))
    for row, (_, owner, _) in zip(original[1:61], symbols): identity(row, pins[int(owner)])
    di2 = pins[12]; assert di2['name'] == 'DiskImages227.dylib'
    names = ['DIOpenParams', 'DIImageHandle', 'DIDiskImageBridge', 'DICreateParams', 'DIAttachParams']
    for index, name in enumerate(names):
        identity(original[61 + index * 2], di2)
        same(original[62 + index * 2], dict(record='class', name=name, actualPrivateDI2Class=True))
    for index, pin in enumerate(methods):
        rva = pin['rawIMP'] - 0x23fd3e000
        identity(original[71 + index * 2], di2, rva=rva)
        same(original[72 + index * 2], dict(record='method', **{'class': pin['class']}, selector=pin['selector'], actualOriginalRVA=hex(rva), calls=0))
    same(original[-1], dict(record='summary', PID=pid, genuine27UUID=di2['UUID'], privateProviders=60, classes=5, methods=8,
                          DI2APICalls=0, diskVMGPUCalls=0, passed=True))
    for phase, offset in [('before', 89)]:
        for index, row in enumerate(rows[offset:offset + 10]):
            same(row, dict(record='DIKitSecurityCounter', phase=phase, entry=index, calls=0))
    bootstrap = rows[99]
    keys = {'record','status','checks','requiredImports','factoryCalls','requirementBindingsAuthenticated',
            'authenticatedBefore','authenticatedAfter','rollbackAuthenticated','pageProtectionBefore','pageMaximumBefore',
            'pageProtectionAfter','pageMaximumAfter','pagesChanged','rolledBack','protectionRestored','handlePublished',
            'failureStage','DIKitAPICalls','diskVMGPUCalls'}
    assert set(bootstrap) == keys and bootstrap['record'] == 'DIKitBootstrap'
    for key in keys - {'record'}: assert type(bootstrap[key]) is int
    before, maximum = bootstrap['pageProtectionBefore'], bootstrap['pageMaximumBefore']
    assert before in (1, 3) and maximum in (3, 7) and not before & 4
    same(bootstrap, dict(record='DIKitBootstrap', status=0, checks=245, requiredImports=168, factoryCalls=1,
        requirementBindingsAuthenticated=20, authenticatedBefore=3, authenticatedAfter=3, rollbackAuthenticated=0,
        pageProtectionBefore=before, pageMaximumBefore=maximum, pageProtectionAfter=before, pageMaximumAfter=maximum,
        pagesChanged=1, rolledBack=0, protectionRestored=1, handlePublished=1, failureStage=0, DIKitAPICalls=0, diskVMGPUCalls=0))
    for row, pin in zip(rows[100:105], manifest['files'][13:18]): identity(row, pin, record='DIKitClosureIdentity')
    absolute = manifest['files'][18]; assert absolute['name'] == 'VM27SwiftImmortalRefCount.dylib'
    same(rows[105], dict(record='DIKitAbsoluteExport', UUID=absolute['UUID'], path=runtime + '/' + absolute['name'],
        symbol='_swiftImmortalRefCount', providerValue='0x80000004ffffffff', DIKitDiscoveryValue='0x80000004ffffffff', dataDereferences=0))
    identity(rows[106], manifest['files'][13], record='DIKitClosureIdentity')

    names = ['ASIFCreationConfiguration','ASIFLayerCreationConfiguration','RAWCreationConfiguration','OpenConfiguration','_ResolvedCreationConfiguration','DILogger','IncompatibleStackingError','CorruptedImageError','UnsupportedFormatError']
    # Sizes are cross-checked below against the immutable original metadata probe.
    source=(BUILD/'source/modern_diskimagekit_native_metadata_probe.cpp').read_text()
    sizes=[int(value,0)for value in re.search(r'Sizes\[\]=\{([^}]+)\}',source)[1].split(',')]
    strides=[int(value,0)for value in re.search(r'Strides\[\]=\{([^}]+)\}',source)[1].split(',')]
    flags=[int(value,0)for value in re.search(r'Flags\[\]=\{([^}]+)\}',source)[1].split(',')]
    primitiveNames=['swift_retain','swift_release','swift_errorRetain','swift_errorRelease','swift_unknownObjectRetain','swift_unknownObjectRelease','swift_bridgeObjectRetain','swift_bridgeObjectRelease','swift_initStructMetadata']
    ownerKeys={'record','category','index','name','observed','UUID','path','RVA','matchesDIKitUUID','matchesSwiftUUID'}
    def owner(row,category,index,name):
        assert set(row)==ownerKeys
        for key in ['observed','matchesDIKitUUID','matchesSwiftUUID']:assert type(row[key])is bool
        assert type(row['index'])is int
        assert row['record']=='DIKitMetadataOwner' and row['category']==category and row['index']==index and row['name']==name
        assert type(row['UUID'])is str and type(row['path'])is str and type(row['RVA'])is str and re.fullmatch(r'0x[0-9a-f]+',row['RVA'])
        if row['observed']:
            assert re.fullmatch(r'[0-9a-f]{32}',row['UUID'])and row['path'].startswith('/')and int(row['RVA'],16)>0
            assert row['matchesDIKitUUID']==(row['UUID']=='652b07a998be31d298d7ffcaf14aca5e')
            assert row['matchesSwiftUUID']==(row['UUID']in['f896d145e02539d6afd3bc0a2ad4f839','c9b36da7bb3435afbc5d91ecbcaa9ed0'])
        else:same({key:row[key]for key in ['UUID','path','RVA','matchesDIKitUUID','matchesSwiftUUID']},dict(UUID='',path='',RVA='0x0',matchesDIKitUUID=False,matchesSwiftUUID=False))
    for index,name in enumerate(primitiveNames):owner(rows[107+index],'primitive',index,name)
    cursor=116; observations=[]
    responseKeys={'record','typeIndex','typeName','metadataCall','state','selectedGenuineImage','namedDescriptor'}
    boolKeys={'kindRead','tableSlotRead','tableOwnedByDIKit','tableRead','descriptorRead','layoutSlotRead','layoutOwnedByDIKit','layoutHeaderRead','layoutWordsRead'}
    intKeys={'typeIndex','metadataCall','queryStatus','queryType','querySize','queryStride','queryFlags','queryExtraInhabitants','expectedType','expectedSize','expectedStride','expectedLowFlags','expectedExtraInhabitants','metadataKind','tableSize','tableStride','tableFlags','tableExtraInhabitants','descriptorFlags','descriptorFieldCount','descriptorOffsetVector','layoutHeader0','layoutHeader1'}
    observationKeys=boolKeys|intKeys|{'record','typeName','prefillSentinel','layoutWords'}
    for index in range(9):
        response=rows[cursor];assert set(response)==responseKeys
        for key in ['typeIndex','metadataCall','state']:assert type(response[key])is int
        for key in ['selectedGenuineImage','namedDescriptor']:assert type(response[key])is bool
        same(response,dict(record='DIKitMetadataResponse',typeIndex=index,typeName=names[index],metadataCall=index+1,state=0,selectedGenuineImage=True,namedDescriptor=True))
        owner(rows[cursor+1],'valueWitnessTable',index,'valueWitnessTable');owner(rows[cursor+2],'layout',index,'layout')
        extraCursor=cursor+3; nested=[]
        nestedKeys={'record','parentTypeIndex','layoutWordIndex','kindRead','metadataKind','nominalNameRead','nominalName','tableSlotRead','tableRead','size','stride','flags','extraInhabitants'}
        while rows[extraCursor]['record']=='DIKitMetadataOwner':
            nestedOwner=rows[extraCursor];assert nestedOwner['category']=='nestedMetadata'
            assert type(nestedOwner['index'])is int and 0<=nestedOwner['index']<=10
            owner(nestedOwner,'nestedMetadata',nestedOwner['index'],'nestedMetadata')
            field=rows[extraCursor+1];assert set(field)==nestedKeys
            for key in ['parentTypeIndex','layoutWordIndex','metadataKind','size','stride','flags','extraInhabitants']:assert type(field[key])is int
            for key in ['kindRead','nominalNameRead','tableSlotRead','tableRead']:assert type(field[key])is bool
            assert field['record']=='DIKitNestedField'and field['parentTypeIndex']==index and field['layoutWordIndex']==nestedOwner['index']
            assert type(field['nominalName'])is str and len(field['nominalName'])<128
            assert field['nominalNameRead'] or field['nominalName']==''
            nested.append(dict(owner=nestedOwner,fields=field));extraCursor+=2
        offsets=rows[extraCursor];assert set(offsets)=={'record','parentTypeIndex','fieldCount','offsetVector','read','offsets'}
        for key in ['parentTypeIndex','fieldCount','offsetVector']:assert type(offsets[key])is int
        assert offsets['record']=='DIKitOriginalFieldOffsets'and offsets['parentTypeIndex']==index and type(offsets['read'])is bool and type(offsets['offsets'])is list
        assert offsets['fieldCount']==[3,5,3,2,4,2,1,1,1][index]
        if offsets['read']:
            assert len(offsets['offsets'])==offsets['fieldCount']and all(type(value)is int and 0<=value<=256 for value in offsets['offsets'])
        else:assert offsets['offsets']==[]
        observed=rows[extraCursor+1];assert set(observed)==observationKeys
        for key in boolKeys:assert type(observed[key])is bool
        for key in intKeys:assert type(observed[key])is int
        assert observed['record']=='DIKitMetadataObservation'and observed['typeIndex']==index and observed['typeName']==names[index]and observed['metadataCall']==index+1
        assert observed['prefillSentinel']=='0xdeadbeefdeadbeef/0xdeadbeef'
        same({key:observed[key]for key in ['expectedType','expectedSize','expectedStride','expectedLowFlags','expectedExtraInhabitants']},dict(expectedType=index+1,expectedSize=sizes[index],expectedStride=strides[index],expectedLowFlags=flags[index],expectedExtraInhabitants=0x7fffffff))
        assert observed['queryStatus']in(0,1)and type(observed['layoutWords'])is list and len(observed['layoutWords'])<=11
        for word in observed['layoutWords']:assert type(word)is str and re.fullmatch(r'0x[0-9a-f]{16}',word)
        if not observed['layoutWordsRead']:assert observed['layoutWords']==[]
        else:assert observed['layoutHeaderRead']and observed['layoutHeader1']<=80 and observed['layoutHeader1']%8==0 and len(observed['layoutWords'])==observed['layoutHeader1']//8+1
        passed=(observed['queryStatus']==1 and observed['queryType']==index+1 and observed['querySize']==sizes[index]and observed['queryStride']==strides[index]and observed['queryFlags']&0xffffff==flags[index]and observed['queryExtraInhabitants']==0x7fffffff)
        observations.append(dict(response=response,tableOwner=rows[cursor+1],layoutOwner=rows[cursor+2],nestedMetadata=nested,originalFieldOffsets=offsets,fields=observed,strictContractPassed=passed));cursor=extraCursor+2
        if not passed:
            assert wait==83 and failure=='FAIL exact scoped ownership metadata'and cursor==len(rows)
            return dict(passed=False,diagnosticReceiptValid=True,PID=pid,observedWaitExit=wait,originalMetadataAccessorsExecuted=index+1,failedTypeIndex=index,failedTypeName=names[index],queryStatus=observed['queryStatus'],originalStrictContractUnchanged=True,primitiveIdentities=rows[107:116],metadataObservations=observations,genuineDIKitLoaded=True,genuineDI2Loaded=True,bootstrapChecks=245,originalVMMExecuted=False,full27Backend=False)
    assert wait==0 and failure is None and len(rows)==cursor+12
    same(rows[cursor],dict(record='DIKitGenuineMetadata',genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',checks=33,failures=0,metadataCalls=9,scopedCVWQueries=9,diskVMGPUCalls=0));cursor+=1
    for index in range(10):same(rows[cursor+index],dict(record='DIKitSecurityCounter',phase='after',entry=index,calls=0))
    same(rows[-1],dict(record='DIKitClosureSummary',PID=pid,genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',privateAdditionalImages=6,DIKitAPICalls=9,DI2APICalls=0,originalMetadataCalls=9,diskVMGPUCalls=0,fileWrites=0,passed=True,full27Backend=False))
    return dict(passed=True,diagnosticReceiptValid=True,PID=pid,observedWaitExit=wait,originalMetadataAccessorsExecuted=9,metadataChecks=33,primitiveIdentities=rows[107:116],metadataObservations=observations,genuineDIKitLoaded=True,genuineDI2Loaded=True,originalVMMExecuted=False,full27Backend=False)
