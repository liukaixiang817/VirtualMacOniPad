#!/usr/bin/env python3
"""Strict saved genuine DIKit/DI2 load-only receipt, with no device or API operations."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-host-layout-steps-build-v1'
DI2 = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait in (0,84,142,152,153)
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    di2_manifest = json.loads((DI2 / 'candidate.json').read_bytes())
    pins = manifest['files'][:13]; assert len(manifest['files']) == 21
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = di2_manifest['sourceProbeMethods']; assert len(symbols) == 60 and len(methods) == 8
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert 114 <= len(rows) <= 700
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

    sdk=manifest['files'][19];assert sdk['name']=='DIKitHostLayoutStepFixture.dylib'
    for row in rows[106:109]:identity(row,sdk,record='DIKitClosureIdentity')
    dimensions=[]
    for index,row in enumerate(rows[109:114]):
        assert set(row)=={'record','typeIndex','size','stride'}
        for key in ['typeIndex','size','stride']:assert type(row[key])is int
        same(row,dict(record='DIKitRealSDKHostDimension',typeIndex=index,size=[8,17,50,17,9][index],stride=[8,24,56,24,16][index]))
        dimensions.append((row['size'],row['stride']))
    source=(BUILD/'source/modern_diskimagekit_host_layout_step_probe.cpp').read_text()
    methods=re.findall(r'"(\$s[^"\n]+)"',re.search(r'const char \*methods\[\]=\{(.*?)\};',source,re.S)[1]);assert len(methods)==7
    assert len(rows)>=128
    for index,symbol in enumerate(methods):
        identity(rows[114+index*2],manifest['files'][17],record='DIKitClosureIdentity')
        same(rows[115+index*2],dict(record='DIKitOriginalSDKMethodIdentity',methodIndex=index,symbol=symbol,callsAtObservation=0))
    operations=json.loads((BUILD/'source/modern_diskimagekit_host_layout_step_phases.json').read_bytes())
    allowed={item['operation']for item in operations['operations']};mirrorOperations={5,7,9,12,13,15,16,19,21,25,26,29,109}
    stack=[];completed=[];checkpoints=[];semantic=None;ownership=None;summary=None;after=[]
    section='semantics';lastChecks=0
    for row in rows[128:]:
        record=row.get('record')
        if record=='DIKitSDKCheckpoint':
            assert set(row)=={'record','checkpoint','operation','stage','childIndex','checks','failures'}
            for key in set(row)-{'record'}:assert type(row[key])is int
            assert row['checkpoint']==len(checkpoints)+1 and row['stage']in(0,1)and 0<=row['childIndex']<=8
            op=row['operation'];assert op in allowed or (op>=1000 and (op-1000)//10 in mirrorOperations and (op-1000)%10<=5)
            assert 0<=row['failures']<=row['checks'] and lastChecks<=row['checks']<=(12 if section=='semantics'else 3)
            lastChecks=row['checks'];tag=(op,row['childIndex'])
            if row['stage']==0:stack.append(tag)
            else:
                assert stack and stack.pop()==tag
                if op in allowed:completed.append(op)
            checkpoints.append(row)
        elif record=='DIKitRealSDKConfigurationStepSemantics':
            assert not stack and semantic is None and ownership is None
            assert type(row.get('failures'))is int and 0<=row['failures']<=12
            same(row,dict(record=record,checks=12,failures=row['failures'],iterations=1,originalConfigurationFactories=7,SDKImplicitMetadataAndGetterCallsUncounted=True,diskAPICalls=0))
            assert completed==list(range(1,42));semantic=row;section='ownership';lastChecks=0
        elif record=='DIKitRealSDKURLStepOwnership':
            assert not stack and semantic is not None and ownership is None
            assert type(row.get('failures'))is int and 0<=row['failures']<=3
            same(row,dict(record=record,checks=3,failures=row['failures'],iterations=1,originalConfigurationFactories=1,weakObjectLifecycleChecksPassed=row['failures']==0,diskAPICalls=0))
            assert completed[:41]==list(range(1,42)) and completed[41:]==[101,103,104,105,102,106,107,108,109,110,111,112]
            ownership=row
        elif record=='DIKitSecurityCounter':
            assert semantic is not None and ownership is not None and not stack
            same(row,dict(record=record,phase='after',entry=len(after),calls=0));after.append(row);assert len(after)<=10
        elif record=='DIKitClosureSummary':
            assert summary is None and semantic is not None and ownership is not None and len(after)==10 and not stack
            same(row,dict(record=record,PID=pid,genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',privateAdditionalImages=6,originalExplicitMetadataCalls=0,knownOriginalConfigurationFactoryCalls=8,SDKImplicitMetadataAndGetterCallsUncounted=True,DI2APICalls=0,originalMacGoldenPassClaimed=False,diskVMGPUCalls=0,fileWrites=0,passed=True,full27Backend=False));summary=row
        else:raise AssertionError('unexpected record '+str(record))
    functional=semantic is not None and ownership is not None and semantic['failures']==0 and ownership['failures']==0 and summary is not None and wait==0
    if wait==0:assert functional
    else:assert summary is None
    return dict(passed=functional,diagnosticReceiptValid=True,PID=pid,observedWaitExit=wait,genuineDIKitLoaded=True,genuineDI2Loaded=True,hostSpecificDimensions=dimensions,originalStrongSDKMethodIdentities=7,checkpointRecords=len(checkpoints),lastCheckpoint=checkpoints[-1]if checkpoints else None,unfinishedCheckpointStack=stack,completedOperations=completed,semanticCompleted=semantic is not None,ownershipCompleted=ownership is not None,realSDKSemanticChecks=12 if semantic else 0,realSDKOwnershipChecks=3 if ownership else 0,knownOriginalConfigurationFactories=8 if functional else None,SDKImplicitMetadataAndGetterCallsUncounted=True,originalExplicitMetadataCalls=0,originalDiskAPICalls=0,originalCaseIterableCalls=0,fileWrites=0,fullDIKit27=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
