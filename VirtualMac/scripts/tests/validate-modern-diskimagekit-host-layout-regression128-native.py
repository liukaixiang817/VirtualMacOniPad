#!/usr/bin/env python3
"""Strict saved genuine DIKit/DI2 load-only receipt, with no device or API operations."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BUILD=N/'diskimagekit-host-layout-regression128-build-v1'
DI2 = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows)>=106
    manifest=json.loads((BUILD/'candidate.json').read_bytes());cached=True
    di2_manifest = json.loads((DI2 / 'candidate.json').read_bytes())
    pins = manifest['files'][:13]; assert len(manifest['files']) == 21
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = di2_manifest['sourceProbeMethods']; assert len(symbols) == 60 and len(methods) == 8
    assert len(rows)==147
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

    cursor=106
    def cacheStatus(phase):
        nonlocal cursor
        if cached:identity(rows[cursor],manifest['files'][13],record='DIKitClosureIdentity');cursor+=1
        same(rows[cursor],dict(record='DIKitPrimitiveCacheStatus',phase=phase,cachedProvider=cached,counterAvailable=cached,initializerRuns=1 if cached else 0,nineFixedBindingsValid=cached,dynamicMetadataLayoutCached=False));cursor+=1
    cacheStatus('before')
    sdk=manifest['files'][19];assert sdk['name']=='DIKitHostLayoutSemanticFixture.dylib'
    for row in rows[cursor:cursor+3]:identity(row,sdk,record='DIKitClosureIdentity')
    cursor+=3;dimensions=[]
    for index,row in enumerate(rows[cursor:cursor+5]):
        same(row,dict(record='DIKitRealSDKHostDimension',typeIndex=index,size=[8,17,50,17,9][index],stride=[8,24,56,24,16][index]));dimensions.append((row['size'],row['stride']))
    cursor+=5;boundaries=[]
    def boundary(section,stage):
        nonlocal cursor
        row=rows[cursor];cursor+=1
        assert set(row)=={'record','boundary','section','stage','processCPUNanoseconds','monotonicNanoseconds'}
        for key in ['boundary','processCPUNanoseconds','monotonicNanoseconds']:assert type(row[key])is int and row[key]>0
        if boundaries:assert row['processCPUNanoseconds']>=boundaries[-1]['processCPUNanoseconds']and row['monotonicNanoseconds']>=boundaries[-1]['monotonicNanoseconds']
        same(row,dict(record='DIKitSDK128CallBoundary',boundary=len(boundaries)+1,section=section,stage=stage,processCPUNanoseconds=row['processCPUNanoseconds'],monotonicNanoseconds=row['monotonicNanoseconds']));boundaries.append(row)
    boundary('semantic','begin');boundary('semantic','end')
    same(rows[cursor],dict(record='DIKitRealSDKConfigurationSemantics',checks=1536,failures=0,iterations=128,originalConfigurationFactories=896,SDKImplicitMetadataAndGetterCallsUncounted=True,diskAPICalls=0));cursor+=1
    boundary('ownership','begin');boundary('ownership','end')
    same(rows[cursor],dict(record='DIKitRealSDKURLOwnership',checks=384,failures=0,iterations=128,originalConfigurationFactories=128,weakObjectLifecycleChecksPassed=True,diskAPICalls=0));cursor+=1
    timing=rows[cursor];cursor+=1
    assert set(timing)=={'record','iterationsPerSection','originalConfigurationFactories','CPUStartNanoseconds','CPUEndNanoseconds','wallStartNanoseconds','wallEndNanoseconds','CPUElapsedNanoseconds','wallElapsedNanoseconds','boundaryRecords','originalSDKFixtureBytesUnchanged'}
    for key in set(timing)-{'record','originalSDKFixtureBytesUnchanged'}:assert type(timing[key])is int and timing[key]>0
    assert type(timing['originalSDKFixtureBytesUnchanged'])is bool and timing['originalSDKFixtureBytesUnchanged']is True
    assert timing['CPUElapsedNanoseconds']==timing['CPUEndNanoseconds']-timing['CPUStartNanoseconds']and 0<timing['CPUElapsedNanoseconds']<3000000000
    assert timing['wallElapsedNanoseconds']==timing['wallEndNanoseconds']-timing['wallStartNanoseconds']and 0<timing['wallElapsedNanoseconds']<10000000000
    assert timing['CPUStartNanoseconds']<=boundaries[0]['processCPUNanoseconds']<=boundaries[-1]['processCPUNanoseconds']<=timing['CPUEndNanoseconds']
    assert timing['wallStartNanoseconds']<=boundaries[0]['monotonicNanoseconds']<=boundaries[-1]['monotonicNanoseconds']<=timing['wallEndNanoseconds']
    same(timing,dict(record='DIKitSDK128PerformanceTiming',iterationsPerSection=128,originalConfigurationFactories=1024,CPUStartNanoseconds=timing['CPUStartNanoseconds'],CPUEndNanoseconds=timing['CPUEndNanoseconds'],wallStartNanoseconds=timing['wallStartNanoseconds'],wallEndNanoseconds=timing['wallEndNanoseconds'],CPUElapsedNanoseconds=timing['CPUElapsedNanoseconds'],wallElapsedNanoseconds=timing['wallElapsedNanoseconds'],boundaryRecords=4,originalSDKFixtureBytesUnchanged=True))
    cacheStatus('after')
    identity(rows[cursor],manifest['files'][13],record='DIKitClosureIdentity');cursor+=1
    names=['ASIFCreationConfiguration','ASIFLayerCreationConfiguration','RAWCreationConfiguration','OpenConfiguration','_ResolvedCreationConfiguration','DILogger','IncompatibleStackingError','CorruptedImageError','UnsupportedFormatError']
    source=(BUILD/'source/modern_diskimagekit_native_metadata_probe.cpp').read_text()
    oldSizes=[int(value,0)for value in re.search(r'Sizes\[\]=\{([^}]+)\}',source)[1].split(',')]
    oldStrides=[int(value,0)for value in re.search(r'Strides\[\]=\{([^}]+)\}',source)[1].split(',')]
    oldFlags=[int(value,0)for value in re.search(r'Flags\[\]=\{([^}]+)\}',source)[1].split(',')]
    metadata=[]
    for index,row in enumerate(rows[cursor:cursor+9]):
        assert set(row)=={'record','typeIndex','typeName','originalMetadataCall','queryStatus','type','size','stride','flags','extraInhabitants','matchesRealSDKPublicDimensions','matchesOriginalMacGolden'}
        for key in ['typeIndex','originalMetadataCall','queryStatus','type','size','stride','flags','extraInhabitants']:assert type(row[key])is int
        for key in ['matchesRealSDKPublicDimensions','matchesOriginalMacGolden']:assert type(row[key])is bool
        assert row['record']=='DIKitHostMetadata'and row['typeIndex']==index and row['typeName']==names[index]and row['originalMetadataCall']==index+1 and row['queryStatus']==1 and row['type']==index+1
        assert 0<row['size']<=256 and row['stride']==(row['size']+7)&~7
        assert row['flags']&0xffffff==(0x10007|(0x20000 if row['size']>24 else 0))and row['extraInhabitants']==0x7fffffff
        assert row['matchesRealSDKPublicDimensions']is True
        if index<4:assert (row['size'],row['stride'])==dimensions[index+1]
        legacy=(row['size']==oldSizes[index]and row['stride']==oldStrides[index]and row['flags']&0xffffff==oldFlags[index])
        assert row['matchesOriginalMacGolden']==legacy
        metadata.append(row)
    assert metadata[0]['matchesOriginalMacGolden']is False
    cursor+=9
    same(rows[cursor],dict(record='DIKitGenuineHostMetadata',genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',checks=33,failures=0,metadataCalls=9,scopedCVWQueries=9,diskVMGPUCalls=0))
    cursor+=1
    for index,row in enumerate(rows[cursor:cursor+10]):same(row,dict(record='DIKitSecurityCounter',phase='after',entry=index,calls=0))
    cursor+=10;assert cursor==len(rows)-1
    same(rows[-1],dict(record='DIKitClosureSummary',PID=pid,genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',privateAdditionalImages=6,originalExplicitMetadataCalls=9,knownOriginalConfigurationFactoryCalls=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,DI2APICalls=0,originalMacGoldenPassClaimed=False,diskVMGPUCalls=0,fileWrites=0,passed=True,full27Backend=False))
    return dict(passed=True,PID=pid,observedWaitExit=wait,genuineDIKitLoaded=True,genuineDI2Loaded=True,requiredImports=168,bootstrapChecks=245,authenticatedISAsBefore=3,authenticatedISAsAfter=3,originalRequirementPACBindingsAuthenticated=20,originalCurrentAndMaximumProtectionRestored=True,exactABSValue='0x80000004ffffffff',absoluteDataDereferences=0,originalExplicitMetadataAccessorsExecuted=9,scopedMetadataChecks=33,realSDKPublicConfigurationTypeSemanticOracles=4,realSDKSemanticChecks=1536,realSDKURLOwnershipChecks=384,realSDKIterations=128,knownOriginalConfigurationFactories=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,cachedPrimitives=cached,primitiveIdentityInitializerRuns=1 if cached else None,dynamicMetadataLayoutCached=False,exactOriginal49507SDKFixturePreserved=True,internalIterationProgressUnavailable=True,callBoundaryRecords=4,performanceCPUNanoseconds=timing['CPUElapsedNanoseconds'],performanceWallNanoseconds=timing['wallElapsedNanoseconds'],hostSpecificDimensions=dimensions,hostMetadata=metadata,originalMacGoldenPassClaimed=False,oldFailedReceiptsPreserved=True,DI2APICalls=0,originalDiskAPICalls=0,VMGPUCalls=0,fileWrites=0,originalCNProvided=False,fullDIKit27=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
