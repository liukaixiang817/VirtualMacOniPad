#!/usr/bin/env python3
"""Strict saved genuine DIKit/DI2 load-only receipt, with no device or API operations."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-host-layout-semantics-build-v1'
DI2 = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    di2_manifest = json.loads((DI2 / 'candidate.json').read_bytes())
    pins = manifest['files'][:13]; assert len(manifest['files']) == 21
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = di2_manifest['sourceProbeMethods']; assert len(symbols) == 60 and len(methods) == 8
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 138
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
    for phase, offset in [('before', 89), ('after', 127)]:
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

    sdk=manifest['files'][19];assert sdk['name']=='DIKitHostLayoutSemanticFixture.dylib'
    for row in rows[106:109]:identity(row,sdk,record='DIKitClosureIdentity')
    dimensions=[]
    for index,row in enumerate(rows[109:114]):
        assert set(row)=={'record','typeIndex','size','stride'}and row['record']=='DIKitRealSDKHostDimension'
        for key in ['typeIndex','size','stride']:assert type(row[key])is int
        assert row['typeIndex']==index and 0<row['size']<=256 and row['size']<=row['stride']<=256 and row['stride']%8==0
        dimensions.append((row['size'],row['stride']))
    assert dimensions[0]==(8,8) # Frozen actual48646 native Foundation.URL field metadata.
    assert dimensions[1]==(17,24)and dimensions[3]==(17,24)and dimensions[4]==(9,16)
    same(rows[114],dict(record='DIKitRealSDKConfigurationSemantics',checks=1536,failures=0,iterations=128,originalConfigurationFactories=896,SDKImplicitMetadataAndGetterCallsUncounted=True,diskAPICalls=0))
    same(rows[115],dict(record='DIKitRealSDKURLOwnership',checks=384,failures=0,iterations=128,originalConfigurationFactories=128,weakObjectLifecycleChecksPassed=True,diskAPICalls=0))
    identity(rows[116],manifest['files'][13],record='DIKitClosureIdentity')
    names=['ASIFCreationConfiguration','ASIFLayerCreationConfiguration','RAWCreationConfiguration','OpenConfiguration','_ResolvedCreationConfiguration','DILogger','IncompatibleStackingError','CorruptedImageError','UnsupportedFormatError']
    source=(BUILD/'source/modern_diskimagekit_native_metadata_probe.cpp').read_text()
    oldSizes=[int(value,0)for value in re.search(r'Sizes\[\]=\{([^}]+)\}',source)[1].split(',')]
    oldStrides=[int(value,0)for value in re.search(r'Strides\[\]=\{([^}]+)\}',source)[1].split(',')]
    oldFlags=[int(value,0)for value in re.search(r'Flags\[\]=\{([^}]+)\}',source)[1].split(',')]
    metadata=[]
    for index,row in enumerate(rows[117:126]):
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
    same(rows[126],dict(record='DIKitGenuineHostMetadata',genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',checks=33,failures=0,metadataCalls=9,scopedCVWQueries=9,diskVMGPUCalls=0))
    same(rows[-1],dict(record='DIKitClosureSummary',PID=pid,genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',privateAdditionalImages=6,originalExplicitMetadataCalls=9,knownOriginalConfigurationFactoryCalls=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,DI2APICalls=0,originalMacGoldenPassClaimed=False,diskVMGPUCalls=0,fileWrites=0,passed=True,full27Backend=False))
    return dict(passed=True,PID=pid,observedWaitExit=wait,genuineDIKitLoaded=True,genuineDI2Loaded=True,requiredImports=168,bootstrapChecks=245,authenticatedISAsBefore=3,authenticatedISAsAfter=3,originalRequirementPACBindingsAuthenticated=20,originalCurrentAndMaximumProtectionRestored=True,exactABSValue='0x80000004ffffffff',absoluteDataDereferences=0,originalExplicitMetadataAccessorsExecuted=9,scopedMetadataChecks=33,realSDKPublicConfigurationTypeSemanticOracles=4,realSDKSemanticChecks=1536,realSDKURLOwnershipChecks=384,realSDKIterations=128,knownOriginalConfigurationFactories=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,hostSpecificDimensions=dimensions,hostMetadata=metadata,originalMacGoldenPassClaimed=False,oldFailedReceiptsPreserved=True,DI2APICalls=0,originalDiskAPICalls=0,VMGPUCalls=0,fileWrites=0,originalCNProvided=False,fullDIKit27=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
