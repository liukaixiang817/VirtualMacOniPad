#!/usr/bin/env python3
"""Strict saved genuine DIKit/DI2 load-only receipt, with no device or API operations."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-genuine-metadata-build-v1'
DI2 = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-foundation-loadonly-build-v2'


def same(actual, expected):
    assert json.dumps(actual, sort_keys=True, separators=(',', ':')) == json.dumps(expected, sort_keys=True, separators=(',', ':'))


def native_transcript(path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    manifest = json.loads((BUILD / 'candidate.json').read_bytes())
    di2_manifest = json.loads((DI2 / 'candidate.json').read_bytes())
    pins = manifest['files'][:13]; assert len(manifest['files']) == 20
    header = (BUILD / 'ios/diskimages227-pins.h').read_text()
    symbols = re.findall(r'\{"([^"\n]+)",(\d+),(0|1)\}', re.search(r'ProviderSymbols\[\]=\{(.*?)\};', header, re.S)[1])
    methods = di2_manifest['sourceProbeMethods']; assert len(symbols) == 60 and len(methods) == 8
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 119
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
    for phase, offset in [('before', 89), ('after', 108)]:
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
    same(rows[107], dict(record='DIKitGenuineMetadata', genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',
        checks=33, failures=0, metadataCalls=9, scopedCVWQueries=9, diskVMGPUCalls=0))
    same(rows[-1], dict(record='DIKitClosureSummary', PID=pid, genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',
        genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3', privateAdditionalImages=6,
        DIKitAPICalls=9, DI2APICalls=0, originalMetadataCalls=9, diskVMGPUCalls=0, fileWrites=0, passed=True, full27Backend=False))
    return dict(passed=True, PID=pid, observedWaitExit=wait, genuineDIKitLoaded=True, genuineDI2Loaded=True,
        DI2ProviderIdentities=60, DI2ClassIdentities=5, DI2MethodABIRVAIdentities=8, additionalClosureIdentities=5,
        requiredOriginalAndCurrentImports=168, bootstrapChecks=245, completedMetadataFactoryCalls=1,
        authenticatedStaticISAsBefore=3, authenticatedStaticISAsAfter=3, originalRequirementPACBindingsAuthenticated=20,
        ownedPagesChanged=1, originalCurrentAndMaximumPageProtectionRestored=True, handlePublishedAfterRepair=True,
        desktopSecurityCalls=0, originalCNProvided=False, exactAbsoluteExportValue='0x80000004ffffffff',
        originalAbsoluteSymbolDiscoveryVerified=True, absoluteDataDereferences=0, DIKitAPICalls=9, DI2APICalls=0, originalMetadataCalls=9,
        originalGenuineMetadataAccessorsExecuted=9, metadataChecks=33, scopedOwnershipMetadataQueries=9,
        diskVMGPUCalls=0, fileWrites=0, RAWReadWriteVerified=False, fullDIKit27=False, fullSwift27Runtime=False,
        originalVMMExecuted=False, guestInstructionOracle=0, full27Backend=False)
