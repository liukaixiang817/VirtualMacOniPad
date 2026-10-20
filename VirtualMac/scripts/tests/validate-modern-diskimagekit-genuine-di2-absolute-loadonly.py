#!/usr/bin/env python3
"""Review and freeze the isolated local DIKit + genuine DI2 loader; never executes it."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BUILD = N / 'diskimagekit-genuine-di2-loadonly-build-v3'
BASE = N / 'diskimagekit-static-bootstrap-build-v12'
DI2 = N / 'diskimages2-foundation-loadonly-build-v2'
RAW = N / 'diskimages2-foundation-owned-raw-v2-saved-adjudication-v2'
PARSER = ROOT / 'VirtualMac/scripts/tests/validate-modern-diskimagekit-genuine-di2-absolute-native.py'
SHA = lambda content: hashlib.sha256(content).hexdigest()
sys.path.insert(0, str(ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands, segments, imports, chain_entries, export_trie


def main():
    args = argparse.ArgumentParser(description=__doc__); args.add_argument('--output', type=Path, required=True)
    output = args.parse_args().output.resolve(); output.mkdir()
    candidate = BUILD / 'candidate.json'
    assert SHA(candidate.read_bytes()) == '8e7134cc7a2658084c2013ee06b05f4ff4f72aa4cb92c8dfb1d3696978dd6f8f'
    manifest = json.loads(candidate.read_bytes()); files = manifest['files']; assert len(files) == 20
    assert manifest['nativeExecutionPending'] is True and manifest['deviceOperations'] is False
    for key in ['actualIOSRun','completeOriginalClosure','fullDIKit27','fullSwift27Runtime','fullVZ27Backend','full27Backend']:
        assert manifest[key] is False
    frozen = json.loads((BASE / 'manifest.json').read_bytes())
    base_files = {Path(item['path']).name: item for item in frozen['files'] if '/ios/' in item['path']}
    old_di2 = json.loads((DI2 / 'candidate.json').read_bytes())['files'][:-1]
    for new, old in zip(files[:13], old_di2):
        assert new['name'] == old['name'] and Path(new['path']).read_bytes() == Path(old['path']).read_bytes()
    for item in files[13:16]: assert Path(item['path']).read_bytes() == Path(base_files[item['name']]['path']).read_bytes()
    for item in manifest['inputs']:
        content = Path(item['path']).read_bytes(); assert len(content) == item['bytes'] and SHA(content) == item['sha256']
        assert content == (BUILD / 'source' / Path(item['path']).name).read_bytes()
    before = Path(base_files['DiskImageKit27.dylib']['path']).read_bytes()
    after = Path(files[17]['path']).read_bytes()
    def dependencies(content):
        values = []
        for command, offset, size in commands(content):
            if command in (12,0x80000018,0x8000001f,0x80000023):
                start = struct.unpack_from('<I', content, offset + 8)[0]
                values.append((command, offset, size, content[offset + start:offset + size].split(b'\0')[0].decode()))
        return values
    expected = dependencies(before); expected[3] = (*expected[3][:3], '@loader_path/DiskImages227.dylib')
    assert dependencies(after) == expected and len(expected) == 16
    assert imports(before)['imports'] == imports(after)['imports'] and len(imports(after)['imports']) == 164
    assert all(not item['weak'] for item in imports(after)['imports'])
    assert list(chain_entries(before)) == list(chain_entries(after))
    for group in segments(before):
        for section in group['sections']:
            if section['size'] and section['fileoff']:
                offset=section['fileoff']; size=section['size']; assert before[offset:offset + size] == after[offset:offset + size]
    assert (BUILD / 'source/modern_swift_static_array_bootstrap.cpp').read_bytes() == (ROOT / 'VirtualMac/vz/host/modern_swift_static_array_bootstrap.cpp').read_bytes()
    assert (BUILD / 'ios/diskimagekit_bootstrap_required_imports.h').read_bytes() == (BASE / 'ios/diskimagekit_bootstrap_required_imports.h').read_bytes()
    required = re.findall(r'^ "([^"\n]+)",$', (BUILD / 'ios/diskimagekit_bootstrap_required_imports.h').read_text(), re.M)
    assert len(required) == len(set(required)) == 168 and '$ss20__StaticArrayStorageCN' not in required
    commands_log = []
    for item in files:
        path=Path(item['path']); content=path.read_bytes(); assert len(content)==item['bytes'] and SHA(content)==item['sha256']
        assert next(content[offset + 8:offset + 24].hex() for command, offset, _ in commands(content) if command==27) == item['UUID']
        for arguments in [['codesign','--verify','--strict',path],['xcrun','dyld_info','-validate_only',path],
                ['codesign','-d','--verbose=4',path],['codesign','-d','--entitlements',':-',path]]:
            result=subprocess.run([str(value) for value in arguments],capture_output=True,timeout=20)
            commands_log.append(dict(argv=[str(value) for value in arguments],wait=result.returncode,
                stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace')))
            assert result.returncode==0
            if '--verbose=4' in arguments: assert re.search(rb'CDHash=([0-9a-f]{40})',result.stderr)[1].decode()==item['CDHash']
            if '--entitlements' in arguments: assert (plistlib.loads(result.stdout) if result.stdout.strip() else {})==item.get('entitlements', {})
    source=(BUILD / 'source/modern_diskimagekit_genuine_di2_immortal_loadonly_probe.cpp').read_text()
    assert 'VM27FoundationDI2LoadOnly(argc,argv)' in source and 'VM27StaticArrayBootstrapLoad(DIKitPath,FactoryPath,0,' in source
    assert 'setrlimit(RLIMIT_CPU,&cpu)' in source and 'alarm(10)' in source
    assert all(name not in source for name in ['pwrite(', 'ftruncate(', 'O_CREAT', '--metadata', 'vm_deallocate(', 'mach_vm_write('])
    actual=json.loads((RAW / 'result.json').read_bytes()); assert actual['passed'] is True and actual['oldWrapperPassed'] is False
    assert manifest['originalDIKitV2BytesUnchanged'] is True
    assert after == (N/'diskimagekit-genuine-di2-loadonly-build-v2/ios/DiskImageKit27.dylib').read_bytes()
    absolute=Path(files[18]['path']).read_bytes();assert files[18]['name']=='VM27SwiftImmortalRefCount.dylib'
    export_at=next(at for cmd,at,size in commands(absolute) if cmd==0x80000033)
    export_offset,export_size=struct.unpack_from('<II',absolute,export_at+8)
    assert export_trie(absolute[export_offset:export_offset+export_size])==[dict(symbol='__swiftImmortalRefCount',flags=2,address=0x80000004ffffffff)]
    symbol_at=next(at for cmd,at,size in commands(absolute) if cmd==2)
    symbol_offset,symbol_count,string_offset,string_size=struct.unpack_from('<4I',absolute,symbol_at+8);assert symbol_count==1
    strx,typ,section,description,value=struct.unpack_from('<IBBHQ',absolute,symbol_offset)
    assert (typ,section,description,value)==(3,0,0,0x80000004ffffffff)
    assert absolute[string_offset+strx:string_offset+string_size].split(b'\0')[0]==b'__swiftImmortalRefCount'
    bootstrap=Path(files[16]['path']).read_bytes();reexport=[]
    for cmd,at,size in commands(bootstrap):
        if cmd==0x8000001f:
            offset=struct.unpack_from('<I',bootstrap,at+8)[0];reexport.append(bootstrap[at+offset:at+size].split(b'\0')[0].decode())
    assert reexport==['@rpath/VM27SwiftImmortalRefCount.dylib']
    current_names={row['name'][1:] for row in imports(after)['imports']}
    assert set(required)-current_names=={'__chkstk_darwin','_swiftImmortalRefCount','memcpy','memmove'}
    host_rows=[json.loads(line) for line in (N/'di2-system-import-native-v1/native.stdout').read_bytes().splitlines()]
    host={row['name']:row for row in host_rows if row['record']=='symbol'}
    assert all(host[name]['found'] is True for name in ('__chkstk_darwin','memcpy','memmove'))
    failed=json.loads((N/'diskimagekit-genuine-di2-loadonly-native-v1/result.json').read_bytes())
    assert failed['passed'] is False and failed['childPID']==46580 and failed['observedWaitExit']==78
    failed_rows=[json.loads(line) for line in (N/'diskimagekit-genuine-di2-loadonly-native-v1/native.stdout').read_bytes().splitlines()]
    assert len(failed_rows)==100 and failed_rows[-1]['status']==78 and failed_rows[-1]['requiredImports']==111 and failed_rows[-1]['pagesChanged']==0
    mac_original=json.loads((N/'swift-immortalrefcount-contract-v1/original-runtime-symbol.stdout').read_bytes())
    mac_private=json.loads((N/'swift-immortalrefcount-provider-build-v2/oracle.stdout').read_bytes())
    assert mac_original==mac_private==dict(symbol='_swiftImmortalRefCount',dlsymValue='0x80000004ffffffff',dlsymError=False,dataDereferences=0)
    original_contract=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-full-runtime-port-audit-v1/original-image-contract.json'
    original_text=original_contract.read_text()
    assert '\"symbol\": \"__swiftImmortalRefCount\"' in original_text
    assert source.count('dataDereferences\\\":0')==1 and 'ptrauth_strip(own' not in source and '*(uint64_t *)own' not in source
    plan=dict(scope=manifest['scope'],deviceDirectory=manifest['nativeDirectory'],
        files=[dict(path=item['path'],name=item['name'],bytes=item['bytes'],sha256=item['sha256'],UUID=item['UUID'],
                    cdhash=item['CDHash'],entitlements=item.get('entitlements', {}),code=True) for item in files],
        executable=manifest['executable'],arguments=manifest['arguments'],candidateManifestSHA256=SHA(candidate.read_bytes()),
        bootstrapMustRestoreOriginalCurrentAndMaximumProtection=True,authenticatedStaticISAsBefore=3,
        authenticatedStaticISAsAfter=3,originalRequirementPACBindings=20,ownedPageMaximum=1,requiredStrongImports=164,
        requiredOriginalAndCurrentImports=168,originalMetadataCalls=0,DIKitAPICalls=0,DI2APICalls=0,diskVMGPUCalls=0,
        CPUSecondsSoft=3,CPUSecondsHard=4,wallSecondsLimit=10,actualExternalWaitAndAbsenceRequired=True,
        nativeValidator=str(PARSER),nativeValidatorSHA256=SHA(PARSER.read_bytes()),
        prerequisiteRAWActualPID=46014,prerequisiteRAWActualWait=0,prerequisiteSavedAdjudicationSHA256=SHA((RAW/'result.json').read_bytes()),
        originalFailedRAWWrapperPreserved=True,exactAbsoluteSymbol='_swiftImmortalRefCount',exactAbsoluteValue='0x80000004ffffffff',absoluteDataDereferences=0,full27Backend=False)
    (output/'consumer-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    verification=dict(passed=True,files=20,strictSignatures=20,dyldValidations=20,original13DI2LibrariesUnchanged=True,
        threeSwiftLibrariesUnchanged=True,bootstrapSourceUnchanged=True,bootstrapRecompiledForPrivateAbsoluteReexport=True,
        genuineDIKitUUID=files[17]['UUID'],genuineDI2UUID=files[12]['UUID'],original164StrongImportRowsUnchanged=True,
        original168RequiredImportsRetained=True,originalAllChainedWordsAndPACUnchanged=True,
        originalAllNonemptySectionBytesUnchanged=True,onlyOneOriginalDependencyPathChanged=True,
        originalCNProvided=False,actualIOSRun=False,DIKitAPICalls=0,originalMetadataCalls=0,
        originalDIKitV2BytesUnchanged=True,exactAbsoluteExportFlags=2,exactAbsoluteNlistType=3,
        exactAbsoluteValue='0x80000004ffffffff',absoluteDataDereferences=0,all168RequiredNamesPreserved=True,
        original164NamesBoundInPriorActualRTLDNOW=True,otherThreeExtraNamesFoundInPriorActualHostInventory=True,
        nativeExecutionPending=True,deviceOperations=False,fullDIKit27=False,full27Backend=False)
    (output/'verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    (output/'commands.json').write_text(json.dumps(commands_log,indent=2)+'\n')
    pinned=set(path for path in BUILD.rglob('*') if path.is_file()); pinned.update(Path(item['path']) for item in manifest['inputs'])
    pinned.update([original_contract,N/'di2-system-import-native-v1/native.stdout',N/'di2-system-import-inventory-build-v1/imports.h',
        N/'diskimagekit-genuine-di2-loadonly-native-v1/result.json',N/'diskimagekit-genuine-di2-loadonly-native-v1/native.stdout',
        N/'diskimagekit-genuine-di2-loadonly-native-v1/native.stderr',N/'swift-immortalrefcount-contract-v1/original-runtime-symbol.stdout',
        N/'swift-immortalrefcount-contract-v1/processes.json',N/'swift-immortalrefcount-provider-build-v2/oracle.stdout',
        N/'swift-immortalrefcount-provider-build-v2/oracle-processes.json'])
    pinned.update([Path(__file__),PARSER,RAW/'result.json',RAW/'freeze.json',output/'consumer-plan.json',output/'verification.json',output/'commands.json'])
    def pin(path):
        content=path.read_bytes(); return dict(path=str(path),bytes=len(content),sha256=SHA(content))
    (output/'freeze.json').write_text(json.dumps(dict(files=[pin(path) for path in sorted(pinned)]),indent=2)+'\n')
    ready=dict(scope=manifest['scope'],localReadyForRootDeviceReview=True,nativeExecutionPending=True,
        candidate=pin(candidate),consumerPlan=pin(output/'consumer-plan.json'),freeze=pin(output/'freeze.json'),
        nativeParser=pin(PARSER),RAWPrerequisite=pin(RAW/'result.json'),deviceOperations=False,full27Backend=False)
    (output/'READY-v1.json').write_text(json.dumps(ready,indent=2)+'\n')
    print(json.dumps(dict(candidateSHA256=SHA(candidate.read_bytes()),planSHA256=SHA((output/'consumer-plan.json').read_bytes()),
        freezeSHA256=SHA((output/'freeze.json').read_bytes()),nativeParserSHA256=SHA(PARSER.read_bytes()),
        READY_SHA256=SHA((output/'READY-v1.json').read_bytes()),pins=len(pinned),nativeExecutionPending=True),indent=2))


if __name__=='__main__': main()
