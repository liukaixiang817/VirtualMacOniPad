#!/usr/bin/env python3
"""Prepare an isolated genuine DIKit nine-type metadata caller; no native API or device execution."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE=N/'diskimagekit-genuine-di2-loadonly-build-v3'
ACTUAL=N/'diskimagekit-genuine-di2-loadonly-native-v2'
HOST=ROOT/'VirtualMac/vz/host'
SHA=lambda data:hashlib.sha256(data).hexdigest()
RIGHTS={'platform-application':True,'com.apple.private.security.no-container':True,
        'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--cached-primitives',action='store_true')
    args=parser.parse_args();output=args.output.resolve();output.mkdir();ios=output/'ios';ios.mkdir();source=output/'source';source.mkdir()
    mode='cached'if args.cached_primitives else'original'
    runtime='/var/root/VirtualMac2/testing/diskimagekit27-host-layout-performance-'+mode+'-v1'
    assert SHA((BASE/'candidate.json').read_bytes())=='8e7134cc7a2658084c2013ee06b05f4ff4f72aa4cb92c8dfb1d3696978dd6f8f'
    assert SHA((ACTUAL/'result.json').read_bytes())=='4089f813be94913fea4c4b43d26e3f9ff25b0de766b88dd9214c6d9515243e46'
    actual=json.loads((ACTUAL/'result.json').read_bytes());assert actual['passed'] is True and actual['childPID']==47088 and actual['observedWaitExit']==0
    assert actual['native']['originalMetadataCalls']==0 and actual['native']['genuineDIKitLoaded'] is True and actual['childAbsent'] is True
    baseline=json.loads((BASE/'candidate.json').read_bytes());files=[]
    for item in baseline['files'][:-1]:
        content=Path(item['path']).read_bytes();assert len(content)==item['bytes'] and SHA(content)==item['sha256']
        path=ios/item['name'];path.write_bytes(content);files.append(dict(item,path=str(path),unchangedFromActualDIKitClosure=True))
    assert len(files)==19
    for filename in ['diskimagekit_genuine_di2_pins.h','diskimages227-pins.h','diskimagekit_required_imports.h','diskimagekit_bootstrap_required_imports.h']:
        (ios/filename).write_text((BASE/'ios'/filename).read_text().replace(baseline['nativeDirectory'],runtime))
    inputs=[]
    for path in [HOST/'modern_diskimagekit_host_layout_performance_probe.cpp',HOST/'modern_diskimagekit_native_metadata_probe.cpp',
                 HOST/'modern_diskimagekit_host_layout_performance_fixture.swift',HOST/'modern_swift_diskimagekit_cvw_primitives_once.cpp',HOST/'modern_swift_static_array_bootstrap.h',HOST/'modern_swift_diskimagekit_cvw_compat.h',
                 HOST/'modern_diskimages2_hpke_loadonly_probe.c',Path(__file__),BASE/'candidate.json',ACTUAL/'result.json']:
        content=path.read_bytes();(source/path.name).write_bytes(content);inputs.append(dict(path=str(path),bytes=len(content),sha256=SHA(content)))
    processes=[]
    def run(label,argv):
        child=subprocess.Popen([str(value) for value in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=40)
        except subprocess.TimeoutExpired:child.kill();child.communicate();raise
        (output/(label+'.stdout')).write_bytes(stdout);(output/(label+'.stderr')).write_bytes(stderr)
        processes.append(dict(label=label,argv=[str(value) for value in argv],PID=child.pid,wait=child.returncode,reaped=True))
        (output/'processes.json').write_text(json.dumps(processes,indent=2)+'\n');assert child.returncode==0,label+': '+stderr.decode(errors='replace')[-4000:]
        return stdout,stderr
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path'])[0].decode().strip()
    sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'));from compiler_image import commands,imports,segments
    if args.cached_primitives:
        library=ios/'VM27DIKCVW.dylib'
        exports=['VM27DIKCVWQuery','swift_cvw_destroy','swift_cvw_initWithCopy','swift_cvw_initWithTake','swift_cvw_assignWithCopy','swift_cvw_assignWithTake','swift_cvw_initializeBufferWithCopyOfBuffer','swift_cvw_initStructMetadataWithLayoutString','VM27DIKCVWPrimitiveIdentityCacheStatus']
        run('cvw-cached-build',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-std=c++17','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-cxx-new-delete','-fno-typed-memory-operations','-Wall','-Wextra','-Werror','-dynamiclib','-I',HOST,source/'modern_swift_diskimagekit_cvw_primitives_once.cpp','-L'+sdk+'/usr/lib/swift','-lswiftCore','-lobjc','-Wl,-install_name,@rpath/VM27DIKCVW.dylib',*[f'-Wl,-exported_symbol,_{name}'for name in exports],'-o',library])
        run('cvw-cached-sign',['codesign','--force','--sign','-','--timestamp=none',library])
        _,sign=run('cvw-cached-identity',['codesign','-d','--verbose=4',library]);data=library.read_bytes();old=files[13]
        files[13]=dict(name=old['name'],path=str(library),bytes=len(data),sha256=SHA(data),UUID=next(data[at+8:at+24].hex()for command,at,size in commands(data)if command==27),CDHash=re.search(rb'CDHash=([0-9a-f]{40})',sign)[1].decode(),entitlements={},fixedPrimitiveIdentityOnlyCached=True)
        header=ios/'diskimagekit_genuine_di2_pins.h';text=header.read_text();text=text.replace(old['UUID'],files[13]['UUID']).replace(str(old['bytes'])+',',str(files[13]['bytes'])+',')
        oldsha=','.join('0x'+old['sha256'][at:at+2]for at in range(0,64,2));newsha=','.join('0x'+files[13]['sha256'][at:at+2]for at in range(0,64,2));assert oldsha in text;text=text.replace(oldsha,newsha);header.write_text(text)
    macsdk=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path'])[0].decode().strip()
    originalIR=output/'original-mac-sdk.ll'
    run('original-sdk-ir',['xcrun','swiftc','-target','arm64e-apple-macos27.0','-sdk',macsdk,'-module-cache-path',output/'mac-module-cache','-parse-as-library','-module-name','VM27DIKitHostPerformanceFixture','-O','-Xfrontend','-disable-layout-string-value-witnesses','-Xfrontend','-disable-layout-string-value-witnesses-instantiation',source/'modern_diskimagekit_host_layout_performance_fixture.swift','-emit-ir','-o',originalIR])
    original=originalIR.read_text();retarget=[];removed=[]
    for line in original.splitlines(keepends=True):
        if line.startswith('@"_swift_FORCE_LOAD_$_')or line.startswith('declare extern_weak void @"_swift_FORCE_LOAD_$_'):
            removed.append(line);continue
        if line.startswith('@llvm.used = '):
            start=line.index('[ptr ');end=line.index('], section');pieces=line[start+1:end].split(', ');kept=[value for value in pieces if '_swift_FORCE_LOAD_$_'not in value]
            line=line[:start]+'['+', '.join(kept)+line[end:];line=re.sub(r'global \[\d+ x ptr\]',f'global [{len(kept)} x ptr]',line)
        if line.startswith('target triple = '):line='target triple = "arm64e-apple-ios16.1.0"\n'
        if line.startswith('!llvm.linker.options = '):line='!llvm.linker.options = !{}\n'
        retarget.append(line)
    updated=''.join(retarget);assert len(removed)==16
    functions=lambda value:re.findall(r'^define .*?^}',value,re.M|re.S)
    assert functions(original)==functions(updated) and functions(original)
    ir=output/'original-sdk-ios-target.ll';ir.write_text(updated)
    fixtureObject=output/'original-sdk-ios.o'
    run('sdk-object',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-Wno-override-module','-c','-x','ir',ir,'-o',fixtureObject])
    fixture=ios/'DIKitHostLayoutPerformanceFixture.dylib'
    run('sdk-link',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-dynamiclib',fixtureObject,ios/'DiskImageKit27.dylib',ios/'VM27SwiftLookup.dylib','-L'+sdk+'/usr/lib/swift','-lswiftCore','-framework','Foundation','-lobjc','-Wl,-rpath,@loader_path','-Wl,-install_name,@rpath/DIKitHostLayoutPerformanceFixture.dylib','-o',fixture])
    before=fixture.read_bytes();data=bytearray(before);changed=[]
    for command,at,count in commands(data):
        if command==12:
            offset=int.from_bytes(data[at+8:at+12],'little');owner=bytes(data[at+offset:at+count]).split(b'\0')[0].decode()
            if owner=='/var/root/VirtualMac2/testing/modern-swift-lookup-wrapper-native-v1/lookup_wrapper.ios.dylib':
                name=b'@loader_path/VM27SwiftLookup.dylib\0';assert len(name)<=count-offset;data[at+offset:at+count]=name+bytes(count-offset-len(name));changed.append(dict(before=owner,after='@loader_path/VM27SwiftLookup.dylib'))
    assert len(changed)==1 and imports(data)==imports(before)
    info=imports(before);start=info['data'];count=info['size'];assert before[start:start+count]==data[start:start+count]
    sectionPins=[]
    for segment in segments(before):
        for section in segment['sections']:
            if section['size']and section['fileoff']:
                start=section['fileoff'];count=section['size'];assert before[start:start+count]==data[start:start+count]
                sectionPins.append(dict(segment=segment['name'],name=section['name'],sha256=SHA(before[start:start+count]),bytes=count))
    fixture.write_bytes(data);run('sdk-sign',['codesign','--force','--sign','-','--timestamp=none',fixture])
    _,signature=run('sdk-identity',['codesign','-d','--verbose=4',fixture]);rights,_=run('sdk-rights',['codesign','-d','--entitlements',':-',fixture]);assert not rights.strip()
    data=fixture.read_bytes();assert imports(data)==imports(before)
    info=imports(before);start=info['data'];count=info['size'];assert before[start:start+count]==data[start:start+count]
    for segment in segments(before):
        for section in segment['sections']:
            if section['size']and section['fileoff']:start=section['fileoff'];count=section['size'];assert before[start:start+count]==data[start:start+count]
    fixturePin=dict(name=fixture.name,path=str(fixture),bytes=len(data),sha256=SHA(data),UUID=next(data[at+8:at+24].hex()for command,at,size in commands(data)if command==27),CDHash=re.search(rb'CDHash=([0-9a-f]{40})',signature)[1].decode(),entitlements={})
    files.append(fixturePin);assert len(files)==20
    pin='static const ClosurePin SDKFixtureImage={'+json.dumps(runtime+'/'+fixture.name)+','+str(fixturePin['bytes'])+','+json.dumps(fixturePin['UUID'])+',{'+','.join('0x'+fixturePin['sha256'][at:at+2]for at in range(0,64,2))+'},"VM27DIKitHostLayoutPerformanceSemanticFixture",false};\n'
    with(ios/'diskimagekit_genuine_di2_pins.h').open('a')as header:header.write(pin)
    contract=dict(originalSDKDeclarations=True,originalSDKTypes=True,originalIRSHA256=SHA(original.encode()),retargetIRSHA256=SHA(updated.encode()),functionDefinitionsPreserved=len(functions(original)),allFunctionBodiesAndSwiftABIAndPACInstructionsPreserved=True,removedOnlyCompilerAutolinkRegistrations=8,removedWeakForceLoadDeclarations=8,relativeLookupPathChange=changed,fixupBlobAndEveryNonemptySectionPreserved=sectionPins,fixtureStrongImportRows=imports(data)['imports'],actualIOSRun=False)
    (output/'sdk-abi-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
    run('sdk-imports',['xcrun','dyld_info','-imports','-linked_dylibs',fixture])
    obj=output/'di2-loadonly.o'
    run('di2-object',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-Wno-deprecated-declarations','-fptrauth-abi-version=0','-fno-typed-memory-operations-experimental','-I',ios,
        '-Dmain=VM27FoundationDI2LoadOnly','-c',source/'modern_diskimages2_hpke_loadonly_probe.c','-o',obj])
    executable=ios/'diskimagekit27-host-layout-performance-probe'
    run('metadata-probe',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c++17','-O2','-Wall','-Wextra','-Werror',
        '-Wno-deprecated-declarations','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete',
        '-DVM27_EXPECT_PRIMITIVE_CACHE='+('1'if args.cached_primitives else'0'),'-I',ios,'-I',source,source/'modern_diskimagekit_host_layout_performance_probe.cpp',obj,ios/'VM27StaticArrayBootstrap.dylib',
        '-lobjc','-Wl,-rpath,@executable_path','-Wl,-no_adhoc_codesign','-o',executable])
    rights=output/'Probe.entitlements';rights.write_bytes(plistlib.dumps(RIGHTS))
    run('probe-sign',['codesign','--force','--sign','-','--timestamp=none','--entitlements',rights,executable])
    _,sig=run('probe-identity',['codesign','-d','--verbose=4',executable]);ent,_=run('probe-rights',['codesign','-d','--entitlements',':-',executable]);assert plistlib.loads(ent)==RIGHTS
    sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'));from compiler_image import commands
    content=executable.read_bytes();files.append(dict(name=executable.name,path=str(executable),bytes=len(content),sha256=SHA(content),
        UUID=next(content[at+8:at+24].hex() for command,at,size in commands(content) if command==27),
        CDHash=re.search(rb'CDHash=([0-9a-f]{40})',sig)[1].decode(),entitlements=RIGHTS))
    for item in files:
        run('strict-'+item['name'],['codesign','--verify','--strict',item['path']]);run('dyld-'+item['name'],['xcrun','dyld_info','-validate_only',item['path']])
    for item in inputs:assert SHA(Path(item['path']).read_bytes())==item['sha256']
    result=dict(scope='private-genuine27-DIKit-genuineDI2-host-layout-performance-'+mode,nativeDirectory=runtime,files=files,executable=executable.name,arguments=['--host-performance'],inputs=inputs,
        original19LibrariesByteIdentical=not args.cached_primitives,original18LibrariesByteIdentical=True,fixedPrimitivesOnlyCached=args.cached_primitives,prerequisiteLoadPID=47088,prerequisiteLoadWait=0,prerequisiteActualLoadSHA256=SHA((ACTUAL/'result.json').read_bytes()),
        genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',
        originalMetadataAccessors=9,expectedMetadataChecks=33,realSDKSemanticChecks=192,realSDKOwnershipChecks=48,semanticIterations=16,knownOriginalConfigurationFactoryCalls=128,implicitSDKMetadataAndGetterCallsUncounted=True,originalMacGoldenClaimed=False,originalHostLayoutDifferentAcceptedOnlyAfterRealSDKSemanticOwnershipOracle=True,scopedOwnershipMetadataQueries=9,originalMetadataCallerSourceRetained=True,
        exactMetadataAccessorABI='original swiftcall request uintptr_t -> {const void *value, uintptr_t state}',
        originalMetadataOwnership='complete state0; genuine descriptor; query strict own layout; public dimensions match realSDK; runtime size-stride-inline flags; real NSURL lifecycle verified',
        originalCaseIterableCalls=0,originalDI2APICalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,
        CPUSecondsSoft=5,CPUSecondsHard=6,wallSecondsLimit=10,requiresActualExternalWaitAndAbsence=True,
        originalCNProvided=False,nativeExecutionPending=True,actualIOSRun=False,fullDIKit27=False,full27Backend=False,deviceOperations=False)
    (output/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(candidate=str(output/'candidate.json'),candidateSHA256=SHA((output/'candidate.json').read_bytes()),files=len(files),nativeExecutionPending=True),indent=2))


if __name__=='__main__':main()
