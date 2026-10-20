#!/usr/bin/env python3
"""Build a strict cached 128-round regression with the exact failed original SDK fixture bytes."""
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
HOST=ROOT/'VirtualMac/vz/host'
BASE=N/'diskimagekit-host-layout-performance-cached-build-v1'
ACTUAL=N/'diskimagekit-host-layout-performance-cached-native-v1'
OLD=N/'diskimagekit-host-layout-semantics-build-v1'
FAILED=N/'diskimagekit-host-layout-semantics-native-v1'
SHA=lambda data:hashlib.sha256(data).hexdigest()
RIGHTS={'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve();output.mkdir();ios=output/'ios';ios.mkdir();source=output/'source';source.mkdir()
    runtime='/var/root/VirtualMac2/testing/diskimagekit27-host-layout-regression128-v1'
    assert SHA((BASE/'candidate.json').read_bytes())=='7c63bd46816d1f28910762bc6dfccbcf896c72e70f7f82ba36595a70c1eefd0d'
    assert SHA((OLD/'candidate.json').read_bytes())=='33e5fd06779b9d632393a26270ade33cd8ff8c5ce4156cacd6a780331f965a45'
    actual=json.loads((ACTUAL/'result.json').read_bytes());assert actual['passed'] is True and actual['childPID']==51380 and actual['observedWaitExit']==0 and actual['childAbsent'] is True
    assert actual['native']['realSDKSemanticChecks']==192 and actual['native']['realSDKURLOwnershipChecks']==48 and actual['native']['scopedMetadataChecks']==33
    failed=json.loads((FAILED/'result.json').read_bytes());assert failed['passed'] is False and failed['childPID']==49507 and failed['observedWaitExit']==152
    baseline=json.loads((BASE/'candidate.json').read_bytes());original=json.loads((OLD/'candidate.json').read_bytes());files=[]
    for item in baseline['files'][:19]+[original['files'][19]]:
        data=Path(item['path']).read_bytes();assert len(data)==item['bytes']and SHA(data)==item['sha256']
        path=ios/item['name'];path.write_bytes(data);files.append(dict(item,path=str(path),copiedExactBytes=True))
    for name in ['diskimagekit_genuine_di2_pins.h','diskimages227-pins.h','diskimagekit_required_imports.h','diskimagekit_bootstrap_required_imports.h']:
        text=(BASE/'ios'/name).read_text().replace(baseline['nativeDirectory'],runtime)
        if name=='diskimagekit_genuine_di2_pins.h':
            item=files[19]
            pin='static const ClosurePin SDKFixtureImage={'+json.dumps(runtime+'/'+item['name'])+','+str(item['bytes'])+','+json.dumps(item['UUID'])+',{'+','.join('0x'+item['sha256'][at:at+2]for at in range(0,64,2))+'},"VM27DIKitHostLayoutSemanticFixture",false};'
            text,count=re.subn(r'^static const ClosurePin SDKFixtureImage=.*?;$',lambda _:pin,text,flags=re.M);assert count==1
        (ios/name).write_text(text)
    inputs=[]
    for path in [HOST/'modern_diskimagekit_host_layout_regression128_probe.cpp',HOST/'modern_diskimagekit_native_metadata_probe.cpp',HOST/'modern_swift_static_array_bootstrap.h',HOST/'modern_swift_diskimagekit_cvw_compat.h',HOST/'modern_diskimages2_hpke_loadonly_probe.c',HOST/'modern_diskimagekit_host_layout_semantic_owned_fixture.swift',Path(__file__)]:
        data=path.read_bytes();(source/path.name).write_bytes(data);inputs.append(dict(path=str(path),bytes=len(data),sha256=SHA(data)))
    assert (source/'modern_diskimagekit_host_layout_semantic_owned_fixture.swift').read_bytes()==(OLD/'source/modern_diskimagekit_host_layout_semantic_owned_fixture.swift').read_bytes()
    processes=[]
    def run(label,argv):
        child=subprocess.Popen([str(value)for value in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:child.kill();child.communicate();raise
        (output/(label+'.stdout')).write_bytes(stdout);(output/(label+'.stderr')).write_bytes(stderr);processes.append(dict(label=label,argv=[str(value)for value in argv],PID=child.pid,wait=child.returncode,reaped=True));(output/'processes.json').write_text(json.dumps(processes,indent=2)+'\n');assert child.returncode==0,stderr.decode(errors='replace');return stdout,stderr
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path'])[0].decode().strip();obj=output/'di2-loadonly.o'
    run('di2-object',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fptrauth-abi-version=0','-fno-typed-memory-operations-experimental','-I',ios,'-Dmain=VM27FoundationDI2LoadOnly','-c',source/'modern_diskimages2_hpke_loadonly_probe.c','-o',obj])
    executable=ios/'diskimagekit27-host-layout-regression128-probe'
    run('probe',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete','-I',ios,'-I',source,source/'modern_diskimagekit_host_layout_regression128_probe.cpp',obj,ios/'VM27StaticArrayBootstrap.dylib','-lobjc','-Wl,-rpath,@executable_path','-Wl,-no_adhoc_codesign','-o',executable])
    rights=output/'Probe.entitlements';rights.write_bytes(plistlib.dumps(RIGHTS));run('sign',['codesign','--force','--sign','-','--timestamp=none','--entitlements',rights,executable]);_,signature=run('identity',['codesign','-d','--verbose=4',executable]);ent,_=run('rights',['codesign','-d','--entitlements',':-',executable]);assert plistlib.loads(ent)==RIGHTS
    sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'));from compiler_image import commands
    data=executable.read_bytes();files.append(dict(name=executable.name,path=str(executable),bytes=len(data),sha256=SHA(data),UUID=next(data[at+8:at+24].hex()for command,at,size in commands(data)if command==27),CDHash=re.search(rb'CDHash=([0-9a-f]{40})',signature)[1].decode(),entitlements=RIGHTS))
    for item in files:run('strict-'+item['name'],['codesign','--verify','--strict',item['path']]);run('dyld-'+item['name'],['xcrun','dyld_info','-validate_only',item['path']])
    for item in inputs:assert SHA(Path(item['path']).read_bytes())==item['sha256']
    provenance=[dict(path=str(path),bytes=path.stat().st_size,sha256=SHA(path.read_bytes()))for path in [BASE/'candidate.json',ACTUAL/'result.json',OLD/'candidate.json',FAILED/'result.json',Path(original['files'][19]['path']),OLD/'original-mac-sdk.ll',OLD/'original-sdk-ios-target.ll',OLD/'sdk-abi-contract.json']]
    candidate=dict(scope='private-genuine27-DIKit-genuineDI2-host-layout-regression128',nativeDirectory=runtime,files=files,executable=executable.name,arguments=['--host-regression128'],inputs=inputs,provenance=provenance,original19CachedLibrariesByteIdentical=True,original49507SDKFixtureBytesIdentical=True,original49507SDKSourceBytesIdentical=True,original49507CPUAndWallLimitsRetained=True,prerequisiteCachedNativePID=51380,prerequisiteCachedNativeWait=0,oldFailedNativePID=49507,oldFailedWait=152,realSDKSemanticChecks=1536,realSDKOwnershipChecks=384,semanticIterations=128,knownOriginalConfigurationFactoryCalls=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,callBoundaryRecords=4,internalIterationProgressUnavailableForExactOriginalFixture=True,originalMetadataAccessors=9,expectedMetadataChecks=33,scopedOwnershipMetadataQueries=9,originalCaseIterableCalls=0,originalDI2APICalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,CPUSecondsSoft=3,CPUSecondsHard=4,wallSecondsLimit=10,requiresActualExternalWaitAndAbsence=True,nativeExecutionPending=True,actualIOSRun=False,fullDIKit27=False,full27Backend=False,deviceOperations=False)
    (output/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n');print(json.dumps(dict(candidate=str(output/'candidate.json'),candidateSHA256=SHA((output/'candidate.json').read_bytes()),files=len(files),actualIOSRun=False),indent=2))


if __name__=='__main__':main()
