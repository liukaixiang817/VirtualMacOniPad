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
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve();output.mkdir();ios=output/'ios';ios.mkdir();source=output/'source';source.mkdir()
    runtime='/var/root/VirtualMac2/testing/diskimagekit27-genuine-metadata-observer-v3'
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
    for path in [HOST/'modern_diskimagekit_genuine_metadata_context_probe.cpp',HOST/'modern_diskimagekit_native_metadata_probe.cpp',
                 HOST/'modern_swift_static_array_bootstrap.h',HOST/'modern_swift_diskimagekit_cvw_compat.h',
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
    obj=output/'di2-loadonly.o'
    run('di2-object',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-Wno-deprecated-declarations','-fptrauth-abi-version=0','-fno-typed-memory-operations-experimental','-I',ios,
        '-Dmain=VM27FoundationDI2LoadOnly','-c',source/'modern_diskimages2_hpke_loadonly_probe.c','-o',obj])
    executable=ios/'diskimagekit27-genuine-metadata-observer-probe'
    run('metadata-probe',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c++17','-O2','-Wall','-Wextra','-Werror',
        '-Wno-deprecated-declarations','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete',
        '-I',ios,'-I',source,source/'modern_diskimagekit_genuine_metadata_context_probe.cpp',obj,ios/'VM27StaticArrayBootstrap.dylib',
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
    result=dict(scope='private-genuine27-DIKit-genuineDI2-metadata-observer',nativeDirectory=runtime,files=files,executable=executable.name,arguments=['--metadata'],inputs=inputs,
        observationOnlySourceChange=True,queryPrefillSentinel='0xdeadbeefdeadbeef/0xdeadbeef',layoutReadsOnlyBoundedOwnMetadata=True,primitiveIdentityObservations=9,valueWitnessAndLayoutOwnerObservations=True,unmodifiedOriginalQuery=True,failedMetadataPID=47608,failedMetadataWait=83,original19LibrariesByteIdentical=True,prerequisiteLoadPID=47088,prerequisiteLoadWait=0,prerequisiteActualLoadSHA256=SHA((ACTUAL/'result.json').read_bytes()),
        genuineDIKitUUID='652b07a998be31d298d7ffcaf14aca5e',genuineDI2UUID='a456d4a4d6ab3549965d0400f3552de3',
        originalMetadataAccessors=9,expectedMetadataChecks=33,scopedOwnershipMetadataQueries=9,originalMetadataCallerSourceRetained=True,
        exactMetadataAccessorABI='original swiftcall request uintptr_t -> {const void *value, uintptr_t state}',
        originalMetadataOwnership='require complete state0; genuine-image descriptor, exact size/stride/flags/extra-inhabitants before use',
        originalCaseIterableCalls=0,originalDI2APICalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,
        CPUSecondsSoft=3,CPUSecondsHard=4,wallSecondsLimit=10,requiresActualExternalWaitAndAbsence=True,
        originalCNProvided=False,nativeExecutionPending=True,actualIOSRun=False,fullDIKit27=False,full27Backend=False,deviceOperations=False)
    (output/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(candidate=str(output/'candidate.json'),candidateSHA256=SHA((output/'candidate.json').read_bytes()),files=len(files),nativeExecutionPending=True),indent=2))


if __name__=='__main__':main()
