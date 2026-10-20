#!/usr/bin/env python3
"""Freeze the new isolated genuine metadata caller. Does not execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BUILD=N/'diskimagekit-genuine-metadata-build-v1'
BASE=N/'diskimagekit-genuine-di2-loadonly-build-v3'
ACTUAL=N/'diskimagekit-genuine-di2-loadonly-native-v2'
PARSER=ROOT/'VirtualMac/scripts/tests/validate-modern-diskimagekit-genuine-metadata-native.py'
SHA=lambda data:hashlib.sha256(data).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve();output.mkdir()
    candidate=BUILD/'candidate.json';assert SHA(candidate.read_bytes())=='ec67b09fb8dfd112a9b288cb392fc98b9accac90838d47a0e5b0d3e264548b76'
    manifest=json.loads(candidate.read_bytes());files=manifest['files'];assert len(files)==20
    baseline=json.loads((BASE/'candidate.json').read_bytes())
    assert manifest['nativeExecutionPending'] is True and manifest['deviceOperations'] is False
    assert manifest['actualIOSRun'] is False and manifest['fullDIKit27'] is False and manifest['full27Backend'] is False
    for new,old in zip(files[:19],baseline['files'][:19]):
        assert new['name']==old['name'] and Path(new['path']).read_bytes()==Path(old['path']).read_bytes()
    for item in manifest['inputs']:
        content=Path(item['path']).read_bytes();assert SHA(content)==item['sha256'] and len(content)==item['bytes']
        assert content==(BUILD/'source'/Path(item['path']).name).read_bytes()
    original=(ROOT/'VirtualMac/vz/host/modern_diskimagekit_native_metadata_probe.cpp').read_bytes()
    assert (BUILD/'source/modern_diskimagekit_native_metadata_probe.cpp').read_bytes()==original
    source=(BUILD/'source/modern_diskimagekit_genuine_metadata_probe.cpp').read_text()
    for expected in ['#include "modern_diskimagekit_native_metadata_probe.cpp"','auto result=Function(target)(0);++MetadataCalls;',
        'query(result.value,&info)==1&&info.type==type+1&&info.size==Sizes[type]&&info.stride==Strides[type]',
        'info.extraInhabitants==0x7fffffff','Checks==33&&Failures==0&&MetadataCalls==9','if(!GenuineMetadata(image))return 83;',
        'VM27FoundationDI2LoadOnly(2,loadArguments)','setrlimit(RLIMIT_CPU,&cpu)','alarm(10)']:
        assert expected in source
    assert all(text not in source for text in ['pwrite(', 'ftruncate(', 'O_CREAT', '--array-fixture'])
    actual=json.loads((ACTUAL/'result.json').read_bytes())
    assert actual['passed'] is True and actual['childPID']==47088 and actual['observedWaitExit']==0 and actual['childAbsent'] is True
    assert actual['native']['genuineDIKitLoaded'] is True and actual['native']['originalMetadataCalls']==0
    log=[]
    for item in files:
        content=Path(item['path']).read_bytes();assert SHA(content)==item['sha256'] and len(content)==item['bytes']
        for argv in [['codesign','--verify','--strict',item['path']],['xcrun','dyld_info','-validate_only',item['path']],
            ['codesign','-d','--verbose=4',item['path']],['codesign','-d','--entitlements',':-',item['path']]]:
            child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:out,err=child.communicate(timeout=20)
            except subprocess.TimeoutExpired:child.kill();child.communicate();raise
            log.append(dict(argv=argv,PID=child.pid,wait=child.returncode,reaped=True,stdout=out.decode(errors='replace'),stderr=err.decode(errors='replace')))
            assert child.returncode==0
            if '--verbose=4' in argv:assert re.search(rb'CDHash=([0-9a-f]{40})',err)[1].decode()==item['CDHash']
            if '--entitlements' in argv:assert (plistlib.loads(out)if out.strip()else{})==item.get('entitlements',{})
    plan=dict(scope=manifest['scope'],deviceDirectory=manifest['nativeDirectory'],
        files=[dict(path=item['path'],name=item['name'],bytes=item['bytes'],sha256=item['sha256'],UUID=item['UUID'],cdhash=item['CDHash'],entitlements=item.get('entitlements',{}),code=True)for item in files],
        executable=manifest['executable'],arguments=['--metadata'],candidateManifestSHA256=SHA(candidate.read_bytes()),
        nativeValidator=str(PARSER),nativeValidatorSHA256=SHA(PARSER.read_bytes()),
        prerequisiteActualLoadPID=47088,prerequisiteActualLoadWait=0,prerequisiteActualLoadSHA256=SHA((ACTUAL/'result.json').read_bytes()),
        original19LibraryBytesUnchanged=True,originalMetadataAccessors=9,originalMetadataChecks=33,scopedOwnershipMetadataQueries=9,
        originalCaseIterableCalls=0,originalDI2APICalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,
        CPUSecondsSoft=3,CPUSecondsHard=4,wallSecondsLimit=10,actualWaitAndExactPIDAbsenceRequired=True,full27Backend=False)
    (output/'consumer-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    verification=dict(passed=True,strictSignatures=20,dyldValidations=20,original19LibrariesUnchanged=True,
        originalMetadataProbeSourceUnchanged=True,exactNineTypeABIAndOwnershipChecksRetained=True,
        genuineLoadPrerequisitePID=47088,genuineLoadPrerequisiteWait=0,originalMetadataAccessors=9,
        originalMetadataChecks=33,scopedOwnershipMetadataQueries=9,actualNativeMetadataExecutionPending=True,
        deviceOperations=False,fullDIKit27=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
    (output/'verification.json').write_text(json.dumps(verification,indent=2)+'\n');(output/'commands.json').write_text(json.dumps(log,indent=2)+'\n')
    def pin(path):
        content=path.read_bytes();return dict(path=str(path),bytes=len(content),sha256=SHA(content))
    files_to_pin=set(path for path in BUILD.rglob('*')if path.is_file());files_to_pin.update(Path(item['path'])for item in manifest['inputs'])
    files_to_pin.update([Path(__file__),PARSER,ACTUAL/'result.json',N/'diskimagekit-genuine-di2-absolute-native-independent-review-v1/verification.json',
        N/'diskimagekit-genuine-di2-absolute-native-independent-review-v1/freeze.json',output/'consumer-plan.json',output/'verification.json',output/'commands.json'])
    (output/'freeze.json').write_text(json.dumps(dict(files=[pin(path)for path in sorted(files_to_pin)]),indent=2)+'\n')
    ready=dict(scope=plan['scope'],localReadyForRootDeviceReview=True,nativeExecutionPending=True,
        candidate=pin(candidate),consumerPlan=pin(output/'consumer-plan.json'),freeze=pin(output/'freeze.json'),nativeParser=pin(PARSER),
        actualLoadPrerequisite=pin(ACTUAL/'result.json'),deviceOperations=False,full27Backend=False)
    (output/'READY-v1.json').write_text(json.dumps(ready,indent=2)+'\n')
    print(json.dumps(dict(candidateSHA256=SHA(candidate.read_bytes()),planSHA256=SHA((output/'consumer-plan.json').read_bytes()),
        freezeSHA256=SHA((output/'freeze.json').read_bytes()),nativeParserSHA256=SHA(PARSER.read_bytes()),
        READY_SHA256=SHA((output/'READY-v1.json').read_bytes()),pins=len(files_to_pin)),indent=2))


if __name__=='__main__':main()
