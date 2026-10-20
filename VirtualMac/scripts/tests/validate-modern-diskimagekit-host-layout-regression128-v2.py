#!/usr/bin/env python3
"""Freeze exact-original-SDK cached 128-round CPU regression; no device operations."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BUILD=N/'diskimagekit-host-layout-regression128-build-v1'
BASE=N/'diskimagekit-host-layout-performance-cached-build-v1'
OLD=N/'diskimagekit-host-layout-semantics-build-v1'
ACTUAL=N/'diskimagekit-host-layout-performance-cached-native-v1'
FAILED=N/'diskimagekit-host-layout-semantics-native-v1'
PARSER=ROOT/'VirtualMac/scripts/tests/validate-modern-diskimagekit-host-layout-regression128-native.py'
SHA=lambda data:hashlib.sha256(data).hexdigest()


def pin(path):
    data=path.read_bytes();return dict(path=str(path),bytes=len(data),sha256=SHA(data))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve();output.mkdir();candidate=BUILD/'candidate.json'
    assert SHA(candidate.read_bytes())=='a69f51d1c7627a0029aed84a1b5f6eb8d2503c25d9f9d60f9c7a75148005098b'
    manifest=json.loads(candidate.read_bytes());base=json.loads((BASE/'candidate.json').read_bytes());old=json.loads((OLD/'candidate.json').read_bytes())
    assert len(manifest['files'])==21
    assert [manifest[key]for key in ['CPUSecondsSoft','CPUSecondsHard','wallSecondsLimit']]==[old[key]for key in ['CPUSecondsSoft','CPUSecondsHard','wallSecondsLimit']]==[3,4,10]
    assert manifest['semanticIterations']==128 and manifest['realSDKSemanticChecks']==1536 and manifest['realSDKOwnershipChecks']==384
    assert manifest['knownOriginalConfigurationFactoryCalls']==1024 and manifest['originalMetadataAccessors']==9 and manifest['expectedMetadataChecks']==33
    assert manifest['nativeExecutionPending']is True and manifest['actualIOSRun']is False and manifest['full27Backend']is False
    for a,b in zip(manifest['files'][:19],base['files'][:19]):assert Path(a['path']).read_bytes()==Path(b['path']).read_bytes()
    sdk=manifest['files'][19];assert Path(sdk['path']).read_bytes()==Path(old['files'][19]['path']).read_bytes()
    for item in manifest['inputs']+manifest['provenance']:
        path=Path(item['path']);assert pin(path)['sha256']==item['sha256']and path.stat().st_size==item['bytes']
    assert (BUILD/'source/modern_diskimagekit_host_layout_semantic_owned_fixture.swift').read_bytes()==(OLD/'source/modern_diskimagekit_host_layout_semantic_owned_fixture.swift').read_bytes()
    code=(BUILD/'source/modern_diskimagekit_host_layout_regression128_probe.cpp').read_text()
    for text in ['rlimit cpu{3,4}','alarm(10)','Boundary("semantic","begin")','Boundary("semantic","end")','Boundary("ownership","begin")','Boundary("ownership","end")','semanticChecks!=1536||semanticFailures','ownershipChecks!=384||ownershipFailures','if(!GenuineHostMetadata(image,sizes,strides))return 83;']:
        assert text in code
    compile(PARSER.read_text(),str(PARSER),'exec')
    result=json.loads((ACTUAL/'result.json').read_bytes());assert result['passed']is True and result['childPID']==51380 and result['observedWaitExit']==0 and result['childAbsent']is True
    assert result['native']['scopedMetadataChecks']==33 and result['native']['primitiveIdentityInitializerRuns']==1
    failure=json.loads((FAILED/'result.json').read_bytes());assert failure['passed']is False and failure['childPID']==49507 and failure['observedWaitExit']==152
    controls=N/'diskimagekit-host-layout-regression128-parser-controls-v1'
    controls_pins=json.loads((controls/'freeze.json').read_bytes())['files']
    for item in controls_pins:assert pin(Path(item['path']))['sha256']==item['sha256']and Path(item['path']).stat().st_size==item['bytes']
    commands=[]
    for item in manifest['files']:
        assert pin(Path(item['path']))['sha256']==item['sha256']
        for argv in [['codesign','--verify','--strict',item['path']],['xcrun','dyld_info','-validate_only',item['path']],['codesign','-d','--verbose=4',item['path']],['codesign','-d','--entitlements',':-',item['path']]]:
            child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:stdout,stderr=child.communicate(timeout=20)
            except subprocess.TimeoutExpired:child.kill();child.communicate();raise
            commands.append(dict(argv=argv,PID=child.pid,wait=child.returncode,reaped=True,stdout=stdout.decode(errors='replace'),stderr=stderr.decode(errors='replace')));assert child.returncode==0
            if '--verbose=4'in argv:assert re.search(rb'CDHash=([0-9a-f]{40})',stderr)[1].decode()==item['CDHash']
            if '--entitlements'in argv:assert (plistlib.loads(stdout)if stdout.strip()else{})==item.get('entitlements',{})
    plan=dict(scope=manifest['scope'],deviceDirectory=manifest['nativeDirectory'],files=[dict(path=item['path'],name=item['name'],bytes=item['bytes'],sha256=item['sha256'],UUID=item['UUID'],cdhash=item['CDHash'],entitlements=item.get('entitlements',{}),code=True)for item in manifest['files']],executable=manifest['executable'],arguments=manifest['arguments'],candidateManifestSHA256=SHA(candidate.read_bytes()),nativeValidator=str(PARSER),nativeValidatorSHA256=SHA(PARSER.read_bytes()),CPUSecondsSoft=3,CPUSecondsHard=4,wallSecondsLimit=10,original49507SDKFixtureBytesIdentical=True,original49507SDKSourceBytesIdentical=True,original49507CPUAndWallLimitsRetained=True,prerequisiteCachedNativePID=51380,prerequisiteCachedNativeWait=0,prerequisiteCachedNativeSHA256=SHA((ACTUAL/'result.json').read_bytes()),oldFailed49507ReceiptSHA256=SHA((FAILED/'result.json').read_bytes()),semanticIterations=128,realSDKSemanticChecks=1536,realSDKURLOwnershipChecks=384,knownOriginalConfigurationFactories=1024,SDKImplicitMetadataAndGetterCallsUncounted=True,callBoundaryRecords=4,internalIterationProgressUnavailableForExactOriginalFixture=True,originalMetadataAccessors=9,originalMetadataChecks=33,scopedOwnershipMetadataQueries=9,originalCaseIterableCalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,actualWaitAndExactPIDAbsenceRequired=True,full27Backend=False)
    (output/'consumer-plan.json').write_text(json.dumps(plan,indent=2)+'\n');(output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    verification=dict(passed=True,strictSignatures=21,dyldValidations=21,original19CachedLibraryBytesUnchanged=True,original128SDKFixtureBinaryAndSourceBytesUnchanged=True,oldCPU3And4AndWall10LimitsRetained=True,newCallerAddsFourCallBoundaryTimingAndTwoCacheStatusObservations=True,original9Metadata33ChecksRetained=True,actualCached16RoundPrerequisitePID=51380,actualCached16RoundPrerequisiteWait=0,old49507FailedReceiptUnchanged=True,native128ExecutionPending=True,deviceOperations=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
    (output/'verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    paths={path for path in BUILD.rglob('*')if path.is_file()};paths.update(Path(item['path'])for item in manifest['inputs']+manifest['provenance']);paths.update(Path(item['path'])for item in controls_pins);paths.update([Path(__file__),PARSER,controls/'freeze.json',output/'consumer-plan.json',output/'commands.json',output/'verification.json'])
    freeze=output/'freeze.json';freeze.write_text(json.dumps(dict(files=[pin(path)for path in sorted(paths)]),indent=2)+'\n')
    ready=dict(scope=plan['scope'],localReadyForRootDeviceReview=True,nativeExecutionPending=True,candidate=pin(candidate),consumerPlan=pin(output/'consumer-plan.json'),freeze=pin(freeze),nativeParser=pin(PARSER),deviceOperations=False,full27Backend=False)
    (output/'READY-v1.json').write_text(json.dumps(ready,indent=2)+'\n');print(json.dumps(dict(pins=len(paths),candidate=pin(candidate),plan=pin(output/'consumer-plan.json'),freeze=pin(freeze),READY=pin(output/'READY-v1.json'),parser=pin(PARSER)),indent=2))


if __name__=='__main__':main()
