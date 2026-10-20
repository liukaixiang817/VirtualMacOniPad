#!/usr/bin/env python3
"""Freeze two local CPU-only DIKit A/B candidates; never execute or deploy them."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST=ROOT/'VirtualMac/vz/host'
PARSER=ROOT/'VirtualMac/scripts/tests/validate-modern-diskimagekit-host-layout-performance-native.py'
SHA=lambda data:hashlib.sha256(data).hexdigest()


def pin(path):
    data=path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=SHA(data))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    output=parser.parse_args().output.resolve();output.mkdir()
    compile(PARSER.read_text(),str(PARSER),'exec')
    specifications=[('original',N/'diskimagekit-host-layout-performance-original-build-v2','f7e78cf2a2283b5acef90db29b83e8339aaa2def81c9cf143c136becc147a38e'),('cached',N/'diskimagekit-host-layout-performance-cached-build-v1','7c63bd46816d1f28910762bc6dfccbcf896c72e70f7f82ba36595a70c1eefd0d')]
    baseline=json.loads((N/'diskimagekit-genuine-di2-loadonly-build-v3/candidate.json').read_bytes())
    once=(HOST/'modern_swift_diskimagekit_cvw_primitives_once.cpp').read_text()
    old=(HOST/'modern_swift_diskimagekit_cvw_compat.cpp').read_text()
    start=old.index('bool Primitives() {');end=old.index('const unsigned char *Authenticate(',start)
    assert once[:start]==old[:start]
    assert once[once.index('const unsigned char *Authenticate('):once.index('// Calling this explicit diagnostic endpoint')].strip()==old[end:].strip()
    assert old[start:end].replace('bool Primitives()','bool VerifyBoundPrimitives()') in once
    for text in ['pthread_once(&PrimitiveOnce,InitializePrimitiveIdentity)','RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL','if(!handle||!Swift(entries[i]))','if(retained==9)PrimitiveIdentityValid=true;','++PrimitiveIdentityInitializationRuns;']:
        assert text in once
    assert once.count('++PrimitiveIdentityInitializationRuns;')==1
    actual=N/'diskimagekit-host-layout-steps-native-v1'
    actual_result=json.loads((actual/'result.json').read_bytes())
    assert actual_result['passed'] is True and actual_result['childPID']==50339 and actual_result['observedWaitExit']==0 and actual_result['childAbsent'] is True
    assert actual_result['native']['realSDKSemanticChecks']==12 and actual_result['native']['realSDKOwnershipChecks']==3
    controls=N/'diskimagekit-host-layout-performance-parser-controls-v1'
    controlpins=json.loads((controls/'freeze.json').read_bytes())['files']
    for item in controlpins:
        path=Path(item['path']);assert pin(path)['sha256']==item['sha256'] and path.stat().st_size==item['bytes']
    mac=N/'diskimagekit-host-layout-performance-mac-baseline-v1'
    macprocess=json.loads((mac/'processes.json').read_bytes())[-1]
    assert macprocess['PID']==12750 and macprocess['wait']==0 and macprocess['reaped'] is True
    macrows=[json.loads(line)for line in (mac/'actual.stdout').read_bytes().splitlines()]
    assert macrows[-1]==dict(record='summary',semanticChecks=192,semanticFailures=0,ownershipChecks=48,ownershipFailures=0,progressRecords=64,cacheStatusBefore=0x100000001,cacheStatusAfter=0x100000001)
    manifests={};commands=[];freeze_paths={Path(__file__),PARSER,HOST/'modern_swift_diskimagekit_cvw_compat.cpp',controls/'freeze.json',actual/'result.json'}
    freeze_paths.update(Path(item['path'])for item in controlpins)
    freeze_paths.update(path for path in mac.iterdir()if path.is_file())
    for mode,build,expected in specifications:
        candidate=build/'candidate.json';assert SHA(candidate.read_bytes())==expected
        manifest=json.loads(candidate.read_bytes());manifests[mode]=manifest
        assert len(manifest['files'])==21 and manifest['fixedPrimitivesOnlyCached']==(mode=='cached')
        assert manifest['CPUSecondsSoft']==5 and manifest['CPUSecondsHard']==6 and manifest['wallSecondsLimit']==10
        assert manifest['realSDKSemanticChecks']==192 and manifest['realSDKOwnershipChecks']==48 and manifest['semanticIterations']==16 and manifest['knownOriginalConfigurationFactoryCalls']==128
        assert manifest['nativeExecutionPending'] is True and manifest['deviceOperations'] is False and manifest['full27Backend'] is False
        assert manifest['originalMetadataAccessors']==9 and manifest['expectedMetadataChecks']==33
        for index,(item,prior)in enumerate(zip(manifest['files'][:19],baseline['files'][:19])):
            if mode=='cached'and index==13:assert item['UUID']=='070c7614390737708f1e3922a6f56458';continue
            assert Path(item['path']).read_bytes()==Path(prior['path']).read_bytes()
        for item in manifest['inputs']:
            path=Path(item['path']);assert pin(path)['sha256']==item['sha256']and path.stat().st_size==item['bytes']
            assert path.read_bytes()==(build/'source'/path.name).read_bytes();freeze_paths.add(path)
        source=(build/'source/modern_diskimagekit_host_layout_performance_fixture.swift').read_bytes()
        assert source==(mac/'modern_diskimagekit_host_layout_performance_fixture.swift').read_bytes()
        sdkcontract=json.loads((build/'sdk-abi-contract.json').read_bytes())
        assert sdkcontract['allFunctionBodiesAndSwiftABIAndPACInstructionsPreserved'] is True
        assert len(sdkcontract['fixtureStrongImportRows'])==81 and all(row['weak'] is False for row in sdkcontract['fixtureStrongImportRows'])
        for item in manifest['files']:
            assert pin(Path(item['path']))['sha256']==item['sha256']
            for argv in [['codesign','--verify','--strict',item['path']],['xcrun','dyld_info','-validate_only',item['path']],['codesign','-d','--verbose=4',item['path']],['codesign','-d','--entitlements',':-',item['path']]]:
                child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:stdout,stderr=child.communicate(timeout=20)
                except subprocess.TimeoutExpired:child.kill();child.communicate();raise
                commands.append(dict(mode=mode,argv=argv,PID=child.pid,wait=child.returncode,reaped=True,stdout=stdout.decode(errors='replace'),stderr=stderr.decode(errors='replace')))
                assert child.returncode==0
                if '--verbose=4' in argv:assert re.search(rb'CDHash=([0-9a-f]{40})',stderr)[1].decode()==item['CDHash']
                if '--entitlements' in argv:assert (plistlib.loads(stdout)if stdout.strip()else{})==item.get('entitlements',{})
        plan=dict(scope=manifest['scope'],deviceDirectory=manifest['nativeDirectory'],files=[dict(path=item['path'],name=item['name'],bytes=item['bytes'],sha256=item['sha256'],UUID=item['UUID'],cdhash=item['CDHash'],entitlements=item.get('entitlements',{}),code=True)for item in manifest['files']],executable=manifest['executable'],arguments=manifest['arguments'],candidateManifestSHA256=expected,nativeValidator=str(PARSER),nativeValidatorSHA256=SHA(PARSER.read_bytes()),CPUSecondsSoft=5,CPUSecondsHard=6,wallSecondsLimit=10,sameSDKWorkloadAB=True,semanticIterations=16,realSDKSemanticChecks=192,realSDKURLOwnershipChecks=48,knownOriginalConfigurationFactories=128,SDKImplicitMetadataAndGetterCallsUncounted=True,originalMetadataAccessors=9,scopedOwnershipMetadataQueries=9,originalMetadataChecks=33,originalCaseIterableCalls=0,originalDiskCalls=0,VMGPUCalls=0,fileWrites=0,fixedPrimitivesOnlyCached=mode=='cached',runtimeHandlesRetainedUntilChildExit=mode=='cached',dynamicMetadataLayoutCached=False,prerequisiteActualSingleRoundPID=50339,prerequisiteActualSingleRoundWait=0,prerequisiteActualSingleRoundSHA256=SHA((actual/'result.json').read_bytes()),actualWaitAndExactPIDAbsenceRequired=True,full27Backend=False)
        planpath=output/('consumer-plan-'+mode+'.json');planpath.write_text(json.dumps(plan,indent=2)+'\n');freeze_paths.add(planpath)
        freeze_paths.update(path for path in build.rglob('*')if path.is_file()and 'mac-module-cache'not in path.parts)
    assert Path(manifests['original']['files'][19]['path']).read_bytes()==Path(manifests['cached']['files'][19]['path']).read_bytes()
    assert [i for i,(a,b)in enumerate(zip(manifests['original']['files'][:19],manifests['cached']['files'][:19]))if a['sha256']!=b['sha256']]==[13]
    verification=dict(passed=True,strictSignatures=42,dyldValidations=42,onlyClosureProviderImplementationDifferenceIndex13=True,SDKFixtureBytesIdentical=True,originalDynamicMetadataLayoutCodePreserved=True,originalNineFixedSwiftIdentityChecksPreserved=True,onlyFixedProcessStrongImportsCached=True,ownedNOLOADImageHandlesRetainedUntilChildExit=True,originalMetadataExpectedGoldenSourceRetained=True,actualMacPID=12750,actualMacWait=0,actualMacSemanticChecks=192,actualMacOwnershipChecks=48,nativeDeviceExecutionPending=True,actualIOSABPerformanceUnproven=True,deviceOperations=False,originalVMMExecuted=False,guestInstructionOracle=0,full27Backend=False)
    (output/'verification.json').write_text(json.dumps(verification,indent=2)+'\n');(output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');freeze_paths.update([output/'verification.json',output/'commands.json'])
    freeze=output/'freeze.json';freeze.write_text(json.dumps(dict(files=[pin(path)for path in sorted(freeze_paths)]),indent=2)+'\n')
    for mode,build,_ in specifications:
        ready=dict(scope=manifests[mode]['scope'],localReadyForRootDeviceReview=True,nativeExecutionPending=True,candidate=pin(build/'candidate.json'),consumerPlan=pin(output/('consumer-plan-'+mode+'.json')),freeze=pin(freeze),nativeParser=pin(PARSER),deviceOperations=False,full27Backend=False)
        (output/('READY-'+mode+'-v1.json')).write_text(json.dumps(ready,indent=2)+'\n')
    print(json.dumps(dict(pins=len(freeze_paths),freezeSHA256=SHA(freeze.read_bytes()),originalPlan=pin(output/'consumer-plan-original.json'),cachedPlan=pin(output/'consumer-plan-cached.json'),originalREADY=pin(output/'READY-original-v1.json'),cachedREADY=pin(output/'READY-cached-v1.json'),nativeParser=pin(PARSER)),indent=2))


if __name__=='__main__':main()
