#!/usr/bin/env python3
"""New unsigned finite ordinary original-namespace CN identity/lifetime helper.

No execution, signing, controller, route, ready or device action. All original
class/method data is copied from the frozen corrected-CfD provider objects.
"""
from pathlib import Path
import argparse, hashlib, json, subprocess
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';H=R/'VirtualMac/vz/host'
def need(v,why):
    if not v:raise ValueError(why)
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    D=a.output.resolve();need(not D.exists(),'fresh output');D.mkdir(parents=True);commands=[]
    def run(label,args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60)
        (D/(label+'.stdout')).write_bytes(r.stdout);(D/(label+'.stderr')).write_bytes(r.stderr)
        commands.append(dict(label=label,argv=args,exit=r.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
        (D/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');need(r.returncode==0,label+' failed');return r.stdout.decode().strip()
    P=N/'static-cn-fixed-original-linked-provider-local-v2';F=P/'freeze.json'
    need(pin(F)['sha256']=='47aa59960138fa5164bda24a44b2ffcc4435c825384813913dccb309fff1a0df','immutable corrected product freeze')
    frozen={r['path']:r for r in json.loads(F.read_bytes())['files']};copied=[]
    for name in ['FixedCN.o','Methods.o','Fatal.o']:
        p=P/'ios-inert'/name;row=pin(p);need(frozen.get(row['path'])==row,'actual frozen original product object')
        (D/name).write_bytes(p.read_bytes());copied.append(dict(source=row,product=pin(D/name),wholeByteEqual=True))
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']);target='arm64e-apple-ios16.1'
    run('fixture-swift-ir',['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',D/'module-cache','-parse-as-library','-O','-emit-ir',H/'modern_swift_static_cn_original_fixture_v1.swift','-o',D/'FixtureSwift.ll'])
    run('fixture-swift',['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',D/'module-cache','-parse-as-library','-O','-emit-object',H/'modern_swift_static_cn_original_fixture_v1.swift','-o',D/'FixtureSwift.o'])
    run('fixture-cxx',['xcrun','clang++','-target',target,'-isysroot',sdk,'-std=c++17','-O1','-Wall','-Wextra','-Werror','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete','-c',H/'modern_swift_static_cn_original_fixture_v1.cpp','-o',D/'FixtureCxx.o'])
    helper=D/'ordinary-static-cn-original-n2-v1'
    run('unsigned-link',['xcrun','clang','-target',target,'-isysroot',sdk,*[D/n for n in ['FixedCN.o','Methods.o','Fatal.o','FixtureSwift.o','FixtureCxx.o']],'-L'+sdk+'/usr/lib/swift','-lswiftCore','-lobjc','-Wl,-rpath,/usr/lib/swift','-Wl,-export_dynamic','-Wl,-no_adhoc_codesign','-o',helper])
    (D/'candidate.json').write_text(json.dumps(dict(schema='Ordinary true original namespace fixed176 CN finite identity/lifetime unsigned candidate v1',sources=[pin(Path(__file__)),pin(H/'modern_swift_static_cn_original_fixture_v1.cpp'),pin(H/'modern_swift_static_cn_original_fixture_v1.swift')],frozenCorrectedProvider=pin(P/'candidate.json'),frozenCorrectedProviderFreeze=pin(F),copiedObjects=copied,fixtureObjects=[pin(D/n) for n in ['FixtureSwift.o','FixtureCxx.o']],linkedProduct=pin(helper),commands=commands,plannedOwnInstanceCount=128,plannedFinalReleaseCompletions=128,destructionCounterClaimed=False,freedPointerRead=False,plannedExternalTimeoutSeconds=20,plannedExternalKillAfterSeconds=1,plannedPreExecCPUSeconds=5,plannedPreExecCoreBytes=0,plannedRemoteWallSeconds=55,plannedMAINBeforeCMa=True,ObjCClasslistMayRegisterBeforeMAIN=True,plannedBeforeAfterCensus=True,plannedExactOldCoreUUID='f896d145e02539d6afd3bc0a2ad4f839',plannedExactOriginalCN_CMa_CMn_CfDHelperOwner=True,plannedExactSameNameLookupMustEqualLinkedCN=True,priorObjCNameAbsenceProven=False,plannedOldBaseN=2,plannedOwnN=3,plannedCMfBytes=176,plannedAP=24,plannedCMnBytes=124,plannedPlus144Call=False,plannedNilGetBodyCall=False,plannedOtherMethodCalls=False,HVVMMVZImportsAllowed=False,unsigned=True,signed=False,loaded=False,executed=False,controllerCreated=False,readyWritten=False,routeCreated=False,originalCNRuntimeIdentityEstablished=False,fullAppleGraph=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,full27Backend=False),indent=2)+'\n')
    print(json.dumps(dict(helper=pin(helper),signed=False,executed=False)))
if __name__=='__main__':main()
