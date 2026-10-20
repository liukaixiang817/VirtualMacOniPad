#!/usr/bin/env python3
"""Compile one new ordinary iOS owned-class fixture, unsigned and unexecuted.

Frozen original-name objects and Mac validation remain unchanged. This script
has no signing, ready, controller, device transport, route or execution action.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H=R/'VirtualMac/vz/host'
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def require(v,why):
    if not v:raise ValueError(why)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    out=a.output.resolve();require(not out.exists(),'fresh output required');out.mkdir(parents=True)
    commands=[]
    def run(label,argv):
        argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,label+' failed '+str(p.returncode));return p.stdout.decode().strip()
    # Source IR copied byte-exact from a frozen own class, with one equal-length
    # module-name substitution. Original-name StaticCN objects are not inputs.
    source=N/'static-cn-fixed-data-provider-local-v4/mac-model/FixedCN.ll'
    sourcePin=pin(source);frozen=json.loads((N/'static-cn-fixed-provider-aggregate-audit-v3/freeze.json').read_text())
    rows=frozen['files'] if isinstance(frozen,dict) else frozen
    require(any(x['path']==sourcePin['path'] and x['sha256']==sourcePin['sha256'] and x['bytes']==sourcePin['bytes'] for x in rows),'actual frozen own class IR pin')
    original=source.read_bytes();require(original.count(b'VM27FixedModel')==57,'exact own module occurrences')
    ownIR=original.replace(b'VM27FixedModel',b'VM27OldN2Model');require(len(ownIR)==len(original),'same-length distinct namespace')
    (out/'OwnCN.ll').write_bytes(ownIR)
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']);run('swift-version',['xcrun','swiftc','--version']);run('clang-version',['xcrun','clang','--version'])
    target='arm64e-apple-ios16.1'
    sources=[Path(__file__),H/'modern_swift_static_cn_old_n2_fixture_v2.cpp',H/'modern_swift_static_cn_old_n2_fixture_v1.swift',H/'modern_swift_static_cn_old_n2_model_v1.ll',H/'modern_swift_static_cn_fixed_methods_v1.ll',H/'modern_swift_static_cn_fixed_fatal_methods_v1.swift']
    run('own-data',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',out/'OwnCN.ll','-o',out/'OwnCN.o'])
    run('own-methods',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',H/'modern_swift_static_cn_fixed_methods_v1.ll','-o',out/'Methods.o'])
    run('own-model',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',H/'modern_swift_static_cn_old_n2_model_v1.ll','-o',out/'Model.o'])
    for label,source in [('fatal',H/'modern_swift_static_cn_fixed_fatal_methods_v1.swift'),('fixture-swift',H/'modern_swift_static_cn_old_n2_fixture_v1.swift')]:
        run(label+'-ir',['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',out/'module-cache','-parse-as-library','-O','-emit-ir',source,'-o',out/(label+'.ll')])
        run(label,['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',out/'module-cache','-parse-as-library','-O','-emit-object',source,'-o',out/(label+'.o')])
    run('fixture-cxx',['xcrun','clang++','-target',target,'-isysroot',sdk,'-std=c++17','-O1','-Wall','-Wextra','-Werror','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete','-c',H/'modern_swift_static_cn_old_n2_fixture_v2.cpp','-o',out/'FixtureCxx.o'])
    # The object-only Swift driver emits clang --sysroot with an incompatible
    # Darwin sysroot warning. Explicit clang -isysroot uses the actual iOS SDK.
    run('link-unsigned',['xcrun','clang','-target',target,'-isysroot',sdk,*[out/f for f in ['OwnCN.o','Methods.o','Model.o','fatal.o','fixture-swift.o','FixtureCxx.o']],'-L'+sdk+'/usr/lib/swift','-lswiftCore','-lobjc','-Wl,-rpath,/usr/lib/swift','-Wl,-no_adhoc_codesign','-o',out/'ordinary-own-n2-class-v1'])
    products=[pin(out/f) for f in ['OwnCN.ll','OwnCN.o','Methods.o','Model.o','fatal.ll','fatal.o','fixture-swift.ll','fixture-swift.o','FixtureCxx.o','ordinary-own-n2-class-v1']]
    report=dict(schema='Ordinary iOS distinct owned176 N3 subclass of actual old N2 registration fixture local v2',sources=[pin(x) for x in sources],frozenOwnClassIR=sourcePin,distinctOwnModule='VM27OldN2Model',sameLengthNamespaceOnly=True,products=products,commands=commands,plannedOwnInstanceCount=128,plannedCPULimitSeconds=5,plannedCoreLimitBytes=0,plannedExternalTimeoutSeconds=20,plannedExactOldCoreUUID='f896d145e02539d6afd3bc0a2ad4f839',plannedOldBaseN=2,plannedOldBaseP=18,plannedOwnClassBytes=176,plannedOwnAP=24,plannedOwnN=3,plannedOwnP=19,plannedTrueCMaObjcOptSelf=True,plannedMAINBeforeMetadataAccessor=True,plannedBeforeAfterActualImageCensus=True,plannedActualOwnCallerAndAccessorImageIdentity=True,IOSLinked=True,IOSSigned=False,IOSLoaded=False,IOSExecuted=False,readyWritten=False,controllerCreated=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,originalStaticCNNamePresent=False,originalStaticCNIdentityExecuted=False,oldN2RegistrationExecuted=False,HVVMMVZImportsAllowed=False,full27Backend=False)
    (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),executable=pin(out/'ordinary-own-n2-class-v1'),executed=False,signed=False)))
if __name__=='__main__':main()
