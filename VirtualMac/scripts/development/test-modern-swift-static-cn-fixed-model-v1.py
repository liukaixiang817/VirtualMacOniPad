#!/usr/bin/env python3
"""Ordinary local Mac owned-class validation. Never builds an iPad executor."""
from pathlib import Path
import argparse, hashlib, json, os, resource, subprocess, signal
R=Path(__file__).resolve().parents[3]; HOST=R/'VirtualMac/vz/host'
def pin(p):
    p=Path(p); b=p.read_bytes(); return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def bounds():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0)); resource.setrlimit(resource.RLIMIT_CPU,(10,10))
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,required=True); ap.add_argument('--provider',type=Path,required=True); args=ap.parse_args()
    out=args.output.resolve(); provider=args.provider.resolve(); assert not out.exists(); out.mkdir(parents=True); commands=[]
    def run(label,argv,execute=False,expected=0):
        argv=list(map(str,argv)); env=dict(os.environ)
        if execute: env['ASAN_OPTIONS']='detect_leaks=0:abort_on_error=1'
        p=subprocess.run(argv,capture_output=True,timeout=40,preexec_fn=bounds if execute else None,env=env)
        (out/(label+'.stdout')).write_bytes(p.stdout); (out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr')))); (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        if p.returncode!=expected: raise RuntimeError(label+' failed exit '+str(p.returncode))
        return p.stdout.decode().strip()
    sdk=run('sdk',['xcrun','--sdk','macosx','--show-sdk-path']); clangRuntime=Path(run('clang-resource-dir',['xcrun','clang','--print-resource-dir'])); ubsan=clangRuntime/'lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib'; target='arm64e-apple-macos27.0'; results=[]
    for mode,san in [('normal',False),('sanitized',True)]:
        d=out/mode; d.mkdir(); swiftFlags=['-sanitize=address'] if san else []; cxxFlags=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if san else []
        # Only model namespace/bridge targets differ. No original class alias.
        control=(provider/'mac-model/FixedCN.ll').read_text().replace('OwnStaticStorage','OwnStaticControl').replace('VM27StaticCNVerbatimNil','VM27StaticCNModelBridgeControl').replace('VM27StaticCNForbiddenBaseInitializer','VM27StaticCNModelControlForbiddenInitializer'); (d/'ControlCN.ll').write_text(control)
        run(mode+'-control',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',d/'ControlCN.ll','-o',d/'ControlCN.o'])
        run(mode+'-swift-ir',['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',d/'cache','-parse-as-library','-O','-emit-ir',HOST/'modern_swift_static_cn_fixed_fixture_v1.swift','-o',d/'Fixture.ll'])
        run(mode+'-swift',['xcrun','swiftc','-target',target,'-sdk',sdk,'-module-cache-path',d/'cache','-parse-as-library','-O',*swiftFlags,'-emit-object',HOST/'modern_swift_static_cn_fixed_fixture_v1.swift','-o',d/'FixtureSwift.o'])
        run(mode+'-cxx',['xcrun','clang++','-target',target,'-isysroot',sdk,'-std=c++17','-O1','-Wall','-Wextra','-Werror',*cxxFlags,'-c',HOST/'modern_swift_static_cn_fixed_fixture_v1.cpp','-o',d/'FixtureCxx.o'])
        run(mode+'-model',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',HOST/'modern_swift_static_cn_fixed_model_v1.ll','-o',d/'Model.o'])
        run(mode+'-link',['xcrun','swiftc','-target',target,'-sdk',sdk,'-emit-executable',*swiftFlags,provider/'mac-model/FixedCN.o',provider/'mac-model/Methods.o',provider/'mac-model/Fatal.o',d/'ControlCN.o',d/'FixtureSwift.o',d/'FixtureCxx.o',d/'Model.o','-framework','Foundation','-lobjc','-lc++',*(['-Xlinker',ubsan] if san else []),'-o',d/'fixture'])
        stdout=run(mode+'-run',[d/'fixture'],True); run(mode+'-none-trap',[d/'fixture','--none-trap'],True,-signal.SIGTRAP); results.append(dict(mode=mode,stdout=stdout,fixture=pin(d/'fixture'),noneTrapExit=-signal.SIGTRAP))
    sources=[pin(Path(__file__))]+[pin(HOST/f) for f in ['modern_swift_static_cn_fixed_model_v1.ll','modern_swift_static_cn_fixed_fixture_v1.cpp','modern_swift_static_cn_fixed_fixture_v1.swift']]
    (out/'result.json').write_text(json.dumps(dict(schema='Distinct own Mac fixed176 class validation v1',results=results,commands=commands,sourcePins=sources,providerObjects=[pin(provider/'mac-model'/f) for f in ['FixedCN.o','Methods.o','Fatal.o']],oldN2RegistrationExecuted=False,originalStaticCNIdentityExecuted=False,modelOnlyHeapDeallocator=True,originalIOSDeallocatorRemainsTrap=True,iOSLinked=False,iOSSigned=False,iOSLoaded=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,full27Backend=False),indent=2)+'\n')
if __name__=='__main__': main()
