#!/usr/bin/env python3
"""Correct genuine CfD on new own fixed-class objects; iOS link is unsigned.

The only product source delta is native deallocation(self,32,7) and removal
of its noreturn declaration. The original +144 BRK and initializer remain.
No signing, loading, routing, device transport or CPU/VM API execution.
"""
from pathlib import Path
import argparse, hashlib, json, subprocess
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H=R/'VirtualMac/vz/host'
def need(v,why):
    if not v: raise ValueError(why)
def pin(p):
    p=Path(p); b=p.read_bytes()
    return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    D=a.output.resolve();need(not D.exists(),'fresh output');D.mkdir(parents=True)
    freeze=N/'static-cn-fixed-provider-aggregate-audit-v3/freeze.json'
    frozen={r['path']:r for r in json.loads(freeze.read_bytes())['files']}
    old=N/'static-cn-fixed-data-provider-local-v4';commands=[];objects=[];deltas=[]
    def exact(p):
        row=pin(p);need(frozen.get(row['path'])==row,'original immutable compile source pin');return p.read_bytes()
    def run(label,argv):
        argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,timeout=60)
        (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
        (D/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');need(p.returncode==0,label+' failed');return p.stdout.decode().strip()
    priorMethods=H/'modern_swift_static_cn_fixed_methods_v1.ll';newMethods=H/'modern_swift_static_cn_fixed_methods_v2.ll'
    expected=exact(priorMethods).decode();oldBody='define swiftcc void @VM27StaticCNDeallocator(ptr swiftself %self) noreturn #0 {\n  call void @llvm.trap()\n  unreachable\n}'
    newBody='; Genuine CN-16 full helper passes Swift self, size 32, alignment mask 7.\ndefine swiftcc void @VM27StaticCNDeallocator(ptr swiftself %self) #0 {\n  call void @swift_deallocClassInstance(ptr %self, i64 32, i64 7)\n  ret void\n}'
    need(expected.count(oldBody)==1,'one exact original incorrect trap body')
    expected=expected.replace('declare void @llvm.trap() noreturn nounwind','declare void @swift_deallocClassInstance(ptr, i64, i64)\ndeclare void @llvm.trap() noreturn nounwind').replace(oldBody,newBody)
    need(newMethods.read_text()==expected,'only closed CfD product delta')
    genuine=N/'static-cn-genuine-deallocator-tail-target-host-readonly-v1/contract.json'
    need(pin(genuine)['sha256']=='d6418fc0f9a6f2408af4fb52e57098e2b2312d4e94abbbf6f9ee19b38f43945a','actual genuine full helper contract')
    for mode,sdkname,target in [('mac-model','macosx','arm64e-apple-macos27.0'),('ios-inert','iphoneos','arm64e-apple-ios16.1')]:
        d=D/mode;d.mkdir();sdk=run(mode+'-sdk',['xcrun','--sdk',sdkname,'--show-sdk-path'])
        ir=exact(old/mode/'FixedCN.ll').decode();decl='declare swiftcc void @VM27StaticCNDeallocator(ptr swiftself) noreturn'
        need(ir.count(decl)==1,'one fixed-CN obsolete noreturn declaration');ir=ir.replace(decl,decl.removesuffix(' noreturn'))
        (d/'FixedCN.ll').write_text(ir)
        run(mode+'-fixed',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',d/'FixedCN.ll','-o',d/'FixedCN.o'])
        run(mode+'-methods',['xcrun','clang','-target',target,'-isysroot',sdk,'-x','ir','-c',newMethods,'-o',d/'Methods.o'])
        fatal=exact(old/mode/'Fatal.o');(d/'Fatal.o').write_bytes(fatal)
        need((d/'FixedCN.o').read_bytes()==exact(old/mode/'FixedCN.o'),'metadata compiled bytes unchanged by declaration correction')
        objects.extend(pin(d/name) for name in ['FixedCN.o','Methods.o','Fatal.o'])
        deltas.append(dict(mode=mode,metadataIR=pin(d/'FixedCN.ll'),metadataObjectWholeByteUnchanged=True,fatalObjectWholeByteUnchanged=True))
        if mode=='ios-inert':
            dylib=D/'VM27StaticCNFixed.dylib'
            run('unsigned-link',['xcrun','clang','-target',target,'-isysroot',sdk,'-dynamiclib',d/'FixedCN.o',d/'Methods.o',d/'Fatal.o','-L'+sdk+'/usr/lib/swift','-lswiftCore','-lobjc','-Wl,-rpath,/usr/lib/swift','-Wl,-install_name,@rpath/VM27StaticCNFixed.dylib','-Wl,-no_adhoc_codesign','-o',dylib])
    (D/'candidate.json').write_text(json.dumps(dict(schema='Corrected genuine CfD original fixed176 unsigned linked provider local v2',source=pin(Path(__file__)),oldProviderFreeze=pin(freeze),preservedV1RejectedFreeze=pin(N/'static-cn-fixed-original-linked-provider-local-v1/freeze.json'),genuineCfD=pin(genuine),genuineCfDFreeze=pin(genuine.parent/'freeze.json'),productSource=pin(newMethods),priorProductSource=pin(priorMethods),objects=objects,sourceDeltas=deltas,linkedProduct=pin(dylib),commands=commands,CfDNativeSize=32,CfDNativeAlignmentMask=7,CfDReturns=True,CfDDynamicStockCall=True,plus144BRK1Unchanged=True,forbiddenInitializerUnchanged=True,usesTrueOwn176ClassData=True,AP24=True,N3=True,P19=True,CMnBytes=124,ROMetaLayoutOriginal=True,oldFactoryAlias=False,oldEmptyAlias=False,rawCachedInheritedMethodPointerBorrowed=False,unsigned=True,signed=False,loaded=False,executed=False,routeCreated=False,originalStaticCNRuntimeIdentityEstablished=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,full27Backend=False),indent=2)+'\n')
    print(json.dumps(dict(product=pin(dylib),metadataWholeByteUnchanged=True,signed=False,loaded=False)))
if __name__=='__main__':main()
