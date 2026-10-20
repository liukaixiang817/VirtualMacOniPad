#!/usr/bin/env python3
"""Link frozen true original-name fixed CN objects into one unsigned dylib.

Compile/link only: no route creation, signing, loading, fixture execution,
device operation or original-class identity acceptance.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def require(v,why):
    if not v:raise ValueError(why)
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();out=a.output.resolve();require(not out.exists(),'new output required');out.mkdir(parents=True)
    source=N/'static-cn-fixed-data-provider-local-v4/ios-inert';freeze=N/'static-cn-fixed-provider-aggregate-audit-v3/freeze.json';frozen=json.loads(freeze.read_bytes());rows={x['path']:x for x in frozen['files']};objects=[]
    for name in ['FixedCN.o','Methods.o','Fatal.o']:
        p=source/name;row=pin(p);require(rows.get(row['path'])==row,'frozen original-name object identity');objects.append(p)
    commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=60);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))));(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');require(p.returncode==0,label+' failed '+str(p.returncode));return p.stdout.decode().strip()
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']);run('clang-version',['xcrun','clang','--version']);dylib=out/'VM27StaticCNFixed.dylib'
    run('unsigned-link',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-dynamiclib',*objects,'-L'+sdk+'/usr/lib/swift','-lswiftCore','-lobjc','-Wl,-rpath,/usr/lib/swift','-Wl,-install_name,@rpath/VM27StaticCNFixed.dylib','-Wl,-no_adhoc_codesign','-o',dylib])
    (out/'candidate.json').write_text(json.dumps(dict(schema='True original-symbol fixed176 StaticCN unsigned linked provider local v1',source=pin(Path(__file__)),frozenCompileOnlyProvider=pin(N/'static-cn-fixed-data-provider-local-v4/candidate.json'),frozenProviderAggregate=pin(N/'static-cn-fixed-provider-aggregate-audit-v3/audit.json'),frozenProviderFreeze=pin(freeze),objects=[pin(p) for p in objects],originalNameIR=pin(source/'FixedCN.ll'),linkedProduct=pin(dylib),installName='@rpath/VM27StaticCNFixed.dylib',commands=commands,originalSymbolAndClassNamePreserved=True,usesTrueOwn176ClassData=True,AP24=True,N3=True,P19=True,CMnBytes=124,ROMetaLayoutOriginal=True,originalBRKDeallocatorPreserved=True,originalForbiddenInitializerSemanticsPreserved=True,oldFactoryAlias=False,oldEmptyAlias=False,rawCachedInheritedMethodPointerBorrowed=False,sourceChanged=False,unsigned=True,linked=True,signed=False,loaded=False,executed=False,routeCreated=False,latestDERouteBaseStillRequired=True,ordinaryOldN2ActualResultStillRequired=True,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,originalStaticCNRuntimeIdentityEstablished=False,full27Backend=False),indent=2)+'\n');print(json.dumps(dict(product=pin(dylib),executed=False,signed=False)))
if __name__=='__main__':main()
