#!/usr/bin/env python3
"""Build an owned private data-import probe. No deployment or iOS execution."""
import argparse,hashlib,json,plistlib,re,subprocess,sys
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    root=Path(__file__).resolve().parents[3];out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    commands=[]
    def run(label,argv):
        p=subprocess.run(argv,capture_output=True);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode));p.check_returncode();return p
    base=root/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-constants-build-v1'
    m=json.loads((base/'manifest.json').read_bytes());provider=Path(m['library']['path']);h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    assert provider.stat().st_size==50256 and h(provider)=='c4c15117398f6c08cab3759d76ee1113707123fb9b853aad85f36197df4365c6'
    for row in m['sourceFreeze']:assert h(Path(row['path']))==row['sha256']
    run('provider-strict',['codesign','--verify','--strict',str(provider)])
    sys.path.insert(0,str(root/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
    from compiler_image import commands as macho_commands
    d=provider.read_bytes();uuid=next(d[a+8:a+24].hex() for k,a,n in macho_commands(d) if k==0x1b)
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip();exe=out/'di2-constants-probe';source=root/'VirtualMac/scripts/tests/test-modern-diskimages2-constants.c'
    run('compile',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-typed-memory-operations-experimental','-framework','CoreFoundation','-Wl,-platform_version,ios,16.1,16.1','-DVM27_CONSTANTS_UUID="'+uuid+'"',str(source),'-o',str(exe)])
    rights={'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True}
    ent=out/'Probe.entitlements';ent.write_bytes(plistlib.dumps(rights));run('sign',['codesign','--force','--sign','-','--timestamp=none','--entitlements',str(ent),str(exe)])
    run('strict',['codesign','--verify','--strict',str(exe)]);sig=run('signature',['codesign','-d','--verbose=4',str(exe)]).stderr
    run('dyld',['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(exe)])
    providerCopy=out/provider.name;providerCopy.write_bytes(d)
    freeze=[]
    for p in [source,Path(__file__).resolve(),base/'manifest.json']+[Path(r['path']) for r in m['sourceFreeze']]:
        f=out/'source'/p.relative_to(root);f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(p.read_bytes());freeze.append(dict(path=str(f),bytes=f.stat().st_size,sha256=h(f)))
    files=[dict(path=str(exe),name=exe.name,bytes=exe.stat().st_size,sha256=h(exe),cdhash=re.search(rb'CDHash=([0-9a-f]{40})',sig)[1].decode(),entitlements=rights,code=True),dict(path=str(providerCopy),name=provider.name,bytes=len(d),sha256=h(providerCopy),cdhash=m['library']['cdhash'],entitlements={},code=True)]
    receipt=dict(files=files,providerUUID=uuid,constants=m['constants'],sourceFreeze=freeze,dataOnly=True,iOSExecuted=False,genuine27DI2Loaded=False,original27ConsumerBindingsChanged=False,targetServiceCalls=0,VMCalls=0,diskCalls=0,GPUCalls=0)
    (out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');print(json.dumps(receipt,indent=2))
if __name__=='__main__':main()
