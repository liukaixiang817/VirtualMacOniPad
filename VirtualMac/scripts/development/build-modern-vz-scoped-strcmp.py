#!/usr/bin/env python3
"""Build app-private strcmp provider and owned fixture; Mac execution only."""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def uuid(p):
    b=p.read_bytes();assert struct.unpack_from('<I',b)[0]==0xfeedfacf
    count,size=struct.unpack_from('<II',b,16);assert size<65536 and count<256
    at=32;found=[]
    for _ in range(count):
        command,length=struct.unpack_from('<II',b,at);assert length>=8 and at+length<=32+size
        if command==27:assert length==24;found.append(b[at+8:at+24].hex())
        at+=length
    assert at==32+size and len(found)==1;return found[0]


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    source=R/'VirtualMac/vz/host/modern_vz_scoped_strcmp.c';fixture=R/'VirtualMac/scripts/tests/test-modern-vz-scoped-strcmp.cpp'
    (out/'provider.c').write_bytes(source.read_bytes());(out/'fixture.cpp').write_bytes(fixture.read_bytes());(out/'exports.list').write_text('__platform_strcmp\n')
    processes=[]
    def run(name,argv,timeout=30):
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE);so,se=p.communicate(timeout=timeout)
        (out/(name+'.stdout')).write_bytes(so);(out/(name+'.stderr')).write_bytes(se)
        processes.append(dict(name=name,pid=p.pid,wait=p.returncode,command=argv));save(out/'processes.json',processes);assert p.returncode==0,se.decode();return so
    products=[]
    for role,target,sdkname in [('macos','arm64e-apple-macos27.0','macosx'),('ios','arm64e-apple-ios16.1','iphoneos')]:
        folder=out/role;folder.mkdir();sdk=run(role+'-sdk',['xcrun','--sdk',sdkname,'--show-sdk-path']).decode().strip()
        provider=folder/'VM27ScopedStringCompare.dylib';binary=folder/'owned-scoped-strcmp-fixture'
        common=['-target',target,'-isysroot',sdk,'-fptrauth-abi-version=0','-fno-typed-memory-operations-experimental','-Wall','-Wextra','-Werror','-O2']
        run(role+'-provider-compile',['xcrun','clang','-std=c11']+common+['-fno-builtin-strcmp','-dynamiclib','-Wl,-install_name,@loader_path/VM27ScopedStringCompare.dylib','-Wl,-exported_symbols_list,'+str(out/'exports.list'),str(out/'provider.c'),'-o',str(provider)])
        run(role+'-provider-sign',['codesign','--force','--sign','-','--timestamp=none',str(provider)])
        run(role+'-provider-strict',['codesign','--verify','--strict',str(provider)])
        export=run(role+'-exports',['xcrun','dyld_info','-exports',str(provider)]).decode();assert '__platform_strcmp' in export
        imports=run(role+'-imports',['xcrun','dyld_info','-imports',str(provider)]).decode();assert '_strcmp' in imports
        (folder/'provider-pins.h').write_text('#define PROVIDER_UUID "'+uuid(provider)+'"\n')
        run(role+'-fixture-compile',['xcrun','clang++','-std=c++17']+common+['-I'+str(folder),str(out/'fixture.cpp'),'-o',str(binary)])
        run(role+'-fixture-sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)])
        run(role+'-fixture-strict',['codesign','--verify','--strict',str(binary)])
        products.append(dict(role=role,provider=pin(provider),providerUUID=uuid(provider),fixture=pin(binary),executed=role=='macos',rootOrSandboxRightsAdded=False))
    run('mac-native',[str(out/'macos/owned-scoped-strcmp-fixture'),str(out/'macos/VM27ScopedStringCompare.dylib')],15)
    rows=[json.loads(l) for l in (out/'mac-native.stdout').read_text().splitlines()];assert len(rows)==1
    s=rows[0];assert s['passed'] is True and s['full27'] is False and s['ownedPairs']==924 and s['checks']==1852
    assert s['originalVZConsumerExecuted'] is False and s['actualVZCalls']==0 and s['originalDispatchTargetPreserved'] is False
    save(out/'candidate.json',dict(products=products,onlyExport='__platform_strcmp',typedABI='int(const char*,const char*)',callsOnlyHostPublicStrcmp=True,twoLevelNamespace=True,interposeRecords=0,constructors=0,nativeSummary=s,originalConsumerValidationPending=[14,15,20,22,40,490],originalVZConsumerExecuted=False,originalVMMExecuted=False,guestInstructions=0,full27=False,deviceOperations=0,systemModified=False))
    save(out/'inputs.json',[pin(p) for p in (source,fixture,pathlib.Path(__file__).resolve())]);print(json.dumps(s))


if __name__=='__main__':main()
