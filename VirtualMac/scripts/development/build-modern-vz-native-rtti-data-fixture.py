#!/usr/bin/env python3
"""Build a new owned RTTI/libc fixture, run Mac only; never loads VZ or deploys."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--contract',required=True,type=pathlib.Path);ap.add_argument('--expected-contract-sha256',required=True);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    assert pin(args.contract)['sha256']==args.expected_contract_sha256
    contract=json.loads(args.contract.read_text());out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    source=R/'VirtualMac/scripts/tests/test-modern-vz-native-rtti-data.cpp'
    (out/'fixture.cpp').write_bytes(source.read_bytes())
    native=contract['strcmpResolverContract']['newTargetPhysicalOwner']
    mac=out/'macos';ios=out/'ios';mac.mkdir();ios.mkdir()
    common=f'#define PLATFORM_OWNER_UUID "{native["uuid"]}"\n#define PLATFORM_OWNER_BASE UINT64_C({native["base"]})\n#define PLATFORM_FINAL_TARGET UINT64_C({contract["strcmpResolverContract"]["newOfflineDecodedTarget"]})\n'
    (mac/'owner-pins.h').write_text('#define CPP_OWNER_UUID "a21743ee6e1c3e7497ea7af793de4bdf"\n'+common)
    (ios/'owner-pins.h').write_text('#define CPP_OWNER_UUID "fa871417be083e90b33ca6aa89813f3b"\n'+common)
    processes=[]
    def run(name,argv,timeout=30):
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE);so,se=p.communicate(timeout=timeout)
        (out/(name+'.stdout')).write_bytes(so);(out/(name+'.stderr')).write_bytes(se);processes.append(dict(name=name,pid=p.pid,wait=p.returncode,command=argv));save(out/'processes.json',processes);assert p.returncode==0,se.decode();return so
    ms=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip();ins=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
    products=[]
    for role,folder,sdk,target in [('macos',mac,ms,'arm64e-apple-macos27.0'),('ios',ios,ins,'arm64e-apple-ios16.1')]:
        binary=folder/'owned-vz-rtti-data-fixture'
        flags=['xcrun','clang++','-std=c++17','-target',target,'-isysroot',sdk,'-fptrauth-abi-version=0','-fno-typed-memory-operations-experimental','-Wall','-Wextra','-Werror','-O2','-I'+str(folder)]
        if role=='ios':flags+=['-DVM27_FIXTURE_IOS']
        run(role+'-compile',flags+[str(out/'fixture.cpp'),'-o',str(binary)])
        run(role+'-sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)])
        run(role+'-strict',['codesign','--verify','--strict',str(binary)])
        products.append(dict(role=role,binary=pin(binary),executed=role=='macos',rootOrSandboxRightsAdded=False))
    run('mac-native',[str(mac/'owned-vz-rtti-data-fixture')],15)
    rows=[json.loads(l) for l in (out/'mac-native.stdout').read_text().splitlines()];assert len(rows)==5 and rows[-1]['passed'] is True and rows[-1]['full27'] is False
    assert rows[-1]['nativeOriginalStrcmpFinalTargetVerified'] is True and rows[-1]['ownedRTTITypes']==4 and rows[-1]['originalVZConsumerExecuted'] is False
    save(out/'result.json',dict(passed=True,products=products,nativeSummary=rows[-1],newExactStrcmpImplementationTargetNativeVerified=True,originalTypeInfoCellsNotCloned=True,originalVZConsumerExecuted=False,relocatedVZLoaded=False,actualVZCalls=0,originalVMMExecuted=False,guestInstructions=0,full27=False,deviceOperations=0,systemModified=False))
    save(out/'inputs.json',[pin(p) for p in (source,args.contract,pathlib.Path(__file__).resolve())]);print(json.dumps(rows[-1]))


if __name__=='__main__':main()
