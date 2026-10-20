#!/usr/bin/env python3
"""Separate bounded app-private LS aggregate self-consumer; local build only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R=Path(__file__).resolve().parents[3]
N=R/"DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
PREVIOUS=N/"vmm-client-services-reexport-contract-v1/build-v4"
PREVIOUS_FREEZE="4ba06eb323bd623f20c380140c48b86b391f1ae4081cee7bd3b7c9082c0759e1"
SOURCE=R/"VirtualMac/scripts/tests/test-modern-vmm-client-services-consumer-v1.c"
RIGHTS={"platform-application":True,"com.apple.private.security.no-container":True,
    "com.apple.private.security.no-sandbox":True,"com.apple.private.amfi.can-execute-cdhash":True}


def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=sha(b))
def uuid(b):
    at=32;found=[]
    for _ in range(struct.unpack_from('<I',b,16)[0]):
        c,z=struct.unpack_from('<II',b,at)
        if c==0x1b:assert z==24;found.append(b[at+8:at+24].hex())
        at+=z
    assert len(found)==1;return found[0]


def main(out):
    assert sha((PREVIOUS/'freeze.json').read_bytes())==PREVIOUS_FREEZE
    for row in json.loads((PREVIOUS/'freeze.json').read_bytes())['files']:
        b=(PREVIOUS/row['path']).read_bytes();assert len(b)==row['bytes'] and sha(b)==row['sha256']
    previous=json.loads((PREVIOUS/'candidate.json').read_bytes())
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=out/'source';source.mkdir()
    shutil.copyfile(SOURCE,source/SOURCE.name);shutil.copyfile(Path(__file__),source/Path(__file__).name)
    logs=[];files=[]
    def run(label,argv,cwd=None):
        env={k:v for k,v in os.environ.items()if not k.startswith('DYLD_')}
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=cwd,env=env)
        try:o,e=p.communicate(timeout=12)
        except subprocess.TimeoutExpired:p.kill();p.communicate();raise
        (out/(label+'.stdout')).write_bytes(o);(out/(label+'.stderr')).write_bytes(e)
        logs.append(dict(label=label,argv=argv,cwd=str(cwd)if cwd else None,actualStartedPID=p.pid,waitExit=p.returncode))
        assert p.returncode==0,(label,e[-3000:]);return o,e
    for platform,sdk,target in [('mac','macosx','arm64e-apple-macos13.2'),('ios','iphoneos','arm64e-apple-ios16.1')]:
        d=out/platform;d.mkdir(mode=0o700)
        previous_record=next(x for x in previous['records']if x['platform']==platform)
        origins=[previous_record['aggregate']]+[x['copy']for x in previous_record['providerCopies']]
        pins=[]
        for key,origin in zip(('AGGREGATE','BRIDGE','TITLE'),origins):
            original=Path(origin['path']);b=original.read_bytes();assert sha(b)==origin['sha256']
            p=d/original.name;shutil.copyfile(original,p);p.chmod(0o600)
            assert p.read_bytes()==b and p.lstat().st_nlink==1 and not p.is_symlink()
            pins += ['#define VM27_'+key+'_UUID "'+uuid(b)+'"', '#define VM27_'+key+'_SHA "'+sha(b)+'"']
            run(platform+'-'+p.name+'-strict',['codesign','--verify','--strict',str(p)])
            files.append(dict(platform=platform,role=key.lower(),**pin(p),UUID=uuid(b),ncmds=struct.unpack_from('<I',b,16)[0],unchanged=True,source=pin(original)))
        (d/'client_services_consumer_pins.h').write_text('\n'.join(pins)+'\n')
        sdkpath=run(platform+'-sdk',['xcrun','--sdk',sdk,'--show-sdk-path'])[0].decode().strip()
        cli=d/'private-client-services-self-consumer'
        run(platform+'-build',['xcrun','clang','-target',target,'-isysroot',sdkpath,'-fptrauth-abi-version=0',
            '-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-framework','CoreFoundation',
            '-I',str(d),str(source/SOURCE.name),'-Wl,-no_adhoc_codesign','-o',str(cli)])
        ent=d/'Probe.entitlements';ent.write_bytes(plistlib.dumps(RIGHTS if platform=='ios' else {}))
        run(platform+'-sign',['codesign','--force','--sign','-','--timestamp=none','--identifier','com.virtualmac.diagnostics.private-client-services-self-consumer.v1','--entitlements',str(ent),str(cli)])
        cli.chmod(0o700)
        run(platform+'-strict',['codesign','--verify','--strict',str(cli)])
        _,desc=run(platform+'-signature',['codesign','-d','--verbose=4',str(cli)])
        run(platform+'-validate',['xcrun','dyld_info','-validate_only',str(cli)])
        run(platform+'-imports',['xcrun','dyld_info','-imports',str(cli)])
        run(platform+'-dependents',['xcrun','dyld_info','-dependents',str(cli)])
        files.append(dict(platform=platform,role='consumer',**pin(cli),UUID=uuid(cli.read_bytes()),CDHash=re.search(rb'CDHash=([a-f0-9]{40})',desc)[1].decode(),entitlements=RIGHTS if platform=='ios'else{}))
        if platform=='mac':run('mac-own-actual',['./'+cli.name,'--private-client-services-self-consumer'],cwd=d)
    c=dict(schema='Bounded private client services real re-export consumer v1',files=files,source=pin(source/SOURCE.name),builder=pin(Path(__file__)),steps=logs,
        originalVMMExecuted=False,originalVZLoaded=False,nativeCPUCalls=0,nativeVMCalls=0,nativeGPUCalls=0,nativeDeviceExecuted=False,
        privateNamespace='/private/var/tmp/vm27-client-services-native-v1-',namespaceSuffixLowerHexLength=16,
        maximumWallAlarmSeconds=8,CPUSoftSeconds=3,CPUHardSeconds=4,fileOutputHardBytes=1<<20,descriptorHardCount=64,
        rootCredentials=[0,0,0,0],providerMode=0o600,consumerMode=0o700,directoryMode=0o700,
        originalFunctionsResolved=4,constantSlotsResolved=2,auxiliaryFunctionsResolved=2,realTitleStores=1,realTitleReadbacks=1,
        XPCPIDInventoryReadOnly=True,XPCPIDFunctionCalled=False,XPCPIDReplacementExported=False,
        productionClientBootstrapIntegrated=False,hostGlobalLSRegistry=False,wholeStrongDependencyClosureAudited=False,full27Backend=False)
    (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),iOSFiles=[x for x in files if x['platform']=='ios']),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);main(ap.parse_args().output.resolve())
