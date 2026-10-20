#!/usr/bin/env python3
"""Build-only NEW iOS V9/V2/reader and zero-code reexport aggregate.

No signing, runtime loading, probe, device operation or original image execution.
Nine old libraries are exact copies; shared Headless/ClientRegistration occur once.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST=R/'VirtualMac/vz/host'
CAPACITY=N/'xpc-original-capacity8-v1/build-v4'
CLIENT=N/'vmm-client-services-reexport-contract-v1/build-v4/ios'
PREPARE=Path(__file__).with_name('prepare-modern-vmm-owned-xpc-v9-data-v1.py')
PINS={
 'modern_xpc_original_instance_transport_v9.c':'990b978147a1344ffa2230fa4da7b0036ae02af29fa161954ca242338bda850a',
 'modern_xpc_original_instance_transport_v9.h':'d06539bca602923b6805dcba7781737624321a9fa85f98293e375b34b14cccff',
 'vm27_bundle_parent_inspection_v1.c':'31ac767de6c299a04d47e76c698ff6e71b9a8eb6b82a6c4aa2cafee7c51180a6',
 'vm27_bundle_parent_inspection_v1.h':'fea320b37f9121360b11b8da55a9de227c53df77fd27a4a59756ba216f09fb54',
 'vm27_owned_startup_coordinator_v2.c':'a759a73a96a587d5fb9acb44decfc20784af950fbec80d51c737e0f1b5a621ac',
 'vm27_owned_startup_coordinator_v2.h':'7b439ee08f7905da12ec4b3740a9c00a3ed6e4726fd0b1df8a2522def8982d61'}
OLD={
 'VM27ApprovedCode.dylib':(CAPACITY/'ios/VM27ApprovedCode.dylib','0444bc12a88ee8fe63e4ab781ecacca7fda6dddbf3026296c862b1d20e1b2b50'),
 'VM27LWCRPolicy.dylib':(CAPACITY/'ios/VM27LWCRPolicy.dylib','1e81edbed68462aee599cb014659e1de960982bb69f78eb272adf6e76f639349'),
 'VM27PrivateEndpoint.dylib':(CAPACITY/'ios/VM27PrivateEndpoint.dylib','925be29cba67d73bf37f76225b82e9961ed8a02696bbcadfc55ce1e9227b4231'),
 'VM27LargeRegistry.dylib':(CAPACITY/'ios/VM27LargeRegistry.dylib','ff4d14ccaf29c3d76f54c70b715dbd3ff0577a5afcde7406265bb86c6f79773a'),
 'VM27LargeConsumer.dylib':(CAPACITY/'ios/VM27LargeConsumer.dylib','2b447e4a302e9d25aad37cc255233b43bfdd92251abdcb66e88da88e33ff3da1'),
 'VM27HeadlessCheckIn.dylib':(N/'vmm-headless-checkin-contract-v1/ios/VM27HeadlessCheckIn.dylib','539d419dc0d9ab3cd769ed383ff5f6541c8d34a971f6329614323defc1713d38'),
 'VM27ClientRegistration.dylib':(CLIENT/'VM27ClientRegistration.dylib','518af91b2c6d0d5c86e6a8123eb029ec145a9dbdfee1bf11278a89db65eb126b'),
 'VM27ClientServices.dylib':(CLIENT/'VM27ClientServices.dylib','2523f38dc890bc1986c2f8737319fa398e92b15af279a6579f8f3e52c5227197'),
 'VM27PrivateProcessTitle.dylib':(CLIENT/'VM27PrivateProcessTitle.dylib','0e4654ed43bfeb38d4df18a60186079105a8c8fc69c6191978158263f5baf300')}
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=sha(b))
def main():
    assert sys.flags.optimize==0
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=out/'source';source.mkdir(mode=0o700);ios=out/'ios';ios.mkdir(mode=0o700)
    sourcePaths=[HOST/name for name in PINS]
    sourcePaths += [HOST/name for name in ['vm27_owned_startup_aggregate_v9.c','modern_xpc_original_instance_pins.h','vm27_headless_checkin_v1.h','vm27_client_registration_v1.h','modern_xpc_large_private_consumer.h','modern_xpc_large_bundle_registry.h','modern_xpc_approved_code.h','modern_xpc_lwcr_policy.h','modern_xpc_private_endpoint.h']]
    sourcePaths += [Path(__file__),PREPARE,R/'VirtualMac/scripts/development/vz_import_addend_image.py',N.parent/'2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py']
    for p in sourcePaths:
        b=p.read_bytes()
        if p.name in PINS:assert sha(b)==PINS[p.name]
        dest=source/p.name;assert not dest.exists();dest.write_bytes(b);dest.chmod(0o600)
    oldPins=[];libraries=[]
    for name,(path,expected) in OLD.items():
        b=path.read_bytes();assert sha(b)==expected and not path.is_symlink() and path.stat().st_nlink==1
        dest=ios/name;dest.write_bytes(b);dest.chmod(0o600);oldPins.append(pin(path));libraries.append(dict(name=name,**pin(dest),source=str(path.resolve()),oldByteExactCopy=True,resigned=False))
    spec=importlib.util.spec_from_file_location('v9_static_route',PREPARE);route=importlib.util.module_from_spec(spec);spec.loader.exec_module(route)
    processes=[]
    def run(label,argv):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:stdout,stderr=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill();stdout,stderr=child.communicate();raise
        (out/(label+'.argv.json')).write_text(json.dumps(argv,indent=2)+'\n');(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
        (out/(label+'.exit')).write_text(str(child.returncode)+'\n');processes.append(dict(label=label,argv=argv,directChildPID=child.pid,observedWaitExit=child.returncode,reaped=True))
        assert child.returncode==0,(label,child.returncode,stderr.decode(errors='replace')[-2000:]);return stdout
    clang=run('clang-path',['/usr/bin/xcrun','--find','clang']).decode().strip()
    sdk=run('ios-sdk',['/usr/bin/xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
    base=[clang,'-std=c11','-fblocks','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-O2','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-fptrauth-abi-version=0','-I',str(source),'-dynamiclib','-Wl,-no_adhoc_codesign','-Wl,-rpath,@loader_path','-Wl,-current_version,1.0','-Wl,-compatibility_version,1.0']
    def build(label,name,c,deps,extra):
        path=ios/name;argv=base+[str(source/c)]+[str(ios/x) for x in deps]+extra+['-Wl,-install_name,@rpath/'+name,'-o',str(path)]
        run(label+'-compile',argv);path.chmod(0o600)
        run(label+'-metadata',['/usr/bin/xcrun','dyld_info','-validate_only',str(path)])
        run(label+'-exports',['/usr/bin/xcrun','dyld_info','-exports',str(path)])
        run(label+'-imports',['/usr/bin/xcrun','dyld_info','-imports',str(path)])
        libraries.append(dict(name=name,**pin(path),source=str((source/c).resolve()),oldByteExactCopy=False,unsigned=True,signingCalls=0))
    build('reader','VM27BundleParentV1.dylib','vm27_bundle_parent_inspection_v1.c',[],['-framework','CoreFoundation'])
    build('v9','VM27OriginalV9Transport.dylib','modern_xpc_original_instance_transport_v9.c',['VM27LargeConsumer.dylib','VM27ApprovedCode.dylib','VM27ClientRegistration.dylib','VM27BundleParentV1.dylib'],['-framework','Security','-framework','CoreFoundation'])
    build('v2','VM27OwnedStartupV2.dylib','vm27_owned_startup_coordinator_v2.c',['VM27OriginalV9Transport.dylib','VM27HeadlessCheckIn.dylib'],['-framework','CoreFoundation'])
    reexport=[]
    for name in ['VM27OriginalV9Transport.dylib','VM27OwnedStartupV2.dylib','VM27HeadlessCheckIn.dylib']:reexport += ['-Wl,-reexport_library,'+str(ios/name)]
    build('aggregate','VM27StartupV9.dylib','vm27_owned_startup_aggregate_v9.c',[],reexport)
    for before in oldPins:assert pin(Path(before['path']))==before
    c=dict(schema='NEW unsigned iOS V9 owned-startup provider graph v1',builder=pin(Path(__file__)),sourceInputs=[pin(p) for p in sourcePaths],sourceSnapshots=[pin(p) for p in sorted(source.iterdir())],libraries=libraries,oldInputsByteExactBeforeAfter=oldPins,processes=processes,noOriginalImagesExecuted=True,providerGraphExecuted=False,deviceOperations=False,signingCalls=0,oldCopiesResigned=False,nativeCPUOperations=0,guestInstructions=0,full27Backend=False,coordinatorPrepareAutomaticallyInvoked=False,trustedPreMainCallerIntegrated=False,sameHeadlessAndRegistrationImagesRequired=True,strictLargeMissingOuterKernelCDHashStillFailsClosed=True)
    (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
    _,images=route.graph_validate(out)
    (out/'graph-verification.json').write_text(json.dumps(dict(schema='Pure data V9 graph verification v1',verified=True,libraries=images,zeroInstructionAggregate=True,sharedRegistrationViaV9AndOriginalClientServices=True,sharedCheckInViaV2AndOriginalOrdinal54=True,noRuntimeResolutionClaim=True,providerGraphExecuted=False,full27Backend=False),indent=2)+'\n')
    files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()];(out/'freeze.json').write_text(json.dumps(dict(files=files),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),libraries=len(libraries),newUnsignedLibraries=4,oldByteExactLibraries=9,originalExecuted=False)))
if __name__=='__main__':main()
