#!/usr/bin/env python3
"""NEW build/sign-only owned IPC package. No iOS execution/device/trustcache.

Six new hashes only: four unsigned-provider copies and two owned executables.
Six old libraries remain byte-identical. Original frameworks are absent.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';H=R/'VirtualMac/vz/host'
GRAPH=N/'owned-vmm-xpc-v10-provider-build-v2';GRAPH_SHA='1eb57954dc7832623824be503a53a47be90aa2ec25da6e59946d0295caab4d53'
RIGHTS=N/'xpc-original-instance-registration-v8-test-development-v1/build-v5/ios/original-xpc-instance-transport-v8-probe.entitlements'
NAMES=['VM27OriginalV10Transport.dylib','VM27BundleParentV1.dylib','VM27OwnedStartupV3.dylib','VM27ApprovedCode.dylib','VM27LWCRPolicy.dylib','VM27PrivateEndpoint.dylib','VM27LargeRegistry.dylib','VM27LargeConsumerV2.dylib','VM27HeadlessCheckIn.dylib','VM27ClientRegistration.dylib']
NEW=set(NAMES[:3])|{'VM27LargeConsumerV2.dylib'};TITLE='VM27 Owned V3 Preparation'
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=sha(b))
def module(p,name):s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=module(R/'VirtualMac/scripts/development/prepare-modern-vmm-owned-xpc-v9-data-v1.py','prep_package_metadata')
def code_directory(path):
    b=path.read_bytes();meta=M.metadata(b);assert len(meta['signatures'])==1
    at,size=meta['signatures'][0];assert at+size<=len(b);sig=b[at:at+size]
    magic,length,count=struct.unpack_from('>3I',sig);assert magic==0xfade0cc0 and length<=len(sig) and count<=16
    candidates=[]
    for i in range(count):
        kind,off=struct.unpack_from('>2I',sig,12+8*i)
        if kind==0:
            magic,sz=struct.unpack_from('>2I',sig,off);assert magic==0xfade0c02 and off+sz<=length;candidates.append(sig[off:off+sz])
    assert len(candidates)==1;cd=candidates[0];offset=struct.unpack_from('>I',cd,16)[0];special,pages,limit=struct.unpack_from('>3I',cd,24);hashSize,hashType,platform,pageExp=struct.unpack_from('4B',cd,36)
    assert hashSize==32 and hashType==2 and pageExp in (12,14) and offset>=special*hashSize and offset+pages*hashSize<=len(cd)
    for page in range(pages):assert hashlib.sha256(b[page*(1<<pageExp):min((page+1)*(1<<pageExp),limit)]).digest()==cd[offset+page*32:offset+(page+1)*32]
    def slot(i):return cd[offset-i*32:offset-(i-1)*32] if i<=special else bytes(32)
    return dict(CDHash=sha(cd)[:40],UUID=meta['UUID'],codePages=pages,codeLimit=limit,slot1=slot(1).hex(),slot3=slot(3).hex(),meta=meta)
def main():
    assert sys.flags.optimize==0
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--runtime-root',required=True);args=ap.parse_args()
    root=args.runtime_root
    assert root=='/private/var/root/VirtualMac2/testing-root/owned-v3-preparation-v2', 'supply the reviewed new runtime root exactly; the old v1 root is retained'
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=out/'source';source.mkdir(mode=0o700);package=out/'package';package.mkdir(mode=0o700);libs=package/'libs';libs.mkdir(mode=0o700)
    g=json.loads((GRAPH/'candidate.json').read_text());assert pin(GRAPH/'candidate.json')['sha256']==GRAPH_SHA
    rights=RIGHTS.read_bytes();assert plistlib.loads(rights)=={'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True,'com.apple.private.virtualization.plugin':True,'com.apple.private.virtualization':True}
    rightsFile=source/'owned-v8-exact.entitlements';rightsFile.write_bytes(rights);empty=source/'empty-dso.entitlements';empty.write_bytes(plistlib.dumps({}))
    sourcePaths=[Path(__file__),R/'VirtualMac/scripts/tests/test-owned-v3-preparation-ipad-v1.c',R/'VirtualMac/scripts/tests/owned-v3-refusal-cleanup-shape.h',R/'VirtualMac/scripts/tests/test-owned-v3-refusal-cleanup-shape.c',R/'VirtualMac/scripts/tests/test-owned-v2-preparation-ipad-v1.c',R/'VirtualMac/scripts/development/build-owned-v2-preparation-ipad-v1.py']+[H/name for name in ['vm27_owned_startup_coordinator_v3.h','modern_xpc_original_instance_transport_v10.h','vm27_bundle_parent_inspection_v1.h','vm27_headless_checkin_v1.h','vm27_client_registration_v1.h','modern_xpc_large_private_consumer_v2.h','modern_xpc_large_bundle_registry.h','modern_xpc_approved_code.h','modern_xpc_lwcr_policy.h','modern_xpc_private_endpoint.h']]
    sourceBefore=[pin(p) for p in sourcePaths]
    for p in sourcePaths:(source/p.name).write_bytes(p.read_bytes())
    processes=[]
    def run(label,argv):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')};child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:stdout,stderr=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:child.kill();stdout,stderr=child.communicate();raise
        (out/(label+'.argv.json')).write_text(json.dumps(argv,indent=2)+'\n');(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr);(out/(label+'.exit')).write_text(str(child.returncode)+'\n');processes.append(dict(label=label,argv=argv,directChildPID=child.pid,observedWaitExit=child.returncode,reaped=True))
        assert child.returncode==0,(label,child.returncode,stderr.decode(errors='replace')[-2000:]);return stdout,stderr
    def sign(label,path,entitlements):
        run(label+'-sign',['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--identifier','com.virtualmac.diagnostics.owned-v3.'+label,'--entitlements',str(entitlements),str(path)])
        if label=='parent':clean_own_app_metadata(path,'post-sign')
        run(label+'-strict',['/usr/bin/codesign','--verify','--strict',str(path)])
    def clean_own_app_metadata(app,stage):
        # Only the fresh self-created .app: preserve provenance/fileprovider,
        # and never touch a source provider or a prior failed package.
        prefix='parent-xattr-'+stage
        run(prefix+'-before',['/usr/bin/xattr','-lr',str(app)])
        for attr in ['com.apple.FinderInfo','com.apple.ResourceFork']:
            run(prefix+'-remove-'+attr.rsplit('.',1)[-1],['/usr/bin/xattr','-dr',attr,str(app)])
        after=run(prefix+'-after',['/usr/bin/xattr','-lr',str(app)])[0]
        assert b'com.apple.FinderInfo:' not in after and b'com.apple.ResourceFork:' not in after
    libraries=[];oldPins=[]
    for name in NAMES:
        row=next(x for x in g['libraries'] if x['name']==name);original=Path(row['path']);assert pin(original)['sha256']==row['sha256'];copy=libs/name;copy.write_bytes(original.read_bytes());copy.chmod(0o600)
        if name in NEW:sign(name,copy,empty)
        else:assert original.read_bytes()==copy.read_bytes();oldPins.append(pin(original))
        cd=code_directory(copy);libraries.append(dict(name=name,**pin(copy),CDHash=cd['CDHash'],UUID=cd['UUID'],oldByteExactCopy=name not in NEW,resigned=name in NEW,source=pin(original),entitlements={} if name in NEW else None))
    pinsHeader=source/'owned_v3_preparation_pins.h'
    lines=['#include <stdint.h>','#define VM27_PREP_TITLE "'+TITLE+'"','typedef struct {const char *name,*SHA,*UUID;uint64_t bytes;} VM27PrepLibraryPin;','static const VM27PrepLibraryPin VM27PrepLibraryPins[10]={']
    lines += ['{"'+x['name']+'","'+x['sha256']+'","'+x['UUID']+'",'+str(x['bytes'])+'ULL},' for x in libraries];lines += ['};'];pinsHeader.write_text('\n'.join(lines)+'\n')
    app=package/'VM27OwnedPreparation.app';app.mkdir(mode=0o700)
    parentInfo={'CFBundleIdentifier':'com.virtualmac.diagnostics.owned-v3-preparation','CFBundleExecutable':'VM27OwnedPreparation','CFBundleName':TITLE,'CFBundleDisplayName':TITLE,'CFBundlePackageType':'APPL','CFBundleSupportedPlatforms':['iPhoneOS'],'MinimumOSVersion':'16.1','DTPlatformName':'iphoneos'}
    (app/'Info.plist').write_bytes(plistlib.dumps(parentInfo));(app/'Info.plist').chmod(0o600)
    bundle=package/'Owned.bundle';macos=bundle/'Contents/XPCServices/One.xpc/Contents/MacOS';macos.mkdir(mode=0o700,parents=True)
    for p in [bundle,bundle/'Contents',bundle/'Contents/XPCServices',bundle/'Contents/XPCServices/One.xpc',bundle/'Contents/XPCServices/One.xpc/Contents']:p.chmod(0o700)
    (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.virtualmac.diagnostics.owned-v3-services','CFBundleDisplayName':TITLE}));(bundle/'Contents/Info.plist').chmod(0o600)
    childInfo={'CFBundleIdentifier':'com.apple.Virtualization.VirtualMachine','CFBundleExecutable':'VM27OwnedPreparationChild','CFBundleDisplayName':TITLE,'CFBundleName':TITLE,'CFBundlePackageType':'XPC!'}
    childBundleInfo=source/'child-bundle-Info.plist';childBundleInfo.write_bytes(plistlib.dumps(childInfo));(macos.parent/'Info.plist').write_bytes(childBundleInfo.read_bytes());(macos.parent/'Info.plist').chmod(0o600)
    clang=run('clang-path',['/usr/bin/xcrun','--find','clang'])[0].decode().strip();sdk=run('ios-sdk',['/usr/bin/xcrun','--sdk','iphoneos','--show-sdk-path'])[0].decode().strip()
    macSDK=run('macos-sdk',['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'])[0].decode().strip()
    shapeTest=out/'refusal-shape-local-test'
    run('refusal-shape-local-compile',[clang,'-std=c11','-Wall','-Wextra','-Werror','-isysroot',macSDK,'-I',str(source),str(source/'test-owned-v3-refusal-cleanup-shape.c'),'-o',str(shapeTest)])
    run('refusal-shape-local-test',[str(shapeTest)])
    base=[clang,'-std=c11','-fblocks','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-O1','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-fptrauth-abi-version=0','-I',str(source),'-Wl,-no_adhoc_codesign']
    executables=[]
    for label,child,path,rpath in [('parent',False,app/'VM27OwnedPreparation','@loader_path/../libs'),('child',True,macos/'VM27OwnedPreparationChild','@loader_path/../../../../../../libs')]:
        # Sign child as a genuine standalone code-only object before exact-byte
        # placement in the registry tree; codesign may infer a surrounding XPC
        # bundle even when handed its nested executable pathname.
        signPath=path
        if child:
            standalone=out/'standalone-code-only';standalone.mkdir(mode=0o700)
            signPath=standalone/path.name
        run(label+'-compile',base+['-DVM27_PREP_CHILD='+str(int(child)),str(source/'test-owned-v3-preparation-ipad-v1.c')]+[str(libs/x) for x in NAMES]+['-framework','CoreFoundation','-Wl,-rpath,'+rpath,'-o',str(signPath)])
        signPath.chmod(0o700)
        if not child:clean_own_app_metadata(app,'pre-sign')
        sign(label,signPath if child else app,rightsFile)
        if child:
            path.write_bytes(signPath.read_bytes());path.chmod(0o700)
            assert pin(path)['sha256']==pin(signPath)['sha256']
        cd=code_directory(path);run(label+'-metadata',['/usr/bin/xcrun','dyld_info','-validate_only',str(path)])
        if child:assert 2*1024*1024<len(path.read_bytes())<=8*1024*1024 and not int(cd['slot1'],16) and not int(cd['slot3'],16)
        else:
            resources=app/'_CodeSignature/CodeResources';assert cd['slot1']==sha((app/'Info.plist').read_bytes()) and cd['slot3']==sha(resources.read_bytes()) and int(cd['slot1'],16) and int(cd['slot3'],16)
        executables.append(dict(role=label,**pin(path),CDHash=cd['CDHash'],UUID=cd['UUID'],entitlements=plistlib.loads(rights),codePages=cd['codePages'],externalInfoSlot=cd['slot1'],externalResourcesSlot=cd['slot3'],embeddedInfo=False,actualCFMainBundleRuntimeVerified=False,actualIOSExecution=False))
    for old in oldPins+sourceBefore:assert pin(Path(old['path']))==old
    newHashes=[dict(name=x['name'],path=x['path'],sha256=x['sha256'],CDHash=x['CDHash']) for x in libraries if not x['oldByteExactCopy']]+[dict(name=x['role'],path=x['path'],sha256=x['sha256'],CDHash=x['CDHash']) for x in executables]
    assert len(newHashes)==6
    parent=next(x for x in executables if x['role']=='parent');child=next(x for x in executables if x['role']=='child')
    codeByPath={x['path']:x for x in libraries+executables};ordered=[]
    for p in sorted(package.rglob('*')):
        if not p.is_file():continue
        row=codeByPath.get(str(p.resolve()))
        ordered.append(dict(sourcePath=str(p.resolve()),relativePath=str(p.relative_to(package)),mode='0700' if row and 'role' in row else '0600',**{k:v for k,v in pin(p).items() if k!='path'},CDHash=row['CDHash'] if row else None,kind=('old-byte-exact-DSO' if row.get('oldByteExactCopy',False) else 'new-signed-code') if row else 'data',ownerUID=0,regularLinkCount=1))
    timeoutEvidence=dict(parentHelloSeconds=3,childStopWaitSeconds=8,titleHelperReplySeconds=2,titleHelperLateReplySeconds=1,parentStopACKSeconds=3,strictRefusalCleanupACKSeconds=3,eachFinalINVALIDSeconds=2,eachSerialAsyncMarkerSeconds=2,V3StopServerFinalSeconds=2,naturalChildWNOHANGPollSeconds=3,postKillChildWNOHANGPollSeconds=2,childPollNapMilliseconds=10,blockingWaitCalled=False,asyncSignalKill=False,ownCPUHardSoftSeconds=5,eachProcessAdvisoryAlarmSeconds=15,advisoryExpirationForcesFinalFailure=True,alarmIsHardWall=False,nativeAPICallsPreemptedByAlarm=False,externalIsolatedProcessGroupWallSeconds=25,externalRunnerIncluded=False,externalRunnerMustIdentifyAndSuperviseOnlyOwnProcessGroup=True,failureKillScope='only sole main waiter: actual WNOHANG EAGAIN + direct PID match + unreaped; no other waiter or signal kill',drainTimeoutLifetime='retain pending markers, queue, connections and context until process exit; no Release on incomplete drain')
    manifest=dict(schema='Owned ordinary V3 iPad preparation signed package v1',builder=pin(Path(__file__)),sourceInputs=[pin(x) for x in sourcePaths],sourceSnapshots=[pin(x) for x in sorted(source.iterdir())],reusedGraphManifest=pin(GRAPH/'candidate.json'),reusedExactV8Entitlements=pin(RIGHTS),newEntitlementKeys=[],libraries=libraries,executables=executables,newSignedHashes=newHashes,oldSixLibraryInputs=oldPins,oldLibrariesResigned=False,newSigningCount=6,processes=processes,localPackage=pin(app/'Info.plist'),orderedPackageFiles=ordered,runtimeRootMustBeCanonicalAndNew=root,exactParentArgv=[root+'/VM27OwnedPreparation.app/VM27OwnedPreparation',root,parent['sha256'],parent['CDHash'],child['sha256'],child['CDHash'],'strict'],explicitApprovedDiagnosticRequiresLiteral='explicit-approved',noAutomaticModeFallback=True,strictRefusalExit=78,typedV2ConsumerIntegrated=True,strictRefusalCleanupHandshake=dict(requestMethod="VM27.owned-v3.refusal.v1",requestFields=["privateMethod","nonce","refusalStatus"],replyFields=["refusalStatus","nonce","cleanupOnly"],status=13,requiresActualPeerAuditCDAndCSValid=True,requiresStrictModeAndZeroRegistrationOrBind=True,requiresChildSendBarrierAndParentACK=True,cleanupCommitMethod="VM27.owned-v3.refusal-cleanup-commit.v1",cleanupCommitFields=["privateMethod","nonce","refusalStatus"],requiresParentActualACKValidationBeforeCleanupCommit=True,requiresChildReceivedCleanupCommitBeforeExit=True,grantsAuthorization=False,nativePolicyChanged=False),localRefusalShapeChecks=33,timeoutEvidence=timeoutEvidence,rootOwnership=0,requiredDirectoryMode='0700',requiredRegularLinkCount=1,symlinksAllowed=False,CPUSeconds=5,advisoryWallSeconds=15,externalHardWallSeconds=25,StartCalls=0,MainCalls=0,bindCalls=0,originalHandlerCalls=0,onlyOwnedNativeFinalINVALIDCallback=True,coordinatorPrepareCalledOnlyByOwnedChild=True,productionAppChanged=False,iOSExecuted=False,deviceOperations=False,trustcacheOperations=0,originalVMMExecuted=False,nativeCPUOperations=0,full27Ready=False,rootReviewBeforeDeviceRequired=True,ordinaryStrictNativeGateUnchanged=True,expectedEACCESMustBePreservedWithoutFallback=True)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]),indent=2)+'\n')
    print(json.dumps(dict(manifest=pin(out/'manifest.json'),freeze=pin(out/'freeze.json'),newHashes=newHashes,oldByteExactLibraries=6,iOSExecuted=False,deviceOperations=False)))
if __name__=='__main__':main()
