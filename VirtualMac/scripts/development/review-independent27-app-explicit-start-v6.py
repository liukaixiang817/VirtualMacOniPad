#!/usr/bin/env python3
"""Finite frozen App6 entry review, including the real main-thread wait."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
checks=0
def need(v,m):
 global checks;checks+=1
 if not v:raise ValueError(m)
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def line(text,term):
 at=text.index(term);return text.count('\n',0,at)+1
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve()
 need(out.parent==N and not out.exists(),'fresh independent review')
 folder=N/'independent27-app-explicit-start-source-v6-attempt2';candidate=folder/'candidate.json';freeze=folder/'freeze.json'
 j=json.loads(candidate.read_bytes());pins=json.loads(freeze.read_bytes())['files']
 for q in pins:need(pin(q['path'])==q,'actual App6 immutable source or compiler pin')
 source=Path(j['source']['path']);text=source.read_text();need(pin(source)==j['source'],'exact App6 source')
 runtime=R/'VirtualMac/vz/host/vm27_independent_app_runtime_v3.m';startup=R/'VirtualMac/vz/host/vm27_owned_app_child_startup_v1.c'
 rtext=runtime.read_text();stext=startup.read_text()
 need('if (!VZIndependent27SourceRouteSelected())\n         VZContinueAfterRootHideInformation(controller, nil);' in text,'launch RootHide continuation excluded')
 start=text.index('if (VZIndependent27SourceRouteSelected()) {\n        // This independent package admits explicit actions only.')
 end=text.index('    requestMicrophoneAccess(^{',start)
 gate=text[start:end];need('[controller presentVMLibrary];' in gate and 'return YES;' in gate,'true library launch returns before global autoboot/visible install consumer')
 url_start=text.index('- (BOOL)application:(UIApplication *)application openURL:')
 url=text[url_start:]
 need('CFBundleURLTypes' in url and 'CFBundleURLSchemes' in url and 'if (!ownScheme) return NO;' in url,'actual package URL scheme validated')
 need('!pthread_main_np()' in url and 'components.user.length' in url and 'components.password.length' in url and 'components.port' in url and 'components.fragment' in url and 'gVirtualMachine || VZBackendIsRunActive()' in url,'actual URL and existing active VM guard')
 begin=url.index('if ([@"runtime-startup" isEqualToString:action])');stop=url.index('NSArray<NSURLQueryItem *> *items',begin)
 action=url[begin:stop]
 need('components.queryItems.count' in action and 'VM27IndependentAppRuntimeLoadV1' in action and 'errorDomain=%s errorCode=%ld error=%s' in action,'real typed runtime startup and error output')
 need('startVirtualMachine(' not in action and 'NEW(' not in action and 'VM27IndependentAppRuntimeBindGuestV1(' not in action,'runtime-startup App code does not construct or start a VM')
 need('items.count == 1' in url and '@"path"' in url and 'VZIsValidVMBundle(path)' in url and 'startVirtualMachine(controller.view, controller, path, VZVMOptionsForBundle(path));' in url,'explicit start uses actual validated VM bundle and existing VM flow')
 need('setNetworkDevices:' in text and 'setAudioDevices:' in text and j['actualNetworkDevicesClearedAndCountChecked'] and j['actualAudioDevicesClearedAndCountChecked'],'first display NIC0/audio0 profile retained')
 need('dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))' in stext,'actual ParentStart blocking wait up to twenty seconds')
 need('actualStart(&config,&RetainedParentV3)' in rtext,'actual Runtime3 calls that real ParentStart')
 need('BOOL loaded = VM27IndependentAppRuntimeLoadV1(VZRuntimeRoot(), &runtimeError);' in action,'main openURL directly enters actual wait')
 need('NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 14 &&' in text and '    startVirtualMachineWorker(container, delegate, bundlePath, runtimeOptions);' in text,'actual iPadOS16 start-vm retains synchronous worker route')
 inherited=R/'VirtualMac/vz/host/vm27_independent_app_runtime_v1.m';base=inherited.read_text()
 load=base[base.index('BOOL VM27IndependentAppRuntimeLoadV1('):base.index('BOOL VM27IndependentAppRuntimeBindGuestV1(')]
 need('pthread_main_np()' not in load,'loader has no source main-thread admission rule')
 bind=R/'VirtualMac/vz/host/vm27_independent_app_runtime_v2.m'
 need('if(!pthread_main_np() || queue!=dispatch_get_main_queue())' in bind.read_text(),'actual BindGuest must retain genuine VM main queue')
 finding=dict(priority=1,title='Real child bootstrap blocks UIKit main for up to twenty seconds',source=pin(source),line=line(text,'BOOL loaded = VM27IndependentAppRuntimeLoadV1(VZRuntimeRoot(), &runtimeError);'),actualWaitSource=pin(startup),actualWaitLine=line(stext,'dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))'),secondTrigger='start-vm URL/main library action -> startVirtualMachine -> iPadOS16 synchronous worker -> loadExtractedFrameworks -> same Runtime3 ParentStart',requiredChange='Run graph load and ParentStart on one private serial bootstrap queue, return promptly from the UIApplication action, hold a main-owned busy admission flag across both explicit actions and real library start, return completion to actual main VM control before configuration/BindGuest/input/display; retain real failed startup owner and require a fresh App process rather than automatically retrying.',actualDeviceWatchdogObserved=False)
 out.mkdir(mode=0o700)
 record=dict(schema='Independent App6 explicit-entry and main-wait source review v1',finiteLocalSourceReviewCompleted=True,finiteLocalScopePassed=False,findings=[finding],checks=checks,candidate=pin(candidate),inputFreeze=pin(freeze),verifiedFrozenPins=len(pins),source=pin(source),explicitLibraryLaunchGlobalAutobootBypassVerified=True,launchRootHideContinuationExcluded=True,actualURLSchemeAndBundleAdmissionVerified=True,actualTypedRuntimeStartupVerified=True,runtimeStartupAppCodeCreatesOrStartsVM=False,explicitStartUsesActualVMFlow=True,actualVMMainQueueMustRemain=True,bootstrapLoaderSourceMainThreadRequirement=False,sourceBuildAlreadyCompletedByOwner=True,fullAppSignedSizeOrDeviceExecutionVerified=False,deviceOperations=0,nativeOperations=0,trustCacheOperations=0,guestBoot=False)
 (out/'review.json').write_text(json.dumps(record,indent=2)+'\n')
 files=[candidate,freeze,source,runtime,startup,inherited,bind,Path(__file__).resolve(),out/'review.json']
 (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in files]),indent=2)+'\n')
 print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=1)))
if __name__=='__main__':main()
