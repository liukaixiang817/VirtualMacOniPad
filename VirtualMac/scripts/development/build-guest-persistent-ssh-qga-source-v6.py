#!/usr/bin/env python3
"""HOST-only QGA6 source compilation and fixed-script parsing; no guest job execution."""
import argparse,hashlib,json,pathlib,plistlib,re,subprocess,difflib
R=pathlib.Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host'
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def dump(p,value):p.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
def need(ok,message):
 if not ok:raise RuntimeError(message)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve()
 need(out.parent==N and out.is_dir() and not (out/'candidate.json').exists(),'own existing HOST script input directory; never overwrite candidate')
 previous=N/'guest-active-vsock-ssh-qga-source-v5-attempt1/candidate.json';prior=json.loads(previous.read_bytes())
 for row in prior['sourceFiles']:
  need(pin(row['path'])==row,'frozen QGA5 source preserved')
 helper=prior['signedHelper'];need(pin(helper['path'])==helper,'same genuine signed guest helper')
 lease=prior['leaseObject'];need(pin(lease['path'])==lease,'same genuine original lease object')
 source=S/'VZGuestTools_owned_active_ssh_v6.m';header=S/'VZGuestTools_owned_active_ssh_v6.h'
 scripts=S/'vm27_owned_ssh_service_scripts_v2.inc';body=scripts.read_text()
 constants={name:json.loads(value) for name,value in re.findall(r'static const char (\w+)\[\] = ("(?:[^"\\]|\\.)*");',body)}
 need(len(constants)==4,'four actual fixed source constants')
 expected={'prepare.sh':constants['VM27OwnedSSHPrepareV2'],'install-start.sh':constants['VM27OwnedSSHInstallStartV2'],'stop-template.sh':constants['VM27OwnedSSHStopTemplateV2']}
 for name,text in expected.items():need((out/name).read_bytes()==text.encode(),'actual source literal equals script '+name)
 plist=constants['VM27OwnedSSHJobPlistV2'].encode();need((out/'service.plist').read_bytes()==plist,'actual fixed plist literal')
 job=plistlib.loads(plist);need(job['UserName']=='lkx' and job['KeepAlive'] is False and job['RunAtLoad'] is False and job['ProgramArguments'][1:] == ['--serve-v1'],'fixed non-restarting own job, original helper')
 commands=[]
 def run(label,argv):
  p=subprocess.run(argv,capture_output=True,timeout=45);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
  row=dict(argv=list(map(str,argv)),exit=p.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr')));commands.append(row)
  need(p.returncode==0,'actual HOST command failed '+label+': '+p.stderr.decode(errors='replace')[:1000]);return row
 common=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot','/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.1.sdk','-O2','-fblocks','-fvisibility=hidden','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',str(S)]
 obj=out/'VZGuestTools_owned_active_ssh_v6.o';ios=run('ios-qga6-compile',common+['-c',str(source),'-o',str(obj)])
 caller=out/'typed-api-caller.mm';caller.write_text('#import "VZGuestTools_owned_active_ssh_v6.h"\nusing API=void(*)(id,void(^)(BOOL,NSData*));\nAPI typedStart=VZGuestToolsStartOwnedSSHServiceV2;\nAPI typedStop=VZGuestToolsStopOwnedSSHServiceV2;\nAPI typedEnded=VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2;\n')
 typedObj=out/'typed-api-caller.o';typed=run('typed-three-api',common+['-std=c++17','-c',str(caller),'-o',str(typedObj)])
 names=run('typed-unmangled-imports',['nm','-uj',str(typedObj)]);text=pathlib.Path(names['stdout']['path']).read_text()
 newAPIs=['VZGuestToolsStartOwnedSSHServiceV2','VZGuestToolsStopOwnedSSHServiceV2','VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2']
 need(all('_'+x in text.splitlines() for x in newAPIs),'new APIs have actual unmangled C linkage')
 component=out/'VM27OwnedQGAPersistentComponentV6.dylib'
 link=run('ios-component-link',common+['-dynamiclib',str(obj),lease['path'],'-framework','Foundation','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-install_name,@rpath/VM27OwnedQGAPersistentComponentV6.dylib','-o',str(component)])
 validate=run('ios-component-validate',['xcrun','dyld_info','-validate_only',str(component)])
 exports=run('actual-component-exports',['xcrun','dyld_info','-exports',str(component)])
 exportText=pathlib.Path(exports['stdout']['path']).read_text();need(all('_'+x in exportText for x in newAPIs),'three actual exported APIs')
 syntax=[]
 for name,text in expected.items():
  if name=='stop-template.sh':text=text.replace('@PID@','42').replace('@UID@','502').replace('@START@','0123456789abcdef'*4)
  actual=out/(name+'.parser-only.sh');actual.write_text(text)
  record=run(name+'-syntax',['/bin/sh','-n',str(actual)]);syntax.append(dict(script=pin(out/name),actualParserInput=pin(actual),receipt=record,guestExecuted=False))
 (out/'v5-to-v6.diff').write_text(''.join(difflib.unified_diff(pathlib.Path(prior['source']['path']).read_text().splitlines(True),source.read_text().splitlines(True),fromfile=prior['source']['path'],tofile=str(source))))
 apiContract=dict(start=newAPIs[0],stop=newAPIs[1],invalidateAfterNativeStop=newAPIs[2],signature='void(id actualVM, void (^)(BOOL success, NSData *output))',completionQueue='actual main VM.queue',actualRunningStateRequired=1,actualNativeStoppedStateRequired=0,rejectPausedUnknownAndDifferentVM=True,nativeStateAndQueueIMPFromOriginalVZImage=True,pointerAuthenticationStrippedOnlyForImageInspection=True,readyWaitSeconds=120,actualOperationLeaseSeconds=45,actualEpochGenerationAndSocketIdentityRequired=True,exclusiveServiceRetainsExactVM=True,liveStopRequiresActualCapturedPIDUIDPPID1PathStartAndFixedJobOff=True,stoppedInvalidationClaims=dict(guestRuntimeEnded=True,jobBootoutVerified=False,capturedPIDExitVerified=False),uncertainNativeQGACleanupRemainsSticky=True)
 plan=dict(schema='Future integration only; QGA6 source is not installed',replaceProductionTU='VZGuestTools.m at original TU8; never append duplicate definitions',replacementSource=pin(source),header=pin(header),additionalLinkedObject=lease,resource=helper,resourceRelativePath='GuestTools/vm27-guest-vsock-ssh-signed-v1',resourceOwnerMode='501:501:0600;nlink1',main19Required=True,guestStartedAndOriginalBridgeRegisteredBeforeStart=True,actualQGAReadyRequired=True,stopOrder='bridge real drain; whileRunning exact Stop, nativeStopped exact Invalidate; then original Reset and VM release only on completion success',startSuccessMeaning='actual captured own launchd PID/UID/PPID1/path/start; no bridge/SSH authentication claim',Mac22222ForwardLeaseAndAuthenticatedSSHStillRequired=True,actualInvoked=False,integrated=False,persistentServiceHandoff=False,deviceOperations=0,guestOperations=0)
 dump(out/'integration-plan.json',plan)
 # Retain the already observed tool result; these27 checks are not rerun.
 observed='[GuestTools] owned SSH retains the earlier actual VM; another Attach is refused\n[GuestTools] owned SSH actual QGA connection replaced; captured service/VM owner retained\n[GuestTools] owned SSH QGA connection reset/replaced; captured service and actual VM stay retained\nOwned SSH service V2: 27 finite HOST delta checks passed; QGA/SDK/guest not executed\n'
 (out/'finite-service-delta-observed-tool-output.txt').write_text(observed)
 finite=dict(actualExitCode=0,actualExecSession=26643,captureKind='actual exec_command/write_stdin output retained without rerun',checks=27,scope='new parser/actual socketpair identity/Attach conflict/Reset retention/real deadline; no SDK/QGA/guest execution',nativeStoppedGateAddedAfterTheseChecks=True,nativeStoppedGateNotExecuted=True,testSource=pin(S/'test-vm27-owned-ssh-service-v2.m'),actualPreviouslyTestedBinary=pin(out/'finite-service-delta'),observedOutput=pin(out/'finite-service-delta-observed-tool-output.txt'))
 dump(out/'finite-host-observation.json',finite)
 dump(out/'commands.json',dict(commands=commands,deviceOperations=0,guestOperations=0))
 sourceFiles=[source,header,S/'vm27_owned_ssh_service_v2.inc',scripts,S/'vm27_owned_qga_operation_v5.inc',S/'vm27_owned_qga_connection_lease_v3.h',S/'vm27_guest_active_ssh_artifact_v1.h']
 candidate=dict(schema='HOST-only QGA6 fixed persistent guest SSH service source',status='HELD_NOT_INTEGRATED_OR_EXECUTED',source=pin(source),header=pin(header),sourceFiles=[pin(x)for x in sourceFiles],builder=pin(__file__),inheritedSourceCandidate=pin(previous),inheritedSourceFreeze=pin(previous.parent/'freeze.json'),newTypedAPIs=newAPIs,serviceContract=apiContract,job=pin(out/'service.plist'),scripts=syntax,iosCompile=ios,typedHeaderCompile=typed,component=pin(component),componentStrictLink=link,componentValidate=validate,actualExportReport=exports,leaseObject=lease,signedHelper=helper,finiteHOSTObservation=pin(out/'finite-host-observation.json'),integrationPlan=pin(out/'integration-plan.json'),originalHelperAndSessionIdle600000WholeUnchanged=True,old300sDiagnosticStillSeparate=True,legacyDiagnosticAndPersistentOwnerMutuallyExclusive=True,actualInvoked=False,integrated=False,persistentServiceHandoff=False,actualGuestJobExecuted=False,actualSSHAuthenticated=False,deviceOperations=0,guestOperations=0,codeSigningOperations=0,trustCacheAdditions=0)
 dump(out/'candidate.json',candidate)
 files=[pin(x)for x in sorted(out.iterdir()) if x.is_file()]+[pin(x)for x in sourceFiles]+[pin(__file__),pin(previous),pin(previous.parent/'freeze.json'),lease,helper,prior['signedHelperCandidate']]
 dump(out/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0,guestOperations=0,codeSigningOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),header=pin(header),source=pin(source))))
if __name__=='__main__':main()
