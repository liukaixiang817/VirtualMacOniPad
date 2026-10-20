#!/usr/bin/env python3
"""Derive the future Main19 from frozen Main18 and genuine QGA7. HOST only."""
import argparse,copy,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
MAIN=N/'independent27-app-future-ssh-source-v18-attempt1/candidate.json'
QGA=N/'guest-persistent-ssh-qga-source-v7-attempt1/candidate.json'
def pin(p):
    p=pathlib.Path(p).resolve();raw=p.read_bytes()
    return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def exact(row):
    p=pathlib.Path(row['path']);assert pin(p)=={k:row[k]for k in('path','bytes','sha256')};return p
def replace_once(text,before,after):
    assert text.count(before)==1,before[:80]
    return text.replace(before,after,1)

LOGGER=r'''
static void VZIndependent27LogSSHServiceV19(const char *phase,BOOL success,
                                          BOOL sameOwner,NSData *output)
{
    NSUInteger count=MIN(output.length,(NSUInteger)2048);
    NSData *prefix=count ? [output subdataWithRange:NSMakeRange(0,count)] : [NSData data];
    NSString *text=[[[NSString alloc] initWithData:prefix encoding:NSUTF8StringEncoding] autorelease];
    text=[[text stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"]
        stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
    printf("[Independent27SSHService] actual-%s success=%d sameOwner=%d outputBytes=%lu outputTruncated=%d guestSSHAuthenticated=0 output=%s\n",
        phase,success,sameOwner,(unsigned long)output.length,output.length>count,
        text.UTF8String ?: "(empty-or-non-UTF8)");
}
'''

CLOSE=r'''    if (gIndependent27SSHServiceVMV19) {
        gIndependent27OwnerClosePending=YES;
        id retainedOwner=[self retain];
        NSError *retainedError=[(error ?: gIndependent27DisplayFailure) retain];
        id retainedVM=[gIndependent27SSHServiceVMV19 retain];
        uint64_t retainedEpoch=gIndependent27SSHServiceEpochV19;
        void (^finishService)(BOOL,NSData *)=^(BOOL success,NSData *output) {
            NSCAssert(pthread_main_np(),@"Owned SSH service completes on actual main VM.queue.");
            BOOL sameOwner=gIndependent27SSHServiceVMV19==retainedVM &&
                gIndependent27SSHServiceEpochV19==retainedEpoch && gVirtualMachine==retainedVM;
            VZIndependent27LogSSHServiceV19("cleanup",success,sameOwner,output);
            gIndependent27OwnerClosePending=NO;
            if (!success || !sameOwner) {
                VZPresentFailureReport(retainedOwner,VZL(@"Virtual Mac Stopped"),
                    @"The owned SSH service cleanup is unproven. The actual VM remains retained.",
                    nil,VZFailureSupportOptionSuggestDebugLogging);
            } else {
                [gIndependent27SSHServiceVMV19 release];gIndependent27SSHServiceVMV19=nil;
                gIndependent27SSHServiceStartPendingV19=NO;
                [retainedOwner finishVMAndShowLibraryWithError:retainedError];
            }
            [retainedVM release];[retainedError release];[retainedOwner release];
        };
        @try {
            if (gVirtualMachine!=retainedVM || ![retainedVM respondsToSelector:S("state")]) {
                finishService(NO,[@"Exact actual service VM identity/state unavailable; no guest cleanup submitted."
                    dataUsingEncoding:NSUTF8StringEncoding]);
            } else {
                NSInteger actualState=((NSInteger(*)(id,SEL))objc_msgSend)(retainedVM,S("state"));
                if (actualState==0) {
                    // The provider independently checks the original native state IMP.
                    // Ended runtime is not a claim that launchd bootout/PID exit was observed.
                    VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2(retainedVM,finishService);
                } else if (actualState==1) {
                    VZGuestToolsStopOwnedSSHServiceV2(retainedVM,finishService);
                } else {
                    finishService(NO,[@"Actual service VM is paused or in an unknown transition; owner retained."
                        dataUsingEncoding:NSUTF8StringEncoding]);
                }
            }
        } @catch (NSException *exception) {
            NSString *detail=[NSString stringWithFormat:@"Actual service cleanup submission raised %@; owner retained.",exception.name];
            finishService(NO,[detail dataUsingEncoding:NSUTF8StringEncoding]);
        }
        return;
    }
'''

START=r'''                if (gIndependent27OwnerClosePending || gIndependent27SSHServiceVMV19 ||
                    gIndependent27SSHServiceStartPendingV19 || gIndependent27SSHServiceEpochV19==UINT64_MAX) {
                    printf("[Independent27SSHService] start not submitted: prior owner/pending cleanup or exhausted epoch; guest display continues; guestSSHAuthenticated=0\n");
                } else {
                    id requestedVM=gVirtualMachine;
                    gIndependent27SSHServiceVMV19=[requestedVM retain];
                    uint64_t requestedEpoch=++gIndependent27SSHServiceEpochV19;
                    gIndependent27SSHServiceStartPendingV19=YES;
                    // QGA7 waits for real guest-info/idle and owns every real socket operation.
                    VZGuestToolsStartOwnedSSHServiceV2(requestedVM,^(BOOL success,NSData *output) {
                        NSCAssert(pthread_main_np(),@"Owned SSH service start completes on actual main VM.queue.");
                        BOOL sameOwner=gIndependent27SSHServiceVMV19==requestedVM &&
                            gIndependent27SSHServiceEpochV19==requestedEpoch && gVirtualMachine==requestedVM;
                        if (sameOwner)gIndependent27SSHServiceStartPendingV19=NO;
                        VZIndependent27LogSSHServiceV19("start",success,sameOwner,output);
                        // Failure does not stop CPU/display; retain possible service ownership until cleanup.
                    });
                }
'''

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
    assert pin(MAIN)['sha256']=='b8094580d80d9023e2dda397ac91e8ad315fc5452ab2c9e7fa7364c9220fea77'
    assert pin(QGA)['sha256']=='9bc2f4d585993782a29ee28f544698c7ff3078cd14faa668e6875cc65f353816'
    old=json.loads(MAIN.read_bytes());qga=json.loads(QGA.read_bytes())
    for p,c,keys in ((MAIN,old,('source',)),(QGA,qga,('source','header','leaseObject','signedHelper'))):
        frozen={x['path']:x for x in json.loads((p.parent/'freeze.json').read_bytes())['files']}
        for key in keys:
            row=c[key];exact(row);assert frozen.get(row['path'])==row
    assert qga['liveStopNativeRunningGateAdded'] is True
    assert qga['newTypedAPIs']==['VZGuestToolsStartOwnedSSHServiceV2','VZGuestToolsStopOwnedSSHServiceV2','VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2']
    original=exact(old['source']);text=original.read_text()
    text=replace_once(text,'#import "VZGuestTools.h"','#import "'+pathlib.Path(qga['header']['path']).name+'"')
    text=replace_once(text,'static BOOL gIndependent27SSHRegisteredV18;','''static BOOL gIndependent27SSHRegisteredV18;
static id gIndependent27SSHServiceVMV19;
static uint64_t gIndependent27SSHServiceEpochV19;
static BOOL gIndependent27SSHServiceStartPendingV19;''')
    text=replace_once(text,'static void VZIndependent27PollActualSSHBridge(void);',
        'static void VZIndependent27PollActualSSHBridge(void);\n'+LOGGER)
    text=replace_once(text,'actual queue drain completed; VM release may proceed',
        'actual bridge queue drain completed; service cleanup must precede VM release')
    text=replace_once(text,'    if (gIndependent27InputQueueV3 || gIndependent27GuestDisplay) {',
        CLOSE+'    if (gIndependent27InputQueueV3 || gIndependent27GuestDisplay) {')
    anchor='''                gIndependent27SSHStarted=YES;
                VZIndependent27PollActualSSHBridge();'''
    text=replace_once(text,anchor,anchor+'\n'+START)
    output=a.output.resolve();assert output.parent==N and not output.exists();output.mkdir(mode=0o700)
    source=output/'VirtualMacApp.independent27.owned-ssh-service-source-v19.m';source.write_text(text)
    diff=output/'main18-to-main19.diff';diff.write_text(''.join(difflib.unified_diff(original.read_text().splitlines(True),text.splitlines(True),fromfile=str(original),tofile=str(source))))
    sdk=subprocess.run(['xcrun','--sdk','iphoneos','--show-sdk-path'],capture_output=True,check=True).stdout.decode().strip()
    command=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',str(S),'-fsyntax-only',str(source)]
    result=subprocess.run(command,capture_output=True);(output/'ios-syntax.stdout').write_bytes(result.stdout);(output/'ios-syntax.stderr').write_bytes(result.stderr)
    receipt=output/'ios-syntax-command.json';save(receipt,dict(argv=command,exit=result.returncode,stdout=pin(output/'ios-syntax.stdout'),stderr=pin(output/'ios-syntax.stderr')))
    if result.returncode:save(output/'failure.json',dict(actualSyntax=pin(receipt),deviceOperations=0));raise SystemExit(result.returncode)
    candidate=copy.deepcopy(old);candidate.update(schema='Future Main19 genuine QGA7 persistent SSH service integration source',source=pin(source),sourceDiff=pin(diff),baselineMain18=pin(MAIN),baselineMain18Source=old['source'],actualIOSSyntax=pin(receipt),actualIOSSyntaxExit=0,preparer=pin(__file__),genuineSSHRegistrationRouteEnabled=True,sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=False,persistentSSHServiceStartIntegrated=True,genuineRuntimeGuestStartedRequiredBeforeServiceStart=True,genuineRegisteredBridgeRequiredBeforeServiceStart=True,actualQGAReadyAndSocketLeaseAdmissionOwnedByProvider=True,serviceOwnerExactVMAndMonotonicEpoch=True,bridgeDrainBeforeServiceCleanupBeforeInputDisplayVMRelease=True,stoppedRuntimeInvalidationNotJobBootoutOrPIDExitClaim=True,cleanupFailureRetainsVMOwner=True,guestInstalled=False,actualSSHAuthenticated=False)
    candidate['ownedSSHService']=dict(sourceCandidate=pin(QGA),source=qga['source'],header=qga['header'],leaseObject=qga['leaseObject'],signedResource=qga['signedHelper'],APIs=qga['newTypedAPIs'],serviceContract=qga['serviceContract'],fullGuestToolsTranslationUnitReplacementRequired=True,automaticallyInvokedAfterRealGuestStartedAndRegisteredBridge=True,actualGuestServiceExecuted=False,actualSSHAuthenticated=False)
    candidate['futureGuestHelper']=dict(sourceCandidate=pin(QGA),signedResource=qga['signedHelper'],requiredConnectionLeaseObject=qga['leaseObject'],automaticallyInvoked=True,integratedIntoThisMain=True,guestInstalled=False,persistentServiceHandoffImplementedInSource=True,actualPersistentServiceHandoffVerified=False,actualSSHAuthenticated=False)
    cp=output/'candidate.json';save(cp,candidate)
    files=[source,diff,receipt,output/'ios-syntax.stdout',output/'ios-syntax.stderr',cp,pathlib.Path(__file__),MAIN,MAIN.parent/'freeze.json',original,QGA,QGA.parent/'freeze.json']+[exact(qga[k])for k in('source','header','leaseObject','signedHelper')]
    save(output/'freeze.json',dict(files=[pin(p)for p in files],deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(cp),freeze=pin(output/'freeze.json'),source=pin(source))))
if __name__=='__main__':main()
