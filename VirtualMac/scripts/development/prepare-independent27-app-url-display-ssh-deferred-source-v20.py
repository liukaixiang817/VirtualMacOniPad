#!/usr/bin/env python3
"""Derive Main20: expose the selected VM display for a valid start URL; defer SSH."""
import argparse,copy,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
OLD=N/'independent27-app-owned-ssh-service-source-v19-attempt1/candidate.json'
def pin(p):
 p=pathlib.Path(p).resolve();raw=p.read_bytes();return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def exact(row):
 p=pathlib.Path(row['path']);assert pin(p)=={k:row[k]for k in('path','bytes','sha256')};return p
def once(text,a,b):
 assert text.count(a)==1,a[:100];return text.replace(a,b,1)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 assert pin(OLD)['sha256']=='5ade1523e683c0e6926c9ec3a9e4c32e82fccef37c6f0b5af5e15f70def5602b'
 old=json.loads(OLD.read_bytes());frozen={r['path']:r for r in json.loads((OLD.parent/'freeze.json').read_bytes())['files']}
 original=exact(old['source']);assert frozen[str(original)]==old['source'];before=original.read_text();text=before
 text=once(text,'static const BOOL kIndependent27FirstDisplaySSHDeferredV13 = NO;','static const BOOL kIndependent27FirstDisplaySSHDeferredV13 = YES;')
 old_url='''        controller.activeVMBundlePath = path;
        [controller activateVMDisplay:YES];
        printf("[Independent27] start-vm accepted path=%s; entering actual VM startup\\n", path.UTF8String);'''
 new_url='''        controller.activeVMBundlePath = path;
        controller.libraryNavigationController.view.hidden = YES;
        gInputView.hidden = NO;
        [controller activateVMDisplay:YES];
        printf("[Independent27] start-vm accepted path=%s; entering actual VM startup\\n", path.UTF8String);'''
 text=once(text,old_url,new_url)
 output=a.output.resolve();assert output.parent==N and not output.exists();output.mkdir(mode=0o700)
 source=output/'VirtualMacApp.independent27.url-display-ssh-deferred-source-v20.m';source.write_text(text)
 diff=output/'main19-to-main20.diff';diff.write_text(''.join(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile=str(original),tofile=str(source))))
 sdk=subprocess.run(['xcrun','--sdk','iphoneos','--show-sdk-path'],capture_output=True,check=True).stdout.decode().strip()
 argv=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',str(S),'-fsyntax-only',str(source)]
 result=subprocess.run(argv,capture_output=True);(output/'ios-syntax.stdout').write_bytes(result.stdout);(output/'ios-syntax.stderr').write_bytes(result.stderr)
 receipt=output/'ios-syntax-command.json';save(receipt,dict(argv=argv,exit=result.returncode,stdout=pin(output/'ios-syntax.stdout'),stderr=pin(output/'ios-syntax.stderr')))
 if result.returncode:save(output/'failure.json',dict(actualSyntax=pin(receipt),deviceOperations=0));raise SystemExit(result.returncode)
 candidate=copy.deepcopy(old);candidate.update(schema='Main20 valid URL display presentation and first basic guest boot SSH deferral source',source=pin(source),sourceDiff=pin(diff),baselineMain19=pin(OLD),baselineMain19Source=old['source'],actualIOSSyntax=pin(receipt),actualIOSSyntaxExit=0,preparer=pin(__file__),genuineSSHRegistrationRouteEnabled=False,sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,guestInstalled=False,actualSSHAuthenticated=False)
 candidate['urlDisplayPresentationContract']=dict(onlyValidatedIndependentStartVMURLBranchChanged=True,libraryViewHiddenBeforeActivateAndStart=True,inputViewUnhiddenBeforeActivateAndStart=True,mirrorsExistingVMLibraryBootDisplayFlags=True,originalPathValidationAndStartInvocationWholeUnchanged=True,noVMResumeBeforeVMConstruction=True,noRuntimeOwnershipOrCPUChanges=True,allOtherMain19SourceWholeUnchangedExceptSSHDeferralConstant=True,actualGuestFrameOrBootClaimed=False)
 candidate['ownedSSHService']['automaticallyInvokedAfterRealGuestStartedAndRegisteredBridge']=False
 candidate['ownedSSHService']['explicitlyDeferredUntilAfterBasicGuestBoot']=True
 candidate['futureGuestHelper']['automaticallyInvoked']=False
 candidate['futureGuestHelper']['explicitlyDeferredUntilAfterBasicGuestBoot']=True
 save(output/'candidate.json',candidate)
 files=[source,diff,receipt,output/'ios-syntax.stdout',output/'ios-syntax.stderr',output/'candidate.json',pathlib.Path(__file__),OLD,OLD.parent/'freeze.json',original]
 files += [exact(row)for row in old['ownedSSHService'].values()if isinstance(row,dict)and set(('path','bytes','sha256'))<=row.keys()]
 save(output/'freeze.json',dict(files=[pin(p)for p in files],deviceOperations=0,codeSigningOperations=0))
 print(json.dumps(dict(candidate=pin(output/'candidate.json'),freeze=pin(output/'freeze.json'),source=pin(source))))
if __name__=='__main__':main()
