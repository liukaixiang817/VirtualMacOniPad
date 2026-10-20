#!/usr/bin/env python3
"""HOST-only minimal DisplayV3 constructor diagnostics; frozen App13/Main13 unchanged."""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 assert pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},r['path'];return pathlib.Path(r['path'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();o=a.output.resolve();assert o.parent==N and not o.exists()
 cp=N/'independent27-actual-app-first-basic-boot-v13-attempt1/candidate.json';c=json.loads(cp.read_bytes());old=exact(c['sourceFiles'][16]);oldtext=old.read_text()
 before='''    if(!(self=[super initWithFrame:frame]))return nil;
    _device=MTLCreateSystemDefaultDevice();_commands=[_device newCommandQueue];
    if(!_device || !_commands)return nil;
'''
 after='''    const void *allocatedIdentityV3=(__bridge const void *)self;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=enter pid=%d self=%p class=%s main=%d\\n",
        (int)getpid(),allocatedIdentityV3,class_getName(object_getClass(self)),(int)NSThread.isMainThread);
    self=[super initWithFrame:frame];
    Class superResultClassV3=self?object_getClass(self):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=super-result allocation=%p self=%p class=%s image=%s\\n",
        allocatedIdentityV3,(__bridge void *)self,superResultClassV3?class_getName(superResultClassV3):"(nil)",
        superResultClassV3 && class_getImageName(superResultClassV3)?class_getImageName(superResultClassV3):"(none)");
    if(!self) {
        fprintf(stderr,"[Independent27DisplayCtorV3] failed=super-init nil=1 pid=%d\\n",(int)getpid());
        return nil;
    }
    _device=MTLCreateSystemDefaultDevice();
    Class deviceClassV3=_device?object_getClass(_device):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=device result=%p class=%s image=%s\\n",
        (__bridge void *)_device,deviceClassV3?class_getName(deviceClassV3):"(nil)",
        deviceClassV3 && class_getImageName(deviceClassV3)?class_getImageName(deviceClassV3):"(none)");
    _commands=[_device newCommandQueue];
    Class commandClassV3=_commands?object_getClass(_commands):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=queue result=%p class=%s image=%s\\n",
        (__bridge void *)_commands,commandClassV3?class_getName(commandClassV3):"(nil)",
        commandClassV3 && class_getImageName(commandClassV3)?class_getImageName(commandClassV3):"(none)");
    if(!_device || !_commands) {
        fprintf(stderr,"[Independent27DisplayCtorV3] failed=%s nil=1\\n",!_device?"native-default-device":"native-command-queue");
        return nil;
    }
'''
 assert oldtext.count(before)==1;newtext=oldtext.replace(before,after,1);source=S/'vm27_uikit_guest_display_v3.mm'
 if source.exists():assert source.read_text()==newtext
 else:source.write_text(newtext)
 assert newtext[:newtext.index('@interface VM27UIKitMetalDisplayV1')]==oldtext[:oldtext.index('@interface VM27UIKitMetalDisplayV1')]
 assert newtext[newtext.index('    _gpuGroup=dispatch_group_create();'):]==oldtext[oldtext.index('    _gpuGroup=dispatch_group_create();'):]
 assert newtext.count('MTLCreateSystemDefaultDevice()')==oldtext.count('MTLCreateSystemDefaultDevice()')==1
 assert newtext.count('_commands=[_device newCommandQueue];')==oldtext.count('_commands=[_device newCommandQueue];')==1
 o.mkdir(mode=0o700);(o/'display-v2-to-v3.diff').write_text(''.join(difflib.unified_diff(oldtext.splitlines(True),newtext.splitlines(True),fromfile=str(old),tofile=str(source))))
 argv=next(r['argv']for r in c['commands']if r['label']=='compile-16');argv=[str(source)if x==str(old)else x for x in argv];argv[argv.index('-o')+1]=str(o/'DisplayV3.o')
 commands=[]
 def run(label,args):
  r=subprocess.run(args,capture_output=True);(o/(label+'.stdout')).write_bytes(r.stdout);(o/(label+'.stderr')).write_bytes(r.stderr);commands.append(dict(label=label,argv=args,exit=r.returncode));assert r.returncode==0,(label,r.stderr.decode());return r.stdout
 run('actual-ios-arm64e-arc',argv)
 nmnew=run('new-undefined',['xcrun','nm','-u',str(o/'DisplayV3.o')]);nmold=run('old-undefined',['xcrun','nm','-u',str(exact(c['objects'][16]))]);assert nmnew==nmold
 record=dict(schema='HOST DisplayV3 actual constructor diagnostics source candidate',source=pin(source),priorSource=pin(old),builder=pin(__file__),priorActualApp13Candidate=pin(cp),actualIOSObject=pin(o/'DisplayV3.o'),actualCompileCommands=commands,sourceDiff=pin(o/'display-v2-to-v3.diff'),actualMain13SourceUnchanged=c['sourceFiles'][0],actualRuntime5AndFactory2AttestationPrefixWholeUnchanged=True,actualMetalAndObserverAndGPUCleanupSuffixWholeUnchanged=True,superDefaultDeviceAndCommandQueueActualPointerClassImageLogs=True,allNativeDeviceAndQueueCallsRemainOnce=True,originalNilAndARCAndOwnershipBehaviorPreserved=True,actualUndefinedSymbolsWholeSameAsPriorObject=True,requestedActualChangedAppObjectIndices=[16],actualApplicationLinked=False,codeSigningOperations=0,deviceOperations=0,actualNilCauseUnknown=True,actualNativeMetalProviderNotAssumedBroken=True,originalFramebufferOnlyAndBlitBehaviorUnchanged=True,actualGuestDisplay=False,actualCPUStarted=False)
 (o/'candidate.json').write_text(json.dumps(record,indent=2)+'\n');rows=[pin(p)for p in o.iterdir()if p.is_file()]+[pin(__file__),pin(source),pin(old),pin(cp),pin(cp.parent/'freeze.json'),c['sourceFiles'][0],c['sourceFiles'][32],c['objects'][16]]
 (o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),source=pin(source))))
if __name__=='__main__':main()
