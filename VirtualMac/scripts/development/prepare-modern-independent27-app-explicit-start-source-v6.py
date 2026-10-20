#!/usr/bin/env python3
"""Copy App5 into an explicit-launch App6; never change the frozen parent."""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def replace_once(source,old,new):
 assert source.count(old)==1,old
 return source.replace(old,new,1)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True)
 a=ap.parse_args();o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 previous=N/'independent27-app-first-display-source-v5-attempt1/candidate.json'
 assert pin(previous)['sha256']=='6e1eddca2c240e38da636bf6b1732095f0840c67df501f731a5179da57ec1e50'
 j=json.loads(previous.read_bytes());sourceOld=pathlib.Path(j['source']['path']);backend=pathlib.Path(j['backendSource']['path'])
 assert pin(sourceOld)==j['source'] and pin(backend)==j['backendSource']
 old=sourceOld.read_text();source=old
 source=replace_once(source,'    VZContinueAfterRootHideInformation(controller, nil);',
 '''    if (!VZIndependent27SourceRouteSelected())
         VZContinueAfterRootHideInformation(controller, nil);''')
 source=replace_once(source,'    unlink("/tmp/virtual-mac-vm-active");\n    gMouseLocation = CGPointMake(CGRectGetMidX(inputView.bounds),',
 '''    if (!VZIndependent27SourceRouteSelected())
         unlink("/tmp/virtual-mac-vm-active");
    gMouseLocation = CGPointMake(CGRectGetMidX(inputView.bounds),''')
 marker='    printf("[VirtualMac] VM picker ready inputWindow=%p\\n", inputView.window);\n    requestMicrophoneAccess(^{'
 source=replace_once(source,marker,'''    printf("[VirtualMac] VM picker ready inputWindow=%p\\n", inputView.window);
    if (VZIndependent27SourceRouteSelected()) {
        // This independent package admits explicit actions only. The older
        // global auto-boot and visible-install requests belong to their owner.
        [controller presentVMLibrary];
        printf("[Independent27] explicit launch ready; library visible; no automatic VM start\\n");
        fflush(stdout);
        return YES;
    }
    requestMicrophoneAccess(^{''')
 marker='    NSString *action = url.host.lowercaseString;\n'
 source=replace_once(source,marker,'''    NSString *action = url.host.lowercaseString;
    if (VZIndependent27SourceRouteSelected() &&
        ([@"runtime-startup" isEqualToString:action] ||
         [@"start-vm" isEqualToString:action])) {
        NSURLComponents *components = [NSURLComponents componentsWithURL:url
                                                  resolvingAgainstBaseURL:NO];
        if (!pthread_main_np() || !components || components.user.length ||
            components.password.length || components.port || components.fragment ||
            components.path.length || gVirtualMachine || VZBackendIsRunActive()) {
            printf("[Independent27] explicit action rejected: invalid URL, wrong queue, or active VM owner\\n");
            fflush(stdout);
            return NO;
        }
        if ([@"runtime-startup" isEqualToString:action]) {
            if (components.queryItems.count) return NO;
            NSError *runtimeError = nil;
            printf("[Independent27] runtime-startup begin root=%s\\n", VZRuntimeRoot().UTF8String);
            fflush(stdout);
            // Genuine Runtime3 bootstrap only. No VM configuration, VM object,
            // BindGuest, or startVirtualMachine is called by this action.
            BOOL loaded = VM27IndependentAppRuntimeLoadV1(VZRuntimeRoot(), &runtimeError);
            printf("[Independent27] runtime-startup result=%d errorDomain=%s errorCode=%ld error=%s\\n",
                loaded, runtimeError.domain.UTF8String ?: "", (long)runtimeError.code,
                runtimeError.description.UTF8String ?: "");
            fflush(stdout);
            return loaded;
        }
        NSArray<NSURLQueryItem *> *items = components.queryItems;
        NSString *path = items.count == 1 && [items[0].name isEqualToString:@"path"]
            ? items[0].value : nil;
        if (!path.length || ![path hasPrefix:@"/"] ||
            [path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound ||
            !VZIsValidVMBundle(path) ||
            ![self.window.rootViewController isKindOfClass:VZViewController.class]) {
            printf("[Independent27] start-vm rejected: invalid bundle path or UI owner\\n");
            fflush(stdout);
            return NO;
        }
        VZViewController *controller = (VZViewController *)self.window.rootViewController;
        controller.activeVMBundlePath = path;
        [controller activateVMDisplay:YES];
        printf("[Independent27] start-vm accepted path=%s; entering actual VM startup\\n", path.UTF8String);
        fflush(stdout);
        startVirtualMachine(controller.view, controller, path, VZVMOptionsForBundle(path));
        // Acceptance is not a successful guest boot. Existing original VM
        // completion and state handling reports the actual startup result.
        return YES;
    }
''')
 sourceFile=o/'VirtualMacApp.independent27.explicit-start-source-v6.m';sourceFile.write_text(source)
 diff=o/'app-v5-to-v6.diff';diff.write_text(''.join(difflib.unified_diff(old.splitlines(True),source.splitlines(True),fromfile=str(sourceOld),tofile=str(sourceFile))))
 commands=[]
 def run(label,args):
  c=subprocess.run(list(map(str,args)),capture_output=True,timeout=90)
  (o/(label+'.stdout')).write_bytes(c.stdout);(o/(label+'.stderr')).write_bytes(c.stderr)
  commands.append(dict(label=label,argv=list(map(str,args)),exit=c.returncode));save(o/'commands.json',commands)
  assert c.returncode==0,(label,c.stderr.decode(errors='replace'));return c.stdout
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
 includes={}
 for tag,q in [('app',sourceFile),('backend',backend)]:
  run(tag+'-compile',flags+['-c',q,'-o',o/(tag+'.o')])
  run(tag+'-ir',flags+['-S','-emit-llvm',q,'-o',o/(tag+'.ll')])
  import shlex
  deps=run(tag+'-deps',flags+['-MM',q]).decode().replace('\\\n',' ').split(':',1)[1]
  for item in shlex.split(deps):
   p=pathlib.Path(item).resolve()
   if p.is_file():includes[str(p)]=pin(p)
 llvm=(o/'app.ll').read_text()
 assert 'runtime-startup result=' in llvm and 'start-vm accepted' in llvm and 'no automatic VM start' in llvm
 assert pin(sourceOld)==j['source'] and pin(backend)==j['backendSource']
 record=dict(j)
 record.update(schema='Copied independent27 App6 explicit library launch and genuine runtime/guest actions',
  source=pin(sourceFile),backendSource=pin(backend),sourceDiff=pin(diff),prior=pin(previous),
  builder=pin(pathlib.Path(__file__)),packageBuilder=pin(R/'VirtualMac/scripts/development/build-independent27-copied-app-v6.py'),
  objects=[pin(o/(tag+'.o'))for tag in ('app','backend')],actualIncludeClosure=list(includes.values()),
  explicitIndependent27Launch=True,launchPresentsActualLibrary=True,globalAutoBootNotConsumed=True,
  automaticVisibleInstallNotConsumed=True,launchRootHideContinuationExcluded=True,
  runtimeStartupAction='runtime-startup',startVMAction='start-vm',runtimeStartupReportsActualTypedError=True,
  runtimeStartupAppCodeCreatesVM=False,runtimeStartupAppCodeStartsGuest=False,
  runtimeStartupOriginalInitializersAndChildMainExecuted=False,
  explicitStartValidatesActualBundle=True,explicitStartRejectsActiveOwner=True,
  explicitStartUsesExistingActualVMFlow=True,requiredOwnScheme='virtualmac27',
  codeSigned=False,deviceOperations=0,guestBoot=False)
 save(o/'candidate.json',record)
 files={str(p):pin(p)for p in o.rglob('*')if p.is_file()}
 for row in includes.values():files[row['path']]=row
 for row in [pin(previous),pin(backend),pin(pathlib.Path(__file__)),record['packageBuilder']]:files[row['path']]=row
 save(o/'freeze.json',dict(schema='App6 explicit launch source freeze',files=sorted(files.values(),key=lambda row:row['path']),
  frozenApp5Modified=False,sourceCompiledForActualIOS=True,fullAppLinkStillRequired=True,deviceOperations=0))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),source=pin(sourceFile))))
if __name__=='__main__':main()
