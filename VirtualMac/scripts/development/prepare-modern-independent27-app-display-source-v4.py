#!/usr/bin/env python3
"""Add the real retained runtime VM binding to the sealed copied App3."""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 parent=N/'independent27-app-source-finalization-v3/freeze.json'
 for row in json.loads(parent.read_bytes())['files']:assert pin(pathlib.Path(row['path']))==row
 old=N/'independent27-app-display-source-candidate-v3-attempt3/candidate.json';j=json.loads(old.read_bytes())
 sourceOld=pathlib.Path(j['source']['path']);sourcePrior=sourceOld.read_text();source=sourcePrior
 marker='''    printf("[VirtualMac] VM runtime constructed=%p\\n", gVirtualMachine);'''
 assert source.count(marker)==1
 source=source.replace(marker,marker+'''
    if (VZIndependent27SourceRouteSelected()) {
        NSError *bindingError=nil;
        dispatch_queue_t actualQueue=((dispatch_queue_t(*)(id,SEL))objc_msgSend)(
            gVirtualMachine,S("queue"));
        if (actualQueue!=dispatch_get_main_queue() ||
            !VM27IndependentAppRuntimeBindGuestV1(gVirtualMachine,actualQueue,&bindingError)) {
            finishVMThreadSafe(delegate,bindingError ?: [NSError errorWithDomain:@"VirtualMac.Independent27"
                code:7 userInfo:@{NSLocalizedDescriptionKey:@"The actual VM could not bind to its independent runtime queue."}]);
            return;
        }
    }''',1)
 sourceFile=o/'VirtualMacApp.independent27.display-source-v4.m';sourceFile.write_text(source)
 diff=o/'app-v3-to-v4.diff';diff.write_text(''.join(difflib.unified_diff(sourcePrior.splitlines(True),source.splitlines(True),fromfile=str(sourceOld),tofile=str(sourceFile))))
 backendOld=pathlib.Path(j['backendSource']['path']);backendPrior=backendOld.read_text();backend=backendPrior
 start=backend.index('NSString *VZBackendSelectedVersion(void) {');end=backend.index('\nNSString *VZBackendLoadedVersion',start)
 backend=backend[:start]+'''NSString *VZBackendSelectedVersion(void) {
    // This separate copied package owns only its independently checked graph.
    return @"27";
}
'''+backend[end:]
 marker='''NSString *VZBackendAvailabilityReason(NSString *version) {''';assert backend.count(marker)==1
 backend=backend.replace(marker,marker+'''
    if ([version isEqualToString:@"13.2.1"])
        return @"This independent package contains only the macOS 27 backend.";''',1)
 marker='''BOOL VZBackendSelectVersion(NSString *version, NSError **error) {''';assert backend.count(marker)==1
 backend=backend.replace(marker,marker+'''
    if (![version isEqualToString:@"27"]) {
        if (error) *error=backendError(@"This independent package supports only its validated macOS 27 graph.");
        return NO;
    }''',1)
 # NSBundle/Info paths may use /var while the runtime requires the actual
 # canonical /private/var directory. Resolve only this copied backend's
 # trusted configured root; the runtime still checks every anchored file.
 marker='''#import "vm27_independent_app_runtime_v1.h"''';assert backend.count(marker)==1
 backend=backend.replace(marker,marker+'\n#include <limits.h>\n#include <stdlib.h>',1)
 start=backend.index('static NSString *rootForVersion(NSString *version) {')
 end=backend.index('\nNSString *VZBackendRuntimeRoot',start)
 backend=backend[:start]+'''static NSString *actualRuntimeRootV4(NSString *requested) {
    NSString *standardized=[requested stringByStandardizingPath];
    char canonical[PATH_MAX];
    if (realpath(standardized.fileSystemRepresentation,canonical))
        return [NSString stringWithUTF8String:canonical];
    // Missing/unreadable paths remain subject to the runtime's true admission.
    return [standardized stringByResolvingSymlinksInPath];
}

static NSString *rootForVersion(NSString *version) {
    if ([version isEqualToString:@"13.2.1"])
        return actualRuntimeRootV4(baseRuntimeRoot());
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"VirtualMac27RuntimeRoot"];
    if ([value isKindOfClass:NSString.class] && [value hasPrefix:@"/"] &&
        [value length] > 1) return actualRuntimeRootV4(value);
    return actualRuntimeRootV4([baseRuntimeRoot() stringByAppendingPathComponent:@"backends/macos27"]);
}
'''+backend[end:]
 backendFile=o/'VZBackendSelection.independent27.v4.m';backendFile.write_text(backend)
 backendDiff=o/'backend-v3-to-v4.diff';backendDiff.write_text(''.join(difflib.unified_diff(backendPrior.splitlines(True),backend.splitlines(True),fromfile=str(backendOld),tofile=str(backendFile))))
 header=S/'vm27_independent_app_runtime_v1.h';assert 'VM27IndependentAppRuntimeBindGuestV1' in header.read_text()
 commands=[]
 def run(name,argv):
  cp=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
  (o/(name+'.stdout')).write_bytes(cp.stdout);(o/(name+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(name=name,argv=list(map(str,argv)),exit=cp.returncode));save(o/'commands.json',commands)
  assert cp.returncode==0,(name,cp.stderr.decode(errors='replace'));return cp
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
 for name,f in [('app',sourceFile),('backend',backendFile)]:
  run('compile-'+name,flags+['-c',f,'-o',o/(name+'.o')])
  run('ir-'+name,flags+['-S','-emit-llvm',f,'-o',o/(name+'.ll')])
 assert 'VM27IndependentAppRuntimeBindGuestV1' in (o/'app.ll').read_text()
 save(o/'candidate.json',dict(schema='Copied independent27 App4 real runtime VM binding source',
  source=pin(sourceFile),backendSource=pin(backendFile),sourceDiff=pin(diff),backendSourceDiff=pin(backendDiff),
  prior=pin(old),sealedApp3Parent=pin(parent),builder=pin(pathlib.Path(__file__)),
  objects=[pin(o/(name+'.o'))for name in ('app','backend')],runtimeInterface=pin(header),
  actualQueueGetterUsed=True,actualVMRuntimeBoundBeforeStart=True,
  actualStateGetterRequiredByGuestStartedProvider=True,independentPackageSelectsOnly27=True,
  actualConfiguredRuntimeRootCanonicalized=True,runtimeFilesStillIndependentlyValidated=True,
  actualGraphPreflightAdmissionStillRequired=True,oldVenturaHostHookExcludedFrom27Route=True,
  applicationBinaryLinked=False,applicationPackaged=False,codeSigned=False,
  actualUIKitRuntimeValidated=False,actualGuestDisplayObserved=False,deviceOperations=0,full27Backend=False))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),source=pin(sourceFile))))
if __name__=='__main__':main()
