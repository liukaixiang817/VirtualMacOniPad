#!/usr/bin/env python3
"""Join copied own UIKit source to the genuine value endpoint in an inert App source."""
import difflib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('app2_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=p.NODE/'independent27-app-input-source-candidate-v2';assert not out.exists()
    old=p.NODE/'independent27-app-input-source-candidate-v1';manifest=json.loads((old/'candidate.json').read_bytes())
    oldsource=Path(manifest['candidateAppSource']['path']);assert p.pin(oldsource)==manifest['candidateAppSource']
    prior=oldsource.read_text();source=prior
    for a,b in [('modern_independent_input_coordinator_v1.h','modern_independent_input_app_entry_v2.h'),
        ('VM27IndependentInputCoordinatorV1','VM27IndependentInputCoordinatorV2'),
        ('VM27IndependentInputEndpointV1','VM27IndependentInputEndpointV2'),
        ('VM27IndependentInputPlatformAvailabilityReasonV1','VM27IndependentInputPlatformAvailabilityReasonV2')]:
        assert a in source;source=source.replace(a,b)
    marker='''        epoch:epoch coordinates:coordinates error:error];
}''';assert source.count(marker)==1
    source=source.replace(marker,marker+'''
BOOL VZIndependent27ConnectGenuineInput(id pointing, id keyboard,
    id<VM27ProvenOwnInputExecutorV1> executor, uint64_t epoch,
    uint64_t coordinates, NSError **error) {
    if (!gIndependent27InputSurface || !gIndependent27InputCoordinator) return NO;
    CGRect bounds=gIndependent27InputSurface.bounds;
    VM27OwnUIKitIngressEndpointV1 *endpoint=nil;
    @try {
        endpoint=[[VM27OwnUIKitIngressEndpointV1 alloc] initWithPointingDevice:pointing
            keyboard:keyboard executor:executor epoch:epoch coordinates:coordinates
            viewport:(VM27InputViewportV1){bounds.origin.x,bounds.origin.y,
                                         bounds.size.width,bounds.size.height}];
    } @catch (NSException *exception) { (void)exception; }
    if (!endpoint) {
        if (error) *error=[NSError errorWithDomain:@"VirtualMac.Independent27Input" code:2
            userInfo:@{NSLocalizedDescriptionKey:@"Independent input validation is incomplete."}];
        return NO;
    }
    BOOL attached=VZIndependent27ConnectInput(endpoint,epoch,coordinates,error);
    [endpoint release];
    return attached;
}
VM27InputResult VZIndependent27CloseInput(void) {
    return gIndependent27InputCoordinator?[gIndependent27InputCoordinator close]:VM27InputClosed;
}''',1)
    marker='''    [gIndependent27InputCoordinator close];
    VZBackendEndRun();''';assert source.count(marker)==1
    source=source.replace(marker,'''    VM27InputResult stopped=VZIndependent27CloseInput();
    if (stopped!=VM27InputOK && stopped!=VM27InputClosed) {
        NSError *inputError=[NSError errorWithDomain:@"VirtualMac.Independent27Input" code:3
            userInfo:@{NSLocalizedDescriptionKey:@"Independent input could not stop safely."}];
        VZPresentFailureReport(self,VZL(@"Virtual Mac Stopped"),inputError.localizedDescription,
            inputError.debugDescription,VZFailureSupportOptionSuggestDebugLogging);
        return;
    }
    VZBackendEndRun();''',1)
    marker='''    [gIndependent27InputCoordinator close];
    [gIndependent27InputCoordinator release];
    gIndependent27InputCoordinator = nil;''';assert source.count(marker)==1
    source=source.replace(marker,'''    VM27InputResult stopped=VZIndependent27CloseInput();
    if (stopped==VM27InputOK || stopped==VM27InputClosed) {
        [gIndependent27InputCoordinator release];
        gIndependent27InputCoordinator = nil;
    }
    // A failed join keeps the globally owned endpoint alive. Its actual VM
    // owner receives the typed close failure; dealloc cannot report success.''',1)
    out.mkdir();file=out/'VirtualMacApp.independent27.source-candidate.m';file.write_text(source)
    (out/'source-v1-to-v2.diff').write_text(''.join(difflib.unified_diff(prior.splitlines(True),source.splitlines(True),fromfile=str(oldsource),tofile=str(file))))
    production=[p.pin(HOST/name)for name in ('VirtualMacApp.m','VZBackendSelection.m')]+[p.pin(p.ROOT/'VirtualMac/scripts/build-ipad-app.sh')]
    runs=[]
    def run(label,args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        runs.append(dict(label=label,argv=args,exit=r.returncode));p.save(out/'commands.json',runs);assert r.returncode==0,(label,r.stderr.decode());return r
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
    flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-fblocks','-O2','-I',HOST]
    run('compile-app',flags+['-c',file,'-o',out/'candidate-app.o'])
    run('compile-app-ir',flags+['-S','-emit-llvm',file,'-o',out/'candidate-app.ll'])
    assert production==[p.pin(HOST/name)for name in ('VirtualMacApp.m','VZBackendSelection.m')]+[p.pin(p.ROOT/'VirtualMac/scripts/build-ipad-app.sh')]
    assert 'VZIndependent27ConnectGenuineInput'in (out/'candidate-app.ll').read_text()
    p.save(out/'candidate.json',dict(schema='Independent27 copied own UIKit genuine value App source integration v2',priorAppSource=p.pin(old/'candidate.json'),
        candidateAppSource=p.pin(file),sourceDiff=p.pin(out/'source-v1-to-v2.diff'),actualSourceEntry=p.pin(HOST/'modern_independent_input_app_entry_v2.h'),
        genuineIngressSource=p.pin(p.NODE/'own-uikit-genuine-input-ingress-source-build-v1/candidate.json'),productionInputPins=production,
        directGenuineDeviceExecutorInputAttachmentImplemented=True,typedCloseFailureBeforeVMReleaseImplemented=True,
        failedJoinEndpointRetained=True,ownCopiedInputCoordinatorV2Connected=True,legacy27WorkerRejected=True,
        productionAppSourceModified=False,applicationBinaryLinked=False,applicationPackaged=False,
        actualBackendExecutorProvided=False,originalVZSendersExecuted=False,actualUIKitRuntimeValidated=False,
        backendAvailabilityGatePreserved=True,sourcePlatformAdmissionGateClosed=True,codeSigned=False,readyWritten=False,
        deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
    pins=production+[p.pin(Path(__file__)),p.pin(HOST/'modern_independent_input_app_entry_v2.h')]
    for directory in (old,p.NODE/'own-uikit-genuine-input-ingress-source-build-v1'):
        for row in json.loads((directory/'freeze.json').read_bytes())['files']:assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(directory/'freeze.json'))
    pins += [p.pin(path)for path in out.iterdir()if path.is_file()]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),source=p.pin(file))))
if __name__=='__main__':main()
