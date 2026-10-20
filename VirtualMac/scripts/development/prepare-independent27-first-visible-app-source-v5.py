"""Make an explicit first-display App from frozen App4, preserving the full goal.

The staged App requires zero NICs, audio and video-codec devices. This is a
boot/display milestone; it does not advertise networking or final usability.
"""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 d=a.output.resolve();need(d.is_relative_to(N) and not d.exists(),'fresh output');d.mkdir()
 prior=N/'independent27-app-source-finalization-v4/finalization.json'
 need(pin(prior)['sha256']=='627dc34702af9d6acbabaea33fd33a6f2f63aeede46e68ee1cb37c13f7eeb6c6','frozen App4')
 final=json.loads(prior.read_bytes());sourceManifest=pathlib.Path(final['sourceCandidate']['path'])
 need(pin(sourceManifest)==final['sourceCandidate'],'source manifest unchanged');old=json.loads(sourceManifest.read_bytes())
 sourceOld=pathlib.Path(old['source']['path']);backend=pathlib.Path(old['backendSource']['path'])
 need(pin(sourceOld)==old['source'] and pin(backend)==old['backendSource'],'actual frozen sources')
 previous=sourceOld.read_text();source=previous
 stages=[('configureNetwork','setNetworkDevices:','Network',
    'Networking is deferred in this explicit first-visible-boot package; final guest SSH remains required.'),
   ('configureAudio','setAudioDevices:','Audio','Audio is deferred while CPU, disk, input and display boot are validated.')]
 for name,setter,label,reason in stages:
  marker='static void '+name+'(id configuration, NSDictionary *options) {'
  need(source.count(marker)==1,'exact configuration function')
  code='''
    if (VZIndependent27SourceRouteSelected()) {
        // %s
        setObj(configuration, "%s", @[]);
        printf("[VirtualMac27] first-visible-boot stage: %s devices=0\\n");
        return;
    }
'''%(reason,setter,label.lower())
  source=source.replace(marker,marker+code,1)
 marker='static void configureVideoToolbox(id configuration, NSDictionary *options) {'
 need(source.count(marker)==1,'exact codec configuration')
 source=source.replace(marker,marker+'''
    if (VZIndependent27SourceRouteSelected()) {
        // Host codec acceleration is optional for the first real display boot.
        printf("[VirtualMac27] first-visible-boot stage: host video codecs deferred\\n");
        return;
    }
''',1)
 marker='''    printf("[VirtualMac] validating VM configuration\\n");'''
 need(source.count(marker)==1,'actual pre-validation gate')
 source=source.replace(marker,'''
    if (VZIndependent27SourceRouteSelected()) {
        NSArray *actualNICs=m0(configuration,"networkDevices");
        NSArray *actualAudio=m0(configuration,"audioDevices");
        if (![actualNICs isKindOfClass:NSArray.class] || actualNICs.count ||
            ![actualAudio isKindOfClass:NSArray.class] || actualAudio.count) {
            NSError *stageError=[NSError errorWithDomain:@"VirtualMac.FirstVisible27"
                code:1 userInfo:@{NSLocalizedDescriptionKey:
                    @"The first display boot requires its disabled optional devices."}];
            finishVMThreadSafe(delegate,stageError);return;
        }
    }
'''+marker,1)
 p=d/'VirtualMacApp.independent27.first-visible-source-v5.m';p.write_text(source)
 diff=d/'app-v4-to-first-visible-v5.diff';diff.write_text(''.join(difflib.unified_diff(previous.splitlines(True),source.splitlines(True),fromfile=str(sourceOld),tofile=str(p))))
 commands=[]
 def run(label,argv):
  cp=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90)
  (d/(label+'.stdout')).write_bytes(cp.stdout);(d/(label+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(label=label,argv=list(map(str,argv)),status=cp.returncode));(d/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  need(cp.returncode==0,label+' '+cp.stderr.decode(errors='replace'));return cp.stdout
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
 run('compile-app',flags+['-c',p,'-o',d/'app.o'])
 run('ir-app',flags+['-S','-emit-llvm',p,'-o',d/'app.ll'])
 need(pin(sourceOld)==old['source'] and pin(backend)==old['backendSource'],'no frozen source edits')
 result=dict(schema='Explicit first-visible independent27 App5 stage source',source=pin(p),backendSource=pin(backend),
  prior=pin(sourceManifest),frozenApp4=pin(prior),sourceDiff=pin(diff),builder=pin(__file__),
  actualIOSAppCompilePassed=True,actualOptionalDeviceArrayAdmissionBeforeValidation=True,
  fixedNICCount=0,fixedAudioDeviceCount=0,hostVideoCodecConfigurationDeferred=True,
  CPUAndDiskAndInputAndActualDisplayPathsInheritedUnchanged=True,
  soleCPUBackendIsOriginal27WithOwnedRoot16=True,old13FallbackUsed=False,
  networkingImplemented=False,guestSSHVerified=False,finalUserGoalSatisfied=False,
  actualProductLinked=False,productAnchorGenerated=False,deviceOperations=0,guestBoot=False,
  futureImplementation=['Actual Ethernet FD attachment and network stack with guest SSH relay.',
   'Host audio input/output and optional host video-codec acceleration after main boot/display.'])
 (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
 rows=[pin(x)for x in sorted(d.rglob('*'))if x.is_file()]+[pin(sourceOld),pin(backend),pin(prior),pin(sourceManifest),pin(__file__)]
 (d/'freeze.json').write_text(json.dumps(dict(candidate=pin(d/'candidate.json'),pins=rows),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(d/'candidate.json'),freeze=pin(d/'freeze.json'),source=pin(p))))
if __name__=='__main__':main()
