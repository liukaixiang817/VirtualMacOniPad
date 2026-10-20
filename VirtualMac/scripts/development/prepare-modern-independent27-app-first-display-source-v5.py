#!/usr/bin/env python3
"""New copied experimental App profile: true zero NIC and zero audio devices.

The frozen App4 is read only. Actual disk/CPU/graphics/VZ owners are retained.
Networking/SSH and sound are deliberately absent from this finite experiment.
"""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();o=a.output.resolve();assert o.is_relative_to(N)and not o.exists();o.mkdir()
 parent=N/'independent27-app-source-finalization-v4/freeze.json'
 for row in json.loads(parent.read_bytes())['files']:assert pin(row['path'])==row,row['path']
 previous=N/'independent27-app-display-source-candidate-v4-attempt2/candidate.json';j=json.loads(previous.read_bytes());sourceOld=pathlib.Path(j['source']['path']);old=sourceOld.read_text();source=old
 for kind,selector in [('Audio','audioDevices'),('Network','networkDevices')]:
  marker='static void configure'+kind+'(id configuration, NSDictionary *options) {';assert source.count(marker)==1
  cap='Audio'if kind=='Audio'else'Network'
  body='''
    if (VZIndependent27SourceRouteSelected()) {
        // First-visible-boot experiment: persisted settings cannot cause an
        // unavailable host attachment to be constructed or selected here.
        setObj(configuration, "set'''+cap+'''Devices:", @[]);
        id actualDevices=((id(*)(id,SEL))objc_msgSend)(configuration,S("'''+selector+'''"));
        if (![actualDevices isKindOfClass:NSArray.class] || [actualDevices count]!=0)
            @throw [NSException exceptionWithName:@"VM27InvalidFirstDisplayProfile"
                reason:@"The actual '''+selector+''' array could not be cleared for this experiment." userInfo:nil];
        printf("[VirtualMac] independent27 first-display experiment actual '''+selector+'''=0; '''+('audio is deferred'if kind=='Audio'else'network and SSH are unavailable')+'''\\n");
        return;
    }
'''
  source=source.replace(marker,marker+body,1)
 sourceFile=o/'VirtualMacApp.independent27.first-display-source-v5.m';sourceFile.write_text(source)
 diff=o/'app-v4-to-v5.diff';diff.write_text(''.join(difflib.unified_diff(old.splitlines(True),source.splitlines(True),fromfile=str(sourceOld),tofile=str(sourceFile))))
 backend=pathlib.Path(j['backendSource']['path']);assert pin(backend)==j['backendSource']
 commands=[]
 def run(name,args):
  c=subprocess.run(list(map(str,args)),capture_output=True,timeout=90);(o/(name+'.stdout')).write_bytes(c.stdout);(o/(name+'.stderr')).write_bytes(c.stderr)
  commands.append(dict(label=name,argv=list(map(str,args)),exit=c.returncode));save(o/'commands.json',commands);assert c.returncode==0,(name,c.stderr.decode(errors='replace'));return c.stdout
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip();flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
 for tag,q in [('app',sourceFile),('backend',backend)]:
  run(tag+'-compile',flags+['-c',q,'-o',o/(tag+'.o')]);run(tag+'-ir',flags+['-S','-emit-llvm',q,'-o',o/(tag+'.ll')])
 llvm=(o/'app.ll').read_text();assert 'setNetworkDevices:'in llvm and 'setAudioDevices:'in llvm and 'first-display experiment actual'in llvm
 record=dict(schema='Copied independent27 first-visible-display App5 finite NIC0/audio0 source',source=pin(sourceFile),backendSource=pin(backend),sourceDiff=pin(diff),
  prior=pin(previous),sealedApp4Parent=pin(parent),builder=pin(pathlib.Path(__file__)),objects=[pin(o/(tag+'.o'))for tag in ('app','backend')],
  runtimeInterface=j['runtimeInterface'],firstVisibleBootExperiment=True,actualNetworkDevicesClearedAndCountChecked=True,
  actualAudioDevicesClearedAndCountChecked=True,userNATOrBridgeSettingsCannotChangeExperimentNIC0=True,
  networkingAvailable=False,guestSSHAvailable=False,soundAvailable=False,finalNetworkAndSSHStillRequired=True,
  actualDiskCPUAndGraphicsConfigurationInherited=True,actualQueueGetterUsed=True,actualVMRuntimeBoundBeforeStart=True,
  independentPackageSelectsOnly27=True,actualConfiguredRuntimeRootCanonicalized=True,oldVenturaHostHookExcludedFrom27Route=True,
  runtimeAdmissionAndSignedAnchorStillRequired=True,actualVZRuntimeExecuted=False,actualGuestDisplayObserved=False,
  applicationBinaryLinked=False,applicationPackaged=False,codeSigned=False,deviceOperations=0,guestBoot=False)
 save(o/'candidate.json',record);print(json.dumps(dict(candidate=pin(o/'candidate.json'),source=pin(sourceFile))))
if __name__=='__main__':main()
