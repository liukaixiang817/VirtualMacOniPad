import pathlib,json,hashlib,copy,subprocess,shutil
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();raw=p.read_bytes();return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def exact(p):
 assert pin(p['path'])==p;return pathlib.Path(p['path'])
oldp=N/'independent27-actual-app-gic-owner-input-recovery-v192-attempt1/candidate.json';old=json.loads(oldp.read_text())
for row in old['sourceFiles']+old['objects']+old['appFiles']+old['actualIncludeClosure']:exact(row)
signedBaseline=json.loads((N/'independent27-signed-app-gic-owner-input-recovery-v192-attempt1/candidate.json').read_text())
for row in signedBaseline['appFiles']:exact(row)
o=N/'independent27-actual-app-disconnect-recovery-v196-attempt1';o.mkdir(mode=0o700);(o/'objects').mkdir();app=o/'VirtualMacIndependent27.app';shutil.copytree(pathlib.Path(signedBaseline['app']),app);binary=app/'VirtualMacIndependent27'
sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects']);commands=[]
def run(label,args):
 p=subprocess.run(args,capture_output=True,timeout=90);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));(o/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert p.returncode==0,p.stderr.decode()
sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
for i,name in ((0,"VirtualMacApp_independent_disconnect_recovery_v50.m"),):
 source=S/name;obj=o/'objects'/f'{i}-{source.stem}.o';dep=o/f'{i}.d';cxx=source.suffix=='.mm'
 args=['xcrun','clang++' if cxx else 'clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',str(S)]
 if source.suffix!='.c':args+=['-fno-objc-arc' if i==0 else '-fobjc-arc']
 if cxx:args+=['-std=c++17']
 args+=['-c',str(source),'-o',str(obj),'-MMD','-MF',str(dep)]
 run(f'compile-{i}',args);sources[i]=pin(source);objects[i]=pin(obj)
link=next(c for c in old['commands'] if c['label']=='link-app' and c['exit']==0);argv=list(link['argv'])
rtp=N/'independent27-signed-runtime-gic-owner-snapshots-v134-attempt1/candidate.json';rt=json.loads(rtp.read_text());sources[34]=rt['anchorSource'];objects[34]=rt['anchorIOSObject'];exact(sources[34]);exact(objects[34])
for i in (0,34):
 assert argv.count(old['objects'][i]['path'])==1;argv[argv.index(old['objects'][i]['path'])]=objects[i]['path']
argv[argv.index(old['binary']['path'])]=str(binary)
run('link-app',argv);run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
closure=[pin(S/'vm27_broken_pipe_policy_v2.h')]+list(old['actualIncludeClosure'])+[pin(S/'modern_input_packet_v3_buttons.h'),pin(S/'vm27_own_uikit_ingress_values_v2_buttons.h')]
a=copy.deepcopy(old);oldkey=a['mainSourceContractKey'];a['historicalApp187AtomicPinsContract']=a.pop(oldkey);key='disconnectRecoveryRuntime134Contract'
a.update(schema='Actual App196 Main50 process-local broken pipe recovery Runtime134 CPU77 GIC13 Surface12',builder=pin(__file__),inheritedCompiledAppCandidate=pin(oldp),sourceFiles=sources,objects=objects,binary=pin(binary),appFiles=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()],actualIncludeClosure=closure,commands=commands,actualChangedAppObjectIndices=[0],actualUnchangedCompiledObjects=37,actualNewAppCompilations=1,actualOnlyMainObjectChanged=False,actualMainSourceChanged=True,mainSourceContractKey=key,codeSigned=False,applicationBinaryLinked=True,applicationPackaged=True,deviceOperations=0,trustCacheOperations=0)
a[key]=dict(actualRuntime134=pin(rtp),ownerOnlyIRQSnapshotsWithCompleteMutationInvalidation=True,atomicCallbackPinsAndControllerLastRelease=True,concreteGIC9PhysicalRouteDeadlinePin=True,allGenericBindingsAndBoundaryGuardsWhole=True,actualMain46PauseClipboardWhole=True,actualGuestTools23RelativeClockWhole=True,ownerExecutingRunDoesNotWakeItself=True,exactFiniteFieldClosure4=True,actualMultiScrollSurface8Whole=True,actualOwnedScalarRead4=True,actualGICEnabledIndex7=True,actualLatestPendingMotionPreserved=True,actualFullContextMapping32KiB=True,actualSecondaryAndAuxiliaryButtonMask=True,actualPointerContactEndReleasesEvenIfMaskNonzero=True,directContactNotEatenByStationaryIndirectTouch=True,actualNativeReleaseBeforeDirectHandover=True,actualPointerQueueVariantPreservesPacketByteLayout=True,actualStableOwnerMetadataCPU=True,actualCPUVersionFastPath=True,Main39Runtime5AndPersistentSSHWhole=True,realCursorUpdateNotDiscarded=True,copiedGuestBGRAImage=True,actualHotspotAndPosition=True,callbackReceiptUptimeForPhysicalHover=True,noSyntheticCursorShape=True,noGuestPreferenceWrites=True,actualPhysicalButtonHeldHoverMoves=True,actualAllInputReceiptClock=True,actualUIKitHostPointerHiddenInGuestOnly=True,nativeFixedDisplayIntervalRemoved=True,allInputObjectsWholeApp155=True,oneInFlightRealCATransactionAndPerFrameACKPreserved=True,CPUCopyFallback100msUnchanged=True,deviceVerified=False)
a.update(actualRuntimeCandidate=pin(rtp),actualRuntime115AndAnchorJoined=False,actualRuntime116AndAnchorJoined=False,actualRuntime117AndAnchorJoined=False,actualRuntime118AndAnchorJoined=False,actualRuntime119AndAnchorJoined=False,actualRuntime120AndAnchorJoined=False,actualRuntime121AndAnchorJoined=False,actualRuntime122AndAnchorJoined=False,actualRuntime123AndAnchorJoined=False,actualRuntime124AndAnchorJoined=False,actualRuntime125AndAnchorJoined=False,actualRuntime126AndAnchorJoined=False,actualRuntime127AndAnchorJoined=False,actualRuntime128AndAnchorJoined=False,actualRuntime129AndAnchorJoined=False,actualRuntime130AndAnchorJoined=False,actualRuntime131AndAnchorJoined=False,actualRuntime132AndAnchorJoined=False,actualRuntime133AndAnchorJoined=False,actualRuntime134AndAnchorJoined=True)
(o/'candidate.json').write_text(json.dumps(a,indent=2)+'\n');files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(oldp),*sources,*objects,*closure];(o/'freeze.json').write_text(json.dumps(dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(o/'candidate.json'),objectChanges=[0])))
