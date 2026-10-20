#!/usr/bin/env python3
"""Compile/link/package the copied App, using real runtime and genuine SSH provider sources.

The output must be new. It never runs the production build/sign/device script.
Components can be compiled while the owned queue/runtime provider is finalized.
Final linking uses strong symbols; unavailable provider functions are not stubs.
"""
import argparse,hashlib,json,pathlib,plistlib,shutil,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True)
 ap.add_argument('--source-candidate',type=pathlib.Path,required=True)
 ap.add_argument('--runtime-source',type=pathlib.Path,action='append',default=[])
 ap.add_argument('--runtime-provider-library',type=pathlib.Path,action='append',default=[])
 ap.add_argument('--own-input-profile-source',type=pathlib.Path,required=True)
 ap.add_argument('--basic-input-surface-source',type=pathlib.Path,required=True)
 ap.add_argument('--uikit-guest-display-source',type=pathlib.Path,required=True)
 ap.add_argument('--runtime-root');ap.add_argument('--components-only',action='store_true');a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir();objectsDir=o/'objects';objectsDir.mkdir()
 manifest=json.loads(a.source_candidate.read_bytes())
 assert manifest['sourceChangesOnlyActualStartErrorDiagnostics'] is True
 assert manifest['originalStartErrorObjectJudgmentQueueAndCleanupWholeUnchanged'] is True
 assert manifest['actualStartErrorFailureMarker']=='[Independent27] start-vm rejected: actual-start-error'
 for key in ('source','backendSource'):
  assert pin(pathlib.Path(manifest[key]['path']))==manifest[key]
 assert manifest['trueSSHRegistrationAfterRuntimeBindBeforeStart'] is False
 assert manifest['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True
 assert manifest['selectedIndependent27FirstDisplaySSHDeferred'] is True
 assert manifest['runtimeGuestStartedActualStateAdmissionPreserved'] is True
 assert manifest['actualRuntimeBindQueueAndFactoryCallsWholeUnchanged'] is True
 assert manifest['actualCPUDisplayInputAndGuestConfigurationWholeUnchanged'] is True
 assert manifest['existingSSHOwnerDrainAndFailureRetentionWholeUnchanged'] is True
 assert manifest['genuineSSHBridgeIncludedAsDormantFutureCode'] is True
 assert manifest['finalNetworkAndSSHStillRequired'] is True
 assert manifest['fakeProtocolOrClassAdded'] is False and manifest['fakeHELLOOrSSHReadyAdded'] is False
 assert manifest['guestSSHAvailable'] is False and manifest['actualSSHVerified'] is False
 priorApp12=N/'independent27-actual-app-vm-class-binding-v12-attempt1/candidate.json'
 assert manifest['priorActualApp12Candidate']==pin(priorApp12)
 assert manifest['sshCleanupJoinsBeforeExistingInputDisplayAndVMRelease']
 assert manifest['sshFactoryFailureOwnerRetained']
 assert not manifest['sshHELLOIsGuestSSHSuccess']
 assert manifest['runtimePendingAllAccessesAtomic'] and manifest['independentApplicationLogIsolated']
 assert manifest['runtimeStartupUsesActualBackgroundSerialQueue'] and manifest['runtimePendingPublishedBeforeDispatch']
 assert manifest['explicitIndependent27Launch'] and manifest['globalAutoBootNotConsumed']
 assert manifest['automaticVisibleInstallNotConsumed'] and manifest['requiredOwnScheme']=='virtualmac27'
 assert manifest['firstVisibleBootExperiment'] and manifest['actualNetworkDevicesClearedAndCountChecked']
 assert manifest['actualAudioDevicesClearedAndCountChecked'] and not manifest['networkingAvailable']
 appSource=pathlib.Path(manifest['source']['path']);backendSource=pathlib.Path(manifest['backendSource']['path'])
 productionNames=['NSViewShim.m','VZAppSettings.m','VZDiagnostics.m','VZFailureDetailsViewController.m',
  'VZRestoreCatalog.m','VZSupport.m','VZGuestTools.m','VZGuestRuntimePolicy.m','VZNewVMViewController.m',
  'VZProgressViewController.m','VZSettingsViewController.m','VZTrackpadScrollBridge.m','VZVMLibraryViewController.m']
 arcNames=['vm27_genuine_display_observer_v1.mm','vm27_uikit_guest_display_v1.mm',
  'modern_uikit_input_surface_v2.m','modern_uikit_input_adapter_v2.m','modern_input_packet_lease_v2.m',
  'vm27_own_uikit_ingress_profile_v1.m','modern_vz_processed_scroll_receiver_v1.m','modern_processed_scroll_sink_v1.m']
 cNames=['modern_input_packet_v2.c','vm27_own_uikit_ingress_values_v1.c',
  'modern_vz_scroll_normalization_v1.c','modern_processed_scroll_native_v1.c']
 profileSource=a.own_input_profile_source.resolve()
 assert profileSource==S/'vm27_own_uikit_ingress_profile_v2.m' and profileSource.is_file()
 assert '#import "vm27_own_uikit_ingress_profile_v1.h"' in profileSource.read_text()
 surfaceSource=a.basic_input_surface_source.resolve()
 assert surfaceSource==S/'modern_uikit_input_surface_v3_basic.m' and surfaceSource.is_file()
 assert 'pan.enabled = NO;' in surfaceSource.read_text() and 'pinch.enabled = NO; rotation.enabled = NO;' in surfaceSource.read_text()
 displaySource=a.uikit_guest_display_source.resolve()
 assert displaySource==S/'vm27_uikit_guest_display_v4.mm' and displaySource.is_file()
 assert 'VM27UIKitCreateActualVirtualMachineV1' in displaySource.read_text()
 sourceOverrides={'vm27_own_uikit_ingress_profile_v1.m':profileSource,'modern_uikit_input_surface_v2.m':surfaceSource,'vm27_uikit_guest_display_v1.mm':displaySource}
 units=[(appSource,False),(backendSource,False)]+[(S/f,False)for f in productionNames]+[(sourceOverrides.get(f,S/f),True)for f in arcNames]+[(S/f,False)for f in cNames]
 queue=S/'vm27_input_queue_v3.m'
 if queue.is_file():units += [(queue,True)]
 # Link this own bridge directly; no duplicate profile or second bridge DSO.
 units += [(pathlib.Path(f['path']), pathlib.Path(f['path']).suffix=='.m')
           for f in manifest['newSSHBuildUnits']]
 assert [pin(f) for f,arc in units[-4:]]==manifest['newSSHBuildUnits']
 if not a.components_only:
  assert a.runtime_source or a.runtime_provider_library,'A real strong runtime provider is required.'
  assert a.runtime_root and a.runtime_root.startswith('/') and len(a.runtime_root)>1
  assert queue.is_file()
 units += [(f.resolve(),True)for f in a.runtime_source]
 pins=[pin(f)for f,arc in units];commands=[]
 def run(label,argv,timeout=90):
  cp=subprocess.run(list(map(str,argv)),capture_output=True,timeout=timeout)
  (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(label=label,argv=list(map(str,argv)),exit=cp.returncode));save(o/'commands.json',commands)
  assert cp.returncode==0,(label,cp.stderr.decode(errors='replace'));return cp
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
 base=['-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',S]
 objects=[];dependencyPins={}
 for i,(f,arc) in enumerate(units):
  compiler='clang++'if f.suffix=='.mm'else'clang'
  flags=['xcrun',compiler]+base+(['-fobjc-arc']if arc and f.suffix in('.m','.mm')else[])
  flags += ['-std=c++17']if f.suffix=='.mm'else['-std=c11']if f.suffix=='.c'else[]
  obj=objectsDir/(str(i)+'-'+f.stem+'.o')
  run('compile-'+str(i),flags+['-c',f,'-o',obj]);objects.append(obj)
  # Actual preprocessing closure. No globs capture another agent's draft.
  cp=run('deps-'+str(i),flags+['-MM',f])
  text=cp.stdout.decode().replace('\\\n',' ');tail=text.split(':',1)[1]
  import shlex
  for item in shlex.split(tail):
   q=pathlib.Path(item).resolve()
   if q.is_file():dependencyPins[str(q)]=pin(q)
 assert pins==[pin(f)for f,arc in units]
 record=dict(schema='Copied independent27 App17 Runtime11 actual NSError start diagnostics with genuine IOSurface CPU bitmap display with SSH deferred component compilation',sourceCandidate=pin(a.source_candidate),
  builder=pin(pathlib.Path(__file__)),sourceFiles=pins,actualIncludeClosure=list(dependencyPins.values()),
  objects=[pin(f)for f in objects],commands=commands,productionSourceModified=False,
  applicationBinaryLinked=False,applicationPackaged=False,codeSigned=False,
  deviceOperations=0,originalVZExecuted=False,actualUIKitRuntimeValidated=False,full27Backend=False)
 if a.components_only:
  save(o/'candidate.json',record);print(json.dumps(dict(candidate=pin(o/'candidate.json'),objects=len(objects))));return
 app=o/'VirtualMacIndependent27.app';app.mkdir();binary=app/'VirtualMacIndependent27'
 frameworks=['AVFAudio','CoreImage','Foundation','GameController','Metal','Security','UIKit',
  'UniformTypeIdentifiers','IOSurface','QuartzCore','CoreGraphics','CoreFoundation','IOKit']
 link=['xcrun','clang++']+base+objects+a.runtime_provider_library
 for framework in frameworks:link += ['-framework',framework]
 link += ['-Wl,-export_dynamic','-Wl,-no_adhoc_codesign','-o',binary]
 run('link-app',link)
 assert binary.stat().st_size<=2097152,'The actual unsigned App already exceeds the true parent self-inspector limit.'
 run('validate-app',['xcrun','dyld_info','-validate_only',binary])
 run('imports-app',['xcrun','dyld_info','-imports',binary]);run('exports-app',['xcrun','dyld_info','-exports',binary])
 info=plistlib.loads((S/'VirtualMac-Info.plist').read_bytes())
 info.update(CFBundleIdentifier='com.mac.virtual.independent27',CFBundleExecutable=binary.name,
  CFBundleName='VirtualMac Independent27',CFBundleDisplayName='VirtualMac 27 First Display',MinimumOSVersion='16.1',
  VirtualMac27RuntimeRoot=a.runtime_root,VirtualMacPVGBackendVersion='27',
  VirtualMacIndependent27FirstVisibleBootExperiment=True,VirtualMacIndependent27ActualNICCount=0,
  VirtualMacIndependent27ActualAudioDeviceCount=0,VirtualMacIndependent27ExplicitLaunchOnly=True,
  CFBundleSupportedPlatforms=['iPhoneOS'],CFBundleURLTypes=[dict(CFBundleURLName='com.mac.virtual.independent27.actions',
    CFBundleURLSchemes=['virtualmac27'])])
 (app/'Info.plist').write_bytes(plistlib.dumps(info,sort_keys=False))
 for src,name in [(R/'VirtualMac/assets/VirtualMac.png','AppIcon1024x1024.png'),
                  (R/'VirtualMac/assets/VirtualMacTemplate.png','VirtualMacTemplate.png'),
                  (R/'VirtualMac/vendor/VirtualBuddy/ipsws_v2.json','ipsws_v2.json')]:
  if src.is_file():shutil.copyfile(src,app/name)
 for src,name in [(R/'VirtualMac/resources/Localizations',''),(R/'VirtualMac/assets/installers','Installers'),
                  (R/'VirtualMac/assets/developers','Developers')]:
  if src.is_dir():
   if name:shutil.copytree(src,app/name)
   else:
    for q in src.glob('*.lproj'):shutil.copytree(q,app/q.name)
 run('launch-screen',['xcrun','ibtool','--compile',app/'VirtualMacLaunchScreen.storyboardc',
   S/'VirtualMacLaunchScreen.storyboard','--target-device','ipad','--minimum-deployment-target','16.1'])
 for size,name in [(120,'AppIcon60x60@2x.png'),(180,'AppIcon60x60@3x.png'),
                   (152,'AppIcon76x76@2x.png'),(167,'AppIcon83.5x83.5@2x.png')]:
  run('icon-'+str(size),['sips','-z',str(size),str(size),R/'VirtualMac/assets/VirtualMac.png','--out',app/name])
 guest=R/'VirtualMac/build/guest-tools/VirtualMacGuestTools.tar.gz'
 if guest.is_file():(app/'GuestTools').mkdir();shutil.copyfile(guest,app/'GuestTools'/guest.name)
 record.update(schema='Copied independent27 App17 Runtime11 actual NSError start diagnostics with genuine IOSurface CPU bitmap display with SSH deferred strong linked unsigned App package',
  applicationBinaryLinked=True,applicationPackaged=True,binary=pin(binary),
  runtimeRoot=a.runtime_root,runtimeProviderLibraries=[pin(f)for f in a.runtime_provider_library],
  appFiles=[pin(f)for f in app.rglob('*')if f.is_file()],commands=commands,
  oldVenturaHostCompatIncluded=False,backendAdmissionRequiresActualGraphPreflight=True,
  actualParentSelfInspectorMaxBytes=2097152,unsignedMainWithinActualSelfInspector=True,
  finalSignedMainSizeStillMustBeChecked=True,
  standaloneRuntimeGraphIncluded=False,readyForDeviceExecution=False,
  firstVisibleBootExperiment=True,actualNICCountRequired=0,actualAudioDeviceCountRequired=0,
  actualSSHVerified=False,genuineSSHBridgeIncluded=True,genuineSSHBridgeDormantForFirstBoot=True,sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,guestHelperInstalled=False,
  networkingAvailable=False,guestSSHAvailable=False,finalNetworkAndSSHStillRequired=True)
 save(o/'candidate.json',record);print(json.dumps(dict(candidate=pin(o/'candidate.json'),binary=pin(binary),app=str(app))))
if __name__=='__main__':main()
