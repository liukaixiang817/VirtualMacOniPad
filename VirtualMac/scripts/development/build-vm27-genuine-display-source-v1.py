#!/usr/bin/env python3
"""Compile actual source display observer/UIKit presenter, no VZ/device/sign."""
import argparse,datetime,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return {'path':str(p.resolve()),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 cmds=[]
 def run(name,argv,expected=0):
  p=subprocess.run(argv,capture_output=True,timeout=40)
  (o/(name+'.stdout')).write_bytes(p.stdout);(o/(name+'.stderr')).write_bytes(p.stderr)
  cmds.append({'name':name,'argv':argv,'exit':p.returncode,'stdout':pin(o/(name+'.stdout')),'stderr':pin(o/(name+'.stderr'))})
  (o/'commands.json').write_text(json.dumps(cmds,indent=2)+'\n');assert p.returncode==expected,(name,p.returncode,p.stderr.decode(errors='replace'))
  return p.stdout.decode()
 common=['xcrun','clang++','-std=c++17','-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror']
 test=str(S/'test-vm27-genuine-display-observer-v1.mm');results={}
 for mode,extra in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  binary=o/('fixture-'+mode);run(mode+'-compile',common+extra+['-framework','Foundation','-framework','IOSurface',test,'-o',str(binary)])
  results[mode]=json.loads(run(mode+'-run',[str(binary)]));assert results[mode]['passed'] and not results[mode]['actualMacIOSurface']
 target=['xcrun','--sdk','iphoneos','clang++','-target','arm64e-apple-ios16.0','-std=c++17','-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror']
 dylib=o/'VM27GenuineUIKitDisplayV1.unsigned.dylib'
 run('ios-build',target+['-dynamiclib','-Wl,-no_adhoc_codesign','-install_name','@executable_path/VM27GenuineUIKitDisplayV1.dylib',str(S/'vm27_genuine_display_observer_v1.mm'),str(S/'vm27_uikit_guest_display_v1.mm'),'-framework','Foundation','-framework','IOSurface','-framework','Metal','-framework','UIKit','-framework','QuartzCore','-o',str(dylib)])
 run('ios-validate',['xcrun','dyld_info','-validate_only',str(dylib)])
 run('ios-imports',['xcrun','dyld_info','-imports',str(dylib)])
 run('ios-fixture-denied',target+['-DVM27_DISPLAY_FIXTURE_V1','-fsyntax-only',str(S/'vm27_genuine_display_observer_v1.mm')],expected=1)
 sources=[S/n for n in('vm27_genuine_display_observer_v1.h','vm27_genuine_display_observer_v1.mm','vm27_genuine_display_profile_v1.inc','vm27_uikit_guest_display_v1.h','vm27_uikit_guest_display_v1.mm','test-vm27-genuine-display-observer-v1.mm')]
 candidate={'schema':'Genuine27 accessor/presenter source observer and UIKit Metal display local v1','recordedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceFiles':[pin(p)for p in sources],'builder':pin(pathlib.Path(__file__)),'commands':cmds,'normal':results['normal'],'sanitized':results['sanitized'],'iosProvider':pin(dylib),'iosCompileLinkValidatePassed':True,'originalEvidence':pin(N/'vz-framebuffer-owner-original-readonly-v16/contract.json'),'originalCandidate':pin(N/'vz-own-uikit-notification-source-port-data-v1/candidate.json'),'modelScope':'Real libc++ argument/destructor ABI and actual serial queue detach/partial-failure retention; ordinary local run does not create Mac IOSurface','originalVZExecuted':False,'actualGuestSurfaceObserved':False,'actualUIKitRendered':False,'actualVMMWorkerStarted':False,'deviceOperations':0,'codeSigned':False,'full27Backend':False}
 (o/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n');print(json.dumps({'candidate':pin(o/'candidate.json'),'iosProvider':pin(dylib),'normal':results['normal'],'sanitized':results['sanitized']}))
if __name__=='__main__':main()
