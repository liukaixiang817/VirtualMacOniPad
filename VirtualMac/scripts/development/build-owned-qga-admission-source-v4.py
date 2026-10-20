#!/usr/bin/env python3
"""HOST-only V4 true QGA admission delta; frozen V3 and helper remain unchanged."""
import argparse,difflib,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';V3=N/'guest-active-vsock-ssh-qga-source-v3-attempt1'
def need(x,m):
 if not x:raise ValueError(m)
def pin(p):p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def run(o,label,args):
 cp=subprocess.run([str(x) for x in args],cwd=R,capture_output=True,timeout=30);(o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr);row=dict(argv=[str(x) for x in args],exit=cp.returncode,stdout=pin(o/(label+'.stdout')),stderr=pin(o/(label+'.stderr')));need(cp.returncode==0,'actual tool failed '+label);return row
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve();need(o.parent==N and not o.exists(),'fresh V4 output');o.mkdir(mode=0o700)
 try:
  old=json.loads((V3/'candidate.json').read_bytes());f=json.loads((V3/'freeze.json').read_bytes())
  for row in f['files']:need(pin(row['path'])==row,'exact frozen V3 input '+row['path'])
  source=S/'VZGuestTools_owned_active_ssh_v4.m';header=S/'VZGuestTools_owned_active_ssh_v4.h';inc=S/'vm27_owned_qga_operation_v4.inc';fixture=S/'test-vm27-owned-qga-admission-v4.m'
  need(inc.read_text()==(S/'vm27_owned_qga_operation_v3.inc').read_text().replace('VM27OwnedQGAOperationV3','VM27OwnedQGAOperationV4'),'private owned operation implementation unchanged except own class version')
  diff=''.join(difflib.unified_diff(pathlib.Path(old['source']['path']).read_text().splitlines(True),source.read_text().splitlines(True),fromfile=old['source']['path'],tofile=str(source)));(o/'v3-to-v4.diff').write_text(diff)
  sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True,timeout=30).strip();flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-fvisibility=hidden','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',S]
  compile_row=run(o,'ios-qga-compile',flags+['-c',source,'-o',o/'VZGuestTools_owned_active_ssh_v4.o'])
  caller=o/'typed-header-caller.mm';oldcaller=pathlib.Path(old['typedHeaderCompile']['argv'][-3]);need(oldcaller.name=='typed-header-caller.mm','actual inherited typed source');caller.write_text(oldcaller.read_text().replace('VZGuestTools_owned_active_ssh_v3.h','VZGuestTools_owned_active_ssh_v4.h'));typed=run(o,'typed-header-compile',flags+['-std=c++17','-c',caller,'-o',o/'typed-header-caller.o'])
  aggregate=o/'VM27OwnedQGAComponentV4.dylib';link=run(o,'ios-component-strict-link',flags+['-dynamiclib',o/'VZGuestTools_owned_active_ssh_v4.o',old['leaseObject']['path'],'-framework','Foundation','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-install_name,@rpath/VM27OwnedQGAComponentV4.dylib','-o',aggregate]);validate=run(o,'ios-component-validate',['xcrun','dyld_info','-validate_only',aggregate])
  tests=[];mac=['xcrun','clang','-O1','-g','-fblocks','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-DVM27_QGA_LEASE_FIXTURE_V3=1','-I',S]
  for kind,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   binary=o/('admission-'+kind);compiled=run(o,'admission-'+kind+'-compile',mac+extra+[fixture,S/'vm27_owned_qga_connection_lease_v3.c','-framework','Foundation','-o',binary]);tested=run(o,'admission-'+kind+'-test',[binary]);need('finite real-socket delta checks passed; SDK and guest not executed' in pathlib.Path(tested['stdout']['path']).read_text(),'actual finite test marker');tests.append(dict(compile=compiled,test=tested,binary=pin(binary)))
  plan=json.loads(pathlib.Path(old['integrationPlan']['path']).read_bytes());plan['schema']='HELD owned QGA V4 true admission and persistent handoff design';plan['connection']['admission']='private BOOL and delegate return actual admitted result; after old socket cleanup, refuse counter MAX or unresolved native cleanup before increment';dump(o/'integration-and-persistent-design.json',plan)
  candidate=dict(schema='Owned QGA true admission source V4 candidate',status=old['status'],source=pin(source),header=pin(header),sourceFiles=[pin(source),pin(header),pin(inc),pin(fixture)],inheritedSourceCandidate=pin(V3/'candidate.json'),inheritedSourceFreeze=pin(V3/'freeze.json'),privateFunctionDiff=pin(o/'v3-to-v4.diff'),actualRetainedPublicAPIs=old['actualRetainedPublicAPIs'],privateAdmissionBOOL=True,refuseAfterCloseCounterExhaustion=True,refuseAfterCloseUnresolvedCleanup=True,ownedOperationBodyUnchangedExceptOwnClassVersion=True,leaseObject=old['leaseObject'],signedHelper=old['signedHelper'],signedHelperCandidate=old['signedHelperCandidate'],scripts=old['scripts'],iosCompile=compile_row,typedHeaderCompile=typed,component=pin(aggregate),componentStrictLink=link,componentValidate=validate,actualDeltaTests=tests,inheritedV3TestsNotRerun=True,integrationPlan=pin(o/'integration-and-persistent-design.json'),actualQGAExecuted=False,helperExecuted=False,guestInstalled=False,persistentSSHImplemented=False,guestSSHAuthenticated=False,app11Integrated=False,deviceOperations=0,guestOperations=0,trustCacheAdditions=0)
  dump(o/'candidate.json',candidate);pins=[pin(p) for p in sorted(o.iterdir()) if p.is_file()]+candidate['sourceFiles']+[pin(__file__),candidate['inheritedSourceCandidate'],candidate['inheritedSourceFreeze'],old['leaseObject'],old['signedHelper'],old['signedHelperCandidate']]+old['scripts']+[pin(S/'vm27_owned_qga_connection_lease_v3.c'),pin(S/'vm27_owned_qga_connection_lease_v3.h'),pin(S/'VZGuestTools.h'),pin(S/'vm27_guest_active_ssh_artifact_v1.h')]
  dump(o/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0,guestOperations=0,status=old['status']));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
 except BaseException as e:
  if not (o/'freeze.json').exists():dump(o/'failure.json',dict(error=str(e),deviceOperations=0))
  raise
if __name__=='__main__':main()
