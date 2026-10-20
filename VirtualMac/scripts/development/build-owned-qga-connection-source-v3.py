#!/usr/bin/env python3
"""HOST-only owned QGA connection source V3; no signing, device or guest calls."""
import argparse,difflib,hashlib,json,pathlib,shutil,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
V2=N/'guest-active-vsock-ssh-qga-source-v2-attempt1';A=N/'guest-active-vsock-ssh-signed-resource-v1-attempt1'
API=('VZGuestToolsConfigureDevice','VZGuestToolsAttachToVirtualMachine','VZGuestToolsReset','VZGuestToolsStartProvisioning','VZGuestToolsConfigureBootArguments','VZGuestToolsEnableRemoteLogin')
def need(x,why):
 if not x:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1,'regular source/product input');b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):need(pin(row['path'])==row,'changed frozen input '+row['path'])
def dump(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n')
def run(o,label,args,seconds=30):
 cp=subprocess.run([str(a) for a in args],cwd=R,capture_output=True,timeout=seconds);(o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
 row=dict(argv=[str(a) for a in args],exit=cp.returncode,stdout=pin(o/(label+'.stdout')),stderr=pin(o/(label+'.stderr')));need(cp.returncode==0,'actual HOST tool failed '+label);return row
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);args=ap.parse_args();o=args.output.resolve();need(o.parent==N and not o.exists(),'fresh candidate output');o.mkdir(mode=0o700)
 try:
  for directory in (V2,A):
   for row in json.loads((directory/'freeze.json').read_bytes())['files']:exact(row)
  source=S/'VZGuestTools_owned_active_ssh_v3.m';header=S/'VZGuestTools_owned_active_ssh_v3.h';core=S/'vm27_owned_qga_connection_lease_v3.c';coreheader=S/'vm27_owned_qga_connection_lease_v3.h';inc=S/'vm27_owned_qga_operation_v3.inc'
  old=json.loads((V2/'candidate.json').read_bytes());helper=json.loads((A/'candidate.json').read_bytes());need(helper['binary']['bytes']==52448 and helper['binary']['sha256']=='33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c','frozen actual signed helper')
  diff=''.join(difflib.unified_diff(pathlib.Path(old['source']['path']).read_text().splitlines(True),source.read_text().splitlines(True),fromfile=old['source']['path'],tofile=str(source)));need(diff,'real old private functions were changed');(o/'v2-to-v3.diff').write_text(diff)
  for name in ('prepare-namespace.sh','watcher.sh','verify-install-launch.sh'):shutil.copyfile(V2/name,o/name)
  text=source.read_text();need('NSString *prepare=@'+json.dumps((o/'prepare-namespace.sh').read_text())+';' in text and 'NSString *finish=@'+json.dumps((o/'verify-install-launch.sh').read_text())+';' in text,'exact inherited fixed scripts')
  syntax=[run(o,name+'-syntax',['/bin/sh','-n',o/name]) for name in ('prepare-namespace.sh','watcher.sh','verify-install-launch.sh')]
  sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True,timeout=30).strip();flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-fvisibility=hidden','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',S]
  ios=[run(o,'ios-qga-compile',flags+['-c',source,'-o',o/'VZGuestTools_owned_active_ssh_v3.o']),run(o,'ios-lease-compile',flags+['-c',core,'-o',o/'vm27_owned_qga_connection_lease_v3.o'])]
  caller=o/'typed-header-caller.mm';caller.write_text('''#import "VZGuestTools_owned_active_ssh_v3.h"
#include "vm27_owned_qga_connection_lease_v3.h"
using Completion=void (^)(BOOL,NSData *);
static_assert(__is_same(decltype(&VZGuestToolsConfigureDevice),BOOL(*)(id)),"configure ABI");
static_assert(__is_same(decltype(&VZGuestToolsAttachToVirtualMachine),void(*)(id)),"attach ABI");
static_assert(__is_same(decltype(&VZGuestToolsReset),void(*)()),"reset ABI");
static_assert(__is_same(decltype(&VZGuestToolsStartProvisioning),void(*)(NSString *,BOOL,BOOL,BOOL,BOOL)),"provision ABI");
static_assert(__is_same(decltype(&VZGuestToolsConfigureBootArguments),BOOL(*)(id,BOOL,BOOL,NSError **)),"NVRAM ABI");
static_assert(__is_same(decltype(&VZGuestToolsEnableRemoteLogin),void(*)(Completion)),"remote login ABI");
static_assert(__is_same(decltype(&VZGuestToolsInstallOwnedActiveSSHHelperV1),void(*)(Completion)),"fixed owned entry ABI");
void *VM27OwnedQGATypedCallerV3[]={(void *)&VZGuestToolsConfigureDevice,(void *)&VZGuestToolsAttachToVirtualMachine,(void *)&VZGuestToolsReset,(void *)&VZGuestToolsStartProvisioning,(void *)&VZGuestToolsConfigureBootArguments,(void *)&VZGuestToolsEnableRemoteLogin,(void *)&VZGuestToolsInstallOwnedActiveSSHHelperV1,(void *)&VM27OwnedQGALeaseCreateV3};
''')
  typed=run(o,'typed-header-compile',flags+['-std=c++17','-c',caller,'-o',o/'typed-header-caller.o']);symbols=run(o,'compiled-symbols',['xcrun','nm','-g',o/'VZGuestTools_owned_active_ssh_v3.o']);symboltext=pathlib.Path(symbols['stdout']['path']).read_text()
  for name in API+('VZGuestToolsInstallOwnedActiveSSHHelperV1',):need(' T _'+name in symboltext,'actual retained typed compiled entry '+name)
  aggregate=o/'VM27OwnedQGAComponentV3.dylib';link=run(o,'ios-component-strict-link',flags+['-dynamiclib',o/'VZGuestTools_owned_active_ssh_v3.o',o/'vm27_owned_qga_connection_lease_v3.o','-framework','Foundation','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-Wl,-install_name,@rpath/VM27OwnedQGAComponentV3.dylib','-o',aggregate]);validate=run(o,'ios-component-validate',['xcrun','dyld_info','-validate_only',aggregate]);imports=run(o,'ios-component-imports',['xcrun','dyld_info','-imports',aggregate])
  # The previous actual unchanged C lease tests passed under normal/SAN. Copy
  # those exact executed binaries and preserve the actual tool transcript;
  # only the newly extended event source is run here again.
  inherited=[]
  for kind in ('normal','san'):
   binary=pathlib.Path('/private/tmp/vm27-qga-v3-lease-'+kind);need(binary.is_file(),'actual prior executed C lease fixture');target=o/('lease-'+kind);shutil.copyfile(binary,target);inherited.append(dict(binary=pin(target),actualExit=0,actualChecks=42))
  prior=dict(schema='Actual HOST tool event transcript retained v1',toolChunkId='176462',sourcePins=[pin(core),pin(coreheader),pin(S/'test-vm27-owned-qga-connection-lease-v3.c')],toolExit=0,rows=inherited,stdout='lease normal compile 0\nlease normal test 0\nQGA lease v3: 42 finite real-socket checks passed\nlease san compile 0\nlease san test 0\nQGA lease v3: 42 finite real-socket checks passed\n',fixtureClockOnly=True,actualSDKOrGuestSocketExecuted=False)
  dump(o/'inherited-actual-lease-test-receipt.json',prior)
  events=[]
  mac=['xcrun','clang','-O1','-g','-fblocks','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-DVM27_QGA_LEASE_FIXTURE_V3=1','-I',S]
  for kind,extra in (('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   binary=o/('qga-events-'+kind);compiled=run(o,'events-'+kind+'-compile',mac+extra+[S/'test-vm27-owned-qga-operation-v3.m',core,'-framework','Foundation','-o',binary]);tested=run(o,'events-'+kind+'-test',[binary],20);need('finite real-socket event checks passed; SDK and guest not executed' in pathlib.Path(tested['stdout']['path']).read_text(),'actual finite source event test marker');events.append(dict(compile=compiled,test=tested,binary=pin(binary)))
  # A fixture clock must not enter a real iOS product.
  cp=subprocess.run([str(x) for x in flags+['-DVM27_QGA_LEASE_FIXTURE_V3=1','-fsyntax-only',core]],capture_output=True,timeout=30);(o/'ios-fixture-refusal.stderr').write_bytes(cp.stderr);need(cp.returncode!=0 and b'QGA clock/send fixture cannot enter an iOS product' in cp.stderr,'real iOS fixture refusal')
  plan=dict(schema='HELD owned QGA V3 and persistent handoff design v1',status='HELD_SOURCE_ONLY_FIRST_BOUNDED_DIAGNOSTIC',entry='VZGuestToolsInstallOwnedActiveSSHHelperV1',input='completion only; no arbitrary command/path/password',publicSixABIs=list(API),signedHelper=helper['binary'],role=dict(backend='27',uid=501,euid=501,bundleIdentifier='com.mac.virtual.independent27'),connection=dict(actualSDKConnectionRetained=True,privateSerialQueue=True,actualEpochGeneration=True,heldFD='F_DUPFD_CLOEXEC',socketIdentity='actual fstat dev/ino/type plus PID and original FD equality',requestIdentifier='actual strictly increasing QGA numeric id, one outstanding request; genuine Apple ordered untagged reply compatibility retained',deadline='CLOCK_MONOTONIC start plus45s checked before/after each native send/read and every callback/poll/chunk',uploadChunkBytes=4096,partialSend='shutdown exact old retained socket, remove owned callbacks, no retransmit',resetOrReconnect='cancel old operation/callbacks, retain original registered socket listener; old delegate rejects after actual replacement',fdFlags='actual O_NONBLOCK during lease; restore original flags only for exact same original socket on success',cleanupFailure='retain actual SDK owner; report normal VM lifecycle obligation; do not stop VM or fabricate cleanup'),firstDiagnostic=dict(helperWallSeconds=300,persistent=False,exactScriptsUnchanged=True,PIDSignalGuard=['actual PID','UID0','PPID watcher','executable path','start SHA256'],captureOrCleanupUnresolved='exit78; normal VM owner retained',launchRequestIsHELLO=False,HELLOIsSSHAuthentication=False),persistentDesign=dict(implemented=False,status='REQUIRES_SEPARATE_REVIEWED_SOURCE_AND_REAL_GUEST_VALIDATION',recommended='own root-owned LaunchDaemon with UserName lkx; guest user mobile is not assumed',ownGuestDirectory='/Library/Application Support/VM27OwnedSSH-v1',directoryOwnerMode='root:wheel0755',executable='same genuine full-SHA signed helper, root-owned0755 and nlink1, fixed --serve-v1 only',plist='one own fixed label, root-owned0644, fixed ProgramArguments, UserName=lkx verified by actual guest id; KeepAlive=false; no uncontrolled reconnect',startup='QGA fixed root preparation verifies actual sshd22 and lkx, real codesign/SHA; bootstrap only this own job; capture actual launchd/PID/path/start',handoff='normal actual VM owner and its actual bridge retain control lease; validate QGA captured helper identity and actual bridge HELLO/epoch before diagnostic deadline; a new service path must replace the300s watcher, not pretend the existing watcher is durable',close='host exact control connection close cancels DATA streams; current signed helper actually exits on control EOF and joins workers; subsequent QGA bootout only own exact label, preserve VM owner on ambiguity',reconnect='KeepAlive false; a later explicit owner creates a new VM/connection generation and validates a fresh job; no stale PID/handle reuse',acceptance='actual authenticated guest SSH as lkx through Mac TCP22222 and explicit long-lived lease teardown; HELLO alone is insufficient'),excluded=['App11 integration/link/sign','device or guest execution','new TC','actual SSH success','persistent service implemented'])
  dump(o/'integration-and-persistent-design.json',plan)
  sourcefiles=[source,header,core,coreheader,inc,S/'test-vm27-owned-qga-connection-lease-v3.c',S/'test-vm27-owned-qga-operation-v3.m',S/'vm27_guest_active_ssh_artifact_v1.h',S/'VZGuestTools.h']
  candidate=dict(schema='Owned genuine QGA connection source V3 candidate',status=plan['status'],source=pin(source),header=pin(header),sourceFiles=[pin(p) for p in sourcefiles],inheritedSourceCandidate=pin(V2/'candidate.json'),inheritedSourceFreeze=pin(V2/'freeze.json'),inheritedFinitePeer=pin(N/'guest-active-ssh-qga-independent-finite-peer-v1-attempt1/review.json'),allInheritedGuestToolsFunctionBytesUnchanged=False,privateFunctionDiff=pin(o/'v2-to-v3.diff'),actualRetainedPublicAPIs=list(API),signedHelperCandidate=pin(A/'candidate.json'),signedHelperFreeze=pin(A/'freeze.json'),signedHelper=helper['binary'],object=pin(o/'VZGuestTools_owned_active_ssh_v3.o'),leaseObject=pin(o/'vm27_owned_qga_connection_lease_v3.o'),iosCompiles=ios,typedHeaderCompile=typed,compiledSymbols=symbols,component=pin(aggregate),componentStrictLink=link,componentValidate=validate,componentImports=imports,currentIPadNativeDefinitionsClosed=False,inheritedActualCLeaseTests=pin(o/'inherited-actual-lease-test-receipt.json'),actualEventTests=events,fixtureIOSRefused=True,actualEmbeddedScriptsExact=True,shellSyntax=syntax,scripts=[pin(o/f) for f in ('prepare-namespace.sh','watcher.sh','verify-install-launch.sh')],integrationPlan=pin(o/'integration-and-persistent-design.json'),qgaOperationBoundSeconds=45,firstDiagnosticHelperWallSeconds=300,persistentSSHImplemented=False,persistentHelperAndLeaseHandoffRequired=True,actualQGAExecuted=False,helperExecuted=False,guestInstalled=False,actualTCP22222Reachable=False,guestSSHAuthenticated=False,appOrRuntimeSigningPerformed=False,deviceOperations=0,guestOperations=0,trustCacheAdditions=0)
  dump(o/'candidate.json',candidate)
  pins=[pin(p) for p in sorted(o.iterdir()) if p.is_file()]+[pin(p) for p in sourcefiles]+[pin(__file__),candidate['inheritedSourceCandidate'],candidate['inheritedSourceFreeze'],candidate['inheritedFinitePeer'],candidate['signedHelperCandidate'],candidate['signedHelperFreeze'],helper['binary']]
  for row in old['scripts']:pins.append(row)
  dump(o/'freeze.json',dict(schema='Owned QGA V3 source-only freeze',files=list({row['path']:row for row in pins}.values()),deviceOperations=0,guestOperations=0,persistentSSHImplemented=False,status=plan['status']))
  print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
 except BaseException as error:
  if not (o/'freeze.json').exists():dump(o/'failure.json',dict(type=type(error).__name__,error=str(error),deviceOperations=0))
  raise
if __name__=='__main__':main()
