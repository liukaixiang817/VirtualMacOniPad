#!/usr/bin/env python3
"""Root's one bounded self-only native memory diagnostic; no guest is created."""
import argparse,datetime,getpass,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PACKET=N/'independent27-gic-base-device-v5-attempt1'
SIGNED=N/'native-memory-reserve-commit-probe-signed-v1-attempt1/candidate.json'
SIGNED_SHA='bbdd762d92bec6247b77de02a251378853a333fa9e8f66bc5ed0ee57b8515b30'
STAGE='/private/var/mobile/Library/.VM27-native-memory-probe-v1'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def need(v,why):
 if not v:raise ValueError(why)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'new single actual diagnostic output')
 need(pin(SIGNED)['sha256']==SIGNED_SHA,'exact Root signed diagnostic')
 for row in json.loads((SIGNED.parent/'freeze.json').read_bytes())['files']:need(pin(row['path'])==row,'exact signed diagnostic source/product')
 c=json.loads(SIGNED.read_bytes());binary=pathlib.Path(c['signedBinary']['path']);need(pin(binary)==c['signedBinary']and c['physicalCommitMaximumBytes']==16384 and c['sparseVirtualOnlyBytes']==8589967360,'actual bounded self-only diagnostic')
 auth=json.loads((PACKET/'authorization-from-continuing-human-v5.json').read_bytes());continuing=json.loads(pathlib.Path(auth['continuingHumanAuthorization']['path']).read_bytes());need(continuing['necessaryHashesProbesAndOwnedProcessPermissionsAuthorized']and continuing['preserveIPadOSStability'],'continuing direct human authorization')
 post=N/'independent27-app20-normal-guest-lifecycle-v15-attempt1/device-receipts/post/receipt.json';actualpost=json.loads(post.read_bytes());need(actualpost['transportExit']==0,'actual own guest cleanup complete')
 sp=importlib.util.spec_from_file_location('native_memory_root_transport',PACKET/'control.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);cd=c['actualSignature']['cdhash'];device=STAGE+'/VM27MemoryReserveCommitProbeV1'
 body=m.prefix(0)+m.off_check()+f'''
[ -d /private/var/mobile/Library ] && [ ! -L /private/var/mobile/Library ]
[ "$(realpath /private/var/mobile/Library)" = /private/var/mobile/Library ]
[ ! -e {STAGE} ] && [ ! -L {STAGE} ]
mkdir -m 700 {STAGE}
trap 'rm -f {device}; rmdir {STAGE}' EXIT
cat > {device}
[ -f {device} ] && [ ! -L {device} ]
[ "$(stat -c %s {device})" = {c['signedBinary']['bytes']} ]
[ "$(sha256sum {device} | cut -d ' ' -f1)" = {c['signedBinary']['sha256']} ]
chmod 700 {device}
chown 501:501 {device} {STAGE}
actual_cd=$(ldid -h {device} 2>&1)
[ "$(printf '%s\\n' "$actual_cd" | sed -n 's/^CDHash=//p')" = {cd} ]
jbctl trustcache add {cd}
actual_trust=$(jbctl trustcache info)
printf '%s\\n' "$actual_trust" | awk 'tolower($NF)=="{cd}" {{found=1}} END {{exit !found}}'
printf 'OWN_SINGLE_NATIVE_MEMORY_PROBE_TRUST_PRESENT {cd}\\n'
probe_exit=0
sudo -u mobile /var/jb/usr/bin/timeout -s TERM -k 3 20 {device} --sparse-original-reserve || probe_exit=$?
printf 'OWN_NATIVE_MEMORY_PROBE_EXEC_EXIT %s\\n' "$probe_exit"
rm -f {device}
rmdir {STAGE}
trap - EXIT
printf 'OWN_NATIVE_MEMORY_PROBE_EXACT_FILES_REMOVED_TRUST_RETAINED\\n'
'''+m.off_check()+'\nexit "$probe_exit"\n'
 script='set -eu\n/var/jb/usr/bin/timeout -s TERM -k 3 45 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 z=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True);need(z.returncode==0,'actual shell syntax')
 out.mkdir(mode=0o700);(out/'script.sh').write_text(script)
 scope=dict(signedCandidate=pin(SIGNED),signedBinary=c['signedBinary'],newTrustCacheCDHashes=[cd],deviceFiles=[device],stage=STAGE,UID=501,EUID=501,physicalCommitMaximumBytes=16384,sparseVirtualOnlyBytes=8589967360,physical8GiBCommit=False,probeTimeoutSeconds=20,remoteActionTimeoutSeconds=45,processSignals='only timeout-owned diagnostic process',perPIDKernelPrivilegeModification=False,systemFilesModified=False,VMCreated=False,HVOperations=0,continuingHumanAuthorization=auth['continuingHumanAuthorization'],actualGuestCleanupPost=pin(post));save(out/'scope.json',scope)
 save(out/'dispatched.json',dict(startedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),source=pin(__file__),scope=pin(out/'scope.json'),script=pin(out/'script.sh'),rootIsSoleDeviceOperator=True))
 password=getpass.getpass('iPad password: ');status,stdout,stderr,error=m.run_remote(script,binary.read_bytes(),True,password);password=None
 (out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr);save(out/'receipt.json',dict(finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),transportExit=status,transportError=error,stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),scope=pin(out/'scope.json'),request=pin(out/'dispatched.json'),guestBootRequested=False))
 print(json.dumps(pin(out/'receipt.json')));print(stdout.decode(errors='replace'));print(stderr.decode(errors='replace'));need(status==0,'actual diagnostic exited nonzero; preserved all actual results')
if __name__=='__main__':main()
