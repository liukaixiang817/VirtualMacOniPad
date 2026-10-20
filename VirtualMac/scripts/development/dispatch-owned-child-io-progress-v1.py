#!/usr/bin/env python3
"""Root installs one read-only observer during the exact owned normal launch."""
import argparse,datetime,getpass,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SIGNED=N/'native-owned-child-io-progress-signed-v1-attempt1/candidate.json'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--normal-packet',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();p=a.normal_packet.resolve();o=a.output.resolve();assert p.parent==o.parent==N and not o.exists()
 assert (p/'device-receipts/start/request.json').exists() and not (p/'device-receipts/start/receipt.json').exists() and not (p/'device-receipts/post').exists()
 assert json.loads((p/'device-receipts/preflight/receipt.json').read_bytes())['transportExit']==0
 z=json.loads(SIGNED.read_bytes());assert z['CDHash']=='9a90acfe2b9ff112f2f3840fcf88a50e1abbf79e' and pin(z['signedBinary']['path'])==z['signedBinary']
 c=json.loads((p/'candidate.json').read_bytes());i=json.loads(pathlib.Path(c['initializerCandidate']['path']).read_bytes());assert pin(i['controller']['path'])==i['controller'];scope=json.loads(pathlib.Path(i['scope']['path']).read_bytes())
 sp=importlib.util.spec_from_file_location('io_progress_transport',i['controller']['path']);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 stage='/private/var/mobile/Library/.VM27-owned-child-io-progress-v1';device=stage+'/VM27OwnedChildIOProgressV1';cd=z['CDHash'];body=m.prefix(0)
 for row in scope['files']:
  if row['archivePath']=='VirtualMacIndependent27.app/VirtualMacIndependent27' or row['archivePath'].endswith('/Contents/MacOS/com.apple.Virtualization.VirtualMachine'):
   body+='[ "$(sha256sum '+shlex.quote(row['devicePath'])+' | cut -d \' \' -f1)" = '+row['local']['sha256']+' ]\n'
 body+=f'''[ ! -e {stage} ] && [ ! -L {stage} ]
mkdir -m 700 {stage}
trap 'rm -f {device}; rmdir {stage}' EXIT
cat > {device}
[ "$(sha256sum {device} | cut -d ' ' -f1)" = {z['signedBinary']['sha256']} ]
[ "$(stat -c %s {device})" = {z['signedBinary']['bytes']} ]
chmod 700 {device}
[ "$(ldid -h {device} 2>&1 | sed -n 's/^CDHash=//p')" = {cd} ]
jbctl trustcache add {cd}
jbctl trustcache info | awk 'tolower($NF)=="{cd}" {{found=1}} END {{exit !found}}'
rows=$(ps -axo pid=,ppid=,uid=,comm=)
apid=$(printf '%s\\n' "$rows" | awk -v p="$OWN_APP_MAIN" '$4==p && $2==1 && $3==501 {{print $1}}')
cpid=$(printf '%s\\n' "$rows" | awk -v p="$OWN_CHILD_MAIN" -v a="$apid" '$4==p && $2==a && $3==501 {{print $1}}')
[ "$(printf '%s\\n' "$apid" | awk 'NF {{n++}} END {{print n+0}}')" = 1 ]
[ "$(printf '%s\\n' "$cpid" | awk 'NF {{n++}} END {{print n+0}}')" = 1 ]
rc=0
/var/jb/usr/bin/timeout -s TERM -k 3 75 {device} --owned-child "$cpid" --owned-parent "$apid" || rc=$?
printf 'OWN_IO_PROBE_EXIT %s\\n' "$rc"
rm -f {device}
rmdir {stage}
trap - EXIT
printf 'OWN_IO_PROBE_FILES_REMOVED_TRUST_RETAINED\\n'
exit "$rc"
'''
 script='set -eu\n/var/jb/usr/bin/timeout -s TERM -k 3 85 /var/jb/bin/sh -c '+shlex.quote(body)+'\n';assert subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True).returncode==0
 auth=N/'independent27-continuing-human-authorization-v2/authorization.json';assert json.loads(auth.read_bytes())['allNecessaryUpcomingFixedHashEntriesAndChangesExplicitlyAuthorized']
 o.mkdir(mode=0o700);(o/'script.sh').write_text(script);save(o/'scope.json',dict(probe=pin(SIGNED),newTrustCacheCDHashes=[cd],deviceFiles=[device],UID=0,target='one exact owned Child and parent only native read-only process counters',targetSignals=0,targetWrites=0,guestRAMReads=0,actualNormalRequest=pin(p/'device-receipts/start/request.json'),continuingHumanAuthorization=pin(auth),externalTimeoutSeconds=85,rootSoleOperator=True));save(o/'request.json',dict(source=pin(__file__),script=pin(o/'script.sh'),scope=pin(o/'scope.json'),UTC=datetime.datetime.now(datetime.timezone.utc).isoformat()))
 password=getpass.getpass('iPad password: ')
 try:rc,stdout,stderr,error=m.run_remote(script,pathlib.Path(z['signedBinary']['path']).read_bytes(),True,password,transport_timeout=100)
 finally:password=None
 (o/'stdout').write_bytes(stdout);(o/'stderr').write_bytes(stderr);save(o/'receipt.json',dict(transportExit=rc,transportError=error,stdout=pin(o/'stdout'),stderr=pin(o/'stderr'),request=pin(o/'request.json'),UTC=datetime.datetime.now(datetime.timezone.utc).isoformat()));print(stdout.decode(errors='replace'));print(stderr.decode(errors='replace'));raise SystemExit(rc)
if __name__=='__main__':main()
