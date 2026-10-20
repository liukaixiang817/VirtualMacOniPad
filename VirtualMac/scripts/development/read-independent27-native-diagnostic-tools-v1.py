#!/usr/bin/env python3
"""Root-only bounded read of existing diagnostic tool availability; no probes installed."""
import datetime, getpass, hashlib, importlib.util, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
C=N/'independent27-run-tail-trace-device-v38-attempt1/control.py'
OUT=N/'independent27-native-diagnostic-tools-readonly-v1-attempt1'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 assert pin(C)['sha256']=='019ea5d0ab5868741d8c8189fb52635efc1b046018605b57c8eb4e48d8e9fb07'
 spec=importlib.util.spec_from_file_location('actual_device38_tools_readonly',C)
 c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
 body=c.prefix(0)+c.off_check()+'''
for name in sample spindump vmmap lsof ps;do
 p=$(command -v "$name" || true)
 if [ -n "$p" ];then printf 'EXISTING_TOOL %s %s\n' "$name" "$p";else printf 'MISSING_TOOL %s\n' "$name";fi
done
rc=0
t=$(ps -L 2>&1) || rc=$?
[ "$(printf '%s' "$t" | wc -c | tr -d ' ')" -le 32768 ]
printf 'PS_KEYWORDS_EXIT %s\nPS_KEYWORDS_BEGIN\n%s\nPS_KEYWORDS_END\n' "$rc" "$t"
printf 'NATIVE_TOOLS_READONLY_COMPLETE_NO_PROCESS_INSPECTION_OR_INSTALL\n'
'''
 script='set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 check=subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True)
 assert check.returncode==0 and not OUT.exists()
 OUT.mkdir(mode=0o700);(OUT/'read-root.sh').write_text(script)
 request=dict(source=pin(__file__),controller=pin(C),script=pin(OUT/'read-root.sh'),deviceWrites=0,signals=0,trustCacheOperations=0)
 (OUT/'request.json').write_text(json.dumps(request,indent=2)+'\n')
 password=getpass.getpass('iPad password: ')
 try:rc,out,err,error=c.run_remote(script,b'',True,password)
 finally:password=None
 (OUT/'stdout').write_bytes(out);(OUT/'stderr').write_bytes(err)
 receipt=dict(request=pin(OUT/'request.json'),finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),transportExit=rc,transportError=error,stdout=pin(OUT/'stdout'),stderr=pin(OUT/'stderr'),deviceWrites=0,signals=0,trustCacheOperations=0)
 (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
 raise SystemExit(rc)
if __name__=='__main__':main()
