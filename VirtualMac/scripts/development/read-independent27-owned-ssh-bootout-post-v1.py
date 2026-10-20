#!/usr/bin/env python3
"""Read facts after the already completed bootout; never repeats mutation."""
import datetime, getpass, hashlib, importlib.util, json, pathlib, shlex, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
C=N/'independent27-device34-stage-recovery-v35-attempt1/control.py'
OUT=N/'independent27-port22222-owned-relay-bootout-post-readonly-v1-attempt1'

def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())

def prepare():
    assert pin(C)['sha256']=='9042ee747f3180d7d8486781f2adcb20cce3a124bb5d7f3a9e84cf39d1c49981'
    s=importlib.util.spec_from_file_location('actual_recovery35',C)
    c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
    body=c.prefix(0)+c.off_check()+'''
j=user/501/com.mac.virtual.guest-ssh-proxy
rc=0
t=$(launchctl print "$j" 2>&1) || rc=$?
[ "$(printf '%s' "$t" | wc -c | tr -d ' ')" -le 16384 ]
printf 'EXACT_JOB_EXIT %s\nEXACT_JOB_BEGIN\n%s\nEXACT_JOB_END\n' "$rc" "$t"
rc=0
t=$(launchctl print user/501 2>&1) || rc=$?
[ "$(printf '%s' "$t" | wc -c | tr -d ' ')" -le 262144 ]
printf 'USER_DOMAIN_EXIT %s\n' "$rc"
printf '%s\n' "$t" | awk 'index($0,"com.mac.virtual.guest-ssh-proxy"){print "DOMAIN_MATCH",$0;n++} END{print "DOMAIN_MATCH_COUNT",n+0}'
rc=0
t=$(ps -p 429 -o pid=,ppid=,uid=,stat=,comm=,args= 2>&1) || rc=$?
printf 'OLD_PID_PS_EXIT %s\nOLD_PID_PS_BEGIN\n%s\nOLD_PID_PS_END\n' "$rc" "$t"
rc=0
t=$(ps -p 429 -o lstart= 2>&1) || rc=$?
printf 'OLD_PID_START_EXIT %s\nOLD_PID_START_SHA256 %s\n' "$rc" "$(printf '%s\n' "$t" | sha256sum | cut -d ' ' -f1)"
rc=0
t=$(ps -p 429 -o comm= 2>&1) || rc=$?
printf 'OLD_PID_COMM_EXIT %s\nOLD_PID_COMM %s\n' "$rc" "$t"
p=/var/jb/Library/LaunchDaemons/com.mac.virtual.guest-ssh-proxy.plist
[ -f "$p" ] && [ ! -L "$p" ]
printf 'PLIST_CANONICAL %s\nPLIST_METADATA %s\nPLIST_SHA256 %s\n' "$(realpath "$p")" "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$p")" "$(sha256sum "$p" | cut -d ' ' -f1)"
printf 'OWN_BOOTOUT_POST_READONLY_COMPLETE_NO_MUTATION\n'
'''
    return c,'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 40 /var/jb/bin/sh -c '+shlex.quote(body)+'\n',body

def main():
    c,script,_=prepare();assert not OUT.exists();OUT.mkdir()
    (OUT/'read-root.sh').write_text(script)
    request=dict(schema='Actual already-booted-out owned job readonly post request',source=pin(__file__),controller=pin(C),script=pin(OUT/'read-root.sh'),deviceWrites=0,signals=0)
    (OUT/'request.json').write_text(json.dumps(request,indent=2)+'\n')
    password=getpass.getpass('iPad password: ')
    try: rc,out,err,error=c.run_remote(script,b'',True,password)
    finally: password=None
    (OUT/'stdout').write_bytes(out);(OUT/'stderr').write_bytes(err)
    receipt=dict(schema='Actual owned legacy SSH bootout readonly post result',request=pin(OUT/'request.json'),finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),transportExit=rc,transportError=error,stdout=pin(OUT/'stdout'),stderr=pin(OUT/'stderr'),deviceWrites=0,signals=0,trustCacheOperations=0)
    (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
    raise SystemExit(rc)

if __name__=='__main__':main()
