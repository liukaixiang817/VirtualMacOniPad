#!/usr/bin/env python3
"""Root cleans only the exact VNC server created by its failed UID0 admission."""
import datetime,getpass,hashlib,importlib.util,json,pathlib,shlex,sys
sys.dont_write_bytecode=True
B=pathlib.Path(__file__).resolve().parent;R=B.parents[2];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
p=B/'vnc-independent27-input-v3.py';assert hashlib.sha256(p.read_bytes()).hexdigest()=='fb4c7788c81af51ee76f1d63972cc7a9415e76381b2729b2c57969de38d7df66'
s=importlib.util.spec_from_file_location('vnc3_diagnostic',p);v=importlib.util.module_from_spec(s);s.loader.exec_module(v);c=v.load_controller()
out=N/'independent27-normal107-vnc3-own-cleanup-v1-attempt1';assert not out.exists();out.mkdir(mode=0o700)
body=c.prefix(0)+'\np=/private/var/mobile/VirtualMacDebug/trollvncserver\n[ "$(realpath "$p")" = "$p" ] && [ -f "$p" ] && [ ! -L "$p" ]\n[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$p")" = 16777223:45453317:501:501:755:1:3620672 ]\n[ "$(sha256sum "$p" | cut -d \' \' -f1)" = 2ecf179b7c527f9321991864b23f4a433293a7cea0be2c43b235c59e035c0f36 ]\npid=94239\nrow=$(ps -p "$pid" -o pid=,ppid=,uid=,comm= | awk \'{$1=$1;print}\')\n[ "$row" = "94239 1 501 $p" ]\nstart=$(ps -p "$pid" -o lstart=)\nstart_epoch=$(LC_ALL=C TZ=UTC date -d "$start" +%s)\n[ "$start_epoch" -ge 1792317498 ] && [ "$start_epoch" -le 1792317533 ]\nprintf \'OWN_VNC3_CREATED_ID %s startEpoch=%s lstart=%s\\n\' "$row" "$start_epoch" "$start"\nverify() {\n [ "$(ps -p "$pid" -o pid=,ppid=,uid=,comm= | awk \'{$1=$1;print}\')" = "$row" ]\n [ "$(ps -p "$pid" -o lstart=)" = "$start" ]\n}\nfor signal in TERM KILL;do\n live=$(ps -p "$pid" -o pid= || true)\n [ -n "$live" ] || { printf \'OWN_VNC3_EXITED\\n\';exit 0; }\n state=$(ps -p "$pid" -o state=)\n case "$state" in *Z*) printf \'OWN_VNC3_ZOMBIE_NO_SIGNAL\\n\';exit 0;;esac\n verify\n kill -"$signal" "$pid"\n printf \'OWN_VNC3_SIGNALED %s %s\\n\' "$signal" "$pid"\n sleep 1\ndone\n[ -z "$(ps -p "$pid" -o pid= || true)" ]\nprintf \'OWN_VNC3_EXACT_CLEANUP_COMPLETE\\n\'\n'
script=c.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 15 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
(out/'read-root.sh').write_text(script)
pw=getpass.getpass('iPad password: ')
try:rc,stdout,stderr,error=c.run_remote(script,b'',True,pw)
finally:pw=None
(out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr)
row=dict(transportExit=rc,error=error,finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),trustCacheOperations=0,deviceFileWrites=0,exactOwnedVNCServerCleanup=True)
(out/'receipt.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps(row));print(stdout.decode(errors='replace'));print(stderr.decode(errors='replace'));raise SystemExit(rc)
