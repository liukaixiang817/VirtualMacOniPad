#!/usr/bin/env python3
"""Root reads existing VNC tool identity and captures a bounded help invocation."""
import datetime,getpass,hashlib,importlib.util,json,pathlib,shlex,sys
sys.dont_write_bytecode=True
B=pathlib.Path(__file__).resolve().parent;R=B.parents[2];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
p=B/'vnc-independent27-input-v3.py';assert hashlib.sha256(p.read_bytes()).hexdigest()=='fb4c7788c81af51ee76f1d63972cc7a9415e76381b2729b2c57969de38d7df66'
s=importlib.util.spec_from_file_location('vnc3_diagnostic',p);v=importlib.util.module_from_spec(s);s.loader.exec_module(v);c=v.load_controller()
out=N/'independent27-normal107-existing-vnc-tool-v1-attempt1';assert not out.exists();out.mkdir(mode=0o700)
body=c.prefix(0)+r'''
p=/private/var/mobile/VirtualMacDebug/trollvncserver
[ "$(realpath "$p")" = "$p" ]
[ -f "$p" ] && [ ! -L "$p" ]
printf 'OWN_VNC_TOOL_META ';stat -c %d:%i:%u:%g:%a:%h:%s "$p"
sha256sum "$p"
ps -axo pid=,ppid=,uid=,comm= | awk -v p="$p" '$4==p {print "OWN_EXISTING_VNC_PROCESS",$0}'
printf 'OWN_VNC_HELP_BEGIN\n'
rc=0
/var/jb/usr/bin/timeout --signal=TERM --kill-after=2 3 "$p" --help || rc=$?
printf 'OWN_VNC_HELP_END status=%s\n' "$rc"
printf 'OWN_VNC_AFTER_PROCESS_BEGIN\n'
ps -axo pid=,ppid=,uid=,comm= | awk -v p="$p" '$4==p {print "OWN_EXISTING_VNC_PROCESS",$0}'
'''
script=c.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 15 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
(out/'read-root.sh').write_text(script)
pw=getpass.getpass('iPad password: ')
try:rc,stdout,stderr,error=c.run_remote(script,b'',True,pw)
finally:pw=None
(out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr)
row=dict(transportExit=rc,error=error,finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),trustCacheOperations=0,deviceFileWrites=0,boundedToolHelpSeconds=3)
(out/'receipt.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps(row));print(stdout.decode(errors='replace'));print(stderr.decode(errors='replace'));raise SystemExit(rc)
