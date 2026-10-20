import pathlib,importlib.util,sys,json,getpass,shlex
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';I=N/'independent27-cache-context-device-v2-attempt1'
s=importlib.util.spec_from_file_location('actual_pid_read_transport',I/'control.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
o=N/'independent27-normal12-captured-pid-state-readonly-v1-attempt1';m.need(not o.exists(),'fresh read');o.mkdir(mode=0o700)
b=m.prefix(0)+'''ps -p 17608,17633 -o pid=,ppid=,uid=,state=,lstart=,comm= || true
for own_pid in 17608 17633;do
 printf 'OWN_CAPTURED_PID_START_HASH %s ' "$own_pid"
 ps -p "$own_pid" -o lstart= | sha256sum
 done
'''
a=m.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 10 /var/jb/bin/sh -c '+shlex.quote(b)+'\n';(o/'script.sh').write_text(a)
p=getpass.getpass('iPad password: ');code,out,err,problem=m.run_remote(a,b'',True,p);p=None
(o/'stdout').write_bytes(out);(o/'stderr').write_bytes(err);(o/'receipt.json').write_text(json.dumps(dict(transportExit=code,transportError=problem,script=m.pin(o/'script.sh'),stdout=m.pin(o/'stdout'),stderr=m.pin(o/'stderr')),indent=2)+'\n');print(code,out.decode())
