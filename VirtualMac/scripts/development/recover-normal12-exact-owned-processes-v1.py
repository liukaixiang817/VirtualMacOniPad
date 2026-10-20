#!/usr/bin/env python3
"""Root: close only two actual captured Normal12 generations, retain real receipts."""
import getpass,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P=N/'independent27-app16-normal-guest-lifecycle-v12-attempt1';I=N/'independent27-cache-context-device-v2-attempt1'
O=N/'independent27-normal12-exact-captured-cleanup-v1-attempt1'
def pin(p):
 d=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
sp=importlib.util.spec_from_file_location('normal12_true_transport',I/'control.py');base=importlib.util.module_from_spec(sp);sp.loader.exec_module(base)
start=json.loads((P/'device-receipts/start/receipt.json').read_bytes());post=json.loads((P/'device-receipts/post/receipt.json').read_bytes())
base.need(start['transportExit']==78 and post['transportExit']==8 and not start['handoffACKAttemptRecorded'],'actual no-ACK cleanup failure')
text=base.exact(start['stdout']).read_text();base.need('OWN_APP_ID 17608 1 501 4bbeb843a255741f50dabee4d619d529077565b0378b35fa28d0368a4ae6c9a3 'in text and 'OWN_CHILD_ID 17633 17608 501 a15e62495540874de64d1598966e037483be1b53b1b6ce167a966e2dd2adf8a0 'in text,'only actual captured generations')
base.need(not O.exists(),'new recovery once');O.mkdir(mode=0o700)
body=base.prefix(0)+base.PROCESS_FUNCTIONS+'''own_app_pid=17608
own_app_start=4bbeb843a255741f50dabee4d619d529077565b0378b35fa28d0368a4ae6c9a3
own_child_pid=17633
own_child_start=a15e62495540874de64d1598966e037483be1b53b1b6ce167a966e2dd2adf8a0
# No enrollment and no signal to another generation. Native checks precede each signal.
signal_own TERM "$own_child_pid" "$OWN_CHILD_MAIN" "$own_child_start" child
signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
sleep 1
signal_own KILL "$own_child_pid" "$OWN_CHILD_MAIN" "$own_child_start" child
signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
'''+base.off_check()+"printf 'OWN_NORMAL12_EXACT_CAPTURED_CLEANUP_OFF\\n'\n"
script=base.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
base.need(subprocess.run(['/bin/sh','-n'],input=body.encode(),capture_output=True).returncode==0,'actual bounded cleanup syntax')
password=getpass.getpass('iPad password: ')
try:
 for action,s in [('exact-cleanup',script),('post',(P/'post.sh').read_text())]:
  q=O/action;q.mkdir(mode=0o700);(q/'script.sh').write_text(s);save(q/'request.json',dict(action=action,script=pin(q/'script.sh'),actualFailure=pin(P/'device-receipts/start/receipt.json'),actualFailedPost=pin(P/'device-receipts/post/receipt.json'),capturedOnly=True,guestBootRequested=False))
  code,out,err,problem=base.run_remote(s,b'',True,password);(q/'stdout').write_bytes(out);(q/'stderr').write_bytes(err);save(q/'receipt.json',dict(action=action,transportExit=code,transportError=problem,request=pin(q/'request.json'),stdout=pin(q/'stdout'),stderr=pin(q/'stderr')))
  print(action,code,out.decode(errors='replace')[-2300:],flush=True);base.need(code==0,'accurate recovery failed; retained captured responsibility')
finally:password=None
