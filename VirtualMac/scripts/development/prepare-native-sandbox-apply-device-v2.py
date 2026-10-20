#!/usr/bin/env python3
"""New once-only packet after V1 was stopped before any mutation or apply."""
import hashlib,json
from pathlib import Path
import subprocess

R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD=N/'native-sandbox-apply-compat-device-v1-attempt1'
D=N/'native-sandbox-apply-compat-device-v2-attempt1'
def pin(p):
 p=Path(p);b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):
 with p.open('x') as f:f.write(json.dumps(v,indent=2)+'\n')
assert pin(OLD/'scope.json')['sha256']=='085bb5352a40192239626db2b73dda5018bd0690081df71d2deb8204f0a79ddc'
assert pin(OLD/'freeze.json')['sha256']=='de54f75b8e1e702f60b4fb5f6144fb5a4369ce56661ae6a3b3061396c080953e'
frozen=json.loads((OLD/'freeze.json').read_text())
for row in frozen['files']:
 assert pin(row['path'])==row,row['path']
actual=json.loads((OLD/'actual-summary.json').read_text())
assert actual['firstFailedAction']=='preflight'
assert [(x['action'],x['exit']) for x in actual['completed']]==[('preflight',8),('post',8)]
assert not any((OLD/('actual-'+a)).exists() for a in ('stage','trust','execute'))
readonly=N/'reopened-owned-app-before-sandbox-readonly-v1-attempt1'
assert pin(readonly/'receipt.json')['sha256']=='8adca77b4f71c92f913558f565182bb3fa22f548ea0b2940eddabf65d73b8ab7'
assert json.loads((readonly/'receipt.json').read_text())['exit']==0
assert b'NO_PROBE_FILES_LEDGER_OR_APPLY_DISPATCHED' in (readonly/'stdout').read_bytes()
source=R/'VirtualMac/scripts/development/native-sandbox-apply-device-control-v1.py'
control=R/'VirtualMac/scripts/development/native-sandbox-apply-device-control-v2.py'
text=source.read_text()
assert text.count('native-sandbox-apply-compat-device-v1-attempt1')==1
text=text.replace('native-sandbox-apply-compat-device-v1-attempt1','native-sandbox-apply-compat-device-v2-attempt1')
with control.open('x') as f:f.write(text)
compile(text,str(control),'exec')
D.mkdir(mode=0o700,exist_ok=False)
copied=[]
for row in frozen['files']:
 p=Path(row['path'])
 if p.parent!=OLD or p.name in ('scope.json','freeze.json'):
  continue
 q=D/p.name;q.write_bytes(p.read_bytes())
 assert q.read_bytes()==p.read_bytes()
 copied.append(dict(source=pin(p),copy=pin(q),wholeBytesIdentical=True))
scope=json.loads((OLD/'scope.json').read_text())
scope['schema']='One self-only native sandbox compatibility device packet v2'
scope['controller']=pin(control)
scope['archive']=pin(D/'products.tar')
for row in scope['ownFiles']:
 if Path(row['local']['path']).parent==OLD:
  row['local']=pin(D/Path(row['local']['path']).name)
for row in scope['scripts']:
 row['script']=pin(D/Path(row['script']['path']).name)
 assert subprocess.run(['/bin/sh','-n',row['script']['path']],capture_output=True,timeout=5).returncode==0
scope.update(priorUnmutatedPacket=pin(OLD/'scope.json'),actualV1PreflightFailure=pin(OLD/'actual-summary.json'),
             actualReadOnlyReinspection=pin(readonly/'receipt.json'),signedCopiedProductIdentical=True,
             noNewSigningOrCodeHashChange=True,priorActualStageTrustOrExecuteCalls=0,
             readyWritten=False,deviceOperations=0,trustCacheAdds=0)
save(D/'scope.json',scope)
save(D/'copy-ledger.json',dict(wholeCopies=copied,controllerOnlyChange='fresh host once-only packet directory',
                              actualDeviceOperations=0,signingReceiptProvenanceRemainsActualV1=True))
save(D/'freeze.json',dict(files=[pin(p) for p in sorted(D.iterdir()) if p.is_file()]+[pin(__file__),pin(source),pin(control),
                             pin(OLD/'scope.json'),pin(OLD/'freeze.json'),pin(OLD/'actual-summary.json'),pin(readonly/'receipt.json')],deviceOperations=0))
print(json.dumps(dict(scope=pin(D/'scope.json'),freeze=pin(D/'freeze.json'),controller=pin(control))))
