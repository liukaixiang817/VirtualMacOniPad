"""App273 -> App274 only. Existing Runtime174 and every entitlement stay whole."""
from pathlib import Path
import json,hashlib,tarfile,io,shlex
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'hibernate-relaunch-device-v251-attempt2';O.mkdir(mode=0o700)
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
a=json.loads((N/'complete-dual-signed-app-v273-attempt1/candidate.json').read_bytes());b=json.loads((N/'complete-dual-signed-app-v274-attempt1/candidate.json').read_bytes());assert a['actualSignature']['embeddedEntitlements']==b['actualSignature']['embeddedEntitlements']
prior=json.loads((N/'hibernate-vt-restore-device-v249-attempt1/scope.json').read_bytes());appRoot=str(Path(prior['files'][0]['path']).parent)
files=[]
for rel in ['VirtualMacIndependent27','_CodeSignature/CodeResources']:
 old=pin(Path(a['app'])/rel);new=pin(Path(b['app'])/rel)
 if old['sha256']==new['sha256']:continue
 files.append(dict(path=appRoot+'/'+rel,old=old,new=new,mode='755'if rel=='VirtualMacIndependent27'else'644'))
stage='/private/var/mobile/Library/.VM27-hibernate-relaunch-v251';hashes=[b['actualSignature']['cdhash']]
scope=dict(schema='App274 active-app automatic Hibernate relaunch and background epoch isolation; background Hibernate, durable marker, automatic relaunch, saved-session library controls and localized UI; Runtime174 and entitlements unchanged',files=files,newTrustCacheCDHashes=hashes,stage=stage,AppPermissionsUnchanged=True,VMMKeychainGroupAdded=False,allRuntimeFilesUnchanged=True,deviceExecutionPending=True)
(O/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
with tarfile.open(O/'product.tar','w')as t:
 for i,r in enumerate(files):
  data=Path(r['new']['path']).read_bytes();info=tarfile.TarInfo('new-'+str(i));info.mode=int(r['mode'],8);info.size=len(data);t.addfile(info,io.BytesIO(data))
body=(N/'native-cache-ownership-device-v235-attempt2/install-root.sh').read_text().split('[ -f /private/preboot/',1)[0]
body=body.replace('/.VM27-native-cache-ownership-v235','/.VM27-hibernate-relaunch-v251').replace('976118c0edfd49f74e7c3023dbd9d5a921c5781ced39d577a2adbfaa95cf4d2a',a['binary']['sha256'])
body=body.replace(' [ "$pid" -gt 1 ]\n',' [ "$pid" -gt 1 ]\n start=$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)\n').replace(' kill -TERM "$pid";',' [ "$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)" = "$start" ]\n kill -TERM "$pid";')
q=shlex.quote
for r in files:body+=f'[ -f {q(r["path"])} ] && [ ! -L {q(r["path"])} ]\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["old"]["sha256"]} ]\n'
body+='[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ]\nmkdir -m 700 "$STAGE"\ncat > "$STAGE/product.tar"\n'
body+=f'[ "$(sha256sum "$STAGE/product.tar" | cut -d \' \' -f1)" = {pin(O/"product.tar")["sha256"]} ]\ntar -xpf "$STAGE/product.tar" -C "$STAGE"\n'
for i,r in enumerate(files):body+=f'cp -p {q(r["path"])} "$STAGE/backup-{i}"\n[ "$(sha256sum "$STAGE/new-{i}" | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
for h in hashes:body+='jbctl trustcache add '+h+'\n'
for i,r in enumerate(files):body+=f'chown 501:501 "$STAGE/new-{i}"\nchmod {r["mode"]} "$STAGE/new-{i}"\nmv "$STAGE/new-{i}" {q(r["path"])}\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
body+='cp -p /tmp/VirtualMacIndependent27.log "$STAGE/previous-app-log"\n: > /tmp/VirtualMacIndependent27.log\nprintf \'HIBERNATE_RELAUNCH_UPDATE_COMPLETE\\n\'\n';(O/'install-root.sh').write_text(body)
controller=(N/'root-install-hibernate-background-app273-v1.py').read_text().replace('hibernate-background-device-v250-attempt1',O.name).replace('HIBERNATE_BACKGROUND_UPDATE_COMPLETE','HIBERNATE_RELAUNCH_UPDATE_COMPLETE');(N/'root-install-hibernate-relaunch-app274-v1.py').write_text(controller)
print(json.dumps(dict(scope=pin(O/'scope.json'),files=len(files),newHashes=hashes)))
