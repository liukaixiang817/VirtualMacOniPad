"""Freeze the exact installed App264/Runtime166 to App265/Runtime167 delta."""
from pathlib import Path
import json, plistlib, hashlib, tarfile, io, shlex
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'hibernate-vt-restore-device-v249-attempt1';O.mkdir(mode=0o700,exist_ok=True)
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
a=json.loads((N/'complete-dual-signed-app-v271-attempt1/candidate.json').read_bytes());b=json.loads((N/'complete-dual-signed-app-v272-attempt1/candidate.json').read_bytes());assert a['actualSignature']['embeddedEntitlements']==b['actualSignature']['embeddedEntitlements']
x=json.loads((N/'independent27-signed-runtime-hibernate-fatal-v173-attempt1/candidate.json').read_bytes());y=json.loads((N/'independent27-signed-runtime-vt-restore-v174-attempt1/candidate.json').read_bytes());xm=plistlib.loads(Path(x['manifest']['path']).read_bytes());ym=plistlib.loads(Path(y['manifest']['path']).read_bytes());xr={r['id']:r for r in xm['files']};yr={r['id']:r for r in ym['files']};assert set(xr)==set(yr)
prior=json.loads((N/'native-cache-ownership-device-v235-attempt2/scope.json').read_bytes());appRoot=str(Path(prior['files'][0]['path']).parent);root=x['canonicalDeviceRoot'];assert root==y['canonicalDeviceRoot'];files=[]
for rel in ['VirtualMacIndependent27','_CodeSignature/CodeResources']:
 old=pin(Path(a['app'])/rel);new=pin(Path(b['app'])/rel)
 if old['sha256']!=new['sha256']:files.append(dict(path=appRoot+'/'+rel,old=old,new=new,mode='755'if rel=='VirtualMacIndependent27'else'644'))
for ident,r in yr.items():
 old=pin(Path(x['runtimeRoot'])/xr[ident]['path']);new=pin(Path(y['runtimeRoot'])/r['path']);assert old['sha256']==xr[ident]['sha256'] and new['sha256']==r['sha256']
 if old['sha256']!=new['sha256']:files.append(dict(path=root+'/'+r['path'],old=old,new=new,mode='755'if r['kind']=='mach-o'else'644'))
files.append(dict(path=root+'/VM27IndependentRuntimeManifestV1.plist',old=pin(x['manifest']['path']),new=pin(y['manifest']['path']),mode='644'))
assert len(files)==7,len(files)
oldProof=json.loads(Path(x['signatureVerification']['path']).read_bytes());newProof=json.loads(Path(y['signatureVerification']['path']).read_bytes());oldV=next(z['embeddedEntitlements']for z in oldProof['actualSignedFiles']if z['key']=='com.apple.Virtualization.VirtualMachine');newV=next(z['embeddedEntitlements']for z in newProof['actualSignedFiles']if z['key']=='com.apple.Virtualization.VirtualMachine');assert oldV==newV
hashes=sorted(set(y['actualChangedRuntimeCDHashes']+[b['actualSignature']['cdhash']]))
assert len(hashes)==4
stage='/private/var/mobile/Library/.VM27-hibernate-vt-restore-v249'
scope=dict(schema='App272 Runtime174 restore-only VT availability guard; saved state format and entitlements unchanged',files=files,newTrustCacheCDHashes=hashes,stage=stage,VMMKeychainGroupAdded=False,AppPermissionsUnchanged=True,CPU94GICStateImplemented=True,guestToolsV4Unchanged=True,nativeVMMCodeUnchanged=True,nativeKernelOperationsUnchanged=True,packetContentNotRead=True,deviceExecutionPending=True)
(O/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
with tarfile.open(O/'product.tar','w')as t:
 for i,r in enumerate(files):
  data=Path(r['new']['path']).read_bytes();info=tarfile.TarInfo('new-'+str(i));info.mode=int(r['mode'],8);info.size=len(data);t.addfile(info,io.BytesIO(data))
body=(N/'native-cache-ownership-device-v235-attempt2/install-root.sh').read_text().split('[ -f /private/preboot/',1)[0]
body=body.replace('/.VM27-native-cache-ownership-v235','/.VM27-hibernate-vt-restore-v249').replace('976118c0edfd49f74e7c3023dbd9d5a921c5781ced39d577a2adbfaa95cf4d2a',a['binary']['sha256'])
body=body.replace(' [ "$pid" -gt 1 ]\n',' [ "$pid" -gt 1 ]\n start=$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)\n').replace(' kill -TERM "$pid";',' [ "$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)" = "$start" ]\n kill -TERM "$pid";')
q=shlex.quote
for r in files:body+=f'[ -f {q(r["path"])} ] && [ ! -L {q(r["path"])} ]\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["old"]["sha256"]} ]\n'
body+='[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ]\nmkdir -m 700 "$STAGE"\ncat > "$STAGE/product.tar"\n'
body+=f'[ "$(sha256sum "$STAGE/product.tar" | cut -d \' \' -f1)" = {pin(O/"product.tar")["sha256"]} ]\ntar -xpf "$STAGE/product.tar" -C "$STAGE"\n'
for i,r in enumerate(files):body+=f'cp -p {q(r["path"])} "$STAGE/backup-{i}"\n[ "$(sha256sum "$STAGE/new-{i}" | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
for h in hashes:body+='jbctl trustcache add '+h+'\n'
for i,r in enumerate(files):body+=f'chown 501:501 "$STAGE/new-{i}"\nchmod {r["mode"]} "$STAGE/new-{i}"\nmv "$STAGE/new-{i}" {q(r["path"])}\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
body+='cp -p /tmp/VirtualMacIndependent27.log "$STAGE/previous-app-log"\n: > /tmp/VirtualMacIndependent27.log\nprintf \'HIBERNATE_VT_RESTORE_UPDATE_COMPLETE\\n\'\n';(O/'install-root.sh').write_text(body)
controller=(N/'root-install-native-bc-app254-v2.py').read_text().replace('native-bc-device-v231-attempt2',O.name).replace('NATIVE_BC_UPDATE_COMPLETE','HIBERNATE_VT_RESTORE_UPDATE_COMPLETE');(N/'root-install-hibernate-vt-restore-app272-v1.py').write_text(controller)

print(json.dumps(dict(scope=pin(O/'scope.json'),files=len(files),newHashes=hashes)))
