"""Freeze the exact installed App258/Runtime163 to App259/Runtime164 delta."""
from pathlib import Path
import json, plistlib, hashlib, tarfile, io, shlex
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'bc-thread-local-device-v236-attempt2';O.mkdir(mode=0o700)
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
a=json.loads((N/'complete-dual-signed-app-v258-attempt1/candidate.json').read_bytes());b=json.loads((N/'complete-dual-signed-app-v259-attempt1/candidate.json').read_bytes());assert a['actualSignature']['embeddedEntitlements']==b['actualSignature']['embeddedEntitlements']
x=json.loads((N/'independent27-signed-runtime-gic-wake-subset-v163-attempt1/candidate.json').read_bytes());y=json.loads((N/'independent27-signed-runtime-bc-thread-local-v164-attempt1/candidate.json').read_bytes());xm=plistlib.loads(Path(x['manifest']['path']).read_bytes());ym=plistlib.loads(Path(y['manifest']['path']).read_bytes());xr={r['id']:r for r in xm['files']};yr={r['id']:r for r in ym['files']};assert set(xr)==set(yr)
prior=json.loads((N/'native-cache-ownership-device-v235-attempt2/scope.json').read_bytes());appRoot=str(Path(prior['files'][0]['path']).parent);root=x['canonicalDeviceRoot'];assert root==y['canonicalDeviceRoot'];files=[]
for rel in ['VirtualMacIndependent27','_CodeSignature/CodeResources']:
 old=pin(Path(a['app'])/rel);new=pin(Path(b['app'])/rel)
 if old['sha256']!=new['sha256']:files.append(dict(path=appRoot+'/'+rel,old=old,new=new,mode='755'if rel=='VirtualMacIndependent27'else'644'))
for ident,r in yr.items():
 old=pin(Path(x['runtimeRoot'])/xr[ident]['path']);new=pin(Path(y['runtimeRoot'])/r['path']);assert old['sha256']==xr[ident]['sha256'] and new['sha256']==r['sha256']
 if old['sha256']!=new['sha256']:files.append(dict(path=root+'/'+r['path'],old=old,new=new,mode='755'if r['kind']=='mach-o'else'644'))
files.append(dict(path=root+'/VM27IndependentRuntimeManifestV1.plist',old=pin(x['manifest']['path']),new=pin(y['manifest']['path']),mode='644'))
assert len(files)==9,len(files)
for ident in xr:
 if 'VM27HV' in xr[ident]['path']:assert xr[ident]==yr[ident]
hashes=sorted(set(y['actualChangedRuntimeCDHashes']+[b['actualSignature']['cdhash']]))
assert len(hashes)==5
stage='/private/var/mobile/Library/.VM27-bc-thread-local-v236'
scope=dict(schema='App259 Runtime164 GPU24 thread-local BC view validation without shared texture mutation',files=files,newTrustCacheCDHashes=hashes,stage=stage,permissionsUnchanged=True,CPU93Unchanged=True,guestToolsV4Unchanged=True,nativeVMMInstructionsWhole=True,deviceExecutionPending=True)
(O/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
with tarfile.open(O/'product.tar','w')as t:
 for i,r in enumerate(files):
  data=Path(r['new']['path']).read_bytes();info=tarfile.TarInfo('new-'+str(i));info.mode=int(r['mode'],8);info.size=len(data);t.addfile(info,io.BytesIO(data))
body=(N/'native-cache-ownership-device-v235-attempt2/install-root.sh').read_text().split('[ -f /private/preboot/',1)[0]
body=body.replace('/.VM27-native-cache-ownership-v235','/.VM27-bc-thread-local-v236').replace('976118c0edfd49f74e7c3023dbd9d5a921c5781ced39d577a2adbfaa95cf4d2a',a['binary']['sha256'])
body=body.replace(' [ "$pid" -gt 1 ]\n',' [ "$pid" -gt 1 ]\n start=$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)\n').replace(' kill -TERM "$pid";',' [ "$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)" = "$start" ]\n kill -TERM "$pid";')
q=shlex.quote
for r in files:body+=f'[ -f {q(r["path"])} ] && [ ! -L {q(r["path"])} ]\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["old"]["sha256"]} ]\n'
body+='[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ]\nmkdir -m 700 "$STAGE"\ncat > "$STAGE/product.tar"\n'
body+=f'[ "$(sha256sum "$STAGE/product.tar" | cut -d \' \' -f1)" = {pin(O/"product.tar")["sha256"]} ]\ntar -xpf "$STAGE/product.tar" -C "$STAGE"\n'
for i,r in enumerate(files):body+=f'cp -p {q(r["path"])} "$STAGE/backup-{i}"\n[ "$(sha256sum "$STAGE/new-{i}" | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
for h in hashes:body+='jbctl trustcache add '+h+'\n'
for i,r in enumerate(files):body+=f'chown 501:501 "$STAGE/new-{i}"\nchmod {r["mode"]} "$STAGE/new-{i}"\nmv "$STAGE/new-{i}" {q(r["path"])}\n[ "$(sha256sum {q(r["path"])} | cut -d \' \' -f1)" = {r["new"]["sha256"]} ]\n'
body+='cp -p /tmp/VirtualMacIndependent27.log "$STAGE/previous-app-log"\n: > /tmp/VirtualMacIndependent27.log\nprintf \'BC_THREAD_LOCAL_UPDATE_COMPLETE\\n\'\n';(O/'install-root.sh').write_text(body)
controller=(N/'root-install-native-bc-app254-v2.py').read_text().replace('native-bc-device-v231-attempt2',O.name).replace('NATIVE_BC_UPDATE_COMPLETE','BC_THREAD_LOCAL_UPDATE_COMPLETE');(N/'root-install-bc-thread-local-app259-v1.py').write_text(controller)
s=(N/'normal286-native-cache-ownership-start-v1.sh').read_text().replace(a['binary']['sha256'],b['binary']['sha256']).replace('APP258_NATIVE_CACHE_OWNERSHIP_NORMAL286','APP259_BC_THREAD_LOCAL_NORMAL289');(N/'normal289-bc-thread-local-start-v1.sh').write_text(s)
print(json.dumps(dict(scope=pin(O/'scope.json'),files=len(files),newHashes=hashes)))
