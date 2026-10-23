"""Freeze a backed-up, exact App-only delta for the connected development iPad."""
import argparse,hashlib,io,json,pathlib,shlex,tarfile
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--old',type=int,required=True);parser.add_argument('--new',type=int,required=True)
    parser.add_argument('--label',required=True);parser.add_argument('--normal',type=int,required=True);args=parser.parse_args()
    assert args.label.replace('-','').isalnum() and args.label.isascii() and args.label.islower()
    old=json.loads((N/f'complete-dual-signed-app-v{args.old}-attempt1/candidate.json').read_bytes())
    new=json.loads((N/f'complete-dual-signed-app-v{args.new}-attempt1/candidate.json').read_bytes())
    assert old['actualSignature']['embeddedEntitlements']==new['actualSignature']['embeddedEntitlements']
    assert old['runtimeCandidate']==new['runtimeCandidate']
    o=N/(args.label+'-attempt1');o.mkdir(mode=0o700)
    previous=json.loads((N/'bc-parent-identity-device-v237-attempt1/scope.json').read_bytes())
    appRoot=pathlib.Path(previous['files'][0]['path']).parent
    before={str(p.relative_to(old['app'])):pin(p)for p in pathlib.Path(old['app']).rglob('*')if p.is_file()}
    after={str(p.relative_to(new['app'])):pin(p)for p in pathlib.Path(new['app']).rglob('*')if p.is_file()}
    assert before.keys()==after.keys()
    changed=[s for s in after if before[s]['sha256']!=after[s]['sha256']]
    assert 'VirtualMacIndependent27' in changed and set(changed)<= {'VirtualMacIndependent27','_CodeSignature/CodeResources'}
    files=[dict(path=str(appRoot/s),old=before[s],new=after[s],mode='755'if s=='VirtualMacIndependent27'else'644')for s in changed]
    stage='/private/var/mobile/Library/.VM27-'+args.label
    scope=dict(schema=f'App{args.new} App-only update; exact old identities and all permissions preserved',files=files,
        newTrustCacheCDHashes=[new['actualSignature']['cdhash']],stage=stage,runtimeUnchanged=True)
    (o/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
    with tarfile.open(o/'product.tar','w')as archive:
        for i,row in enumerate(files):
            data=pathlib.Path(row['new']['path']).read_bytes();info=tarfile.TarInfo('new-'+str(i));info.size=len(data);info.mode=int(row['mode'],8);archive.addfile(info,io.BytesIO(data))
    body=(N/'native-cache-ownership-device-v235-attempt2/install-root.sh').read_text().split('[ -f /private/preboot/',1)[0]
    assert body.count('976118c0edfd49f74e7c3023dbd9d5a921c5781ced39d577a2adbfaa95cf4d2a')==1
    body=body.replace('/.VM27-native-cache-ownership-v235','/.VM27-'+args.label).replace('976118c0edfd49f74e7c3023dbd9d5a921c5781ced39d577a2adbfaa95cf4d2a',old['binary']['sha256'])
    body=body.replace(' [ "$pid" -gt 1 ]\n',' [ "$pid" -gt 1 ]\n start=$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)\n')
    body=body.replace(' kill -TERM "$pid";',' [ "$(ps -p "$pid" -o lstart= | sha256sum | cut -d \' \' -f1)" = "$start" ]\n kill -TERM "$pid";')
    q=shlex.quote
    for row in files:body+=f'[ -f {q(row["path"])} ] && [ ! -L {q(row["path"])} ]\n[ "$(sha256sum {q(row["path"])} | cut -d \' \' -f1)" = {row["old"]["sha256"]} ]\n'
    body+='[ ! -e "$STAGE" ] && [ ! -L "$STAGE" ]\nmkdir -m 700 "$STAGE"\ncat > "$STAGE/product.tar"\n'
    body+=f'[ "$(sha256sum "$STAGE/product.tar" | cut -d \' \' -f1)" = {pin(o/"product.tar")["sha256"]} ]\ntar -xpf "$STAGE/product.tar" -C "$STAGE"\n'
    for i,row in enumerate(files):body+=f'cp -p {q(row["path"])} "$STAGE/backup-{i}"\n[ "$(sha256sum "$STAGE/new-{i}" | cut -d \' \' -f1)" = {row["new"]["sha256"]} ]\n'
    body+='jbctl trustcache add '+new['actualSignature']['cdhash']+'\n'
    for i,row in enumerate(files):body+=f'chown 501:501 "$STAGE/new-{i}"\nchmod {row["mode"]} "$STAGE/new-{i}"\nmv "$STAGE/new-{i}" {q(row["path"])}\n[ "$(sha256sum {q(row["path"])} | cut -d \' \' -f1)" = {row["new"]["sha256"]} ]\n'
    marker='OWNED_APP_ONLY_UPDATE_COMPLETE'
    body+='cp -p /tmp/VirtualMacIndependent27.log "$STAGE/previous-app-log"\n: > /tmp/VirtualMacIndependent27.log\nprintf \'OWNED_APP_ONLY_UPDATE_COMPLETE\\n\'\n'
    (o/'install-root.sh').write_text(body)
    controller=(N/'root-install-native-bc-app254-v2.py').read_text().replace('native-bc-device-v231-attempt2',o.name).replace('NATIVE_BC_UPDATE_COMPLETE',marker)
    controller=controller.replace('n=pathlib.Path(__file__).resolve().parent;','n=pathlib.Path(__file__).resolve().parent.parent;')
    (o/'control.py').write_text(controller)
    start=(N/'normal290-bc-parent-identity-start-v1.sh').read_text()
    baseline=json.loads((N/'complete-dual-signed-app-v260-attempt1/candidate.json').read_bytes())['binary']['sha256']
    assert start.count(baseline)==1
    start=start.replace(baseline,new['binary']['sha256']).replace('APP260_BC_PARENT_IDENTITY_NORMAL290',f'APP{args.new}_HIBERNATE_NORMAL{args.normal}')
    (o/'start-root.sh').write_text(start)
    print(json.dumps(dict(scope=pin(o/'scope.json'),files=len(files),newHashes=scope['newTrustCacheCDHashes'])))
if __name__=='__main__':main()
