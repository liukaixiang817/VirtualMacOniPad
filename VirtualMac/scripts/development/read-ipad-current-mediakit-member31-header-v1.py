"""Capture only fixed main and .31 headers; add .31 after actual identity equality."""
from pathlib import Path
import base64,datetime,hashlib,importlib.util,json,re,struct,subprocess,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'ipad-current-mediakit-member31-header-readonly-v1'
BASE='/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
def need(v,why):
    if not v:raise ValueError(why)
def pin(p):
    p=Path(p);b=p.read_bytes();need(p.is_absolute() and p.is_file() and not p.is_symlink(),'regular absolute input')
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    need(not D.exists(),'new actual capture directory')
    oldpath=N/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    need(pin(oldpath)['sha256']=='b78e135585642c92910f37c2cbf1e3575d7fa069532e6155f270857287e315f1','actual prior seventeen header identity')
    old=json.loads(oldpath.read_bytes());need(len(old['headers'])==17 and '31' not in {r['name'] for r in old['headers']},'exact existing members')
    plan=N/'ipad-current-mediakit-command-prefix-plan-v3';derivation=json.loads((plan/'derivation.json').read_bytes())
    need(pin(plan/'request.json')['sha256']=='80f901fb4abc0842550c69b76bf139a8c123d2739d5e701a80c9f011f4b07f69','bounded subsequent prefix request')
    archive=Path(derivation['archivedHeader']['path']);need(pin(archive)==derivation['archivedHeader'],'archive only expected identity')
    rows=[dict(name='main',path=BASE,UUID='1995ea169d0a33a0b78962cf99891168',sha256='307a229e3e3a2157562d3fe04a2955d898cdaa74dbb4ecfb0e59687fcfd06992'),
        dict(name='31',path=BASE+'.31',UUID='8310ea2468ca31f89f68ef2075185ea2',sha256='295891913737dbbc87c794e67a6800265238914816a5d258183a03ac5a110d8c')]
    remote_path=R/'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py';need(pin(remote_path)['sha256']=='29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424','fixed readonly transport')
    script='set -eu\nexport PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin\n[ "$(id -u)" = 0 ]\n[ "$(sysctl -n hw.machine)" = iPad14,6 ]\n[ "$(sysctl -n kern.osversion)" = 20B101 ]\n'
    for row in rows:
        p=row['path'];name=row['name'];script+=f'''[ -f '{p}' ]
[ ! -L '{p}' ]
[ "$(stat -c '%s' '{p}')" -ge 4096 ]
META_{name}=$(stat -c '%u:%g:%a:%h:%s:%d:%i' '{p}')
[ "$(dd if='{p}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)" = '{row['sha256']}' ]
'''
    for row in rows:
        script+=f"printf 'BEGIN_BASE64 {row['name']}\\n'\ndd if='{row['path']}' bs=4096 count=1 status=none | base64\nprintf '\\nEND_BASE64 {row['name']}\\n'\n"
    for row in rows:
        script+=f'''[ "$(stat -c '%u:%g:%a:%h:%s:%d:%i' '{row['path']}')" = "$META_{row['name']}" ]
[ "$(dd if='{row['path']}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)" = '{row['sha256']}' ]
'''
    script+="printf 'FINAL_MAIN_AND_MEMBER31_HEADERS_MATCH\\n'\n"
    need(subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True).returncode==0,'shell syntax')
    D.mkdir(mode=0o700);(D/'reader-source.py').write_bytes(Path(__file__).read_bytes());(D/'script.sh').write_text(script)
    save(D/'manifest.json',dict(fixedFiles=rows,requestedBytes=8192,deviceWrites=0))
    spec=importlib.util.spec_from_file_location('mediakit_header_remote',remote_path);remote=importlib.util.module_from_spec(spec);spec.loader.exec_module(remote)
    remote.IPAD_SSH=['ssh','-p','2221','-o','ConnectTimeout=8','-o','ControlMaster=no','-o','ControlPath=none',
        '-o','UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts','-o','StrictHostKeyChecking=yes','mobile@127.0.0.1']
    result=remote.run(script,device='ipad',root=True,timeout=45)
    (D/'stdout').write_bytes(result.stdout);(D/'stderr').write_bytes(result.stderr)
    receipt=dict(schema='Actual fixed main and MediaKit member31 readonly header capture v1',recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        transportExit=result.returncode,requestedBytes=8192,deviceWrites=0,nativeCPUCalls=0,nativeVMCalls=0,newFrameworksLoaded=0,
        reader=pin(D/'reader-source.py'),manifest=pin(D/'manifest.json'),script=pin(D/'script.sh'),stdout=pin(D/'stdout'),stderr=pin(D/'stderr'))
    save(D/'receipt.json',receipt);need(result.returncode==0 and result.stdout.endswith(b'FINAL_MAIN_AND_MEMBER31_HEADERS_MATCH\n'),'actual bounded header capture completed')
    frames=re.findall(rb'BEGIN_BASE64 (main|31)\n(.*?)\nEND_BASE64 \1\n',result.stdout,re.S);need(len(frames)==2,'exact two actual frames')
    captured=[]
    for row,(name,text) in zip(rows,frames):
        need(name.decode()==row['name'],'exact frame order');raw=base64.b64decode(re.sub(rb'\s',b'',text),validate=True)
        need(len(raw)==4096 and hashlib.sha256(raw).hexdigest()==row['sha256'] and raw[88:104].hex()==row['UUID'],'actual complete header identity')
        off,count=struct.unpack_from('<II',raw,16);need(0<count<=8 and off+32*count<=4096,'actual mapping table bounds')
        maps=[dict(zip(('address','size','fileOffset','maxProt','initProt'),struct.unpack_from('<QQQII',raw,off+32*i))) for i in range(count)]
        (D/(row['name']+'-header.bin')).write_bytes(raw);captured.append(dict(name=row['name'],sha256=row['sha256'],UUID=row['UUID'],maps=maps))
    need(captured[0]==next(r for r in old['headers'] if r['name']=='main'),'actual main mapping unchanged')
    need((D/'31-header.bin').read_bytes()==archive.read_bytes(),'actual member complete equality to expected archive')
    image=derivation['actualCurrentInventoryRow'];need(any(m['address']<=image['address'] and image['address']+image['textSize']<=m['address']+m['size'] for m in captured[1]['maps']),'actual inventory text inside actual member mapping')
    merged=dict(old);merged.update(schema='Eighteen actual cache header identities with guarded member31 v1',headers=old['headers']+[captured[1]],
        member31ActualReceiptPath=str(D/'receipt.json'),physicalMembersRereadInThisTransaction=['main','31'],otherSeventeenRecordsFromPriorActualCaptures=True)
    save(D/'headers.json',merged);receipt.update(headers=pin(D/'headers.json'),mainAndMemberHeadersGuardedBeforeAndAfter=True,
        currentMediaKitMemberIdentityProven=True,currentMediaKitCommandsOrExportsCaptured=False,frameworkABIExecuted=False,full27Backend=False)
    save(D/'receipt.json',receipt)
    inputs=[Path(__file__).resolve(),oldpath,plan/'request.json',plan/'derivation.json',archive,remote_path,*sorted(D.iterdir())]
    save(D/'freeze.json',dict(files=[pin(p) for p in inputs],deviceWrites=0))
    print(json.dumps(dict(receipt=pin(D/'receipt.json'),headers=pin(D/'headers.json'),newActualMember=captured[1])))
if __name__=='__main__':main()
