"""Prepare one32-byte native stub read from the actual newly captured cache26 header."""
import ast
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PHASE1 = NODE / 'ipad-native-sandbox-apply-edge-readonly-v1'
OUT = NODE / 'ipad-native-sandbox-apply-stub-readonly-plan-v1-attempt1'
RESULT = NODE / 'ipad-native-sandbox-apply-stub-readonly-v1'
HEADERS = NODE / 'ipad-current-mediakit-member31-header-readonly-v1/headers.json'
REMOTE = ROOT / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
V11 = ROOT / 'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v11.py'

def pin(p):
    b = p.read_bytes()
    return dict(path=str(p.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def dump(p,x):
    p.write_text(json.dumps(x,indent=2)+'\n')

def main():
    rp = PHASE1 / 'receipt.json'
    assert pin(rp)['sha256']=='c46be6a41be93c6c952f8e50b1118b903ae697ac1fac4bf3d83dcdc4ad5bba11'
    r=json.loads(rp.read_bytes())
    assert r['transportExit']==r['deviceWrites']==r['nativeSandboxCalls']==0
    assert r['allExisting18HeaderPinsMatchBeforeAndAfter'] and r['newMember26HeaderSameBeforeAndAfter']
    for f in r['captured']: assert pin(Path(f['path']))==f
    assert pin(HEADERS)['sha256']=='ea2d4bda25e393127e3f004e9689d6cd42ace179ffda66374ab9af39f8260fb0'
    assert pin(V11)['sha256']=='742595c2ecd4bf119ba454c17a3e135c7ea4e546336f675dc1eccf32534ddfef'
    assert pin(REMOTE)['sha256']=='29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424'
    h26=PHASE1/'native-stub-member26-header.bin'; b=h26.read_bytes()
    assert b[88:104].hex()==r['actualMember26UUID']=='44b0a31b679f3772aaa4d38b25344470'
    off,count=struct.unpack_from('<II',b,16)
    maps=[dict(zip(('address','size','fileOffset','maxProt','initProt'),struct.unpack_from('<QQQII',b,off+32*i))) for i in range(count)]
    assert maps==r['actualMember26Maps']
    matches=[m for m in maps if m['address']<=0x1d57a5db0 and 0x1d57a5dd0<=m['address']+m['size']]
    assert len(matches)==1
    offset=matches[0]['fileOffset']+0x1d57a5db0-matches[0]['address']
    assert offset==r['nextUnexecutedStubRead']['offset']==351664
    t=ast.parse(V11.read_text()); nodes=[n for n in t.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['BASE','FILES']]
    ns={}; exec(compile(ast.Module(body=nodes,type_ignores=[]),str(V11),'exec'),ns)
    headers=json.loads(HEADERS.read_bytes()); rows=headers['headers']+[dict(name='26',UUID=r['actualMember26UUID'],sha256=pin(h26)['sha256'],maps=maps)]
    paths=dict(ns['FILES']); paths['26']=ns['BASE']+'.26'
    assert len(rows)==len(paths)==19 and {x['name'] for x in rows}==set(paths)
    guards=''
    for x in sorted(rows,key=lambda x:x['name']):
        p=shlex.quote(paths[x['name']]); guards+=f'[ -f {p} ]\n[ ! -L {p} ]\n[ "$(dd if={p} bs=4096 count=1 status=none | sha256sum | cut -d \' \' -f1)" = {shlex.quote(x["sha256"])} ]\n'
    p=shlex.quote(paths['26'])
    body='''set -eu
export LC_ALL=C
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" = 0 ]
[ "$(sysctl -n hw.machine)" = iPad14,6 ]
[ "$(sysctl -n kern.osversion)" = 20B101 ]
'''+guards+f'''[ "$(stat -c '%u:%g:%a:%h:%s' {p})" = 0:80:755:1:393216 ]
printf 'BEGIN_BASE64 native-sandbox-apply-external-stub\n'
dd if={p} bs=65536 skip={offset} count=32 iflag=skip_bytes,count_bytes status=none | base64
printf '\nEND_BASE64 native-sandbox-apply-external-stub\n'
'''+guards+"printf 'FINAL_19_CACHE_HEADERS_MATCH\\n'\n"
    script='exec /var/jb/usr/bin/timeout --signal=TERM --kill-after=1s 20s /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True,check=True)
    assert not RESULT.exists(); OUT.mkdir(exist_ok=False)
    (OUT/'script.sh').write_text(script)
    dump(OUT/'request.json',dict(schema='Native sandbox apply exact stub readonly request v1',ranges=[dict(name='native-sandbox-apply-external-stub',cache='26',offset=offset,length=32)]))
    inputs=[Path(__file__),rp,h26,PHASE1/'native-mac-syscall-export-code.bin',HEADERS,V11,REMOTE,OUT/'script.sh',OUT/'request.json']
    frozen=[pin(p) for p in inputs]
    code='''"""Root explicit one-shot readonly32B; no sandbox function is called."""
import base64,datetime,getpass,hashlib,importlib.util,json,os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
FIXED=__FIXED__
OUT=Path(__OUTPUT__)
SCRIPT=Path(__SCRIPT__)
REMOTE=Path(__REMOTE__)
def pin(p):
 b=p.read_bytes(); return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 for f in FIXED:
  if pin(Path(f['path']))!=f: raise ValueError('Fixed input drift')
 OUT.mkdir(exist_ok=False)
 password=getpass.getpass('iPad password: ')
 if not password: raise ValueError('Runtime authentication absent')
 prior=os.environ.get('VIRTUALMAC_SSH_PASSWORD')
 try:
  os.environ['VIRTUALMAC_SSH_PASSWORD']=password
  s=importlib.util.spec_from_file_location('apply_stub_readonly_remote',REMOTE); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
  m.IPAD_SSH=['ssh','-p','2221','-o','ConnectTimeout=8','-o','ControlMaster=no','-o','ControlPath=none','-o','UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts','-o','StrictHostKeyChecking=yes','mobile@127.0.0.1']
  start=datetime.datetime.now(datetime.timezone.utc).isoformat(); z=m.run(SCRIPT.read_text(),device='ipad',root=True,timeout=30)
 finally:
  password=None
  if prior is None: os.environ.pop('VIRTUALMAC_SSH_PASSWORD',None)
  else: os.environ['VIRTUALMAC_SSH_PASSWORD']=prior
 (OUT/'stdout').write_bytes(z.stdout); (OUT/'stderr').write_bytes(z.stderr)
 r=dict(schema='Actual native apply stub readonly receipt v1',startedUTC=start,recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),transportExit=z.returncode,deviceWrites=0,nativeSandboxCalls=0,nativeCPUCalls=0,newTrustCacheEntries=0,requestedBytes=32,requestedRanges=1,frozenInputs=FIXED,script=pin(SCRIPT),stdoutSHA256=hashlib.sha256(z.stdout).hexdigest(),stderrSHA256=hashlib.sha256(z.stderr).hexdigest())
 (OUT/'receipt.json').write_text(json.dumps(r,indent=2)+'\\n')
 if z.returncode!=0: raise ValueError('Actual readonly failed; do not repeat')
 if not z.stdout.endswith(b'FINAL_19_CACHE_HEADERS_MATCH\\n'): raise ValueError('Actual final guard absent')
 found=re.findall(rb'BEGIN_BASE64 native-sandbox-apply-external-stub\\n(.*?)\\nEND_BASE64 native-sandbox-apply-external-stub\\n',z.stdout,re.S)
 if len(found)!=1: raise ValueError('Actual capture count')
 b=base64.b64decode(re.sub(rb'\\s',b'',found[0]),validate=True)
 if len(b)!=32: raise ValueError('Actual capture size')
 p=OUT/'native-sandbox-apply-external-stub.bin'; p.write_bytes(b)
 r.update(all19HeaderPinsMatchBeforeAndAfter=True,captured=pin(p),actualStubVA='0x1d57a5db0',actualMember26UUID='44b0a31b679f3772aaa4d38b25344470',externalTargetBindingEstablished=False)
 (OUT/'receipt.json').write_text(json.dumps(r,indent=2)+'\\n'); print(json.dumps(dict(receipt=pin(OUT/'receipt.json'),transportExit=0,deviceWrites=0)))
if __name__=='__main__': main()
'''
    for token,value in [('__FIXED__',repr(frozen)),('__OUTPUT__',repr(str(RESULT))),('__SCRIPT__',repr(str(OUT/'script.sh'))),('__REMOTE__',repr(str(REMOTE)))]: code=code.replace(token,value)
    ast.parse(code); (OUT/'read-once.py').write_text(code)
    dump(OUT/'derivation.json',dict(schema='Second phase actual cache26 bounded apply stub preparation v1',deviceOperations=0,captureExecuted=False,actualFirstPhaseReceipt=pin(rp),actual26Header=pin(h26),actual26Maps=maps,stubVA='0x1d57a5db0',offset=offset,bytes=32,headerPinsBeforeAndAfter=19,remoteTimeoutSeconds=20,remoteKillAfterSeconds=1,sshTimeoutSeconds=30,noPointerSlotGuessed=True,noSandboxCalls=True,shellSyntaxCheckPassed=True))
    dump(OUT/'freeze.json',dict(schema='Finite actual native apply stub prepared freeze v1',files=frozen+[pin(OUT/'read-once.py'),pin(OUT/'derivation.json')]))
    dump(OUT/'candidate.json',dict(schema='Finite actual native apply stub prepared candidate v1',deviceOperations=0,captureExecuted=False,requestedBytes=32,requestedRanges=1,actualFirstPhaseReceipt=pin(rp),request=pin(OUT/'request.json'),script=pin(OUT/'script.sh'),dispatchSource=pin(OUT/'read-once.py'),derivation=pin(OUT/'derivation.json'),freeze=pin(OUT/'freeze.json'),command=['python3',str(OUT/'read-once.py')],noReceiptCreated=True))
    print(json.dumps(dict(candidate=pin(OUT/'candidate.json'),freeze=pin(OUT/'freeze.json'))))
if __name__=='__main__': main()
