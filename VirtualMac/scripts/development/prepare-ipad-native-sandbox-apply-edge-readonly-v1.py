"""Prepare two finite native-cache reads on the host; do not contact the iPad."""
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
OUT = NODE / 'ipad-native-sandbox-apply-edge-readonly-plan-v1-attempt1'
RESULT = NODE / 'ipad-native-sandbox-apply-edge-readonly-v1'
HEADERS = NODE / 'ipad-current-mediakit-member31-header-readonly-v1/headers.json'
INDEX = NODE / 'current-native-header-export-index-v3/index.json'
V11 = ROOT / 'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v11.py'
REMOTE = ROOT / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
MEMBER_RECEIPT = NODE / 'ipad-current-cache-member-names-readonly-v1/receipt.json'
MEMBER_STDOUT = MEMBER_RECEIPT.parent / 'stdout'
BASE = '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'


def pin(path):
    b = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    assert pin(HEADERS)['sha256'] == 'ea2d4bda25e393127e3f004e9689d6cd42ace179ffda66374ab9af39f8260fb0'
    assert pin(V11)['sha256'] == '742595c2ecd4bf119ba454c17a3e135c7ea4e546336f675dc1eccf32534ddfef'
    assert pin(REMOTE)['sha256'] == '29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424'
    headers = json.loads(HEADERS.read_bytes())
    assert headers['mainUUID'] == '1995ea169d0a33a0b78962cf99891168'
    assert headers['deviceWrites'] == 0 and headers['matchesArchivedMap'] is True
    tree = ast.parse(V11.read_text())
    base_node = next(n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'BASE')
    files_node = next(n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'FILES')
    ns = {}
    exec(compile(ast.Module(body=[base_node, files_node], type_ignores=[]), str(V11), 'exec'), ns)
    paths = ns['FILES']
    assert ns['BASE'] == BASE and set(paths) == {h['name'] for h in headers['headers']}
    assert len(paths) == 18
    index = json.loads(INDEX.read_bytes())
    image = index['images']['/usr/lib/system/libsystem_kernel.dylib']
    assert image['UUID'] == 'ff27fc8f90ba3332ab7ac5bc2d9ca7b1'
    assert image['definitions']['___mac_syscall'] == dict(flags=0, offset=0x2cc4)
    va = image['base'] + 0x2cc4
    assert va == 0x1c305dcc4
    matches = [(h, m) for h in headers['headers'] for m in h['maps'] if m['address'] <= va and va + 32 <= m['address'] + m['size']]
    assert len(matches) == 1 and matches[0][0]['name'] == '21'
    kernel_offset = matches[0][1]['fileOffset'] + va - matches[0][1]['address']
    assert kernel_offset == 5250244
    mr = json.loads(MEMBER_RECEIPT.read_bytes())
    assert mr['transportExit'] == 0 and mr['deviceWrites'] == 0
    assert hashlib.sha256(MEMBER_STDOUT.read_bytes()).hexdigest() == mr['stdoutSHA256']
    expected = ('ACTUAL_CACHE_MEMBER ' + BASE + '.26\n0:80:755:1:393216:16777223:5246\n').encode()
    assert expected in MEMBER_STDOUT.read_bytes()
    rows = [dict(name='native-stub-member26-header', cache='26', offset=0, length=4096),
            dict(name='native-mac-syscall-export-code', cache='21', offset=kernel_offset, length=32)]
    guard = ''
    for h in sorted(headers['headers'], key=lambda x: x['name']):
        p = paths[h['name']]
        guard += (f'[ -f {shlex.quote(p)} ]\n[ ! -L {shlex.quote(p)} ]\n'
                  f'[ "$(dd if={shlex.quote(p)} bs=4096 count=1 status=none | sha256sum | cut -d \' \' -f1)" = {shlex.quote(h["sha256"])} ]\n')
    p26 = BASE + '.26'
    body = '''set -eu
export LC_ALL=C
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" = 0 ]
[ "$(sysctl -n hw.machine)" = iPad14,6 ]
[ "$(sysctl -n kern.osversion)" = 20B101 ]
''' + guard
    body += f'''[ -f {shlex.quote(p26)} ]
[ ! -L {shlex.quote(p26)} ]
[ "$(stat -c '%u:%g:%a:%h:%s' {shlex.quote(p26)})" = 0:80:755:1:393216 ]
member26_before=$(dd if={shlex.quote(p26)} bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)
printf 'MEMBER26_INITIAL_HEADER_SHA %s\n' "$member26_before"
printf 'BEGIN_BASE64 native-stub-member26-header\n'
dd if={shlex.quote(p26)} bs=4096 count=1 status=none | base64
printf '\nEND_BASE64 native-stub-member26-header\n'
printf 'BEGIN_BASE64 native-mac-syscall-export-code\n'
dd if={shlex.quote(paths['21'])} bs=65536 skip={kernel_offset} count=32 iflag=skip_bytes,count_bytes status=none | base64
printf '\nEND_BASE64 native-mac-syscall-export-code\n'
[ "$(dd if={shlex.quote(p26)} bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)" = "$member26_before" ]
'''
    body += guard + "printf 'FINAL_EXISTING_18_AND_MEMBER26_HEADERS_MATCH\\n'\n"
    script = 'exec /var/jb/usr/bin/timeout --signal=TERM --kill-after=1s 20s /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, check=True)
    assert not RESULT.exists()
    OUT.mkdir(exist_ok=False)
    (OUT / 'script.sh').write_text(script)
    dump(OUT / 'request.json', dict(schema='Finite native apply edge readonly request v1', ranges=rows))
    inputs = [Path(__file__), HEADERS, INDEX, V11, REMOTE, MEMBER_RECEIPT, MEMBER_STDOUT,
              Path(image['actualCompleteCommands']['path']),
              NODE / 'ipad-current-native-sandbox-code-host-audit-v1-attempt2/report.json',
              NODE / 'ipad-current-native-sandbox-code-readonly-v1/sandbox-compiler-text.bin']
    frozen = [pin(p) for p in inputs] + [pin(OUT / 'script.sh'), pin(OUT / 'request.json')]
    wrapper = '''"""Root-only explicit one-shot dispatch of two frozen readonly ranges."""
import base64, datetime, getpass, hashlib, importlib.util, json, os, re, struct, sys
from pathlib import Path
sys.dont_write_bytecode = True
FIXED = __FIXED__
OUT = Path(__RESULT__)
SCRIPT = Path(__SCRIPT__)
REMOTE = Path(__REMOTE__)
def pin(p):
    b = p.read_bytes()
    return dict(path=str(p.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def main():
    for f in FIXED:
        if pin(Path(f['path'])) != f:
            raise ValueError('Frozen readonly source drift')
    OUT.mkdir(exist_ok=False)
    password = getpass.getpass('iPad password: ')
    if not password:
        raise ValueError('Runtime authentication absent')
    previous = os.environ.get('VIRTUALMAC_SSH_PASSWORD')
    try:
        os.environ['VIRTUALMAC_SSH_PASSWORD'] = password
        spec = importlib.util.spec_from_file_location('native_apply_readonly_remote', REMOTE)
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        m.IPAD_SSH = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts', '-o', 'StrictHostKeyChecking=yes', 'mobile@127.0.0.1']
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        z = m.run(SCRIPT.read_text(), device='ipad', root=True, timeout=30)
    finally:
        password = None
        if previous is None: os.environ.pop('VIRTUALMAC_SSH_PASSWORD', None)
        else: os.environ['VIRTUALMAC_SSH_PASSWORD'] = previous
    (OUT/'stdout').write_bytes(z.stdout); (OUT/'stderr').write_bytes(z.stderr)
    receipt = dict(schema='Finite native apply edge actual readonly receipt v1', startedUTC=started, recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), transportExit=z.returncode, deviceWrites=0, nativeSandboxCalls=0, nativeCPUCalls=0, newTrustCacheEntries=0, requestedBytes=4128, requestedRanges=2, script=pin(SCRIPT), frozenInputs=FIXED, stdoutSHA256=hashlib.sha256(z.stdout).hexdigest(), stderrSHA256=hashlib.sha256(z.stderr).hexdigest())
    (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\\n')
    if z.returncode != 0: raise ValueError('Readonly capture failed; do not retry')
    if not z.stdout.endswith(b'FINAL_EXISTING_18_AND_MEMBER26_HEADERS_MATCH\\n'): raise ValueError('Final guard absent')
    found=re.findall(rb'BEGIN_BASE64 ([a-z0-9-]+)\\n(.*?)\\nEND_BASE64 \\1\\n',z.stdout,re.S)
    expected=[('native-stub-member26-header',4096),('native-mac-syscall-export-code',32)]
    if len(found)!=2: raise ValueError('Capture range count')
    rows=[]
    for (n,b),(name,size) in zip(found,expected):
        data=base64.b64decode(re.sub(rb'\\s',b'',b),validate=True)
        if n.decode()!=name or len(data)!=size: raise ValueError('Capture bytes/name')
        p=OUT/(name+'.bin'); p.write_bytes(data); rows.append(pin(p))
    header=(OUT/'native-stub-member26-header.bin').read_bytes()
    if not header.startswith(b'dyld_v1'): raise ValueError('Not a cache header')
    off,count=struct.unpack_from('<II',header,16)
    if not 0<count<=32 or off+count*32>4096: raise ValueError('Header map geometry')
    maps=[dict(zip(('address','size','fileOffset','maxProt','initProt'),struct.unpack_from('<QQQII',header,off+32*i))) for i in range(count)]
    matches=[r for r in maps if r['address']<=0x1d57a5db0 and 0x1d57a5dd0<=r['address']+r['size']]
    if len(matches)!=1: raise ValueError('Actual external stub must map once')
    receipt.update(allExisting18HeaderPinsMatchBeforeAndAfter=True, newMember26HeaderSameBeforeAndAfter=True, actualMember26UUID=header[88:104].hex(), actualMember26Maps=maps, captured=rows, nextUnexecutedStubRead=dict(VA='0x1d57a5db0',bytes=32,offset=matches[0]['fileOffset']+0x1d57a5db0-matches[0]['address']), compiledProfileOrApplySuccessEstablished=False)
    (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\\n')
    print(json.dumps(dict(receipt=pin(OUT/'receipt.json'),transportExit=0,deviceWrites=0)))
if __name__=='__main__': main()
'''
    for token, value in [('__FIXED__', repr(frozen)), ('__RESULT__', repr(str(RESULT))),
                         ('__SCRIPT__', repr(str(OUT / 'script.sh'))), ('__REMOTE__', repr(str(REMOTE)))]:
        wrapper = wrapper.replace(token, value)
    ast.parse(wrapper)
    (OUT / 'read-once.py').write_text(wrapper)
    dump(OUT / 'derivation.json', dict(schema='Host prepared native apply edge readonly plan v1', deviceOperations=0,
        captureExecuted=False, nativeSandboxCalls=0, newTrustCacheEntries=0, requestedBytes=4128,
        remoteTimeoutSeconds=20, remoteKillAfterSeconds=1, sshTimeoutSeconds=30, headersGuardedBeforeAndAfter=18,
        expectedMainCacheUUID=headers['mainUUID'], newHeader26IsEvidenceOnly=True,
        noAssumedMember26MapOrUUID=True, noStubReadBeforeActual26HeaderValidation=True,
        syscallExport=dict(image='/usr/lib/system/libsystem_kernel.dylib', UUID=image['UUID'], symbol='___mac_syscall', RVA=0x2cc4, VA=hex(va), cache='21', offset=kernel_offset),
        firstRequest=pin(OUT / 'request.json'), shellSyntaxCheckPassed=True,
        secondPhase='Root must freeze actual .26 header/map then prepare an independent <=32-byte stub read; pointer-slot read only if decoded actual stub requires it.',
        output=str(RESULT), noReceiptCreated=True, inputs=frozen))
    files = frozen + [pin(OUT / 'read-once.py'), pin(OUT / 'derivation.json')]
    dump(OUT / 'freeze.json', dict(schema='Host-only native apply edge readonly preparation freeze v1', files=files))
    dump(OUT / 'candidate.json', dict(schema='Host-only native apply edge readonly candidate v1', captureExecuted=False,
        deviceOperations=0, requestedBytes=4128, requestedRanges=2, firstRequest=pin(OUT / 'request.json'),
        dispatchSource=pin(OUT / 'read-once.py'), script=pin(OUT / 'script.sh'), derivation=pin(OUT / 'derivation.json'),
        freeze=pin(OUT / 'freeze.json'), command=['python3', str(OUT / 'read-once.py')],
        secondPhaseRequiresActualReceipt=True, nativeSandboxCalls=0, noReceiptCreated=True))
    print(json.dumps(dict(candidate=pin(OUT / 'candidate.json'), freeze=pin(OUT / 'freeze.json'))))


if __name__ == '__main__':
    main()
