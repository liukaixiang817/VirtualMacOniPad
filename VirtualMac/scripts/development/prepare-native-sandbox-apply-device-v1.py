#!/usr/bin/env python3
"""Sign and prepare one self-only native sandbox experiment; no dispatch."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
U = N / 'native-sandbox-apply-compat-probe-unsigned-local-v1-attempt2'
D = N / 'native-sandbox-apply-compat-device-v1-attempt1'
REMOTE = '/private/var/mobile/Library/VirtualMacIndependent27SandboxProbe-v1'
LEDGER = '/var/root/VirtualMacIndependent27SandboxProbeLedger-v1'

def pin(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def need(value, why):
    if not value:
        raise ValueError(why)

def save(path, value):
    with path.open('x') as f:
        f.write(json.dumps(value, indent=2) + '\n')

def main():
    need(pin(U / 'candidate.json')['sha256'] == '86708165caee6594a4494cd4a93afd782094b036230af9a200662558e86b753d', 'exact reviewed unsigned candidate')
    for row in json.loads((U / 'freeze.json').read_text())['files']:
        need(pin(row['path']) == row, 'actual unsigned/source pin ' + row['path'])
    auth = N / 'independent27-continuing-human-authorization-v1/authorization.json'
    need(pin(auth)['sha256'] == 'af1642ec8adb47eee967b044ef67323ac66027410b0ef35cd2a6f24f5ca31d92', 'actual continuing human authorization')
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('native_apply_sign_macho', reader)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    D.mkdir(mode=0o700, exist_ok=False)
    product = D / 'sandbox-apply-compat-probe-v1'
    unsigned = (U / product.name).read_bytes()
    product.write_bytes(unsigned)
    steps = []
    for label, argv in [('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', product]),
                        ('verify', ['codesign', '--verify', '--strict', product]),
                        ('identity', ['codesign', '--display', '--verbose=4', product])]:
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=20)
        (D / (label + '.stdout')).write_bytes(result.stdout)
        (D / (label + '.stderr')).write_bytes(result.stderr)
        steps.append(dict(label=label, argv=argv, exit=result.returncode,
                          stdout=pin(D / (label + '.stdout')), stderr=pin(D / (label + '.stderr'))))
        need(result.returncode == 0, label + ' actual failure')
    identity = (D / 'identity.stderr').read_text()
    match = re.findall(r'^CDHash=([0-9a-f]{40})$', identity, re.M)
    need(len(match) == 1, 'one actual CDHash')
    cdhash = match[0]
    before, after = m.MachO(unsigned), m.MachO(product.read_bytes())
    need(before.uuid == after.uuid and before.imports == after.imports and
         before.binds == after.binds and before.sections == after.sections and
         before.exports == after.exports and before.loads == after.loads, 'signing retains code identity and imports')
    for section in before.sections:
        at, size = section['fileoff'], section['size']
        if at and size and section['flags'] & 255 not in (1, 12, 18):
            need(unsigned[at:at+size] == product.read_bytes()[at:at+size], 'actual instruction/data sections retained')
    command = [x for x in after.commands if x['cmd'] == 0x1d]
    need(len(command) == 1, 'actual single signature')
    offset, size = struct.unpack_from('<II', command[0]['raw'], 8)
    data = product.read_bytes()
    magic, length, count = struct.unpack_from('>III', data, offset)
    need(magic == 0xfade0cc0 and length <= size and count <= 16, 'actual signature superblob')
    slots = [struct.unpack_from('>II', data, offset + 12 + i * 8)[0] for i in range(count)]
    need(5 not in slots and 7 not in slots, 'no entitlement or DER entitlement grant')
    rows = []
    for name, mode in [('sandbox-apply-compat-probe-v1', 0o700), ('compiled-profile.bin', 0o600), ('deny-witness.txt', 0o600)]:
        local = product if name == product.name else U / name
        rows.append(dict(name=name, local=pin(local), mode=mode, uid=501, gid=501, nlink=1,
                         devicePath=REMOTE + '/' + name))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.USTAR_FORMAT) as tar:
        for row in rows:
            raw = Path(row['local']['path']).read_bytes()
            item = tarfile.TarInfo(row['name']); item.mode=row['mode']; item.uid=item.gid=501
            item.size=len(raw); item.mtime=0
            tar.addfile(item, io.BytesIO(raw))
    archive = D / 'products.tar'; archive.write_bytes(stream.getvalue())
    prefix = '''set -eu
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
[ "$(sysctl -n hw.machine)" = iPad14,6 ]
[ "$(sysctl -n kern.osrelease)" = 22.1.0 ]
[ "$(sysctl -n kern.osversion)" = 20B101 ]
[ "$(sysctl -n kern.boottime | sed -n 's/.*sec = \\([0-9]*\\),.*/\\1/p')" = 1791354846 ]
[ ! -e /tmp/vz-autoboot-path ] && [ ! -L /tmp/vz-autoboot-path ]
'''
    off = '''ps -axo pid=,ppid=,uid=,comm= | awk '
NF<4 {bad=1; next} {n++; if($4 ~ /VirtualMacIndependent27[.]app|VirtualMacIndependent27Runtime-v1.*com[.]apple[.]Virtualization[.]VirtualMachine|VirtualMachine[.]xpc|cpu-owned-(brk|gic|creation)|sandbox-apply-compat-probe/) {print "UNEXPECTED_OWN_OR_VM_PROCESS",$0;bad=1}}
END {if(bad || !n)exit 8;print "OWN_PROBE_AND_VM_OFF"}'
'''
    exact = f'''[ -d {REMOTE} ] && [ ! -L {REMOTE} ]
[ "$(realpath {REMOTE})" = {REMOTE} ]
[ "$(stat -c %u:%g:%a {REMOTE})" = 501:501:700 ]
[ "$(find {REMOTE} -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 3 ]
'''
    for row in rows:
        path = row['devicePath']
        exact += f'''[ -f {path} ] && [ ! -L {path} ]
[ "$(stat -c %u:%g:%a:%h:%s {path})" = 501:501:{row['mode']:o}:1:{row['local']['bytes']} ]
[ "$(sha256sum {path} | cut -d ' ' -f1)" = {row['local']['sha256']} ]
'''
    exact += f'''own_cd=$(ldid -h {REMOTE}/sandbox-apply-compat-probe-v1 2>&1)
[ "$(printf '%s\\n' "$own_cd" | sed -n 's/^CDHash=//p')" = {cdhash} ]
printf 'EXACT_3_OWN_FILES_ONE_SIGNED_HASH_NO_ENTITLEMENTS\\n'
'''
    root = prefix + '[ "$(id -u)" = 0 ]\n'
    health = root + off + "printf 'BOOT_TIME ';sysctl -n kern.boottime\n"
    scripts = dict(preflight=health + f'''[ ! -e {REMOTE} ] && [ ! -L {REMOTE} ]
[ ! -e {LEDGER} ] && [ ! -L {LEDGER} ]
[ -d /private/var/mobile/Library ] && [ ! -L /private/var/mobile/Library ]
[ "$(realpath /private/var/mobile/Library)" = /private/var/mobile/Library ]
[ "$(stat -c %u:%g /private/var/mobile/Library)" = 501:501 ]
''')
    scripts['stage'] = scripts['preflight'] + f'''mkdir -m 700 {LEDGER}
[ "$(stat -c %u:%g:%a {LEDGER})" = 0:0:700 ]
mkdir -m 700 {LEDGER}/stage-once
mkdir -m 700 {REMOTE}
tar -xpf - -C {REMOTE}
chown 501:501 {REMOTE} {REMOTE}/sandbox-apply-compat-probe-v1 {REMOTE}/compiled-profile.bin {REMOTE}/deny-witness.txt
''' + exact + "printf 'ONLY_3_NEW_OWN_FILES_STAGED_NO_TRUST_NO_EXECUTION\\n'\n"
    scripts['trust'] = health + exact + f'''[ -d {LEDGER}/stage-once ] && [ ! -L {LEDGER}/stage-once ]
[ ! -e {LEDGER}/trust-once ] && [ ! -L {LEDGER}/trust-once ]
mkdir -m 700 {LEDGER}/trust-once
jbctl trustcache add {cdhash}
printf 'ACTUAL_ONE_TRUST_CACHE_ADD_RETURNED_ZERO {cdhash}\\n'
'''
    mobile = prefix + '[ "$(id -u)" = 501 ]\n' + off + exact
    scripts['execute'] = mobile + f'''[ ! -e {REMOTE}-execute-once ] && [ ! -L {REMOTE}-execute-once ]
mkdir -m 700 {REMOTE}-execute-once
set +e
/var/jb/usr/bin/timeout --signal=TERM --kill-after=1 20 {REMOTE}/sandbox-apply-compat-probe-v1 --self-apply-once-compiled27-v1
own_status=$?
set -e
printf 'ACTUAL_NATIVE_COMPAT_PROCESS_STATUS=%s\\n' "$own_status"
''' + off + '''case "$own_status" in 0|72|73) exit 0;; *) exit "$own_status";; esac
'''
    # Files remain as frozen diagnostic evidence; no global rights or old products change.
    scripts['post'] = health + exact + f'''[ -d {LEDGER}/trust-once ] && [ ! -L {LEDGER}/trust-once ]
[ -d {REMOTE}-execute-once ] && [ ! -L {REMOTE}-execute-once ]
printf 'SELF_ONLY_PROBE_OFF_BOOT_STABLE_OWN_FILES_RETAINED\\n'
'''
    script_rows = []
    for action, text in scripts.items():
        path = D / (action + '.sh'); path.write_text(text)
        result = subprocess.run(['/bin/sh', '-n', path], capture_output=True, timeout=5)
        need(result.returncode == 0, 'actual shell syntax ' + action)
        script_rows.append(dict(action=action, script=pin(path), syntaxExit=0,
                                root=action != 'execute', directSSHSeconds=55))
    control = R / 'VirtualMac/scripts/development/native-sandbox-apply-device-control-v1.py'
    need(control.is_file(), 'actual independently reviewable controller source')
    scope = dict(schema='One self-only native sandbox compatibility device packet v1',
                 unsignedCandidate=pin(U/'candidate.json'), unsignedFreeze=pin(U/'freeze.json'),
                 continuingAuthorization=pin(auth), ownFiles=rows, signedUUID=after.uuid, CDHash=cdhash,
                 signatureSlots=slots, entitlements={}, signingSteps=steps,
                 archive=pin(archive), remoteDirectory=REMOTE, remoteRootLedger=LEDGER,
                 scripts=script_rows, controller=pin(control), externalWallSeconds=20,
                 externalKillGraceSeconds=1, nativeApplyMaximum=1, nativeVMCalls=0,
                 nativeHVCalls=0, onlySelfNativePolicy=True, deviceOperations=0,
                 trustCacheAdds=0, newTrustCacheMaximum=1, platformEntitlementGranted=False,
                 actualIPadCompatibilityVerified=False, all204OperationSemanticsVerified=False,
                 guestBooted=False, readyWritten=False)
    save(D/'scope.json', scope)
    save(D/'freeze.json', dict(files=[pin(p) for p in sorted(D.iterdir()) if p.is_file()] +
                              [pin(__file__),pin(reader),pin(control)], deviceOperations=0))
    print(json.dumps(dict(scope=pin(D/'scope.json'),freeze=pin(D/'freeze.json'))))

if __name__ == '__main__':
    main()
