#!/usr/bin/env python3
"""Verify or explicitly deploy one private disk transport and its own-file probe."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
DEVICE = '/var/mobile/VirtualMacDebug/disk-io-v5'
PATH_VALUE = '/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin'
PREFIX = 'set -eu\nexport PATH=' + PATH_VALUE + '\n'
GUARD = '''[ "$(sysctl -n hw.machine)" = iPad14,6 ]
processes=$(/bin/ps -axo pid=,comm=)
state=$(printf '%s\\n' "$processes" | awk '/VirtualMachine[.]xpc|ParavirtualizedGraphicsGPUTask|Virtualization[.]Installation/ { active=1 } END { print active ? "ACTIVE" : "OFF" }')
[ "$state" = OFF ] || { printf 'ABORT_VM_ACTIVE\\n' >&2; exit 8; }
'''


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(candidate, digest):
    raw = (candidate / 'manifest.json').read_bytes()
    need(sha(raw) == digest and re.fullmatch('[0-9a-f]{64}', digest), 'pinned manifest required')
    manifest = json.loads(raw)
    need(manifest['appleIORingsABI'] is False and manifest['guestDiskAccessed'] is False and
         manifest['deviceOperations'] is False and manifest['maximumProbeFileBytes'] == 131072, 'exact probe scope')
    for source in manifest['sources']:
        path = ROOT / 'VirtualMac' / source['path']
        need(not path.is_symlink() and path.resolve().is_relative_to(ROOT / 'VirtualMac') and
             sha(path.read_bytes()) == source['sha256'], 'source changed')
    rows = []
    for name in ['VM27DiskIO-ios.dylib', 'vm27-disk-io-ios']:
        path = candidate / name
        data = path.read_bytes()
        info = next(row for row in manifest['files'] if row['name'] == name)
        need(not path.is_symlink() and sha(data) == info['sha256'] and len(data) == info['bytes'], 'binary pin')
        subprocess.run(['codesign', '--verify', '--strict', str(path)], capture_output=True, check=True)
        signature = subprocess.run(['codesign', '-d', '--verbose=4', str(path)], capture_output=True, check=True).stderr
        cdhash = re.search(rb'^CDHash=([0-9a-f]{40})$', signature, re.M)
        need(cdhash is not None, 'signed code hash required')
        ent = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(path)], capture_output=True, check=True).stdout
        expected = {} if name.endswith('.dylib') else {'platform-application': True,
            'com.apple.private.security.no-container': True, 'com.apple.private.security.no-sandbox': True}
        if not name.endswith('.dylib') and manifest.get('diagnosticCanExecuteCDHash'):
            expected['com.apple.private.amfi.can-execute-cdhash'] = True
        if not name.endswith('.dylib') and manifest.get('diagnosticGetTaskAllow'):
            expected['get-task-allow'] = True
        need((plistlib.loads(ent) if ent else {}) == expected, 'minimal signed rights')
        rows.append(dict(info, cdhash=cdhash[1].decode(), path=str(path)))
    results = json.loads((candidate / 'local-verification.json').read_text())
    for label in ['exact-mac', 'asan-run']:
        test = next(row for row in results if row['label'] == label)
        observed = json.loads(test['stdout'])
        need(test['exit'] == 0 and observed['checks'] == 4295 and observed['failures'] == 0 and
             observed['fileRemoved'] is True and observed['workerJoined'] is True, 'actual local tests required')
    return rows


def pins(rows):
    script = ''
    for row in rows:
        path = shlex.quote(DEVICE + '/' + row['name'])
        script += '[ -f ' + path + ' ] && [ ! -L ' + path + ' ]\n'
        script += '[ "$(sha256sum ' + path + ' | cut -d " " -f1)" = ' + row['sha256'] + ' ]\n'
        script += '[ "$(ldid -h ' + path + ' 2>&1 | sed -n "s/^CDHash=//p")" = ' + row['cdhash'] + ' ]\n'
        script += '[ "$(stat -c %u ' + path + ')" = 501 ]\n'
    return script


def execute(candidate, digest, output):
    rows = verify(candidate, digest)
    need(not output.exists() and not output.resolve().is_relative_to(candidate.resolve()), 'fresh result directory')
    output.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location('vm27_device_remote', ROOT / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py')
    remote = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(remote)
    archive_data = io.BytesIO()
    with tarfile.open(fileobj=archive_data, mode='w') as archive:
        for row in rows:
            data = Path(row['path']).read_bytes()
            need(sha(data) == row['sha256'], 'payload pin')
            entry = tarfile.TarInfo(row['name'])
            entry.uid = entry.gid = 501
            entry.mode = 0o700
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    stage = PREFIX + GUARD + 'umask 077\n[ ! -e ' + DEVICE + ' ] && [ ! -L ' + DEVICE + ' ]\n'
    stage += 'mkdir -m700 ' + DEVICE + '\ntar -xf - -C ' + DEVICE + '\nchown 501:501 ' + DEVICE + '\n' + pins(rows)
    for row in rows:
        stage += 'jbctl trustcache add ' + row['cdhash'] + ' >&2\n'
    stage += "printf 'PRIVATE_DISK_IO_STAGED\\n'\n"
    (output / 'stage.sh').write_text(stage)
    staged = remote.run(stage, device='ipad', root=True, input_bytes=archive_data.getvalue(), timeout=30)
    (output / 'stage.stdout').write_bytes(staged.stdout)
    (output / 'stage.stderr').write_bytes(staged.stderr)
    need(staged.returncode == 0 and staged.stdout == b'PRIVATE_DISK_IO_STAGED\n', 'exact staging required')
    child = 'set -eu\nulimit -t 5\n' + shlex.join([DEVICE + '/vm27-disk-io-ios', DEVICE + '/own-file.bin']) + ' &\n'
    child += 'child_pid=$!\nprintf "NATIVE_STARTED pid=%s\\n" "$child_pid" >&2\nset +e\nwait "$child_pid"\nchild_exit=$?\n'
    child += 'printf "NATIVE_WAIT pid=%s exit=%s\\n" "$child_pid" "$child_exit" >&2\nexit "$child_exit"\n'
    script = PREFIX + GUARD + pins(rows) + 'umask 077\nset -C\nexec 3>' + DEVICE + '/native.stdout\nexec 4>' + DEVICE + '/native.stderr\nset +e\n'
    script += shlex.join(['timeout', '-k', '1', '12', 'env', '-i', 'PATH=' + PATH_VALUE, '/var/jb/bin/sh', '-c', child]) + ' >&3 2>&4\n'
    script += 'outer_exit=$?\ncat ' + DEVICE + '/native.stdout\ncat ' + DEVICE + '/native.stderr >&2\nexit "$outer_exit"\n'
    (output / 'execute.sh').write_text(script)
    executed = remote.run('/var/jb/bin/sh -c ' + shlex.quote(script), device='ipad', timeout=20)
    (output / 'native.stdout').write_bytes(executed.stdout)
    (output / 'native.stderr').write_bytes(executed.stderr)
    result = dict(passed=False, manifestSHA256=digest, transportExit=executed.returncode,
                  deploymentFiles=rows, deviceDirectory=DEVICE, productionModified=False,
                  completeMacOS27Backend=False, appleIORingsABI=False)
    try:
        raw = json.loads(executed.stdout)
        need(executed.returncode == 0 and raw['checks'] == 4295 and raw['failures'] == 0 and raw['uid'] == raw['euid'] == 501 and
             raw['forbiddenVMImages'] == 0 and raw['workerJoined'] is True and raw['fileRemoved'] is True, 'native behavior required')
        pid = raw['pid']
        need(isinstance(pid, int) and pid > 1, 'real PID required')
        need(('NATIVE_STARTED pid=' + str(pid) + '\n').encode() in executed.stderr and
             ('NATIVE_WAIT pid=' + str(pid) + ' exit=0\n').encode() in executed.stderr, 'exact native wait required')
        post = PREFIX + pins(rows) + '[ ! -e ' + DEVICE + '/own-file.bin ]\n'
        post += 'if kill -0 ' + str(pid) + ' 2>/dev/null; then exit 7; fi\nprintf "PRIVATE_DISK_IO_CHILD_ABSENT\\n"\n'
        (output / 'post.sh').write_text(post)
        after = remote.run(post, device='ipad', root=True, timeout=15)
        (output / 'post.stdout').write_bytes(after.stdout)
        (output / 'post.stderr').write_bytes(after.stderr)
        need(after.returncode == 0 and after.stdout == b'PRIVATE_DISK_IO_CHILD_ABSENT\n', 'files unchanged and child absent required')
        result.update(passed=True, native=raw, nativeChildAbsent=True, ownFileAbsent=True)
    except (ValueError, KeyError) as error:
        result['failure'] = str(error)
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 83


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--manifest-sha', required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.run:
        need(args.output is not None, 'fresh actual output required')
        return execute(args.candidate.resolve(), args.manifest_sha, args.output.resolve())
    rows = verify(args.candidate.resolve(), args.manifest_sha)
    print(json.dumps(dict(verified=True, deploymentFiles=rows, deviceContacted=False), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
