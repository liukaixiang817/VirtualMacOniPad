"""Pinned HOST utilities for an explicit, owned normal guest observation.

Importing this module never invokes a device or generates a successful receipt.
"""
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import plistlib
import re
import shlex
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
GUEST = '/private/var/mobile/Media/VirtualMac/Tahoe3.bundle'
LOG = '/tmp/VirtualMacIndependent27.log'
SIZES = {'MachineIdentifier': 68, 'HardwareModel': 150,
         'AuxiliaryStorage': 33570816, 'Disk.img': 274877906944,
         'VirtualMac.plist': 1415}
SMALL = ('MachineIdentifier', 'HardwareModel', 'VirtualMac.plist')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(path):
    path = pathlib.Path(path)
    need(path.is_absolute() and path.is_relative_to(R) and '..' not in path.parts,
         'ordinary absolute workspace pin')
    need(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
         'ordinary single-link pinned file')
    need(all(not p.is_symlink() for p in path.parents if p.is_relative_to(R)),
         'ordinary pin ancestors')
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def exact(row):
    need(pin(row['path']) == {k: row[k] for k in ('path', 'bytes', 'sha256')},
         'changed exact input: ' + row['path'])
    return pathlib.Path(row['path'])


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dump(path, value, exclusive=True):
    """Persist an actual record and directory entry before any handoff ACK."""
    path = pathlib.Path(path)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def receipt(path):
    path = pathlib.Path(path).resolve()
    row = json.loads(path.read_bytes())
    need(row.get('transportExit') == 0, 'actual successful transport receipt required')
    exact(row['request'])
    stdout = exact(row['stdout']).read_text()
    exact(row['stderr'])
    need(row.get('finishedUTC'), 'actual completion time required')
    return row, stdout


def initializer_success(candidate, launch_path, post_path):
    candidate = pathlib.Path(candidate).resolve()
    packet = json.loads(candidate.read_bytes())
    scope = json.loads(exact(packet['scope']).read_bytes())
    for row in json.loads((candidate.parent / 'freeze.json').read_bytes())['files']:
        exact(row)
    launch, text = receipt(launch_path)
    post, post_text = receipt(post_path)
    for action, row in (('launch', launch), ('post', post)):
        request = json.loads(exact(row['request']).read_bytes())
        need(request['action'] == action and request['packetCandidate'] == pin(candidate),
             'same actual initializer packet required')
    need(text.count('INDEPENDENT27_TRUE_PARENT_CHILD_BOOTSTRAP_READY_GUEST_NOT_REQUESTED') == 1,
         'actual bootstrap ready marker required')
    need(len(re.findall(r'^\[Independent27\] runtime-startup result=1 errorDomain= errorCode=0 error=$', text, re.M)) == 1,
         'actual runtime successful result required')
    need('OWN_APP_ID ' in text and 'OWN_CHILD_ID ' in text, 'actual parent/child captures required')
    need('INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in post_text and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in post_text,
         'actual successful post with exact own processes off required')
    need(datetime.datetime.fromisoformat(post['finishedUTC']) >=
         datetime.datetime.fromisoformat(launch['finishedUTC']), 'post must follow initializer')
    return packet, scope, launch, post


def guest_shell(expected=None):
    """Read three small files only; record/recheck all five actual identities."""
    body = 'OWN_GUEST=' + shlex.quote(GUEST) + '\n'
    body += '''for own_ancestor in /private /private/var /private/var/mobile /private/var/mobile/Media /private/var/mobile/Media/VirtualMac "$OWN_GUEST"; do
 [ -d "$own_ancestor" ] && [ ! -L "$own_ancestor" ]
 [ "$(realpath "$own_ancestor")" = "$own_ancestor" ]
done
own_guest_dir=$(stat -c %d:%i:%u:%g:%a:%h "$OWN_GUEST")
printf 'GUEST_DIRECTORY_META %s\n' "$own_guest_dir"
printf 'GUEST_CANONICAL_PATH %s\n' "$OWN_GUEST"
'''
    for i, (name, size) in enumerate(SIZES.items()):
        mode = 644 if name in SMALL[:2] else 600
        body += 'own_file="$OWN_GUEST/' + name + '"\n'
        body += '''[ -f "$own_file" ] && [ ! -L "$own_file" ]
[ "$(realpath "$own_file")" = "$own_file" ]
'''
        body += f'own_meta_{i}=$(stat -c %d:%i:%u:%g:%a:%h:%s "$own_file")\n'
        body += f'[ "$(stat -c %u:%g:%a:%h:%s "$own_file")" = 501:501:{mode}:1:{size} ]\n'
        if expected is not None:
            body += f'[ "$own_meta_{i}" = ' + shlex.quote(expected['metadata'][name]) + ' ]\n'
        body += f'printf \'GUEST_FILE_META {name} %s\\n\' "$own_meta_{i}"\n'
        if name in SMALL:
            body += '''own_before=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$own_file")
own_sha_before=$(sha256sum "$own_file" | cut -d ' ' -f1)
'''
            if expected is not None:
                body += '[ "$own_sha_before" = ' + expected['smallSHA256'][name] + ' ]\n'
            body += f'printf \'GUEST_SMALL_SHA256 {name} %s\\n\' "$own_sha_before"\n'
            body += f'printf \'GUEST_SMALL_BASE64 {name} \'\n'
            body += '''base64 < "$own_file" | tr -d '\n'
printf '\n'
[ "$(sha256sum "$own_file" | cut -d ' ' -f1)" = "$own_sha_before" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$own_file")" = "$own_before" ]
'''
    for i, name in enumerate(SIZES):
        body += f'[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_GUEST/{name}")" = "$own_meta_{i}" ]\n'
    body += '[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_GUEST")" = "$own_guest_dir" ]\n'
    body += '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
printf 'GUEST_PRIOR_LOG_META %s\n' "$own_log_meta"
printf 'GUEST_PRIOR_LOG_SHA256 %s\n' "$own_log_sha"
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
'''
    body += "printf 'INDEPENDENT27_GUEST_CONFIG_READONLY_COMPLETE_NO_GUEST_EXECUTION\\n'\n"
    return body


def parse_guest(text, output=None):
    need(re.findall(r'^GUEST_CANONICAL_PATH (.+)$', text, re.M) == [GUEST], 'true guest path')
    need(text.count('INDEPENDENT27_GUEST_CONFIG_READONLY_COMPLETE_NO_GUEST_EXECUTION') == 1,
         'complete actual guest read required')
    metadata, hashes, files = {}, {}, {}
    for name, size in SIZES.items():
        rows = re.findall(r'^GUEST_FILE_META ' + re.escape(name) + r' ([0-9:]+)$', text, re.M)
        need(len(rows) == 1, 'one true metadata row per guest file')
        values = rows[0].split(':')
        need(len(values) == 7 and all(v.isdigit() for v in values), 'bounded metadata fields')
        dev, ino, uid, gid, mode, links, count = map(int, values)
        need(dev > 0 and ino > 0 and uid == gid == 501 and links == 1 and count == size and
             mode == (644 if name in SMALL[:2] else 600), 'actual guest file geometry')
        metadata[name] = rows[0]
        if name not in SMALL:
            continue
        rows64 = re.findall(r'^GUEST_SMALL_BASE64 ' + re.escape(name) + r' ([A-Za-z0-9+/=]+)$', text, re.M)
        sha = re.findall(r'^GUEST_SMALL_SHA256 ' + re.escape(name) + r' ([a-f0-9]{64})$', text, re.M)
        need(len(rows64) == len(sha) == 1, 'one actual small data/hash row')
        raw = base64.b64decode(rows64[0], validate=True)
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha[0], 'actual small data matches hash')
        hashes[name] = sha[0]
        if name == 'VirtualMac.plist':
            options = plistlib.loads(raw)
            need(isinstance(options, dict), 'actual saved plist dictionary')
        if output:
            path = pathlib.Path(output) / name
            with open(path, 'xb') as stream:
                stream.write(raw)
            files[name] = pin(path)
    logs = re.findall(r'^GUEST_PRIOR_LOG_META ([0-9:]+)$', text, re.M)
    log_hashes = re.findall(r'^GUEST_PRIOR_LOG_SHA256 ([a-f0-9]{64})$', text, re.M)
    need(len(logs) == len(log_hashes) == 1, 'one actual prior log identity/hash')
    values = logs[0].split(':')
    need(len(values) == 7 and all(v.isdigit() for v in values), 'actual prior log fields')
    dev, ino, uid, gid, mode, links, count = map(int, values)
    need(dev > 0 and ino > 0 and uid == gid == 501 and mode == 600 and links == 1 and count <= 2097152,
         'bounded actual prior log')
    return dict(metadata=metadata, smallSHA256=hashes, sourceFiles=files, priorLogMetadata=logs[0], priorLogSHA256=log_hashes[0],
                actualParsedSavedOptions=options, CPUCountSaved=options.get('CPUCount'),
                MemorySizeSaved=options.get('MemorySize'), savedOptionsAreNotMergedRuntimeDefaults=True)


def guest_success(read_path, config_path, post):
    guest, text = receipt(read_path)
    request = json.loads(exact(guest['request']).read_bytes())
    need(guest.get('deviceWrites') == guest.get('processSignals') == guest.get('trustCacheOperations') == 0,
         'guest facts must be actual read-only')
    need(request['actualPriorPost'] == post, 'fresh read must bind the actual initializer post')
    post_row = json.loads(exact(post).read_bytes())
    need(datetime.datetime.fromisoformat(guest['finishedUTC']) >=
         datetime.datetime.fromisoformat(post_row['finishedUTC']), 'fresh read must follow actual post')
    parsed = parse_guest(text)
    config = json.loads(pathlib.Path(config_path).read_bytes())
    for key in ('metadata', 'smallSHA256', 'actualParsedSavedOptions', 'CPUCountSaved', 'MemorySizeSaved',
                'priorLogMetadata', 'priorLogSHA256'):
        need(config[key] == parsed[key], 'configuration must derive from actual received guest bytes')
    for name in SMALL:
        raw = exact(config['sourceFiles'][name]).read_bytes()
        need(len(raw) == SIZES[name] and hashlib.sha256(raw).hexdigest() == parsed['smallSHA256'][name],
             'pinned actual small-file copy')
    return parsed


def bounded(body, controller, seconds, uid):
    need(seconds <= 135 and seconds > 0, 'finite remote wall bound')
    return controller.prefix(uid) + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 ' + str(seconds) + \
        ' /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'


def quoted_size(script, root):
    command = ('sudo -k -S -p "" ' if root else '') + '/var/jb/bin/sh -c ' + shlex.quote(script)
    return len(command.encode())


def identity_rows(text, app_path, child_path):
    found = {}
    for kind, pid, ppid, start, path in re.findall(
            r'^OWN_(APP|CHILD)_ID ([0-9]+) ([0-9]+) 501 ([a-f0-9]{64}) (\S+)$', text, re.M):
        row = dict(pid=int(pid), ppid=int(ppid), uid=501, startHash=start, path=path)
        need(row['pid'] > 1 and path == (app_path if kind == 'APP' else child_path), 'actual capture path/PID')
        need(kind not in found, 'one actual identity capture per process')
        found[kind] = row
    need(set(found) == {'APP', 'CHILD'} and found['APP']['ppid'] == 1 and
         found['CHILD']['ppid'] == found['APP']['pid'], 'actual direct child of actual App')
    return found
