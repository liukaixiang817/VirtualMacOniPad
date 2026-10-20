#!/usr/bin/env python3
"""Root-only read of one OS kernelcache from the existing official guest IPSW."""
import argparse, datetime, getpass, hashlib, importlib.util, json, pathlib, re, shlex, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
C = N / 'independent27-pg-display-observation-device-v76-attempt1/control.py'
CONTROLLER_SHA = '1381b8ee9587f00d8c1eadc7eed1e809a2b553e47fc12dae3e2800f1fad45db2'
IMAGE = '/private/var/mobile/Media/VirtualMac/Restore Images/UniversalMac_26.6.2_25G83_Restore.ipsw'
IMAGE_BYTES = 19772231540
MAX_MEMBER_BYTES = 134217728
def pin(path):
    p = pathlib.Path(path).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(path, obj): path.write_text(json.dumps(obj, indent=2) + '\n')
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--action', required=True, choices=('inventory', 'extract'))
    ap.add_argument('--output', required=True, type=pathlib.Path)
    ap.add_argument('--inventory', type=pathlib.Path)
    ap.add_argument('--member')
    a = ap.parse_args(argv); outdir = a.output.resolve()
    assert outdir.parent == N and not outdir.exists()
    assert pin(C)['sha256'] == CONTROLLER_SHA
    spec = importlib.util.spec_from_file_location('current_dev76_os_archive_read', C)
    c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
    prior = None
    if a.action == 'extract':
        assert a.inventory and a.member
        ip = a.inventory.resolve(); prior = json.loads(ip.read_bytes())
        assert ip.parent.parent == N and prior['schema'] == 'Actual existing 25G83 IPSW kernelcache inventory v1'
        assert pin(prior['actualReceipt']['path']) == prior['actualReceipt']
        rec = json.loads(pathlib.Path(prior['actualReceipt']['path']).read_bytes())
        assert rec['transportExit'] == 0 and rec['source'] == pin(__file__)
        assert rec['stdout'] == prior['actualStdout'] and pin(rec['stdout']['path']) == rec['stdout']
        assert prior['controller'] == pin(C) and prior['archivePath'] == IMAGE
        assert prior['unzipPath'] in ('/var/jb/usr/bin/unzip', '/usr/bin/unzip')
        assert re.fullmatch(r'[A-Za-z0-9_./-]+', a.member) and '..' not in pathlib.PurePosixPath(a.member).parts
        selected = [x for x in prior['members'] if x['name'] == a.member]
        assert len(selected) == 1 and 0 < selected[0]['bytes'] <= MAX_MEMBER_BYTES
        member_bytes = selected[0]['bytes']
    else:
        assert a.inventory is None and a.member is None
    body = c.prefix(0) + 'archive=' + shlex.quote(IMAGE) + '\n' + '''
[ -f "$archive" ] && [ ! -L "$archive" ]
[ "$(realpath "$archive")" = "$archive" ]
[ "$(stat -c %s "$archive")" = 19772231540 ]
archive_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$archive")
'''
    if a.action == 'inventory':
        body += '''
unzip=
for candidate in /var/jb/usr/bin/unzip /usr/bin/unzip; do
 if [ -x "$candidate" ]; then unzip=$candidate; break; fi
done
[ -n "$unzip" ]
tool_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$unzip")
tool_sha=$(sha256sum "$unzip" | cut -d ' ' -f1)
printf 'ARCHIVE_METADATA %s\\nUNZIP_PATH %s\\nUNZIP_METADATA %s\\nUNZIP_SHA256 %s\\nOS_KERNELCACHE_LIST_BEGIN\\n' "$archive_meta" "$unzip" "$tool_meta" "$tool_sha"
"$unzip" -l "$archive" '*kernelcache*'
printf 'OS_KERNELCACHE_LIST_END\\n'
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$archive")" = "$archive_meta" ]
printf 'OS_ARCHIVE_IDENTITY_STILL_SAME\\n'
'''
        limit = 20
    else:
        body += '[ "$archive_meta" = ' + shlex.quote(prior['archiveMetadata']) + ' ]\n'
        body += 'unzip=' + shlex.quote(prior['unzipPath']) + '\n'
        body += '[ "$(sha256sum "$unzip" | cut -d \' \' -f1)" = ' + shlex.quote(prior['unzipSHA256']) + ' ]\n'
        body += '[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$unzip")" = ' + shlex.quote(prior['unzipMetadata']) + ' ]\n'
        body += "printf 'OS_KERNELCACHE_MEMBER_BEGIN\\n'\n"
        body += '"$unzip" -p "$archive" ' + shlex.quote(a.member) + '\n'
        body += "printf '\\nOS_KERNELCACHE_MEMBER_END\\n'\n"
        body += '[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$archive")" = "$archive_meta" ]\n'
        body += "printf 'OS_ARCHIVE_IDENTITY_STILL_SAME\\n'\n"
        limit = 90
    script = 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 ' + str(limit) + ' /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    outdir.mkdir(mode=0o700); (outdir/'read-root.sh').write_text(script)
    request = dict(source=pin(__file__), controller=pin(C), action=a.action, script=pin(outdir/'read-root.sh'),
                   archivePath=IMAGE, expectedArchiveBytes=IMAGE_BYTES, wholeArchiveSHARechecked=False,
                   inventory=pin(a.inventory) if a.inventory else None, member=a.member,
                   remoteTimeoutSeconds=limit, transportTimeoutSeconds=100 if limit == 90 else 55,
                   deviceWrites=0, processSignalsRequested=False, trustCacheOperations=0)
    save(outdir/'request.json', request)
    password = getpass.getpass('iPad password: ')
    try: rc, stdout, stderr, error = c.run_remote(script, b'', True, password, transport_timeout=100 if limit == 90 else 55)
    finally: password = None
    (outdir/'stdout').write_bytes(stdout); (outdir/'stderr').write_bytes(stderr)
    result = dict(source=pin(__file__), transportExit=rc, transportError=error,
                  finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  request=pin(outdir/'request.json'), stdout=pin(outdir/'stdout'), stderr=pin(outdir/'stderr'),
                  deviceWrites=0, processSignalsRequested=False, trustCacheOperations=0)
    save(outdir/'receipt.json', result)
    if rc == 0:
        if a.action == 'inventory':
            text = stdout.decode('utf-8')
            assert text.endswith('OS_KERNELCACHE_LIST_END\nOS_ARCHIVE_IDENTITY_STILL_SAME\n')
            def field(name):
                rows = [x[len(name)+1:] for x in text.splitlines() if x.startswith(name+' ')]
                assert len(rows) == 1
                return rows[0]
            members = []
            listing = text.split('OS_KERNELCACHE_LIST_BEGIN\n', 1)[1].split('OS_KERNELCACHE_LIST_END\n', 1)[0]
            for line in listing.splitlines():
                match = re.fullmatch(r'\s*(\d+)\s+\S+\s+\S+\s+([A-Za-z0-9_./-]*kernelcache[A-Za-z0-9_./-]*)\s*', line)
                if match: members.append(dict(name=match[2], bytes=int(match[1])))
            assert members and len({x['name'] for x in members}) == len(members)
            save(outdir/'inventory.json', dict(schema='Actual existing 25G83 IPSW kernelcache inventory v1',
                 archivePath=IMAGE, archiveMetadata=field('ARCHIVE_METADATA'),
                 unzipPath=field('UNZIP_PATH'), unzipMetadata=field('UNZIP_METADATA'), unzipSHA256=field('UNZIP_SHA256'),
                 members=members, controller=pin(C), actualReceipt=pin(outdir/'receipt.json'), actualStdout=result['stdout']))
        else:
            prefix = b'OS_KERNELCACHE_MEMBER_BEGIN\n'
            suffix = b'\nOS_KERNELCACHE_MEMBER_END\nOS_ARCHIVE_IDENTITY_STILL_SAME\n'
            assert stdout.startswith(prefix) and stdout.endswith(suffix)
            payload = stdout[len(prefix):-len(suffix)]
            assert len(payload) == member_bytes <= MAX_MEMBER_BYTES
            (outdir/'kernelcache.img4').write_bytes(payload)
            save(outdir/'extraction.json', dict(archivePath=IMAGE, inventory=pin(a.inventory), member=a.member,
                 actualReceipt=pin(outdir/'receipt.json'), actualComponent=pin(outdir/'kernelcache.img4'),
                 actualUnzipCRCExitZero=True, archiveIdentitySameBeforeAfter=True, wholeArchiveSHARechecked=False))
    print(json.dumps(result)); raise SystemExit(rc)
if __name__ == '__main__': main()
