"""Read bounded data from the UUID-pinned iPad cache; never load or modify it; use a direct SSH session."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
BASE = '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
FILES = {'main': BASE, '01': BASE+'.01', '03': BASE+'.03', '05': BASE+'.05',
         '07': BASE+'.07', '09': BASE+'.09', '11': BASE+'.11', '13': BASE+'.13', '15': BASE+'.15', '17': BASE+'.17', '21': BASE+'.21', '25': BASE+'.25', '33': BASE+'.33', '39': BASE+'.39', '27-data': BASE+'.27.dylddata', '28-linkedit': BASE+'.28.dyldlinkedit', '44-linkedit': BASE+'.44.dyldlinkedit'}
EXPECTED_UUID = '1995ea169d0a33a0b78962cf99891168'
REMOTE_SHA = '29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True, type=Path)
    ap.add_argument('--headers', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    headers_bytes = args.headers.read_bytes()
    manifest = json.loads(manifest_bytes)
    headers = json.loads(headers_bytes)
    assert headers['mainUUID'] == EXPECTED_UUID and headers['matchesArchivedMap'] is True
    assert headers['deviceWrites'] == 0
    pinned = {row['name']: row for row in headers['headers']}
    assert set(pinned) == set(FILES)
    rows = manifest['ranges']
    assert 0 < len(rows) <= 16
    total = 0
    seen = set()
    for row in rows:
        assert set(row) == {'name', 'cache', 'offset', 'length'}
        assert re.fullmatch(r'[a-z0-9-]{1,80}', row['name'])
        assert row['name'] not in seen
        seen.add(row['name'])
        assert row['cache'] in FILES
        assert type(row['offset']) is int and row['offset'] >= 4096
        assert type(row['length']) is int and 0 < row['length'] <= 2*1024*1024
        assert any(m['fileOffset'] <= row['offset'] and
                   row['offset'] + row['length'] <= m['fileOffset'] + m['size']
                   for m in pinned[row['cache']]['maps'])
        total += row['length']
    assert total <= 4*1024*1024
    helper = ROOT/'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
    assert sha(helper.read_bytes()) == REMOTE_SHA
    script = '''set -eu
export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" = 0 ]
[ "$(sysctl -n hw.machine)" = iPad14,6 ]
[ "$(sysctl -n kern.osversion)" = 20B101 ]
'''
    def guards():
        result = ''
        for name in sorted({r['cache'] for r in rows} | {'main'}):
            path = FILES[name]
            digest = pinned[name]['sha256']
            assert re.fullmatch('[0-9a-f]{64}', digest)
            result += f'''[ -f '{path}' ]
[ ! -L '{path}' ]
[ "$(dd if='{path}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f 1)" = '{digest}' ]
'''
        return result
    script += guards()
    for row in rows:
        path = FILES[row['cache']]
        end = row['offset'] + row['length']
        script += f'''[ "$(stat -c '%s' '{path}')" -ge {end} ]
printf 'BEGIN_BASE64 {row['name']}\\n'
dd if='{path}' bs=65536 skip={row['offset']} count={row['length']} iflag=skip_bytes,count_bytes status=none | base64
printf '\\nEND_BASE64 {row['name']}\\n'
'''
    script += guards()
    script += "printf 'FINAL_CACHE_HEADERS_MATCH\\n'\n"
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, check=True)
    args.output.mkdir(exist_ok=False)
    (args.output/'manifest.json').write_bytes(manifest_bytes)
    (args.output/'script.sh').write_text(script)
    (args.output/'reader-source.py').write_bytes(Path(__file__).read_bytes())
    spec = importlib.util.spec_from_file_location('readonly_cache_remote', helper)
    remote = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(remote)
    # A new ordinary SSH connection avoids local multiplexed FD transfer.
    # Existing USB forwarders and the previous control socket are untouched.
    remote.IPAD_SSH = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8',
                       '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                       '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts',
                       '-o', 'StrictHostKeyChecking=yes', 'mobile@127.0.0.1']
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = remote.run(script, device='ipad', root=True, timeout=55)
    (args.output/'stdout').write_bytes(result.stdout)
    (args.output/'stderr').write_bytes(result.stderr)
    receipt = {'schema': 'UUID-pinned bounded iPad cache read receipt v1',
               'startedUTC': started, 'recordedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'deviceWrites': 0, 'nativeCPUCalls': 0, 'newFrameworksLoaded': 0,
               'mainCacheUUID': EXPECTED_UUID, 'transportExit': result.returncode,
               'requestedBytes': total, 'requestedRanges': len(rows),
               'manifestSHA256': sha(manifest_bytes), 'headersSHA256': sha(headers_bytes),
               'scriptSHA256': sha(script.encode()), 'readerSHA256': sha(Path(__file__).read_bytes()),
               'stdoutSHA256': sha(result.stdout), 'stderrSHA256': sha(result.stderr)}
    (args.output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')[:1000]
    assert result.stdout.endswith(b'FINAL_CACHE_HEADERS_MATCH\n')
    decoded = re.findall(rb'BEGIN_BASE64 ([a-z0-9-]+)\n(.*?)\nEND_BASE64 \1\n', result.stdout, re.S)
    assert len(decoded) == len(rows)
    captures = []
    for row, (name, encoded) in zip(rows, decoded):
        assert name.decode() == row['name']
        data = base64.b64decode(encoded)
        assert len(data) == row['length']
        path = args.output/(row['name']+'.bin')
        path.write_bytes(data)
        captures.append({**row, 'path': str(path.resolve()), 'sha256': sha(data)})
    receipt['ranges'] = captures
    receipt['allHeaderPinsMatchBeforeAndAfter'] = True
    (args.output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'transportExit': result.returncode, 'ranges': len(captures),
                      'bytes': total, 'receipt': str((args.output/'receipt.json').resolve())}))

if __name__ == '__main__':
    main()
