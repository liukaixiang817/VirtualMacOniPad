"""Read fixed main/.09 identities and add .09 only after actual identity equality."""
from pathlib import Path
import argparse, base64, datetime, hashlib, importlib.util, json, re, struct, subprocess, sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'

def need(value, reason):
    if not value:
        raise ValueError(reason)

def pin(path):
    path = Path(path)
    need(path.is_absolute() and path.is_file() and not path.is_symlink(), 'regular absolute input')
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.is_relative_to(N) and not out.exists(), 'new diagnostic directory required')
    plan = N / 'ipad-current-hid-trace-member-header-plan-v1'
    request_path, derivation_path = plan / 'request.json', plan / 'derivation.json'
    need(pin(request_path)['sha256'] == '586f31810275d85838580742279d726293571c28ec0594190bd8f04e9530c123', 'fixed request')
    need(pin(plan / 'freeze.json')['sha256'] == '4285c7eb79208e4904ceb3a66aed546c21dc06c45eff954502db186146122f45', 'fixed plan freeze')
    for row in json.loads((plan / 'freeze.json').read_bytes())['files']:
        need(pin(row['path']) == row, 'plan input drift')
    request, derivation = json.loads(request_path.read_bytes()), json.loads(derivation_path.read_bytes())
    rows = request['fixedFiles']
    expected = [('main', BASE, '1995ea169d0a33a0b78962cf99891168', '307a229e3e3a2157562d3fe04a2955d898cdaa74dbb4ecfb0e59687fcfd06992'),
                ('09', BASE + '.09', 'a0382d94e343309f9c547d8ac8bb852b', 'd120bffcc61c867c8c6e4f6fa478c0a30f85c9b43744cb37dbabf55f4834c28b')]
    need(len(rows) == 2 and request['requestedBytes'] == 8192, 'fixed two pages')
    for row, (name, path, uuid, digest) in zip(rows, expected):
        need(row == dict(name=name, path=path, offset=0, length=4096, expectedUUID=uuid, expectedHeaderSHA256=digest), 'fixed member request')
    old_path = Path(derivation['currentHeaders']['path'])
    need(pin(old_path) == derivation['currentHeaders'], 'thirteen current header identity')
    old = json.loads(old_path.read_bytes())
    need(len(old['headers']) == 13 and '09' not in {r['name'] for r in old['headers']}, 'strict previous header set')
    main_prefix = (N.parent / '2026-10-02-macos27-backend/ipad-cache-headers.bin').read_bytes()[:4096]
    need(hashlib.sha256(main_prefix).hexdigest() == expected[0][3], 'main prefix equals guarded current bytes')
    tail = Path(derivation['actualMainTail']['path'])
    need(pin(tail) == derivation['actualMainTail'], 'actual main suffix-table pin')
    main_bytes = main_prefix + tail.read_bytes()
    record = derivation['actualMainRecord']
    at = record['actualMainRecordOffset']
    actual = main_bytes[at:at + 56]
    need(len(actual) == 56 and actual.hex() == record['rawRecord'], 'actual main suffix record')
    need(actual[:16].hex() == expected[1][2] and actual[24:].split(b'\0')[0] == b'.09', 'actual .09 UUID and suffix')
    need(struct.unpack_from('<Q', actual, 16)[0] == record['cacheVMOffset'] == 438697984, 'actual .09 VM offset')
    archive_path = Path(derivation['archivedMemberExpectedHeader']['path'])
    need(pin(archive_path) == derivation['archivedMemberExpectedHeader'], 'archive used only as expected identity')
    helper = R / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
    need(pin(helper)['sha256'] == '29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424', 'fixed root transport')
    script = "set -eu\nexport PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin\n[ \"$(id -u)\" = 0 ]\n[ \"$(sysctl -n hw.machine)\" = iPad14,6 ]\n[ \"$(sysctl -n kern.osversion)\" = 20B101 ]\n"
    for row in rows:
        path, name = row['path'], row['name']
        script += f"[ -f '{path}' ]\n[ ! -L '{path}' ]\n[ \"$(stat -c '%s' '{path}')\" -ge 4096 ]\nMETA_{name.upper()}=$(stat -c '%u:%g:%a:%h:%s:%d:%i' '{path}')\n[ \"$(dd if='{path}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)\" = '{row['expectedHeaderSHA256']}' ]\n"
    for row in rows:
        script += f"printf 'BEGIN_BASE64 {row['name']}\\n'\ndd if='{row['path']}' bs=4096 count=1 status=none | base64\nprintf '\\nEND_BASE64 {row['name']}\\n'\n"
    for row in rows:
        script += f"[ \"$(stat -c '%u:%g:%a:%h:%s:%d:%i' '{row['path']}')\" = \"$META_{row['name'].upper()}\" ]\n[ \"$(dd if='{row['path']}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)\" = '{row['expectedHeaderSHA256']}' ]\n"
    script += "printf 'FINAL_MAIN_AND_MEMBER09_HEADERS_MATCH\\n'\n"
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, check=True)
    out.mkdir(mode=0o700, exist_ok=False)
    (out / 'reader-source.py').write_bytes(Path(__file__).read_bytes())
    (out / 'manifest.json').write_bytes(request_path.read_bytes())
    (out / 'script.sh').write_text(script)
    save(out / 'input-pins.json', dict(request=pin(request_path), derivation=pin(derivation_path), oldHeaders=pin(old_path), archiveExpected=pin(archive_path), actualMainTail=pin(tail), remote=pin(helper)))
    spec = importlib.util.spec_from_file_location('readonly_trace_header_remote', helper)
    remote = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(remote)
    remote.IPAD_SSH = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts', '-o', 'StrictHostKeyChecking=yes', 'mobile@127.0.0.1']
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = remote.run(script, device='ipad', root=True, timeout=45)
    (out / 'stdout').write_bytes(result.stdout)
    (out / 'stderr').write_bytes(result.stderr)
    receipt = dict(schema='Actual fixed main and .09 readonly header capture v1', startedUTC=started, recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), transportExit=result.returncode, requestedBytes=8192, deviceWrites=0, nativeCPUCalls=0, nativeVMCalls=0, newFrameworksLoaded=0, reader=pin(out / 'reader-source.py'), manifest=pin(out / 'manifest.json'), script=pin(out / 'script.sh'), inputPins=pin(out / 'input-pins.json'), stdout=pin(out / 'stdout'), stderr=pin(out / 'stderr'))
    save(out / 'receipt.json', receipt)
    need(result.returncode == 0 and result.stdout.endswith(b'FINAL_MAIN_AND_MEMBER09_HEADERS_MATCH\n'), 'actual bounded header transaction completed')
    frames = re.findall(rb'BEGIN_BASE64 (main|09)\n(.*?)\nEND_BASE64 \1\n', result.stdout, re.S)
    need(len(frames) == 2, 'exact two captured header frames')
    captured = []
    for row, (name, encoded) in zip(rows, frames):
        need(name.decode() == row['name'], 'ordered actual frame')
        raw = base64.b64decode(re.sub(rb'\s', b'', encoded), validate=True)
        need(len(raw) == 4096 and hashlib.sha256(raw).hexdigest() == row['expectedHeaderSHA256'] and raw[88:104].hex() == row['expectedUUID'], 'actual entire header identity')
        off, count = struct.unpack_from('<II', raw, 16)
        need(0 < count <= 8 and off + count * 32 <= 4096, 'actual mapping span')
        maps = [dict(zip(('address', 'size', 'fileOffset', 'maxProt', 'initProt'), struct.unpack_from('<QQQII', raw, off + i * 32))) for i in range(count)]
        (out / (row['name'] + '-header.bin')).write_bytes(raw)
        captured.append(dict(name=row['name'], sha256=hashlib.sha256(raw).hexdigest(), UUID=row['expectedUUID'], maps=maps))
    need((out / 'main-header.bin').read_bytes() == main_prefix and (out / '09-header.bin').read_bytes() == archive_path.read_bytes(), 'actual headers match expected complete bytes')
    need(captured[0] == next(row for row in old['headers'] if row['name'] == 'main'), 'main mapping identity unchanged')
    need(captured[1]['maps'][0]['address'] - 0x180000000 == record['cacheVMOffset'], 'current member agrees with actual main VM offset')
    trace = derivation['actualTraceInventoryRow']
    need(any(m['address'] <= trace['address'] and trace['address'] + trace['textSize'] <= m['address'] + m['size'] for m in captured[1]['maps']), 'actual trace text in actual member mapping')
    merged = dict(old)
    merged['schema'] = 'Fourteen actual guarded current cache header identities v1'
    merged['headers'] = old['headers'] + [captured[1]]
    merged['trace09ActualReceiptPath'] = str(out / 'receipt.json')
    merged['actualMainSuffixAndMemberVMOffsetVerified'] = True
    need(len(merged['headers']) == len({r['name'] for r in merged['headers']}) == 14, 'exact fourteen identities')
    save(out / 'headers.json', merged)
    receipt.update(headers=pin(out / 'headers.json'), mainAndMemberHeadersGuardedBeforeAndAfter=True, currentTraceMemberIdentityProven=True, currentTraceCommandsOrExportsCaptured=False, frameworkABIExecuted=False, full27Backend=False)
    save(out / 'receipt.json', receipt)
    print(json.dumps(dict(receipt=pin(out / 'receipt.json'), headers=pin(out / 'headers.json'), newActualMember=captured[1])))

if __name__ == '__main__':
    main()
