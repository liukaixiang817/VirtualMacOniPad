"""Read four header pages and add three members derived from the actual main table."""
from pathlib import Path
import argparse, base64, datetime, hashlib, importlib.util, json, re, struct, subprocess, sys
from DyldExtractor.dyld.dyld_structs import dyld_cache_header, dyld_subcache_entry2
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
PATHS = ['/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer', '/System/Library/Frameworks/Accelerate.framework/Accelerate', '/usr/lib/libz.1.dylib']
def need(value, reason):
    if not value: raise ValueError(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(path):
    path = Path(path)
    need(path.is_absolute() and path.is_file() and not path.is_symlink(), 'regular absolute input')
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))
def save(path, value): path.write_text(json.dumps(value, indent=2) + '\n')
def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    need(out.is_relative_to(N) and not out.exists(), 'fresh output')
    old_path = N / 'ipad-current-cache-trace-header-readonly-v1/headers.json'
    need(pin(old_path)['sha256'] == 'f457d8f2168723936b1e363967b3d07ed047f89da967cc7d8eed9603ff1bb868', 'actual fourteen header set')
    old = json.loads(old_path.read_bytes()); need(len(old['headers']) == 14, 'fourteen input members')
    prefix_path = old_path.parent / 'main-header.bin'
    prefix = prefix_path.read_bytes(); main_row = next(x for x in old['headers'] if x['name'] == 'main')
    need(len(prefix) == 4096 and sha(prefix) == main_row['sha256'], 'actual main whole page')
    tail = N / 'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin'
    receipt_path = tail.parent / 'receipt.json'; receipt = json.loads(receipt_path.read_bytes())
    need(receipt['transportExit'] == 0 and receipt['allHeaderPinsMatchBeforeAndAfter'] is True, 'actual main table receipt')
    need(any(x['path'] == str(tail) and x['sha256'] == pin(tail)['sha256'] for x in receipt['ranges']), 'actual main tail pin')
    body = prefix + tail.read_bytes(); head = dyld_cache_header.from_buffer_copy(body)
    need(bytes(head.uuid).hex() == old['mainUUID'] == '1995ea169d0a33a0b78962cf99891168', 'actual main UUID')
    entries = []
    for i in range(head.subCacheArrayCount):
        at = head.subCacheArrayOffset + i * dyld_subcache_entry2.SIZE
        need(at + dyld_subcache_entry2.SIZE <= len(body), 'actual suffix bounds')
        x = dyld_subcache_entry2.from_buffer_copy(body, at)
        entries.append(dict(suffix=bytes(x.fileExtension).split(b'\0')[0].decode(), UUID=bytes(x.uuid).hex(), cacheVMOffset=x.cacheVMOffset, actualRecordOffset=at, rawRecord=body[at:at + dyld_subcache_entry2.SIZE].hex()))
    images_path = N / 'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    need(pin(images_path)['sha256'] == '9e7319c0c1f6feddb0e956c1ca0d2b3b5753155a3624b41f02f774ccdf487f8d', 'actual image inventory')
    inventory = json.loads(images_path.read_bytes()); selected = {}
    for path in PATHS:
        found = [r for r in inventory if r['path'] == path]; need(len(found) == 1, 'actual one image')
        image = found[0]
        # This table chooses a header to inspect. Actual image coverage is
        # established only after parsing that member's captured mappings.
        candidates = [e for e in entries if 0x180000000 + e['cacheVMOffset'] <= image['address']]
        need(bool(candidates), 'table candidate exists')
        entry = max(candidates, key=lambda e: e['cacheVMOffset'])
        name = entry['suffix'][1:]; need(re.fullmatch('[0-9]{2}', name) is not None, 'text member suffix')
        selected[name] = dict(entry, actualInventoryImage=image)
    need(set(selected) == {'15', '33', '39'} and not set(selected) & {r['name'] for r in old['headers']}, 'three new member candidates')
    rows = [dict(name='main', path=BASE, UUID=old['mainUUID'])] + [dict(name=k, path=BASE + v['suffix'], UUID=v['UUID']) for k, v in sorted(selected.items())]
    helper = R / 'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py'
    need(pin(helper)['sha256'] == '29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424', 'fixed root transport')
    script = 'set -eu\nexport PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin\n[ "$(id -u)" = 0 ]\n[ "$(sysctl -n hw.machine)" = iPad14,6 ]\n[ "$(sysctl -n kern.osversion)" = 20B101 ]\n'
    for row in rows:
        path, name = row['path'], row['name']
        script += f'[ -f \'{path}\' ]\n[ ! -L \'{path}\' ]\n[ "$(stat -c \'%s\' \'{path}\')" -ge 4096 ]\nMETA_{name}=$(stat -c \'%u:%g:%a:%h:%s:%d:%i\' \'{path}\')\nSHA_{name}=$(dd if=\'{path}\' bs=4096 count=1 status=none | sha256sum | cut -d \' \' -f1)\n'
    script += f'[ "$SHA_main" = \'{main_row["sha256"]}\' ]\n'
    for row in rows:
        script += f'printf \'BEGIN_BASE64 {row["name"]}\\n\'\ndd if=\'{row["path"]}\' bs=4096 count=1 status=none | base64\nprintf \'\\nEND_BASE64 {row["name"]}\\n\'\n'
    for row in rows:
        script += f'[ "$(stat -c \'%u:%g:%a:%h:%s:%d:%i\' \'{row["path"]}\')" = "$META_{row["name"]}" ]\n[ "$(dd if=\'{row["path"]}\' bs=4096 count=1 status=none | sha256sum | cut -d \' \' -f1)" = "$SHA_{row["name"]}" ]\n'
    script += 'printf \'FINAL_VZ_STOCK_MEMBER_HEADERS_MATCH\\n\'\n'
    subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, check=True)
    out.mkdir(mode=0o700)
    (out / 'source.py').write_bytes(Path(__file__).read_bytes()); (out / 'script.sh').write_text(script)
    save(out / 'manifest.json', dict(fixedFiles=rows, selectedActualMainEntries=selected, inputPins=[pin(x) for x in (old_path, prefix_path, tail, receipt_path, images_path, helper)], deviceWrites=0))
    spec = importlib.util.spec_from_file_location('readonly_stock_member_remote', helper)
    remote = importlib.util.module_from_spec(spec); spec.loader.exec_module(remote)
    remote.IPAD_SSH = ['ssh', '-p', '2221', '-o', 'ConnectTimeout=8', '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts', '-o', 'StrictHostKeyChecking=yes', 'mobile@127.0.0.1']
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = remote.run(script, device='ipad', root=True, timeout=45)
    (out / 'stdout').write_bytes(result.stdout); (out / 'stderr').write_bytes(result.stderr)
    proof = dict(schema='Actual main and three missing VZ native member headers v1', startedUTC=started, recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), transportExit=result.returncode, requestedBytes=16384, deviceWrites=0, nativeCPUCalls=0, nativeVMCalls=0, newFrameworksLoaded=0, source=pin(out / 'source.py'), script=pin(out / 'script.sh'), manifest=pin(out / 'manifest.json'), stdout=pin(out / 'stdout'), stderr=pin(out / 'stderr'))
    save(out / 'receipt.json', proof)
    need(result.returncode == 0 and result.stderr == b'' and result.stdout.endswith(b'FINAL_VZ_STOCK_MEMBER_HEADERS_MATCH\n'), 'actual header transaction completed')
    frames = re.findall(rb'BEGIN_BASE64 (main|15|33|39)\n(.*?)\nEND_BASE64 \1\n', result.stdout, re.S)
    need(len(frames) == len(rows) == 4, 'four whole frames')
    captured = []
    for row, (name, encoded) in zip(rows, frames):
        raw = base64.b64decode(re.sub(rb'\s', b'', encoded), validate=True)
        need(name.decode() == row['name'] and len(raw) == 4096 and raw[88:104].hex() == row['UUID'], 'actual header UUID')
        off, count = struct.unpack_from('<II', raw, 16)
        need(0 < count <= 8 and off + count * 32 <= 4096, 'actual mapping span')
        maps = [dict(zip(('address', 'size', 'fileOffset', 'maxProt', 'initProt'), struct.unpack_from('<QQQII', raw, off + i * 32))) for i in range(count)]
        actual = dict(name=row['name'], UUID=row['UUID'], sha256=sha(raw), maps=maps)
        (out / (row['name'] + '-header.bin')).write_bytes(raw)
        if row['name'] == 'main': need(raw == prefix and actual == main_row, 'whole main header unchanged')
        else:
            chosen = selected[row['name']]; image = chosen['actualInventoryImage']
            need(maps[0]['address'] - 0x180000000 == chosen['cacheVMOffset'], 'actual member offset matches main')
            need(any(m['address'] <= image['address'] and image['address'] + image['textSize'] <= m['address'] + m['size'] for m in maps), 'actual image coverage in actual member mapping')
            captured.append(actual)
    merged = dict(old); merged['schema'] = 'Seventeen actual current cache header identities v1'; merged['headers'] = old['headers'] + captured
    merged['vzStockMemberHeadersActualReceipt'] = str(out / 'receipt.json')
    need(len(merged['headers']) == len({r['name'] for r in merged['headers']}) == 17, 'seventeen distinct actual headers')
    save(out / 'headers.json', merged)
    proof.update(headers=pin(out / 'headers.json'), mainAndNewMemberHeadersGuardedBeforeAndAfter=True, actualNewMembers=selected, functionDefinitionsOrABIProven=False, full27Backend=False)
    save(out / 'receipt.json', proof)
    print(json.dumps(dict(receipt=pin(out / 'receipt.json'), headers=pin(out / 'headers.json'), newMembers=list(selected))))
if __name__ == '__main__': main()
