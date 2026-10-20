#!/usr/bin/env python3
"""Read only ZIP metadata and one kernelcache member from the official 25G83 IPSW."""
import argparse, datetime, hashlib, io, json, pathlib, signal, struct, sys, time, urllib.request, zipfile, zlib
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
URL = 'https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75212/A2A24B94-1FC1-45A3-93F7-C51B02AF1F4D/UniversalMac_26.6.2_25G83_Restore.ipsw'
ARCHIVE_BYTES = 19772231540
MAX_COMPRESSED = 67108864
MAX_DECODED = 134217728
def pin(path):
    p = pathlib.Path(path).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(path, obj): path.write_text(json.dumps(obj, indent=2) + '\n')
def timeout_handler(signum, frame): raise TimeoutError('bounded HOST-only range read deadline')
class Ranges(io.RawIOBase):
    def __init__(self, output, budget, entity=None):
        self.output, self.budget, self.entity = output, budget, entity
        self.position = 0; self.requests = []; self.total = 0
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=0):
        value = offset if whence == 0 else self.position + offset if whence == 1 else ARCHIVE_BYTES + offset if whence == 2 else -1
        assert 0 <= value <= ARCHIVE_BYTES
        self.position = value; return value
    def read(self, size=-1):
        if size < 0: size = ARCHIVE_BYTES - self.position
        size = min(size, ARCHIVE_BYTES - self.position)
        if not size: return b''
        data = self.get(self.position, size); self.position += len(data); return data
    def get(self, start, size):
        assert 0 <= start < ARCHIVE_BYTES and 0 < size <= MAX_COMPRESSED
        assert start + size <= ARCHIVE_BYTES and self.total + size <= self.budget and len(self.requests) < 16
        end = start + size - 1
        req = urllib.request.Request(URL, headers={'Range':f'bytes={start}-{end}', 'Accept-Encoding':'identity'})
        with urllib.request.urlopen(req, timeout=30) as response:
            assert response.status == 206, 'CDN ignored Range; full archive download is forbidden'
            assert response.geturl() == URL, 'unexpected redirect'
            assert response.headers.get('Content-Range') == f'bytes {start}-{end}/{ARCHIVE_BYTES}'
            assert response.headers.get('Content-Encoding', 'identity') == 'identity'
            if response.headers.get('Content-Length') is not None: assert int(response.headers['Content-Length']) == size
            entity = dict(etag=response.headers.get('ETag'), lastModified=response.headers.get('Last-Modified'))
            if self.entity is None: self.entity = entity
            else: assert self.entity == entity, 'CDN entity changed'
            data = response.read(size + 1)
            assert len(data) == size
            p = self.output/f'range-{len(self.requests):02d}.bin'; p.write_bytes(data)
            self.requests.append(dict(start=start, end=end, status=206, contentRange=response.headers['Content-Range'], body=pin(p)))
            self.total += len(data)
            return data
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--action', required=True, choices=('inventory','extract'))
    ap.add_argument('--output', required=True, type=pathlib.Path)
    ap.add_argument('--inventory', type=pathlib.Path)
    ap.add_argument('--member')
    a = ap.parse_args(argv); out = a.output.resolve()
    assert out.parent == N and not out.exists()
    prior = None
    if a.action == 'extract':
        assert a.inventory and a.member
        ip = a.inventory.resolve(); assert ip.parent.parent == N
        prior = json.loads(ip.read_bytes())
        assert prior['schema'] == 'Actual official 25G83 ZIP64 HTTP Range kernelcache inventory v1'
        assert prior['archiveURL'] == URL and prior['archiveBytes'] == ARCHIVE_BYTES
        assert pin(prior['actualReceipt']['path']) == prior['actualReceipt']
        rr = json.loads(pathlib.Path(prior['actualReceipt']['path']).read_bytes())
        assert rr['exit'] == 0 and rr['source'] == pin(__file__) and rr['requests'] == prior['requests']
        for row in rr['requests']: assert pin(row['body']['path']) == row['body']
        matches = [x for x in prior['members'] if x['name'] == a.member]
        assert len(matches) == 1; member = matches[0]
        assert 0 < member['compressedBytes'] <= MAX_COMPRESSED and 0 < member['bytes'] <= MAX_DECODED
        assert member['compression'] in (0,8) and not member['flags'] & 1
        assert '..' not in pathlib.PurePosixPath(a.member).parts and not a.member.startswith('/')
    else: assert a.inventory is None and a.member is None
    out.mkdir(mode=0o700)
    save(out/'request.json', dict(source=pin(__file__), action=a.action, archiveURL=URL, archiveBytes=ARCHIVE_BYTES,
         inventory=pin(a.inventory) if a.inventory else None, member=a.member, fullArchiveDownloadAllowed=False,
         deadlineSeconds=45 if a.action == 'inventory' else 90, deviceOperations=0))
    reader = Ranges(out, 33554432 if a.action == 'inventory' else MAX_COMPRESSED+131072, prior['entity'] if prior else None)
    result = None; error = None; code = 1
    signal.signal(signal.SIGALRM, timeout_handler); signal.alarm(45 if a.action == 'inventory' else 90)
    try:
        if a.action == 'inventory':
            with zipfile.ZipFile(reader) as archive:
                members = [dict(name=x.filename, headerOffset=x.header_offset, compression=x.compress_type,
                               compressedBytes=x.compress_size, bytes=x.file_size, crc32=x.CRC, flags=x.flag_bits)
                           for x in archive.infolist() if 'kernelcache' in x.filename.lower() and not x.is_dir()]
            assert members and len({x['name'] for x in members}) == len(members)
            result = dict(schema='Actual official 25G83 ZIP64 HTTP Range kernelcache inventory v1',
                          archiveURL=URL, archiveBytes=ARCHIVE_BYTES, entity=reader.entity, members=members)
        else:
            start = member['headerOffset']; header = reader.get(start,30)
            sig,version,flags,compression,mt,md,crc,csize,usize,nlen,xlen = struct.unpack('<I5H3I2H',header)
            assert sig == 0x04034b50 and compression == member['compression'] and flags == member['flags']
            assert nlen > 0 and nlen + xlen <= 131070
            names = reader.get(start+30,nlen+xlen)
            assert names[:nlen].decode('utf-8' if flags & 0x800 else 'cp437') == a.member
            compressed = reader.get(start+30+nlen+xlen,member['compressedBytes'])
            if compression == 0: payload = compressed
            else:
                decoder = zlib.decompressobj(-15)
                payload = decoder.decompress(compressed,member['bytes']+1)
                assert decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
            assert len(payload) == member['bytes'] and zlib.crc32(payload) & 0xffffffff == member['crc32']
            (out/'kernelcache.img4').write_bytes(payload)
            result = dict(schema='Actual one official 25G83 kernelcache HTTP Range extraction v1', inventory=pin(a.inventory),
                          archiveURL=URL, member=member, actualComponent=pin(out/'kernelcache.img4'),
                          actualMemberCRCAndSizeVerified=True, wholeArchiveSHARechecked=False)
        code = 0
    except Exception as exc: error = f'{type(exc).__name__}: {exc}'
    finally: signal.alarm(0)
    receipt = dict(source=pin(__file__), request=pin(out/'request.json'), exit=code, error=error,
                   finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(), requests=reader.requests,
                   actualRequestedBytes=reader.total, entity=reader.entity, deviceOperations=0,
                   fullArchiveDownloaded=False, wholeArchiveSHARechecked=False)
    save(out/'receipt.json',receipt)
    if result is not None:
        result['actualReceipt'] = pin(out/'receipt.json'); result['requests'] = reader.requests
        save(out/('inventory.json' if a.action == 'inventory' else 'extraction.json'),result)
    print(json.dumps(receipt)); raise SystemExit(code)
if __name__ == '__main__': main()
