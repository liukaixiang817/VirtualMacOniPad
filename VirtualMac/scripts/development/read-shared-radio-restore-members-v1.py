#!/usr/bin/env python3
"""Read a bounded ZIP directory or selected member from an Apple restore image.

Refuses servers that ignore Range, verifies ZIP CRC, and records the exact CDN
entity. Useful for auditing each guest's kernel before its full restore finishes.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.parse
import urllib.request
import zipfile


class RemoteArchive(io.RawIOBase):
    def __init__(self, url, size, entity):
        self.url, self.size, self.entity = url, size, entity
        self.position, self.total, self.requests = 0, 0, []

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        value = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if not 0 <= value <= self.size:
            raise ValueError('invalid ZIP seek')
        self.position = value
        return value

    def read(self, size=-1):
        size = self.size - self.position if size < 0 else min(size, self.size - self.position)
        if not size:
            return b''
        if size > 64*1024*1024 or self.total + size > 160*1024*1024 or len(self.requests) >= 64:
            raise ValueError('range-read budget exceeded')
        start, end = self.position, self.position + size - 1
        request = urllib.request.Request(self.url, headers={'Range': f'bytes={start}-{end}', 'Accept-Encoding': 'identity'})
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 206 or response.geturl() != self.url or response.headers.get('Content-Range') != f'bytes {start}-{end}/{self.size}':
                raise ValueError('CDN did not return the exact requested range')
            entity = (response.headers.get('ETag'), response.headers.get('Last-Modified'))
            if entity != self.entity:
                raise ValueError('CDN entity changed during read')
            data = response.read(size+1)
            if len(data) != size:
                raise ValueError('incomplete range')
        self.position += size
        self.total += size
        self.requests.append({'start': start, 'bytes': size, 'sha256': hashlib.sha256(data).hexdigest()})
        return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--member', action='append', default=[])
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != 'https' or parsed.hostname != 'updates.cdn-apple.com' or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        parser.error('requires an unmodified Apple restore CDN URL')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with urllib.request.urlopen(urllib.request.Request(args.url, method='HEAD'), timeout=20) as response:
        if response.geturl() != args.url:
            raise ValueError('unexpected redirect')
        size = int(response.headers['Content-Length'])
        entity = (response.headers.get('ETag'), response.headers.get('Last-Modified'))
    if not 1024*1024*1024 <= size <= 40*1024*1024*1024:
        raise ValueError('unexpected restore image size')
    reader = RemoteArchive(args.url, size, entity)
    saved = []
    with zipfile.ZipFile(reader) as archive:
        boot_members = {'Firmware/all_flash/iBoot.vma2.RELEASE.im4p',
                        'Firmware/all_flash/LLB.vma2.RELEASE.im4p'}
        members = [{'name': item.filename, 'bytes': item.file_size, 'compressedBytes': item.compress_size,
                    'crc32': item.CRC} for item in archive.infolist()
                   if 'kernelcache' in item.filename.lower() or item.filename == 'BuildManifest.plist'
                   or item.filename in boot_members]
        for name in args.member:
            item = archive.getinfo(name)
            if name not in [row['name'] for row in members] or item.file_size > 128*1024*1024 or item.compress_size > 64*1024*1024:
                raise ValueError('member is outside the bounded kernel audit scope')
            if name in boot_members and (item.file_size > 8*1024*1024 or item.compress_size > 8*1024*1024):
                raise ValueError('boot firmware member exceeds its bounded audit size')
            data = archive.read(name)  # zipfile validates the CRC and complete member size.
            destination = output / Path(name).name
            if destination.exists():
                raise ValueError('colliding output member name')
            destination.write_bytes(data)
            saved.append({'member': name, 'path': str(destination), 'sha256': hashlib.sha256(data).hexdigest()})
    result = {'schema': 1, 'url': args.url, 'archiveBytes': size, 'entity': entity,
              'members': members, 'saved': saved, 'ranges': reader.requests,
              'bytesRead': reader.total, 'fullArchiveDownloaded': False}
    (output / 'receipt.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(output), 'members': members, 'saved': saved, 'bytesRead': reader.total}))


if __name__ == '__main__':
    main()
