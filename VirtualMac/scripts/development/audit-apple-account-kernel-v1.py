#!/usr/bin/env python3
"""Measure the ARM64_VMAPPLE sysctl policy site without changing an input.

Adapted from the supplied Henge Build104 audit_icloud_kernel.py. This audit
does not establish that a hypervisor hook ran, or that an account signed in.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct


def commands(data, start):
    if start < 0 or start + 32 > len(data) or data[start:start + 4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('expected a decompressed 64-bit Mach-O')
    count, total = struct.unpack_from('<II', data, start + 16)
    if count > 65536 or total > len(data) - start - 32:
        raise ValueError('invalid load-command table')
    offset, end = start + 32, start + 32 + total
    for _ in range(count):
        if offset + 8 > end: raise ValueError('truncated command')
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or size % 4 or size > end - offset:
            raise ValueError('invalid command size')
        yield command, offset, size
        offset += size
    if offset != end: raise ValueError('unused load-command bytes')


def matcher(code):
    shape = [0xd503237f, 0xd100c3ff, 0xa9014ff4, 0xa9027bfd, 0x910083fd,
             0xaa0303f3, 0xb9000fff, 0, 0, 0x910033e1, 0x52800082, 0,
             0xb9400fe8, 0x7100011f, 0x1a9f07e8, 0xb9000fe8, 0xf9401668,
             0x910033e1, 0xaa1303e0, 0x52800082, 0xd28d04f1, 0xd73f0911,
             0xa9427bfd, 0xa9414ff4, 0x9100c3ff, 0xd65f0fff]
    if len(code) != 104: return False
    words = struct.unpack('<26I', code)
    return (all(not expected or expected == actual for expected, actual in zip(shape, words))
            and words[7] & 0x9f00001f == 0x90000000
            and words[8] & 0xffc003ff == 0x91000000
            and words[11] & 0xfc000000 == 0x94000000)


def audit(path):
    data = Path(path).read_bytes()
    segments, kernel = [], None
    for cmd, off, size in commands(data, 0):
        if cmd == 0x19:
            if size < 72: raise ValueError('truncated segment')
            name = data[off + 8:off + 24].rstrip(b'\0').decode('ascii')
            vm, vsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            if filesize > len(data) or fileoff > len(data) - filesize:
                raise ValueError('segment outside file')
            segments.append((name, vm, vsize, fileoff, filesize))
        if cmd == 0x80000035:
            if size < 32: raise ValueError('truncated fileset entry')
            _, fileoff, nameoff, _ = struct.unpack_from('<QQII', data, off + 8)
            if not 32 <= nameoff < size: raise ValueError('invalid fileset name')
            name = data[off + nameoff:off + size].split(b'\0')[0]
            if name == b'com.apple.kernel':
                if kernel is not None: raise ValueError('duplicate kernel')
                kernel = fileoff
    if kernel is None: raise ValueError('missing kernel fileset entry')

    def virtual(offset):
        found = [vm + offset - fo for _, vm, _, fo, fs in segments if fo <= offset < fo + fs]
        if len(found) != 1: raise ValueError('file offset has no unique mapping')
        return found[0]

    def physical(address):
        found = [fo + address - vm for _, vm, _, fo, fs in segments if vm <= address < vm + fs]
        if len(found) != 1: raise ValueError('virtual address has no unique file mapping')
        return found[0]

    symtabs = [struct.unpack_from('<IIII', data, off + 8) for cmd, off, size in commands(data, kernel)
               if cmd == 2 and size == 24]
    if len(symtabs) != 1: raise ValueError('missing unique kernel symbols')
    symboloff, count, stringoff, stringsize = symtabs[0]
    if (count > len(data) // 16 or symboloff > len(data) - count * 16
            or stringsize > len(data) or stringoff > len(data) - stringsize):
        raise ValueError('symbol table outside file')
    procs = []
    for i in range(count):
        index, _, _, _, address = struct.unpack_from('<IBBHQ', data, symboloff + i * 16)
        if index >= stringsize: raise ValueError('invalid symbol string index')
        end = data.index(b'\0', stringoff + index, stringoff + stringsize)
        if data[stringoff + index:end] == b'_proc_name': procs.append(physical(address))
    if len(procs) != 1: raise ValueError('missing unique proc_name')
    proc = procs[0]
    offsets = {(word >> 10) & 0xfff for word in struct.unpack_from('<32I', data, proc)
               if word & 0xffc003ff == 0x91000001}
    if len(offsets) != 1: raise ValueError('ambiguous process command offset')
    comm = offsets.pop()
    accessor = struct.pack('<6I', 0x91000008 | ((comm + 17) << 10),
        0x39400009 | ((comm + 17) << 10), 0x9100000a | (comm << 10),
        0x7100013f, 0x9a880140, 0xd65f03c0)
    if accessor not in data[proc:proc + 0x200]: raise ValueError('unverified full-name accessor')
    prefix = struct.pack('<7I', 0xd503237f, 0xd100c3ff, 0xa9014ff4, 0xa9027bfd,
                         0x910083fd, 0xaa0303f3, 0xb9000fff)
    handlers, offset = [], 0
    while (offset := data.find(prefix, offset)) >= 0:
        if matcher(data[offset:offset + 104]): handlers.append(offset)
        offset += 4
    if len(handlers) != 1: raise ValueError('sysctl handler is not unique')
    fileoff = handlers[0]
    handler = virtual(fileoff)
    adrp, add = struct.unpack_from('<II', data, fileoff + 28)
    immediate = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3)
    if immediate & 1 << 20: immediate -= 1 << 21
    key = ((handler + 28) & ~0xfff) + immediate * 4096 + (add >> 10 & 0xfff)
    if data[physical(key):physical(key) + 12] != b'vmm-present\0':
        raise ValueError('handler does not resolve vmm-present')
    versionoff = data.index(b'Darwin Kernel Version ')
    version = data[versionoff:data.index(b'\0', versionoff)].decode('ascii')
    caves = []
    for name, vm, _, off, size in segments:
        if name != '__TEXT_EXEC': continue
        # Record zero padding as a research candidate, not as permission to
        # execute it. Native execution and instruction-cache handling require
        # their own on-device validation.
        end = off + size
        start = end - min(0x4000, size)
        tail = data[start:end]
        nonzero = max((i for i, byte in enumerate(tail) if byte), default=-1)
        zero = start + nonzero + 1
        aligned = (zero + 15) & ~15
        if end - aligned >= 1024:
            caves.append(dict(fileOffset=hex(aligned), address=hex(vm + aligned - off), bytes=end - aligned))
    # The fileset-wide tail above becomes PXN after XNU finalizes its mappings.
    # Inspect the embedded kernel's real __text section separately. Candidates
    # must share a 16KiB page with actual text and fit wholly on that page.
    text_caves = []
    for cmd, off, size in commands(data, kernel):
        if cmd != 0x19 or data[off + 8:off + 24].rstrip(b'\0') != b'__TEXT_EXEC': continue
        count = struct.unpack_from('<I', data, off + 64)[0]
        if size != 72 + 80 * count: raise ValueError('invalid kernel text sections')
        for i in range(count):
            at = off + 72 + 80 * i
            if data[at:at + 16].rstrip(b'\0') != b'__text': continue
            vm, length, fileoff = struct.unpack_from('<QQI', data, at + 32)
            if length > len(data) or fileoff > len(data) - length: raise ValueError('text outside file')
            for match in re.finditer(b'\0{1024,}', data[fileoff:fileoff + length]):
                begin = (match.start() + 15) & ~15
                address = vm + begin
                available = min(match.end() - begin, 0x4000 - (address & 0x3fff))
                if available < 1024: continue
                page_start = fileoff + begin - (address & 0x3fff)
                if not any(data[page_start:fileoff + begin]): continue
                text_caves.append(dict(fileOffset=hex(fileoff + begin), address=hex(address), bytes=available))
    return dict(file=str(Path(path).resolve()), sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data), version=version, versionDelta=hex(handler - virtual(versionoff)),
        handler=hex(handler), handlerFileOffset=hex(fileoff), procComm=hex(comm),
        procFullName=hex(comm + 17), handlerUnique=True, keyVerified=True,
        fullNameAccessorVerified=True, executablePaddingCandidates=caves,
        kernelTextPaddingCandidates=text_caves,
        guestExecuted=False, accountSignInVerified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernels', type=Path, nargs='+')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = [audit(p) for p in args.kernels]
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        with args.output.open('x') as f: f.write(text)
    print(text, end='')


if __name__ == '__main__': main()
