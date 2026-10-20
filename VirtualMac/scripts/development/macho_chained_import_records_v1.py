"""Strict active Mach-O chained import records, including real addends.

This parses records only; it does not prove chained rebases, process-global
lookup, provider initialization, or metadata semantics.
"""
import struct


def read(raw, commands):
    records = [(at, size) for command, at, size in commands(raw) if command == 0x80000034]
    if len(records) != 1:
        raise ValueError('expected one active chained import load command')
    at, size = records[0]
    if size != 16:
        raise ValueError('invalid chained fixups load command length')
    offset, length = struct.unpack_from('<II', raw, at + 8)
    if offset > len(raw) or length < 28 or length > len(raw) - offset:
        raise ValueError('chained fixups outside file')
    version, starts, imports, symbols, count, fmt, compression = struct.unpack_from('<7I', raw, offset)
    width = {1: 4, 2: 8, 3: 16}.get(fmt)
    if version or compression or not width or not 28 <= starts <= imports <= symbols <= length:
        raise ValueError('unsupported or malformed chained import schema')
    if count > 1048576 or count * width > symbols - imports:
        raise ValueError('active import records overlap symbols or exceed budget')
    rows = []
    for index in range(count):
        location = offset + imports + index * width
        if fmt in (1, 2):
            word = struct.unpack_from('<I', raw, location)[0]
            ordinal = word & 255
            if ordinal & 128: ordinal -= 256
            weak = bool(word >> 8 & 1)
            name = word >> 9
            addend = struct.unpack_from('<i', raw, location + 4)[0] if fmt == 2 else 0
        else:
            word = struct.unpack_from('<Q', raw, location)[0]
            if word >> 17 & 0x7fff:
                raise ValueError('import64 reserved bits must be zero')
            ordinal = word & 65535
            if ordinal & 32768: ordinal -= 65536
            weak = bool(word >> 16 & 1)
            name = word >> 32
            addend = struct.unpack_from('<q', raw, location + 8)[0]
        if ordinal < -3:
            raise ValueError('unsupported special library ordinal')
        if name >= length - symbols:
            raise ValueError('symbol offset outside active symbol pool')
        first = offset + symbols + name
        last = raw.find(b'\0', first, offset + length)
        if last <= first:
            raise ValueError('unterminated or empty import symbol')
        try:
            symbol = raw[first:last].decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('invalid import symbol UTF-8') from error
        rows.append(dict(index=index,name=symbol,ordinal=ordinal,weak=weak,addend=addend,command=location))
    return dict(importsFormat=fmt,symbolsFormat=compression,activeFixupsOffset=offset,
        activeFixupsLength=length,recordWidth=width,imports=rows,recordSchemaOnly=True)
