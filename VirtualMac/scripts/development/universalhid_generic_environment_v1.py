#!/usr/bin/env python3
"""Bounded GenericEnvironment schema for explicitly identified HID records.

GenericContext.h TargetGenericEnvironment orders the four-byte flags, uint16
cumulative parameter counts, one-byte parameter descriptors, alignment to four,
then twelve-byte requirements. This binary record is not a mangled string.
No arbitrary typeref word is treated as a descriptor; callers select a proven
record address, and unsupported requirement/parameter kinds reject parsing.
"""
import struct


def parse_environment(data, offset, bound):
    def unpack(fmt, at):
        size=struct.calcsize(fmt)
        assert 0<=offset<=at and at+size<=bound<=len(data), 'truncated generic environment'
        return struct.unpack_from(fmt,data,at)
    flags=unpack('<I',offset)[0]
    assert not flags&0xf0000000, 'unknown generic environment flags'
    levels=flags&0xfff;requirements=(flags>>12)&0xffff
    assert 0<levels<=256 and requirements<=1024, 'unbounded generic environment'
    counts=list(unpack('<'+'H'*levels,offset+4))
    assert counts[0]>0 and counts[-1]<=1024
    assert all(a<=b for a,b in zip(counts,counts[1:])), 'non-cumulative generic counts'
    params_at=offset+4+2*levels
    params=list(unpack('<'+'B'*counts[-1],params_at))
    # This scope handles ordinary type parameters and their key-argument bit.
    # Type packs/value parameters/unknown extra bits need their own schema.
    assert all(param in (0,0x80) for param in params), 'unsupported generic parameter'
    req_at=(params_at+len(params)+3)&~3
    assert not any(data[params_at+len(params):req_at]), 'nonzero alignment padding'
    rows=[]
    for index in range(requirements):
        at=req_at+index*12;rf,param,value=unpack('<Iii',at);kind=rf&31
        assert not rf&~0x9f and kind in(0,1,2,3,4,31), 'unsupported generic requirement'
        assert param, 'null generic parameter mangling'
        if kind!=31:assert value, 'null generic requirement target'
        rows.append(dict(offset=at,flags=rf,kind=kind,parameterOffset=at+4,
                         valueOffset=at+8,parameterRelative32=param,valueRelative32=value))
    return dict(offset=offset,flags=flags,levels=levels,counts=counts,parameters=params,
                requirements=rows,end=req_at+requirements*12)
