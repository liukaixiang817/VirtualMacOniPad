"""Private bounded format1/format2 reader; no existing Mach-O reader changes."""
import importlib.util
import pathlib
import struct

R=pathlib.Path(__file__).resolve().parents[3]
path=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py'
spec=importlib.util.spec_from_file_location('private_vz_addend_reader',path)
_reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(_reader)
commands=_reader.commands
segments=_reader.segments
cstring=_reader.cstring
export_trie=_reader.export_trie


def imports(data):
    rows=[a for c,a,z in commands(data) if c==0x80000034];assert len(rows)==1
    start,size=struct.unpack_from('<II',data,rows[0]+8)
    assert size>=28 and start+size<=len(data)
    header=struct.unpack_from('<7I',data,start)
    version,starts,entries,strings,count,fmt,compressed=header
    assert version==compressed==0 and fmt in (1,2) and count<=8192
    width=4 if fmt==1 else 8
    assert 28<=starts<entries and entries+count*width<=strings<=size
    result=[]
    for i in range(count):
        at=start+entries+i*width;word=struct.unpack_from('<I',data,at)[0]
        ordinal=word&255
        if ordinal>240:ordinal-=256
        offset=word>>9;assert strings+offset<size
        result.append(dict(index=i,name=cstring(data,start+strings+offset,start+size),ordinal=ordinal,weak=bool(word&256),addend=struct.unpack_from('<i',data,at+4)[0] if fmt==2 else 0,command=at))
    return dict(data=start,size=size,header=header,imports=result)


# Changes this newly instantiated Python module only, never the source file or
# another audit's reader. Chain decoding remains the pinned fmt9 implementation.
_reader.imports=imports
chain_entries=_reader.chain_entries
