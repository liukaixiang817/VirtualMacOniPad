#!/usr/bin/env python3
"""Derive an isolated iOS load-only VZ27 copy; never install or execute it.

The saved reconstructor used flat/weak imports. This does NOT restore original
strong fixups or provide missing implementations. Before function calls the
companion native probe must enforce the saved nonweak-nlist presence gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

PIN = 'a55130db33e6b25a48bd7899f7f12d0c81cfb73095db5a4f5b1bf67c8701fccc'


def commands(data):
    assert struct.unpack_from('<III',data) == (0xfeedfacf,0x100000c,0x80000002)
    count,total = struct.unpack_from('<II',data,16)
    at,end = 32,32+total
    assert end <= len(data)
    for _ in range(count):
        cmd,size = struct.unpack_from('<II',data,at)
        assert size >= 8 and size % 8 == 0 and at+size <= end
        yield cmd,at,size
        at += size
    assert at == end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--flatten-framework-paths',action='store_true')
    args = parser.parse_args()
    original = args.input.read_bytes()
    assert len(original) == 4066104 and hashlib.sha256(original).hexdigest() == PIN
    data = bytearray(original)
    sections, versions, libraries, initializers, dependency_edits, uuid = [],[],[],[],[],None
    for cmd,at,size in commands(data):
        if cmd == 0x32:
            before = struct.unpack_from('<III',data,at+8)
            assert before == (1,0x1b0000,0x1b0000)
            struct.pack_into('<III',data,at+8,2,0x100100,0x100100)
            versions.append(dict(offset=at+8,before=before,after=(2,0x100100,0x100100)))
        if cmd == 0x1b: uuid = data[at+8:at+24].hex()
        if cmd in (0xc,0x80000018,0x8000001f,0x80000023):
            off=at+struct.unpack_from('<I',data,at+8)[0]
            name=bytes(data[off:data.index(0,off)]).decode()
            libraries.append(dict(name=name,command=hex(cmd)))
            if args.flatten_framework_paths:
                flat=name.replace('/Versions/A/','/').replace('/Versions/C/','/')
                if flat != name:
                    encoded=flat.encode()+b'\0'
                    assert '.framework/' in name and len(encoded) <= at+size-off
                    data[off:at+size]=encoded+bytes(at+size-off-len(encoded))
                    dependency_edits.append(dict(loadCommandOffset=at,nameOffset=off,command=hex(cmd),
                        before=name,after=flat,commandSizeUnchanged=size,weakOrReexportKindUnchanged=True))
        if cmd == 0x1a:
            address = struct.unpack_from('<Q',data,at+8)[0]
            initializers.append(dict(kind='LC_ROUTINES_64',address=address))
        if cmd == 0x19:
            count = struct.unpack_from('<I',data,at+64)[0]
            assert size == 72+80*count
            for i in range(count):
                s=at+72+i*80
                name=bytes(data[s:s+16]).split(b'\0')[0].decode()
                length,offset,flags=struct.unpack_from('<Q',data,s+40)[0],struct.unpack_from('<I',data,s+48)[0],struct.unpack_from('<I',data,s+64)[0]
                if length and (name in ('__mod_init_func','__init_offsets','__objc_nlclslist','__objc_nlcatlist') or flags & 255 == 9):
                    initializers.append(dict(kind=name,bytes=length))
                if length and offset and flags & 255 not in (1,12,18):
                    assert offset+length <= len(data)
                    sections.append(dict(name=name,offset=offset,bytes=length,
                        sha256=hashlib.sha256(original[offset:offset+length]).hexdigest()))
    assert uuid == '418efc4809d93606918eb6f95baeffdc' and len(versions) == 1
    assert not initializers, 'A constructor or nonlazy +load list needs a separate code audit'
    assert all(original[s['offset']:s['offset']+s['bytes']] == data[s['offset']:s['offset']+s['bytes']] for s in sections)
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    candidate=output/'Virtualization27.load-only.ios.dylib';candidate.write_bytes(data)
    records=[]
    for label,argv in [('sign',['codesign','--force','--sign','-','--timestamp=none',str(candidate)]),
        ('strict',['codesign','--verify','--strict',str(candidate)]),
        ('dyld',['xcrun','dyld_info','-validate_only',str(candidate)]),
        ('signature',['codesign','-d','--verbose=4',str(candidate)])]:
        r=subprocess.run(argv,capture_output=True,text=True,timeout=30)
        records.append(dict(label=label,argv=argv,exit=r.returncode,stdout=r.stdout,stderr=r.stderr))
        (output/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
        assert r.returncode == 0,r.stderr
    final=candidate.read_bytes()
    assert all(hashlib.sha256(final[s['offset']:s['offset']+s['bytes']]).hexdigest() == s['sha256'] for s in sections)
    def indexed_commands(blob):
        result, occurrences = {}, {}
        for index,(cmd,at,size) in enumerate(commands(blob)):
            key=(cmd,occurrences.get(cmd,0));occurrences[cmd]=key[1]+1
            result[key]=(index,at,blob[at:at+size])
        return result
    before,after=indexed_commands(original),indexed_commands(final)
    load_diffs=[]
    for key in sorted(before.keys()|after.keys()):
        old,new=before.get(key),after.get(key)
        if old and new and old[2] == new[2]:continue
        load_diffs.append(dict(command=hex(key[0]),occurrence=key[1],
            beforeIndex=old[0] if old else None,afterIndex=new[0] if new else None,
            beforeFileOffset=old[1] if old else None,afterFileOffset=new[1] if new else None,
            beforeHex=old[2].hex() if old else None,afterHex=new[2].hex() if new else None))
    result=dict(source=str(args.input.resolve()),sourceSHA256=PIN,candidate=str(candidate),bytes=len(final),
        sha256=hashlib.sha256(final).hexdigest(),uuid=uuid,
        cdhash=re.search(r'CDHash=([0-9a-f]{40})',records[-1]['stderr'])[1],
        platformEdits=versions,dependencyEdits=dependency_edits,originalReconstructedDependencies=libraries,
        loadCommandDiffs=load_diffs,dependencyEditCount=len(dependency_edits),
        headerCommandCountAndSizeBefore=struct.unpack_from('<II',original,16),
        headerCommandCountAndSizeAfter=struct.unpack_from('<II',final,16),
        allFileBackedSectionsByteIdentical=True,sections=sections,
        originalStrongFixupsRecovered=False,reconstructorFlatWeakPreserved=True,
        appPrivateProviderPolicyImplemented=False,initializerOrNonlazyClassLoadSections=initializers,
        requiredNonweakNlistGate=844,functionCallsAllowedWithoutGate=False,
        nativeExecuted=False,deviceOperations=False,productionModified=False)
    (output/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['candidate','sha256','uuid','cdhash','allFileBackedSectionsByteIdentical']},indent=2))


if __name__ == '__main__':main()
