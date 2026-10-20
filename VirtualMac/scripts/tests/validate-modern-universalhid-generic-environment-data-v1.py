#!/usr/bin/env python3
"""Independent exact-record, arithmetic and retained-PAC audit; no loading."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands,segments,imports,chain_entries
ADDRESS=0x29fdbbde0;PARAMETER=0x29fdbbdd0;PROTOCOL_SLOT=0x2d1d3ede8;PROTOCOL=0x29fdbb800


def pin(path):
    b=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def locate(segs,address):
    rows=[(g,s)for g in segs for s in g['sections']if s['address']<=address<s['address']+s['size']]
    assert len(rows)==1,hex(address);g,s=rows[0]
    return g,s,s['fileoff']+address-s['address']


def mapped(oldsegs,newsegs,address):
    g,s,_=locate(oldsegs,address)
    rows=[t for p in newsegs for t in p['sections']if p['name']==g['name']and t['name']==s['name']]
    assert len(rows)==1;return rows[0]['address']+address-s['address']


def verify(data,source,raw,report):
    old,new=segments(raw),segments(data)
    _,section,offset=locate(old,ADDRESS)
    assert section['name']=='__swift5_typeref'and offset+20<=section['fileoff']+section['size']
    # Independently spell out this concrete ABI layout; do not import the
    # builder or its parsing module for the verification verdict.
    flags,count,param,pad,req,paramrel,protorel=struct.unpack_from('<IHBBIii',raw,offset)
    assert (flags,count,param,pad,req)==(0x1001,1,0x80,0,0x80)
    assert ADDRESS+12+paramrel==PARAMETER and ADDRESS+16+protorel-1==PROTOCOL_SLOT and protorel&1
    assert raw[locate(old,PARAMETER)[2]:locate(old,PARAMETER)[2]+2]==b'x\0'
    pg,ps,po=locate(old,PROTOCOL_SLOT)
    assert (pg['name'],ps['name'])==('__AUTH_CONST','__auth_ptr')and struct.unpack_from('<Q',raw,po)[0]==PROTOCOL
    local=mapped(old,new,ADDRESS);_,_,at=locate(new,local)
    assert data[at:at+12]==raw[offset:offset+12]
    assert struct.unpack_from('<i',data,at+12)[0]==mapped(old,new,PARAMETER)-(local+12)
    expected=mapped(old,new,PROTOCOL_SLOT)-(local+16)+1
    assert expected&1 and -(1<<31)<=expected<(1<<31)
    assert struct.unpack_from('<i',data,at+16)[0]==expected
    assert expected!=protorel
    auth=report['originalProtocolAuth']
    assert auth['originalSlotVA']==PROTOCOL_SLOT and auth['actualTarget']==hex(PROTOCOL)
    assert auth['chainMembershipVerified']and auth['slideInfoVersion']==5
    assert (auth['auth'],auth['key'],auth['addressDiversity'],auth['diversity'])==(1,2,1,'0xae86')
    chain=next(r for r in chain_entries(data)if r['address']==mapped(old,new,PROTOCOL_SLOT))
    assert chain['auth']and not chain['bind']
    assert chain['word']&0xffffffff==mapped(old,new,PROTOCOL)-0x100000000
    assert (chain['word']>>32)&65535==0xae86 and (chain['word']>>49)&3==2 and chain['word']&(1<<48)
    assert list(chain_entries(data))==list(chain_entries(source))
    assert imports(data)==imports(source)and all(r['ordinal']>0 and not r['weak']for r in imports(data)['imports'])
    assert list(commands(data))==list(commands(source))
    assert len(data)==len(source)
    assert all(at+16<=i<at+20 for i,(a,b)in enumerate(zip(data,source))if a!=b)
    assert report['fullMetadataSchema']is False and report['stockTransitiveClosureProven']is False
    assert report['nativeExecuted']is False and report['deviceOperations']==0 and report['full27Backend']is False
    return dict(concreteRecordBytes=20,actualRelativeFields=2,changedRelativeFields=1,
                mappedProtocolSlot=hex(chain['address']),allExistingPACPreserved=True,
                importsUnchanged=len(imports(data)['imports']),opaqueRecordClassifiedFromOriginalData=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve()
    assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((root/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    report=json.loads((root/'candidate.json').read_text());raw=Path(report['originalRaw']['path']).read_bytes()
    source=Path(report['source']['path']).read_bytes();data=Path(report['candidate']['path']).read_bytes()
    facts=verify(data,source,raw,report);negative=[]
    _,_,off=locate(segments(data),mapped(segments(raw),segments(data),ADDRESS))
    def reject(label,offset,xor):
        mutant=bytearray(data);mutant[offset]^=xor
        try:verify(mutant,source,raw,report)
        except(AssertionError,ValueError,IndexError):negative.append(label)
        else:raise AssertionError('negative accepted: '+label)
    reject('changed generic environment level count',off,1)
    reject('changed generic parameter descriptor',off+6,1)
    reject('changed protocol requirement flags',off+8,1)
    reject('wrong generic parameter mangling',off+12,4)
    reject('wrong protocol relative distance',off+16,2)
    reject('lost relative indirection bit',off+16,1)
    slot=next(r for r in chain_entries(data)if r['address']==mapped(segments(raw),segments(data),PROTOCOL_SLOT))
    reject('changed existing protocol PAC key',slot['fileoff']+6,2)
    row=imports(data)['imports'][0];reject('weakened existing strong import',row['command']+1,1)
    out.mkdir();result=dict(schema='Independent genuine UHK generic environment relocation review v1',
        candidate=pin(root/'candidate.json'),verified=facts,negativeControlsRejected=negative,
        staticReviewPassed=True,fullMetadataSchema=False,stockTransitiveClosureProven=False,
        nativeExecuted=False,deviceOperations=0,full27Backend=False)
    target=out/'review.json';target.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(review=pin(target),negativeControls=len(negative))))


if __name__=='__main__':main()
