#!/usr/bin/env python3
"""Independent real-protocol relative arithmetic and complete chain preservation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands,segments,imports,chain_entries


def pin(path):
    b=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def locate(segs,address):
    rows=[(g,s)for g in segs for s in g['sections']if s['address']<=address<s['address']+s['size']]
    assert len(rows)==1;g,s=rows[0];return g,s,s['fileoff']+address-s['address']


def mapped(old,new,address):
    g,s,_=locate(old,address);rows=[t for p in new for t in p['sections']if p['name']==g['name']and t['name']==s['name']]
    assert len(rows)==1;return rows[0]['address']+address-s['address']


def declared_fields(raw):
    segs=segments(raw);fields=[];protocols=[]
    def word(at,fmt):return struct.unpack_from(fmt,raw,locate(segs,at)[2])
    def add(at,indirect=False,nullable=False):
        if not nullable or word(at,'<i')[0]:fields.append((at,indirect))
    table=next(s for g in segs for s in g['sections']if s['name']=='__swift5_protos')
    for slot in range(table['address'],table['address']+table['size'],4):
        add(slot);d=slot+word(slot,'<i')[0];f,_,_,sn,rn,_=word(d,'<IiiIIi')
        assert f&31==3 and not f&0x80 and (f>>16)&~3==0 and sn<1024 and rn<1024
        protocols.append(d);add(d+4,True,True);add(d+8);add(d+20,False,True);at=d+24
        for _ in range(sn):
            flag=word(at,'<I')[0];kind=flag&31;assert flag&~0x9f==0 and kind in(0,1,2,3,4,31)
            add(at+4)
            if kind!=31:add(at+8,kind in(0,3))
            at+=12
        for _ in range(rn):
            flag=word(at,'<I')[0];assert flag&~0xffff003f==0 and flag&15<=8
            add(at+4,False,True);at+=8
    table=next(s for g in segs for s in g['sections']if s['name']=='__swift5_assocty')
    at=table['address'];end=at+table['size']
    while at<end:
        _,_,count,size=word(at,'<iiII');assert size==8 and at+16+count*size<=end
        add(at);add(at+4)
        for i in range(count):add(at+16+i*size);add(at+20+i*size)
        at+=16+count*size
    assert at==end;return fields,protocols


def verify(data,source,raw,plan):
    old,new=segments(raw),segments(data);fields,protocols=declared_fields(raw)
    assert len(protocols)==plan['ownDeclaredProtocols']
    assert {s for s,_ in fields}=={r['slot']for r in plan['relativeFields']}
    external={r['originalSlotVA']:r['existingAuthRoute']['newSlotVA']for r in plan['reusedActualAuthSlots']}
    external.update({r['originalSlotVA']:r['newSlotVA']for r in plan['addedActualAuthSlots']})
    whitelist=set();actualchanges=0
    for slot,indirect in fields:
        _,_,oldoff=locate(old,slot);value=struct.unpack_from('<i',raw,oldoff)[0];low=value&1 if indirect else 0
        target=slot+value-low;newslot=mapped(old,new,slot);_,_,offset=locate(new,newslot)
        try:newtarget=mapped(old,new,target)
        except AssertionError:newtarget=external[target]
        expected=newtarget-newslot+low
        assert -(1<<31)<=expected<(1<<31) and struct.unpack_from('<i',data,offset)[0]==expected
        if struct.unpack_from('<i',source,offset)[0]!=expected:
            actualchanges+=1;whitelist.update(range(offset,offset+4))
    assert actualchanges==len(plan['changedFields'])
    before=list(chain_entries(source));after={r['fileoff']:r for r in chain_entries(data)}
    added=plan['addedActualAuthSlots'];change=plan['soleOriginalChainNextChange']
    assert len(after)==len(before)+len(added)
    for row in before:
        expected=row['word']
        if change and row['fileoff']==change['fileoff']:
            assert change['before']==expected and not(expected>>51)&0x7ff
            expected=change['after'];assert expected==row['word']|(1<<51)
            whitelist.update(range(row['fileoff'],row['fileoff']+8))
        assert after[row['fileoff']]['word']==expected
    a,b=imports(source),imports(data)
    assert len(b['imports'])==len(a['imports'])+len(added)
    for x,y in zip(a['imports'],b['imports']):assert all(x[k]==y[k]for k in('name','ordinal','weak','index'))
    assert all(x['ordinal']>0 and not x['weak']for x in b['imports'])
    for row in plan['reusedActualAuthSlots']+added:
        auth=row['originalAuth'];assert auth['chainMembershipVerified']and auth['slideInfoVersion']==5
        assert (auth['auth'],auth['key'],auth['addressDiversity'],auth['diversity'])==(1,2,1,'0xae86')
        route=row.get('existingAuthRoute',row);slot=after[locate(new,route['newSlotVA'])[2]]
        assert slot['auth']and slot['bind']and slot['import_index']==route['importIndex']
        assert (slot['word']>>32)&65535==0xae86 and (slot['word']>>49)&3==2 and slot['word']&(1<<48)
        bound=b['imports'][slot['import_index']]
        assert bound['name']==route['symbol']and bound['ordinal']==8 and not bound['weak']
        proof=route['genuineExport'];assert proof['exportedSymbol']==bound['name']and proof['exportAddress']==int(auth['actualTarget'],16)
        if row in added:whitelist.update(range(slot['fileoff'],slot['fileoff']+8))
    assert list(commands(data))==list(commands(source))
    for cmd,at,size in commands(source):
        if added and cmd==0x80000034:whitelist.update(range(at+8,at+16))
        if added and cmd==0x19:
            name=source[at+8:at+24].split(b'\0')[0]
            if name==b'__LINKEDIT':whitelist.update(range(at+32,at+40));whitelist.update(range(at+48,at+56))
            for g in segments(source):
                for s in g['sections']:
                    if s['name']=='__got':whitelist.update(range(s['command']+40,s['command']+48))
    assert all(i in whitelist for i,(x,y)in enumerate(zip(data,source))if x!=y)
    if added:
        assert len(added)==1 and b['data']==(len(source)+7)&~7
        assert not any(data[len(source):b['data']])
        oldblob=source[a['data']:a['data']+a['size']];newblob=data[b['data']:b['data']+b['size']]
        prefix=bytearray(oldblob[:a['header'][2]])
        struct.pack_into('<II',prefix,12,a['header'][3]+4,a['header'][4]+1)
        words=oldblob[a['header'][2]:a['header'][3]];names=oldblob[a['header'][3]:]
        expected=prefix+words+struct.pack('<I',(len(names)<<9)|8)+names+added[0]['symbol'].encode()+b'\0'
        assert newblob==expected and b['data']+b['size']==len(data)
    else:assert len(data)==len(source)and imports(data)==imports(source)
    assert plan['fullMetadataSchema']is False and plan['nativeExecuted']is False and plan['deviceOperations']==0
    return dict(declaredProtocols=len(protocols),relativeFields=len(fields),actualChangedFields=actualchanges,
                existingChainWords=len(before),newAuthSlots=len(added),originalPACPreserved=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve();assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((root/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    report=json.loads((root/'candidate.json').read_text());checks=[];negatives=[]
    for plan in report['providers']:
        raw=Path(plan['originalRaw']['path']).read_bytes();source=Path(plan['source']['path']).read_bytes();data=Path(plan['candidate']['path']).read_bytes()
        checks.append(dict(name=plan['name'],**verify(data,source,raw,plan)))
        def reject(label,offset,xor):
            mutant=bytearray(data);mutant[offset]^=xor
            try:verify(mutant,source,raw,plan)
            except(AssertionError,ValueError,IndexError,KeyError):negatives.append(plan['name']+' '+label)
            else:raise AssertionError('negative accepted: '+label)
        row=plan['changedFields'][0];reject('wrong protocol signature target',row['fileoff'],2);reject('lost indirection bit',row['fileoff'],1)
        d=next(r['descriptor']for r in plan['schemas']if r['kind']=='declaredOwnProtocol')
        reject('changed protocol requirement count',locate(segments(data),mapped(segments(raw),segments(data),d))[2]+16,1)
        reused=plan['reusedActualAuthSlots'][0]['existingAuthRoute'];offset=locate(segments(data),reused['newSlotVA'])[2]
        reject('wrong existing protocol PAC diversity',offset+4,1)
        reject('weak existing protocol import',imports(data)['imports'][reused['importIndex']]['command']+1,1)
        if plan['addedActualAuthSlots']:
            extra=plan['addedActualAuthSlots'][0];reject('wrong new original PAC key',extra['fileoff']+6,2)
            reject('wrong new original PAC diversity',extra['fileoff']+4,1)
            newimport=imports(data)['imports'][extra['importIndex']]
            reject('weak new protocol import',newimport['command']+1,1);reject('wrong new protocol owner ordinal',newimport['command'],1)
            reject('lost original chain next extension',plan['soleOriginalChainNextChange']['fileoff']+6,8)
    out.mkdir();result=dict(schema='Independent genuine HID own-protocol data review v1',candidate=pin(root/'candidate.json'),
        providers=checks,negativeControlsRejected=negatives,staticReviewPassed=True,
        fullMetadataSchema=False,stockTransitiveClosureProven=False,nativeExecuted=False,deviceOperations=0,full27Backend=False)
    target=out/'review.json';target.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(review=pin(target),negativeControls=len(negatives))))


if __name__=='__main__':main()
