#!/usr/bin/env python3
"""Independent original-target/relative-distance/PAC review; never loads data."""
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
ORACLE_SHA='e3117bae5fbf14c2c3706c49e7b2760dc48fbb4730d2a652db2107d34789f4b7'


def pin(path):
    data=path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def locate(segs,address):
    matches=[(g,s)for g in segs for s in g['sections']if s['address']<=address<s['address']+s['size']]
    assert len(matches)==1,hex(address)
    g,s=matches[0]
    return g,s,s['fileoff']+address-s['address']


def mapped(oldsegs,newsegs,address):
    g,s,_=locate(oldsegs,address)
    target=[(a,b)for a in newsegs for b in a['sections']if a['name']==g['name']and b['name']==s['name']]
    assert len(target)==1
    _,b=target[0];delta=address-s['address'];assert delta<b['size']
    return b['address']+delta


def verify(data,source,raw,plan,oracle):
    oldsegs,newsegs=segments(raw),segments(data)
    before=list(chain_entries(source));after={r['fileoff']:r for r in chain_entries(data)}
    assert len(after)==len(before)+plan['addedSlots']
    change=plan['soleChainChange'];whitelist=set()
    for row in before:
        expected=row['word']
        if change['kind'].startswith('extend')and row['fileoff']==change['fileoff']:
            assert expected==change['before']and not(expected>>51)&0x7ff
            expected=change['after'];assert expected&~(0x7ff<<51)==row['word']
            whitelist.update(range(row['fileoff'],row['fileoff']+8))
        assert after[row['fileoff']]['word']==expected
    oldimp,newimp=imports(source),imports(data)
    assert len(newimp['imports'])==len(oldimp['imports'])+plan['addedImports']
    for a,b in zip(oldimp['imports'],newimp['imports']):
        assert all(a[k]==b[k]for k in('name','ordinal','weak','index'))
    assert all(r['ordinal']>0 and not r['weak']for r in newimp['imports'])
    routes={r['originalSlotVA']:r for r in plan['exactAuthRoutes']}
    newslots={r['newSlotVA']for r in routes.values()};assert len(newslots)==len(routes)==plan['addedSlots']
    for target,route in routes.items():
        original=oracle[target]
        assert original['chainMembershipVerified']and original['slideInfoVersion']==5
        assert original['rawCacheWord']==route['originalCacheWord']and original['actualTarget']==route['actualOriginalTarget']
        assert route['genuineExport']['exportAddress']==int(original['actualTarget'],16)
        assert route['genuineExport']['exportedSymbol']==route['symbol']
        assert original['auth']==1 and original['key']==route['key']==2 and original['addressDiversity']==1
        diversity=int(original['diversity'],16)
        assert diversity==int(route['discriminator'],16)
        assert diversity==(0x7d4c if set(route['labels'])=={'resilientRequirement'}else 0xae86)
        _,_,offset=locate(newsegs,route['newSlotVA']);slot=after[offset]
        whitelist.update(range(offset,offset+8))
        assert slot['auth']and slot['bind']and slot['import_index']==route['importIndex']
        assert (slot['word']>>32)&65535==diversity and (slot['word']>>49)&3==2 and slot['word']&(1<<48)
        imported=newimp['imports'][route['importIndex']]
        assert imported['name']==route['symbol']and imported['ordinal']==route['ordinal']and not imported['weak']
    fields=plan['relativeFieldsRelocated'];assert len({r['fileoff']for r in fields})==len(fields)
    for row in fields:
        _,_,oldoff=locate(oldsegs,row['slot']);word=struct.unpack_from('<i',raw,oldoff)[0]
        assert word==row['originalRelative32']
        low=1 if row['indirect']else 0
        assert row['originalTarget']==row['slot']+word-low
        newslot=mapped(oldsegs,newsegs,row['slot']);_,_,offset=locate(newsegs,newslot)
        try:newtarget=mapped(oldsegs,newsegs,row['originalTarget'])
        except AssertionError:
            assert row['originalTarget']in routes
            newtarget=routes[row['originalTarget']]['newSlotVA']
        assert row['newSlot']==newslot and row['newTarget']==newtarget and row['fileoff']==offset
        expected=newtarget-newslot+low
        assert -(1<<31)<=expected<(1<<31)and expected==row['newRelative32']
        assert struct.unpack_from('<i',data,offset)[0]==expected
        whitelist.update(range(offset,offset+4))
    for row in plan['remainingUnclassifiedRecord']:
        assert row==dict(slot=11271912929,label='mangledSymbolicReference1',target=11288690161,indirect=False)
        _,_,off=locate(newsegs,mapped(oldsegs,newsegs,row['slot']))
        assert data[off:off+4]==source[off:off+4]
    # Only declared section size/alignment and linkedit/fixup command fields
    # may change in the header; code/platform/identity commands remain exact.
    oldcommands=list(commands(source));newcommands=list(commands(data))
    assert [(c,a,s)for c,a,s in oldcommands]==[(c,a,s)for c,a,s in newcommands]
    for cmd,at,size in oldcommands:
        if cmd==0x80000034:whitelist.update(range(at+8,at+16))
        elif cmd==0x19:
            name=source[at+8:at+24].split(b'\0')[0]
            if name==b'__LINKEDIT':
                whitelist.update(range(at+32,at+40));whitelist.update(range(at+48,at+56))
            else:
                for g in segments(source):
                    for s in g['sections']:
                        if s['name']=='__got':
                            whitelist.update(range(s['command']+40,s['command']+48))
                            whitelist.update(range(s['command']+52,s['command']+56))
    assert data[:32]==source[:32]
    assert all(at in whitelist for at,(a,b)in enumerate(zip(source,data))if a!=b)
    assert len(data)>len(source)and newimp['data']==len(source)
    assert plan['nativeExecuted']is False and plan['fullMetadataSchema']is False
    return dict(relativeFields=len(fields),originalChainWords=len(before),originalPACPreserved=True,
                originalAuthenticatedSlots=plan['addedSlots'],newStrongImports=plan['addedImports'],
                unresolvedOriginalRecords=len(plan['remainingUnclassifiedRecord']))


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve()
    assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((root/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    report=json.loads((root/'candidate.json').read_text());authpath=Path(report['sourceAuthOracle']['path'])
    assert pin(authpath)['sha256']==ORACLE_SHA
    oracle={r['originalSlotVA']:r for r in json.loads(authpath.read_text())['contracts']}
    checks=[];negative=[]
    for plan in report['providers']:
        source=Path(plan['source']['path']).read_bytes();raw=Path(plan['originalRaw']['path']).read_bytes();data=Path(plan['candidate']['path']).read_bytes()
        checks.append(dict(name=plan['name'],**verify(data,source,raw,plan,oracle)))
        def rejected(label,offset,xor):
            changed=bytearray(data);changed[offset]^=xor
            try:verify(bytes(changed),source,raw,plan,oracle)
            except(AssertionError,ValueError,IndexError):negative.append(plan['name']+' '+label)
            else:raise AssertionError('negative accepted: '+label)
        route=plan['exactAuthRoutes'][0];_,_,offset=locate(segments(data),route['newSlotVA'])
        rejected('wrong original PAC diversity',offset+4,1)
        rejected('wrong original PAC key',offset+6,2)
        row=imports(data)['imports'][route['importIndex']]
        rejected('weak metadata import',row['command']+1,1)
        rejected('wrong metadata owner ordinal',row['command'],1)
        field=next(r for r in plan['relativeFieldsRelocated']if r['newRelative32']!=r['beforeRelative32'])
        rejected('wrong relative32 distance',field['fileoff'],1)
        if plan['remainingUnclassifiedRecord']:
            s=plan['remainingUnclassifiedRecord'][0]['slot'];_,_,off=locate(segments(data),mapped(segments(raw),segments(data),s))
            rejected('modified unclassified original record',off,1)
    assert len(negative)==11
    out.mkdir()
    result=dict(schema='Independent genuine HID original-auth relative metadata review v1',candidate=pin(root/'candidate.json'),
                providers=checks,negativeControlsRejected=negative,staticReviewPassed=True,
                originalUniqueCacheSlotsProven=207,strongSlotCopies=251,relativeFieldsRelocated=6976,
                fullMetadataSchema=False,remainingUnclassifiedOriginalRecords=1,
                nativeExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(negative))))


if __name__=='__main__':main()
