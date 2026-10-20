#!/usr/bin/env python3
"""Independent declared roots, relative arithmetic, actual-cache PAC and negatives."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sys.path.insert(0,str(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
from compiler_image import commands,segments,imports,chain_entries
PYTHON=ROOT/'DeviceDiagnostics/2026-10-02-macos27-backend/toolchain/venv/bin/python3'
CACHE=Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')


def pin(path):
    b=path.read_bytes();return dict(path=str(path.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def locate(segs,address):
    rows=[(g,s)for g in segs for s in g['sections']if s['address']<=address<s['address']+s['size']]
    assert len(rows)==1;g,s=rows[0];return g,s,s['fileoff']+address-s['address']


def mapped(old,new,address):
    g,s,_=locate(old,address);rows=[t for p in new for t in p['sections']if p['name']==g['name']and t['name']==s['name']]
    assert len(rows)==1;return rows[0]['address']+address-s['address']


def verify(data,source,raw,plan,oracle):
    old,new=segments(raw),segments(data);whitelist=set();rows={r['slot']:r for r in plan['relativeFields']}
    assert len(rows)==len(plan['relativeFields'])
    table=next(s for g in old for s in g['sections']if s['name']=='__swift5_types')
    count=table['size']//4;assert count==(198 if plan['name']=='UniversalHID'else 16)
    generic=0
    for slot in range(table['address'],table['address']+table['size'],4):
        _,_,offset=locate(old,slot);d=slot+struct.unpack_from('<i',raw,offset)[0]
        _,_,offset=locate(old,d);flags=struct.unpack_from('<I',raw,offset)[0]
        assert flags&31 in(16,17,18)and slot in rows and d+8 in rows
        for delta in(4,12,16):
            v=struct.unpack_from('<i',raw,offset+delta)[0]
            assert (d+delta in rows)==bool(v)
        if flags&0x80:
            generic+=1;head=d+(44 if flags&31==16 else 28)
            assert rows[head]['label']=='typeInstantiationCache'and rows[head+4]['label']=='typeInstantiationPattern'
            po=locate(old,head+4)[2];pattern=head+4+struct.unpack_from('<i',raw,po)[0]
            for relative,label in((0,'patternInstantiationFunction'),(4,'patternCompletionFunction'),(12,'patternDestroyFunction')):
                assert rows[pattern+relative]['label']==label
            assert rows[pattern+32]['label']=='patternPartialData'
    assert generic==(1 if plan['name']=='UniversalHID'else 10)
    for row in rows.values():
        slot=row['slot'];offset=locate(old,slot)[2];value=struct.unpack_from('<i',raw,offset)[0]
        low=1 if row['indirect']else 0
        assert row['originalRelative32']==value and row['originalTarget']==slot+value-low
        ns=mapped(old,new,slot);nt=mapped(old,new,row['originalTarget']);no=locate(new,ns)[2];expected=nt-ns+low
        assert row['fileoff']==no and row['newSlot']==ns and row['newTarget']==nt and row['newRelative32']==expected
        assert struct.unpack_from('<i',data,no)[0]==expected
        if expected!=struct.unpack_from('<i',source,no)[0]:whitelist.update(range(no,no+4))
    assert len(whitelist)==len(plan['changedFields'])*4
    assert all(i in whitelist for i,(a,b)in enumerate(zip(data,source))if a!=b)
    assert len(data)==len(source)and list(commands(data))==list(commands(source))
    assert list(chain_entries(data))==list(chain_entries(source))and imports(data)==imports(source)
    assert all(r['ordinal']>0 and not r['weak']for r in imports(data)['imports'])
    actual_chain={r['address']:r for r in chain_entries(data)}
    for target,contract in oracle.items():
        assert contract['chainMembershipVerified']and contract['slideInfoVersion']==5
        word=struct.unpack_from('<Q',raw,locate(old,target)[2])[0]
        assert word==int(contract['actualTarget'],16)
        site=actual_chain[mapped(old,new,target)]
        assert site['auth']==bool(contract['auth'])
        assert (site['word']>>49)&3==contract['key']and (site['word']>>32)&65535==int(contract['diversity'],16)
        assert bool(site['word']&(1<<48))==bool(contract['addressDiversity'])
        if not site['bind']:
            assert site['word']&0xffffffff==mapped(old,new,word)-0x100000000
    assert plan['fullMetadataSchema']is False and plan['nativeExecuted']is False and plan['deviceOperations']==0
    return dict(declaredTypes=count,genericClassPatterns=generic,relativeFields=len(rows),
                actualChangedFields=len(plan['changedFields']),originalMappedAuthSlots=len(oracle),
                allPACInstructionsAndImportsPreserved=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    root=args.candidate.resolve();out=args.output.resolve();assert root.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    for row in json.loads((root/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    out.mkdir();report=json.loads((root/'candidate.json').read_text());checks=[];negative=[]
    for plan in report['providers']:
        raw=Path(plan['originalRaw']['path']).read_bytes();source=Path(plan['source']['path']).read_bytes();data=Path(plan['candidate']['path']).read_bytes()
        targets=sorted({r['originalTarget']for r in plan['changedFields']if r['indirect']})
        route=out/(plan['name']+'.original-mapped-auth-routes.json')
        route.write_text(json.dumps([dict(originalSlotVA=t,labels=['declared type/generic context'])for t in targets],indent=2)+'\n')
        authdir=out/(plan['name']+'.original-auth')
        argv=[str(PYTHON),str(ROOT/'VirtualMac/scripts/development/audit-swift-cache-indirection-auth.py'),
            '--routes',str(route),'--expected-routes-sha256',pin(route)['sha256'],'--cache',str(CACHE),
            '--expected-cache-uuid','c284a291b68b3d0da1a03f866f87efdc','--output',str(authdir)]
        result=subprocess.run(argv,capture_output=True,text=True);assert result.returncode==0,result.stderr
        oracle={r['originalSlotVA']:r for r in json.loads((authdir/'contract.json').read_text())['contracts']}
        checks.append(dict(name=plan['name'],originalAuthOracle=pin(authdir/'contract.json'),**verify(data,source,raw,plan,oracle)))
        def reject(label,offset,xor):
            mutant=bytearray(data);mutant[offset]^=xor
            try:verify(mutant,source,raw,plan,oracle)
            except(AssertionError,ValueError,IndexError,KeyError):negative.append(plan['name']+' '+label)
            else:raise AssertionError('negative accepted: '+label)
        for label,role in(('wrong real instantiation cache','typeInstantiationCache'),
                           ('wrong real instantiation pattern','typeInstantiationPattern'),
                           ('wrong original instantiator code target','patternInstantiationFunction'),
                           ('wrong original completion code target','patternCompletionFunction'),
                           ('wrong genuine extra-data target','patternPartialData')):
            row=next(r for r in plan['changedFields']if r['label']==role);reject(label,row['fileoff'],4)
        row=next(r for r in plan['changedFields']if r['indirect']);reject('lost generic context indirection',row['fileoff'],1)
        site=next(r for r in chain_entries(data)if r['auth']);reject('changed original PAC key',site['fileoff']+6,2)
        binding=imports(data)['imports'][0];reject('weak existing import',binding['command']+1,1)
        text=next(s for g in segments(data)for s in g['sections']if s['name']=='__text');reject('changed source instruction',text['fileoff'],1)
    result=dict(schema='Independent genuine HID type generic pattern review v1',candidate=pin(root/'candidate.json'),providers=checks,
        negativeControlsRejected=negative,staticReviewPassed=True,fullMetadataSchema=False,
        stockTransitiveClosureProven=False,nativeExecuted=False,deviceOperations=0,full27Backend=False)
    target=out/'review.json';target.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(review=pin(target),negativeControls=len(negative))))


if __name__=='__main__':main()
