#!/usr/bin/env python3
"""Independent old-protocol schema and byte-contract review of inert HID data."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
sys.path.insert(0,str(READER))
from compiler_image import commands, segments, imports, chain_entries


def pin(path):
    b=path.read_bytes(); return dict(path=str(path.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def section_at(buf, va):
    matches=[s for g in segments(buf) for s in g['sections'] if s['address']<=va<s['address']+s['size']]
    assert len(matches)==1; s=matches[0]; assert s['fileoff'] and s['flags']&255 not in(1,12)
    return s['fileoff']+va-s['address']


def verify(before, after, descriptor, removed_va, native):
    assert len(after)>len(before)
    off=section_at(before,descriptor); assert section_at(after,descriptor)==off
    assert struct.unpack_from('<II',before,off+12)==(0x30000,2)
    assert struct.unpack_from('<II',after,off+12)==(0x30000,1)
    # All original protocol/type/witness-pattern identity fields and the old
    # requirement/witness pair are exact. Only the incompatible second pair
    # is omitted from the trailing object's declared count.
    assert after[off:off+16]==before[off:off+16]
    assert after[off+20:off+28]==before[off+20:off+28]
    assert struct.unpack_from('<HHi',before,off+36)==struct.unpack_from('<HHi',after,off+28)==(0,1,0)
    oldprivate=descriptor+44+struct.unpack_from('<i',before,off+44)[0]
    assert oldprivate==descriptor+36+struct.unpack_from('<i',after,off+36)[0]
    assert after[off+40:off+48]==before[off+40:off+48], 'unused original tail bytes are preserved'
    assert struct.unpack_from('<IIII',native,12)==(0,1,0,0x5cdf0011)
    assert struct.unpack_from('<i',native,28)[0]==0
    a=imports(before); b=imports(after)
    assert a['header'][4]==714 and b['header'][4]==713
    assert a['header'][5:]==b['header'][5:]==(1,0)
    removed=a['imports'][533]; assert 'ContiguousBytes' in removed['name'] and 'RawSpan' in removed['name']
    assert not removed['weak'] and removed['ordinal']==3
    contracts=lambda rows:[(r['name'],r['ordinal'],r['weak'])for r in rows]
    assert contracts(b['imports'])==contracts(a['imports'][:533]+a['imports'][534:])
    assert all(r['ordinal']>0 and not r['weak'] for r in b['imports'])
    old=list(chain_entries(before)); new=list(chain_entries(after)); oldby={r['fileoff']:r for r in old}
    deleted=[r for r in old if r['address']==removed_va]; assert len(deleted)==1
    deleted=deleted[0]; assert deleted['bind'] and deleted['import_index']==533 and deleted['auth']
    assert len(new)==len(old)-1 and all(r['fileoff']!=deleted['fileoff'] for r in new)
    predecessor=deleted['previous']; assert predecessor is not None
    whitelist=set(range(off+16,off+20))|set(range(off+28,off+40))
    for r in new:
        original=oldby[r['fileoff']]
        assert (r['symbol'],r['bind'],r['auth'])==(original['symbol'],original['bind'],original['auth'])
        expected_index=original['import_index']-(original['import_index']>533) if original['bind'] else None
        assert r['import_index']==expected_index
        bits=65535 if r['bind'] else 0
        if r['fileoff']==predecessor:
            bits|=2047<<51
            assert (r['word']>>51)&2047==2 and (original['word']>>51)&2047==1
        assert r['word']&~bits==original['word']&~bits, 'original auth key/discriminator/address diversity/target bits'
        if r['word']!=original['word']: whitelist.update(range(r['fileoff'],r['fileoff']+8))
    assert after[deleted['fileoff']:deleted['fileoff']+8]==before[deleted['fileoff']:deleted['fileoff']+8]
    assert b['data']==(len(before)+7)&~7 and not any(after[len(before):b['data']])
    assert len(after)==b['data']+b['size'] and b['size']==a['size']-4
    originalblob=before[a['data']:a['data']+a['size']]; newblob=after[b['data']:b['data']+b['size']]
    # Independent comparison of preserved starts and symbol strings, without
    # importing the adaptation builder or reconstructing through its output.
    assert b['header'][:3]==a['header'][:3]
    assert b['header'][3]==a['header'][3]-4
    assert newblob[28:b['header'][2]]==originalblob[28:a['header'][2]]
    assert newblob[b['header'][3]:]==originalblob[a['header'][3]:]
    assert before[a['data']:a['data']+a['size']]==after[a['data']:a['data']+a['size']], 'previous fixup blob remains inert source bytes'
    for (cmd,at,z),(ncmd,nat,nz) in zip(commands(before),commands(after),strict=True):
        assert (cmd,at,z)==(ncmd,nat,nz)
        if cmd==0x80000034:
            whitelist.update(range(at+8,at+16)); assert struct.unpack_from('<II',after,at+8)==(b['data'],b['size'])
        elif cmd==0x19 and before[at+8:at+24].split(b'\0')[0]==b'__LINKEDIT':
            fileoff=struct.unpack_from('<Q',before,at+40)[0]
            assert struct.unpack_from('<Q',after,at+32)[0]==(len(after)-fileoff+16383)&~16383
            assert struct.unpack_from('<Q',after,at+48)[0]==len(after)-fileoff
            whitelist.update(range(at+32,at+40)); whitelist.update(range(at+48,at+56))
    assert all(i in whitelist for i,(x,y)in enumerate(zip(before,after))if x!=y), 'unapproved original-byte mutation'
    # The only candidate relative field targeting the removed Tq GOT slot
    # has disappeared; the new generic control structure must not retain it.
    hits=[]
    for g in segments(after):
        for s in g['sections']:
            if not s['fileoff']or s['flags']&255 in(1,12):continue
            for q in range(max(0,s['size']-3)):
                word=struct.unpack_from('<i',after,s['fileoff']+q)[0];va=s['address']+q
                if va+word==removed_va or va+word-(word&1)==removed_va:hits.append(va)
    assert not hits
    return dict(remainingImports=len(b['imports']),remainingChainWords=len(new),
        unchangedAllInstructionAndWitnessFunctionBytes=True,remainingOriginalPACSemantics=True,
        privateDataTarget=oldprivate,removedSlotFileoff=deleted['fileoff'],predecessorFileoff=predecessor)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    folder=args.candidate.resolve();out=args.output.resolve();assert folder.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists();out.mkdir()
    plan=json.loads((folder/'candidate.json').read_text())
    assert plan['conformanceMetadataAdapted'] and not plan['completeOriginal27MetadataPreserved']
    assert not any(plan[k]for k in('fullMetadataSchema','stockTransitiveClosureProven','nativeExecuted','codeSigned','deviceOperations','full27Backend'))
    for row in json.loads((folder/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    before=Path(plan['providerSource']['path']).read_bytes();after=Path(plan['providerCandidate']['path']).read_bytes()
    native=Path(plan['oldNativeProtocol']['source']['path']).read_bytes()
    descriptor=plan['conformanceCandidateVA'];removed_va=plan['removedUnreferencedChainSlot']['address'];off=section_at(before,descriptor)
    result=verify(before,after,descriptor,removed_va,native)
    cases=[]
    def bad(name,pos,fmt,value):
        changed=bytearray(after);struct.pack_into(fmt,changed,pos,value);rejected=False
        try:verify(before,bytes(changed),descriptor,removed_va,native)
        except(AssertionError,ValueError,struct.error):rejected=True
        assert rejected,name;cases.append(dict(name=name,rejected=True))
    bad('reintroduce second requirement count',off+16,'<I',2)
    bad('omit old witness',off+24,'<I',0)
    bad('change protocol identity',off,'<I',struct.unpack_from('<I',after,off)[0]^2)
    bad('private data relative not adjusted',off+36,'<i',struct.unpack_from('<i',before,off+44)[0])
    bad('add generic instantiator',off+32,'<I',4)
    bad('change generic private words',off+30,'<H',3)
    bad('restore removed chain member',result['predecessorFileoff'],'<Q',struct.unpack_from('<Q',after,result['predecessorFileoff'])[0]^(3<<51))
    entries=list(chain_entries(after));bound=next(r for r in entries if r['bind']and r['import_index']>=533)
    bad('wrong bind renumber',bound['fileoff'],'<Q',bound['word']^1)
    bad('weaken a remaining import',imports(after)['imports'][532]['command'],'<I',struct.unpack_from('<I',after,imports(after)['imports'][532]['command'])[0]|256)
    auth=next(r for r in entries if r['auth']and r['bind'])
    bad('change PAC key',auth['fileoff'],'<Q',auth['word']^(1<<49))
    bad('change PAC discriminator',auth['fileoff'],'<Q',auth['word']^(1<<32))
    bad('change PAC address diversity',auth['fileoff'],'<Q',auth['word']^(1<<48))
    text=next(s for g in segments(after)for s in g['sections']if s['name']=='__text')
    bad('modify genuine instruction',text['fileoff'],'<I',struct.unpack_from('<I',after,text['fileoff'])[0]^1)
    bad('modify unchained original padding',result['removedSlotFileoff'],'<Q',struct.unpack_from('<Q',after,result['removedSlotFileoff'])[0]^1)
    bad('change new import count',imports(after)['data']+16,'<I',714)
    validation=subprocess.run(['xcrun','dyld_info','-validate_only',plan['providerCandidate']['path']],capture_output=True,text=True);assert validation.returncode==0
    report=dict(schema='Independent oldhost HIDReport conformance adaptation data review v1',candidate=pin(folder/'candidate.json'),
        verifier=pin(Path(__file__)),verification=result,negativeControls=cases,dyldValidationExit=validation.returncode,
        conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,
        fullCurrentLoadGraphProven=False,stockTransitiveClosureProven=False,fullMetadataSchema=False,
        nativeExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(Path(__file__)),pin(out/'review.json'),pin(folder/'candidate.json'),
        pin(Path(plan['providerSource']['path'])),pin(Path(plan['providerCandidate']['path'])),pin(Path(plan['oldNativeProtocol']['source']['path']))],nativeExecuted=False,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),negativeControls=len(cases),remainingStrongImports=713)))


if __name__=='__main__':main()
