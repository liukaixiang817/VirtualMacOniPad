#!/usr/bin/env python3
"""Read genuine original ingress LSDA and cleanup exits; never execute VZ."""
import bisect
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('exceptions_q',HERE/'prepare-modern-vz-own-uikit-packet-port-v2.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
p,n=q.p,q.n
BASE=0x225f36000
CALLS={0x1462d0:[0x1462fc],0x1464dc:[0x14657c],0x1472a0:[0x147558],
    0x183364:[0x18349c,0x1834c8,0x183524,0x183568],0x183ef8:[0x183f70,0x183fb4]}

def sleb(raw,at):
    value=shift=0
    for _ in range(10):
        assert at<len(raw);b=raw[at];at+=1;value|=(b&127)<<shift;shift+=7
        if not b&128:return value-(1<<shift)if b&64 else value,at
    raise ValueError('unbounded SLEB')

def main():
    out=n/'vz-mac-ingress-original-exception-contract-readonly-v3';assert not out.exists();out.mkdir()
    candidate=n/'vz-own-uikit-notification-source-port-data-v1/candidate.json';m=json.loads(candidate.read_bytes())
    file=Path(m['frontendCandidate']['path']);assert p.pin(file)==m['frontendCandidate'];raw=file.read_bytes()
    original=n/'vz-mac-ingress-callers-original-readonly-v3/contract.json';contract=json.loads(original.read_bytes())
    section=next(t for g in p.segments(raw)for t in g['sections']if t['name']=='__unwind_info');u=section['fileoff']
    header=struct.unpack_from('<7I',raw,u);assert header[0]==1 and header[4]==1
    indices=[struct.unpack_from('<III',raw,u+header[5]+i*12)for i in range(header[6])];ls={}
    for i in range(len(indices)-1):
        assert indices[i][2]<=indices[i+1][2]<=section['size']
        for a in range(indices[i][2],indices[i+1][2],8):
            fn,at=struct.unpack_from('<II',raw,u+a);assert fn not in ls;ls[fn]=at
    proofs=[]
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
        def read(va,z):
            assert 0<z<=4096;off,owner=cache.convertAddr(va);return owner.getBytes(off,z)
        try:
            for fn,calls in CALLS.items():
                body=next(row for row in contract['originalBoundedConsumerHelperBodies']if row['functionStart']==BASE+fn)
                original_body=read(BASE+fn,body['bytes']);filebody=out/(hex(fn)+'.original-body.bin');filebody.write_bytes(original_body)
                assert p.pin(filebody)['sha256']==body['sha256']
                start=ls[fn];at=start;assert raw[at]==255;at+=1;encoding=raw[at];at+=1;typebase=None
                if encoding!=255:
                    assert encoding==0x9b;off,at=q.uleb(raw,at);typebase=at+off
                assert raw[at]==1;at+=1;length,at=q.uleb(raw,at);end=at+length;rows=[]
                while at<end:
                    first,at=q.uleb(raw,at);size,at=q.uleb(raw,at);landing,at=q.uleb(raw,at);action,at=q.uleb(raw,at)
                    assert first+size<=body['bytes']
                    if landing:assert landing<body['bytes']
                    row=dict(start=fn+first,end=fn+first+size,landingRVA=fn+landing if landing else 0,action=action)
                    if action:
                        assert action==1 and typebase and typebase>=end+2
                        filter_type,aa=sleb(raw,end+action-1);next_action,aa=sleb(raw,aa)
                        assert filter_type==1 and next_action==0
                        entry=raw[typebase-4:typebase];assert entry==bytes(4)
                        row['catchAllDuringCleanup']=True;row['typeFilter']=filter_type;row['nullTypeTableEntry']=entry.hex()
                    rows.append(row)
                assert at==end
                extent=typebase if typebase else end
                assert extent-start<=4096;genuine=read(BASE+start,extent-start);assert genuine==raw[start:extent]
                table=out/(hex(fn)+'.original-lsda.bin');table.write_bytes(genuine)
                affected=[]
                for call in calls:
                    matches=[row for row in rows if row['start']<=call<row['end']];assert len(matches)==1
                    assert matches[0]['action']==0
                    cleanup=matches[0]['landingRVA'];instructions=[row for row in body['instructions']if row['pc']>=BASE+cleanup]
                    # The genuine cleanup ultimately forwards the original
                    # exception to its original unwind-resume island.
                    if cleanup:assert any(row['mnemonic']=='bl'and row['operands']=='#0x22804e190'for row in instructions)
                    else:instructions=[]
                    affected.append(dict(callRVA=call,cleanup=matches[0],ownUnsupportedIsNotCaughtOrConvertedHere=True,originalRangeHasNoLandingPad=not bool(cleanup),
                        completeLandingExitInstructions=instructions))
                proofs.append(dict(functionRVA=fn,originalCompleteBody=p.pin(filebody),originalLSDA=p.pin(table),
                    allCallSites=rows,affectedIngressCalls=affected,sourceGenuineBody=body,
                    originalCodeNotExecuted=True))
        finally:
            for sub in subs:sub.close()
    assert sum(len(row['affectedIngressCalls'])for row in proofs)==9
    p.save(out/'audit.json',dict(schema='Original27 Mac ingress cleanup-only exception boundary v3',
        originalImageUUID='418efc4809d93606918eb6f95baeffdc',actualCurrentCandidate=p.pin(candidate),originalMethodContract=p.pin(original),
        completeOriginalFunctions=proofs,selectedIngressCalls=9,genuineCleanupOnlyRanges=sum(bool(c['cleanup']['landingRVA'])for r in proofs for c in r['affectedIngressCalls']),
        genuineRangesWithoutLandingPad=sum(c['originalRangeHasNoLandingPad']for r in proofs for c in r['affectedIngressCalls']),
        originalMacIngressDoesNotConvertOwnUnsupportedAtTheseBoundaries=True,
        broaderExternalCallbackExceptionPolicyValidated=False,originalThreadOrAppCrashOutcomeExecuted=False,
        ownSourceAvoidsMacViewSetCapturesAndPacketRegistration=True,applicationGatesPreserved=True,
        originalVZExecuted=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
    pins=[p.pin(Path(__file__)),p.pin(candidate),p.pin(original),p.pin(file)]
    for name in ('contract.json','inputs.json','original-cache-header.bin'):pins.append(p.pin(original.parent/name))
    pins += [p.pin(file)for file in out.iterdir()if file.is_file()]
    p.save(out/'freeze.json',dict(files=pins,deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),functions=5,actionZeroIngressCalls=9)))
if __name__=='__main__':main()
