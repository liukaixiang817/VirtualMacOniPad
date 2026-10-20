#!/usr/bin/env python3
"""Read-only finite peer review of the two original error recipes."""
from pathlib import Path
import argparse, hashlib, json, runpy, struct, sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
checks=0
def need(ok,msg):
    global checks; checks+=1
    if not ok: raise ValueError(msg)
def pin(p):
    p=Path(p).resolve(); b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def target(word,pc):
    if word&0xfc000000 not in (0x14000000,0x94000000):return None
    imm=word&0x3ffffff
    if imm&(1<<25):imm-=1<<26
    return pc+imm*4
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve()
    need(out.parent==N and not out.exists(),'fresh peer review output')
    peer=N/'original27-el2-tso-explicit-refusal-data-v1-attempt1'
    own=N/'original27-optional-state-fields-fail-closed-data-v1-attempt1'
    paths=[peer/'candidate.json',peer/'patch-recipe.json',peer/'freeze.json',own/'candidate.json',own/'patch-recipe.json',own/'freeze.json']
    for folder in [peer,own]:
        for q in json.loads((folder/'freeze.json').read_bytes())['files']:need(pin(q['path'])==q,'actual immutable source pin')
    j=json.loads(paths[0].read_bytes());rp=json.loads(paths[1].read_bytes())
    jo=json.loads(paths[3].read_bytes());ro=json.loads(paths[4].read_bytes())
    source=Path(j['sourceImage']['path']);need(pin(source)==j['sourceImage']==jo['source'],'shared genuine base')
    parser=N/'vmm-public-adapter-gap-design-v1/audit.py';a=runpy.run_path(str(parser));m=a['MachO'](source.read_bytes())
    output=Path(j['output']['path']);need(pin(output)==j['output'],'actual compiled peer output')
    actual=output.read_bytes();expected=bytearray(m.b);combined=bytearray(m.b);allowed=set();all_allowed=set();summary=[]
    for q,method in zip(rp['patches'],j['actualMethods']):
        start,end=q['startRVA'],q['endRVA'];before=bytes.fromhex(q['beforeHex']);after=bytes.fromhex(q['afterHex'])
        need(m.bounds(start)==(start,end) and m.raw(start,end-start)==before,'actual full function bounds and before bytes')
        off=q['originalFileOffset'];need(m.b[off:off+end-start]==before,'actual section translation')
        prefix=method['prologueBytes'];ep=method['epilogueStart']-start
        need(before[:prefix]==after[:prefix] and before[ep:]==after[ep:],'original frame/PAC prefix and epilogue')
        need(target(struct.unpack_from('<I',after,prefix)[0],start+prefix)==0x40fe48,'true original assertion helper BL')
        need(struct.unpack_from('<I',after,prefix+4)[0]==0xd4200020,'true no-return BRK guard')
        need(all(struct.unpack_from('<I',after,k)[0]==0xd503201f for k in range(prefix+8,ep,4)),'all intervening body bytes only NOP')
        if 'vtableSlotRVA' in method:
            slot=method['vtableSlotRVA'];word=struct.unpack('<Q',m.raw(slot,8))[0]
            need(word==int(method['actualVtableWord'],16) and word&0xffffffff==start,'true authenticated virtual table binding')
        else:
            need(start==0x30673c and method['field']==0xa00 and method['kind']=='TSO frozen closure invoke','actual separate closure invocation body')
        need(not method['externalDirectInteriorEntries'] and not method['chainedInteriorEntries']['interior'],'finite direct/chained entry census')
        need(not q['successStateProduced'],'explicit no success state')
        need(not all_allowed.intersection(range(off,off+len(after))),'peer methods disjoint')
        allowed.update(range(off,off+len(after)));all_allowed.update(range(off,off+len(after)))
        expected[off:off+len(after)]=after;combined[off:off+len(after)]=after
        summary.append(dict(startRVA=hex(start),endRVA=hex(end),prologueBytes=prefix,epilogueOffset=ep))
    need(bytes(expected)==actual,'whole peer candidate exactly reconstructed')
    for q in ro['codePatches']:
        off=q['originalFileOffset'];before=bytes.fromhex(q['beforeHex']);after=bytes.fromhex(q['afterHex'])
        need(m.b[off:off+len(before)]==before,'independent peer method before bytes')
        need(not all_allowed.intersection(range(off,off+len(after))),'nineteen methods disjoint')
        all_allowed.update(range(off,off+len(after)));combined[off:off+len(after)]=after
    for data in [actual,combined]:
        obj=a['MachO'](data)
        need(obj.imports==m.imports and obj.binds==m.binds and obj.libs==m.libs and obj.uuid==m.uuid and obj.starts==m.starts and obj.sections==m.sections and obj.segments==m.segments,'actual original PAC/fixup/import/metadata unchanged')
    obj=a['MachO'](combined);text=next(s for s in obj.sections if s['name']=='__text');calls=[]
    for k in range(0,text['bytes'],4):
        pc=text['va']-obj.base+k;word=struct.unpack_from('<I',combined,text['offset']+k)[0]
        if word&0xfc000000==0x94000000 and target(word,pc)==0x4125b4:calls.append(pc)
    need(calls==[0x289288,0x289adc,0x289be8,0x289db4,0x28bd70,0x28c7cc,0x28c914,0x28caf0],'actual combined only eight original frame calls remain')
    # Independently read the final fatal import instead of inferring its name.
    fatal=0x40fe84;stub=target(struct.unpack('<I',m.raw(fatal,4))[0],fatal)
    slot,bind=a['authenticated_stub'](m,m.raw(stub,16),stub)
    need(bind['importRecord']['name']=='__os_crash' and not bind['importRecord']['weak'],'original outcome is no-return OS crash')
    need(m.raw(0x44ef0c,len(b'assertion failed\0'))==b'assertion failed\0','actual original assertion text')
    need(j['failureIsNoReturnOSCrash'] and not j['failureIsRecoverableUnsupportedStatus'],'peer semantics match actual bytes')
    out.mkdir(mode=0o700)
    record=dict(schema='Independent finite EL2/TSO refusal and nineteen-method composition review v1',finiteLocalScopePassed=True,findings=[],checks=checks,peerCandidate=pin(paths[0]),peerRecipe=pin(paths[1]),peerFreeze=pin(paths[2]),optionalCandidate=pin(paths[3]),optionalRecipe=pin(paths[4]),optionalFreeze=pin(paths[5]),source=pin(source),actualPeerOutput=pin(output),methods=summary,combinedMethodCount=19,removedActualContextCalls=20,remainingContextCallRVAs=list(map(hex,calls)),hypotheticalCombinedBytes=len(combined),hypotheticalCombinedSHA256=hashlib.sha256(combined).hexdigest(),combinedImageWritten=False,actualFatalSymbol=bind['importRecord']['name'],failureIsNoReturnOSCrash=True,failureIsRecoverableUnsupportedStatus=False,nativeStateOrSoftwareSuccessImplemented=False,allDynamicConsumersProvedUnreachable=False,actualColdBootObserved=False,deviceOperations=0,nativeOperations=0,signingCalls=0)
    (out/'review.json').write_text(json.dumps(record,indent=2)+'\n')
    frozen=paths+[source,output,parser,Path(__file__).resolve(),out/'review.json']
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in frozen]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=[])))
if __name__=='__main__':main()
