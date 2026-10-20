#!/usr/bin/env python3
"""Pin actual V3 relocation in the recipe without rerunning signing or models."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P=N/'owned-uikit-mac-event-filter-source-port-v3-attempt1'
O=N/'owned-uikit-mac-event-filter-source-port-v3-finalization-v1-attempt1'
def pin(p):
    p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
    if pin(r['path'])!=r:raise ValueError('changed actual producer pin')
def save(p,d):p.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
def main():
    if O.exists():raise ValueError('fresh metadata finalization required')
    c=json.loads((P/'candidate.json').read_bytes());f=json.loads((P/'freeze.json').read_bytes())
    for r in f['files']:exact(r)
    sp=importlib.util.spec_from_file_location('actual_filter_v3_reader',c['reader']['path']);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
    data=Path(c['patchedVZ']['path']).read_bytes();im=m.MachO(data)
    fix=next(r for r in im.commands if r['cmd']==0x80000034);offset,size=struct.unpack_from('<II',data,fix['at']+8)
    actual=dict(fileOffset=offset,bytes=size,sha256=hashlib.sha256(data[offset:offset+size]).hexdigest())
    if actual!=c['ownMacEventFilterContract']['fixupPayloadAfter']:raise ValueError('actual final relocation must match source contract')
    recipe=json.loads(Path(c['recipe']['path']).read_bytes());recipe['fixupPayloadAfter']=actual
    O.mkdir(mode=0o700);save(O/'patch-recipe.json',recipe)
    c.update(originalBuilder=c['builder'],builder=pin(__file__),actualLayoutProducerCandidate=pin(P/'candidate.json'),actualLayoutProducerFreeze=pin(P/'freeze.json'),recipe=pin(O/'patch-recipe.json'),metadataFinalizationOnly=True,signatureCompileOrModelReruns=0)
    save(O/'candidate.json',c)
    rows=f['files']+[pin(__file__),pin(P/'candidate.json'),pin(P/'freeze.json'),pin(O/'patch-recipe.json'),pin(O/'candidate.json')]
    save(O/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(O/'candidate.json'),freeze=pin(O/'freeze.json'))))
if __name__=='__main__':main()
