#!/usr/bin/env python3
"""Scoped genuine27 HID conformance schema; generic reader remains unchanged.

Trailing order and twelve-byte generic requirements follow the pinned Swift
ABI Metadata.h, MetadataValues.h and GenericContext.h already in this project.
Unknown pack/actor/value-requirement schemas still block application.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READERS=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
UPSTREAM=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream'
sys.path.insert(0,str(READERS))
sys.path.insert(0,str(Path(__file__).parent))
from swift_relative_metadata import RelativeMetadata


class HIDRelativeMetadata(RelativeMetadata):
    def conformances(self,external=None):
        for descriptor in self.entries('__swift5_proto'):
            flags=self.read(descriptor+12,'<I')[0];kind=(flags>>3)&7
            schema=dict(descriptor=descriptor,flags=flags,typeReferenceKind=kind,kind='conformance',
                        retroactive=bool(flags&0x40),synthesizedNonUnique=bool(flags&0x80),
                        conditionalRequirements=(flags>>8)&255)
            self.schemas.append(schema)
            # The new scope adds only ordinary retroactive and conditional
            # trailing objects. No pack shape/global actor/value layout guess.
            if flags&~0x3fff8 or kind not in(0,1,2,3):
                self.unresolved.append(dict(descriptor=descriptor,label='unsupported HID conformance trailing schema',flags=flags));continue
            self.relative(descriptor,'protocol',True,external=external)
            self.relative(descriptor+4,'indirectTypeReference'if kind==1 else 'typeReference',external=external)
            self.relative(descriptor+8,'witnessPattern',nullable=True,external=external)
            at=descriptor+16
            if flags&0x40:
                self.relative(at,'retroactiveContext',True,external=external);at+=4
            for index in range(schema['conditionalRequirements']):
                requirementFlags=self.read(at,'<I')[0];requirementKind=requirementFlags&31
                row=dict(descriptor=at,kind='conditionalRequirement',flags=requirementFlags,
                         requirementKind=requirementKind)
                self.schemas.append(row)
                if requirementFlags&~0x9f or requirementKind not in(0,1,2,3,4,31):
                    self.unresolved.append(dict(descriptor=at,label='unsupported HID conditional requirement schema',flags=requirementFlags))
                    at+=12;continue
                self.relative(at+4,'conditionalParameter',external=external)
                if requirementKind==0:
                    self.relative(at+8,'conditionalProtocol',True,external=external)
                elif requirementKind in(1,2,4):
                    self.relative(at+8,'conditionalType',external=external)
                elif requirementKind==3:
                    self.relative(at+8,'conditionalConformance',True,external=external)
                # Layout is an integer constraint, not a relative address.
                at+=12
            if flags&0x10000:
                count=self.read(at,'<I')[0];assert count<1024
                schema['resilientWitnessCount']=count;at+=4
                for index in range(count):
                    self.relative(at,'resilientRequirement',True,external=external)
                    self.relative(at+4,'resilientWitnessImpl',nullable=True,external=external);at+=8
            if flags&0x20000:
                schema['genericWitnessTable']=at
                self.relative(at+4,'genericWitnessInstantiator',nullable=True,external=external)
                self.relative(at+8,'genericWitnessPrivateData',nullable=True,external=external)


def pin(path):
    data=path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--candidate',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();source=args.candidate.resolve();out=args.output.resolve()
    assert source.is_relative_to(NODE)and out.is_relative_to(NODE)and not out.exists()
    candidate=json.loads((source/'candidate.json').read_text())
    for row in json.loads((source/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    out.mkdir()
    results=[]
    for provider in candidate['providers']:
        raw=Path(provider['original']['path']).read_bytes();new=Path(provider['candidate']['path']).read_bytes()
        a=HIDRelativeMetadata(raw,new);a.singletons();a.conformances();a.reflection()
        report=dict(name=provider['name'],original=provider['original'],candidate=provider['candidate'],
                    schemas=a.schemas,relativePointers=a.rows,unresolved=a.unresolved,
                    declaredSchemasExpanded=True,applied=False,fullMetadataSchema=False,
                    nativeExecuted=False,deviceOperations=0)
        path=out/(provider['name']+'.audit.json');path.write_text(json.dumps(report,indent=2)+'\n')
        results.append(dict(name=provider['name'],audit=pin(path),schemas=len(a.schemas),fields=len(a.rows),
                            unresolved=len(a.unresolved),uniqueExternalTargets=len({r['target']for r in a.unresolved if'target'in r})))
    sources=[UPSTREAM/('include--swift--ABI--'+name+'.h')for name in('Metadata','MetadataValues','GenericContext')]
    report=dict(schema='Scoped genuine27 HID retroactive and conditional conformance schema audit v1',
                candidate=pin(source/'candidate.json'),results=results,upstreamSources=[pin(p)for p in sources],
                source=pin(Path(__file__)),genericReaderUnchanged=True,fullMetadataSchema=False,
                applied=False,nativeExecuted=False,deviceOperations=0,full27Backend=False)
    (out/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(audit=pin(out/'audit.json'),providers=results)))


if __name__=='__main__':main()
