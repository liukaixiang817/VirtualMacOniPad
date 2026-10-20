#!/usr/bin/env python3
"""Relocate real declared HID type/generic/class patterns in inert data only."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hid_reader',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from compiler_image import imports,chain_entries
from universalhid_type_metadata_v1 import HIDTypeMetadata

ROOT=p.ROOT;NODE=p.NODE;pin=p.pin;save=p.save
BASE=NODE/'universalhid-genuine-own-protocol-data-v3'
UPSTREAM=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    for row in json.loads((BASE/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    previous=json.loads((BASE/'candidate.json').read_text());results=[];files=[]
    for plan in previous['providers']:
        source=Path(plan['candidate']['path']);rawpath=Path(plan['originalRaw']['path']);raw=rawpath.read_bytes();before=source.read_bytes()
        a=HIDTypeMetadata(raw,before);a.types();assert not a.unresolved
        assert len({r['fileoff']for r in a.rows})==len(a.rows)
        changes=[r for r in a.rows if r['newRelative32']!=r['beforeRelative32']]
        assert len(changes)==(8 if plan['name']=='UniversalHID'else 69)
        repaired=a.apply();assert len(repaired)==len(before)
        assert list(chain_entries(repaired))==list(chain_entries(before))and imports(repaired)==imports(before)
        whitelist={i for r in changes for i in range(r['fileoff'],r['fileoff']+4)}
        assert all(i in whitelist for i,(x,y)in enumerate(zip(before,repaired))if x!=y)
        target=out/(plan['name']+'27.genuine-type-metadata.mac.inert.macho-data');target.write_bytes(repaired)
        validation=subprocess.run(['xcrun','dyld_info','-validate_only',str(target)],capture_output=True,text=True)
        assert validation.returncode==0,(validation.stdout,validation.stderr)
        results.append(dict(name=plan['name'],source=pin(source),originalRaw=pin(rawpath),candidate=pin(target),
            schemas=a.schemas,relativeFields=a.rows,changedFields=changes,dyldValidationExit=validation.returncode,
            existingImportBytesUnchanged=True,allPACAndInstructionBytesUnchanged=True,
            fullMetadataSchema=False,nativeExecuted=False,deviceOperations=0))
        files.extend([source,rawpath,target])
    result=dict(schema='Genuine HID declared type generic class-pattern relocation v1',sourceCandidate=pin(BASE/'candidate.json'),
        providers=results,actualChangedRelativeFields=77,declaredTypes=214,genericClassPatterns=11,
        newImports=0,newGOTSlots=0,fullMetadataSchema=False,stockTransitiveClosureProven=False,
        nativeExecuted=False,codeSigned=False,deviceOperations=0,originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    save(out/'candidate.json',result);files.extend([Path(__file__),HERE/'universalhid_type_metadata_v1.py',out/'candidate.json'])
    files.extend(UPSTREAM/('include--swift--ABI--'+n+'.h')for n in('Metadata','MetadataValues','GenericContext'))
    files.append(ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-lookup-version-compatibility-audit-v1/upstream/include--swift--ABI--TargetLayout.h')
    save(out/'freeze.json',dict(files=[pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),actualChangedFields=77)))


if __name__=='__main__':main()
