#!/usr/bin/env python3
"""Repair one genuine UHK generic environment in a new inert data candidate.

Keeps all imported symbols, witness/code bytes, original PAC and existing
routes. The cache's exact local-symbol identity and the documented descriptor
layout resolve a former false mangled-symbol reference. No provider is loaded.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hid_owner_reader',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from compiler_image import commands,segments,imports,chain_entries
from swift_relative_metadata import RelativeMetadata
from universalhid_generic_environment_v1 import parse_environment

ROOT=p.ROOT;NODE=p.NODE;pin=p.pin;save=p.save
BASE=NODE/'cgaffine-genuine-equal-private-v6'
RAW=NODE/'universalhid-original-contract-v1/raw/UniversalHIDKit'
SOURCE=BASE/'UniversalHIDKit27.genuine-equal-route.mac.inert.macho-data'
ADDRESS=0x29fdbbde0
PROTOCOL_SLOT=0x2d1d3ede8
PROTOCOL=0x29fdbb800
PROTOCOL_SYMBOL='_$s15UniversalHIDKit15NSEventProtocolMp'
PARAMETER=0x29fdbbdd0
SYMBOL='_generic environment 15UniversalHIDKit15NSEventProtocolRzl'
IPSW=ROOT/'DeviceDiagnostics/2026-10-02-macos27-backend/toolchain/ipsw'
PYTHON=ROOT/'DeviceDiagnostics/2026-10-02-macos27-backend/toolchain/venv/bin/python3'
UPSTREAM=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream'


def run(out,label,argv):
    result=subprocess.run([str(x)for x in argv],capture_output=True,text=True)
    save(out/(label+'.json'),dict(argv=[str(x)for x in argv],exitCode=result.returncode,
                                stdout=result.stdout,stderr=result.stderr))
    assert result.returncode==0,(label,result.stderr)
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    for row in json.loads((BASE/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    raw=RAW.read_bytes();source=SOURCE.read_bytes();audit=RelativeMetadata(raw,source)
    g,s=audit.section(ADDRESS);assert g['name']=='__TEXT'and s['name']=='__swift5_typeref'
    offset=audit.offset(ADDRESS);shape=parse_environment(raw,offset,s['fileoff']+s['size'])
    assert shape['flags']==0x1001 and shape['counts']==[1]and shape['parameters']==[0x80]
    assert len(shape['requirements'])==1 and shape['requirements'][0]['flags']==0x80
    assert shape['end']==offset+20
    # A fresh cache index pins the current exact local symbol. An adjacent
    # address must be reported with an offset, preventing nearest-symbol use.
    lookup=run(out,'exact-original-local-symbol',[IPSW,'dyld','a2s',p.CACHE,hex(ADDRESS),
        '--cache',out/'fresh-original-symbols.a2s','--image','--demangle'])
    exactline=hex(ADDRESS)+': '+SYMBOL
    assert exactline in lookup.stdout.splitlines()
    adjacent=run(out,'adjacent-original-local-symbol',[IPSW,'dyld','a2s',p.CACHE,hex(ADDRESS+1),
        '--cache',out/'fresh-original-symbols.a2s','--image','--demangle'])
    assert hex(ADDRESS+1)+': '+SYMBOL not in adjacent.stdout.splitlines()
    # Follow the real original relative-indirectable protocol pointer into
    # the original declared auth_ptr section, rather than inventing a GOT.
    requirement=shape['requirements'][0]
    assert ADDRESS+requirement['parameterOffset']-offset+requirement['parameterRelative32']==PARAMETER
    value_slot=ADDRESS+requirement['valueOffset']-offset
    low=requirement['valueRelative32']&1
    assert low==1 and value_slot+requirement['valueRelative32']-low==PROTOCOL_SLOT
    pg,ps=audit.section(PROTOCOL_SLOT);assert pg['name']=='__AUTH_CONST'and ps['name']=='__auth_ptr'
    assert audit.read(PROTOCOL_SLOT,'<Q')[0]==PROTOCOL
    routes=out/'original-slot-route.json'
    save(routes,[dict(originalSlotVA=PROTOCOL_SLOT,symbol=PROTOCOL_SYMBOL,labels=['protocol'])])
    run(out,'original-cache-auth',[PYTHON,HERE/'audit-swift-cache-indirection-auth.py',
        '--routes',routes,'--expected-routes-sha256',pin(routes)['sha256'],'--cache',p.CACHE,
        '--expected-cache-uuid','c284a291b68b3d0da1a03f866f87efdc','--output',out/'original-auth'])
    original_auth=json.loads((out/'original-auth/contract.json').read_text())['contracts'][0]
    assert original_auth['chainMembershipVerified']and original_auth['actualTarget']==hex(PROTOCOL)
    assert (original_auth['auth'],original_auth['key'],original_auth['diversity'],original_auth['addressDiversity'])==(1,2,'0xae86',1)
    with p.CACHE.open('rb')as f:
        from DyldExtractor.dyld.dyld_context import DyldContext
        cache=DyldContext(f);subs=cache.addSubCaches(p.CACHE)
        try:proof=p.GenuineCacheExports(cache).resolve('/System/Library/PrivateFrameworks/UniversalHIDKit.framework/Versions/A/UniversalHIDKit',PROTOCOL_SYMBOL)
        finally:
            for sub in subs:sub.close()
    assert proof['exportAddress']==PROTOCOL
    mapped_slot=audit.mapped(PROTOCOL_SLOT)
    entry=next(r for r in chain_entries(source)if r['address']==mapped_slot)
    assert entry['auth']and not entry['bind']
    assert (entry['word']>>32)&65535==0xae86 and (entry['word']>>49)&3==2 and entry['word']&(1<<48)
    assert entry['word']&0xffffffff==audit.mapped(PROTOCOL)-0x100000000
    audit.relative(ADDRESS+requirement['parameterOffset']-offset,'genericEnvironmentParameter')
    audit.relative(value_slot,'genericEnvironmentProtocol',True)
    assert not audit.unresolved and len(audit.rows)==2
    repaired=bytearray(source)
    for row in audit.rows:struct.pack_into('<i',repaired,row['fileoff'],row['newRelative32'])
    assert list(chain_entries(repaired))==list(chain_entries(source))and imports(repaired)==imports(source)
    changed=[i for i,(a,b)in enumerate(zip(source,repaired))if a!=b]
    assert changed and all(audit.rows[1]['fileoff']<=i<audit.rows[1]['fileoff']+4 for i in changed)
    target=out/'UniversalHIDKit27.genuine-generic-environment.mac.inert.macho-data';target.write_bytes(repaired)
    run(out,'candidate-dyld',['xcrun','dyld_info','-validate_only',target])
    report=dict(schema='Genuine UHK explicit generic-environment data relocation v1',
        source=pin(SOURCE),originalRaw=pin(RAW),candidate=pin(target),originalDescriptorVA=ADDRESS,
        exactOriginalLocalSymbol=SYMBOL,exactSymbolLookup=pin(out/'exact-original-local-symbol.json'),
        adjacentSymbolLookup=pin(out/'adjacent-original-local-symbol.json'),
        boundedSchema=shape,originalProtocolSlot=PROTOCOL_SLOT,originalProtocol=PROTOCOL,
        originalProtocolAuth=original_auth,genuineProtocolExport=proof,
        mappedProtocolSlot=mapped_slot,preservedProtocolChainWord=entry,
        relativeFields=audit.rows,onlyActualProtocolRelative32Changed=True,
        formerOpaqueRecordIsBinaryGenericEnvironment=True,selectedDeclaredSchemasRelocated=True,
        importBytesUnchanged=True,allChainPACUnchanged=True,instructionsUnchanged=True,
        fullMetadataSchema=False,stockTransitiveClosureProven=False,nativeExecuted=False,
        codeSigned=False,deviceOperations=0,originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    save(out/'candidate.json',report)
    files=[Path(__file__),HERE/'universalhid_generic_environment_v1.py',HERE/'audit-swift-cache-indirection-auth.py',
        RAW,SOURCE,target,routes,out/'original-auth/contract.json',out/'exact-original-local-symbol.json',
        out/'adjacent-original-local-symbol.json',out/'candidate.json']
    files.extend(UPSTREAM/('include--swift--ABI--'+n+'.h')for n in('Metadata','MetadataValues','GenericContext'))
    save(out/'freeze.json',dict(files=[pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),data=pin(target),relativeFields=2,actualChangedFields=1)))


if __name__=='__main__':main()
