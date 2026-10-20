#!/usr/bin/env python3
"""Bind the last State2 import to the existing, guarded old-host entry adapter."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
spec=importlib.util.spec_from_file_location('state2_genuine_reader',ROOT/'VirtualMac/scripts/development/prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
SOURCE=NODE/'vz-arraybuffer-consume-strong-data-v1/candidate.json'
PROVIDER=NODE/'vz-genuine-strong-closure-design-v2/build-v1/bundle/VM27SwiftLookup.dylib'
PROJECT=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-lookup-project-build-v1/manifest.json'
RAWBASE=ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1'
SYMBOL='_swift_getTypeByMangledNameInContextInMetadataState2'


def verify(before,after):
    old=p.vz_reader.parse(before);new=p.vz_reader.parse(after)
    assert len(before)==len(after)and old['deps']==new['deps']and old['words']==new['words']and old['nlists']==new['nlists']
    assert old['deps'][57]['name']=='@loader_path/VM27SwiftLookup.dylib'
    row=old['imports'][705];assert row['index']==705 and row['name']==SYMBOL and row['ordinal']==36 and not row['weak']and row['addend']==0
    assert old['imports'][704]['name']=='_swift_getTypeByMangledNameInContext2'and old['imports'][704]['ordinal']==58
    for a,b in zip(old['imports'],new['imports'],strict=True):assert b==({**a,'ordinal':58}if a['index']==705 else a)
    assert all(i==row['at']for i,(a,b)in enumerate(zip(before,after))if a!=b)
    assert len(new['imports'])==1056 and sum(not r['weak']for r in new['imports'])==1011
    return row


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    assert p.pin(SOURCE)['sha256']=='4c4a7853c15fab508a3d682f2463933d0bffe52ac05dfdac5cf349d6f853a140'
    for row in json.loads((SOURCE.parent/'freeze.json').read_text())['files']:assert p.pin(Path(row['path']))==row
    assert p.pin(PROVIDER)['sha256']=='d9b1f6d932a035a68de125c0523b902c5248680899b83576c77fdc3f12180914'
    project=json.loads(PROJECT.read_text());reference=Path(project['library']['path'])
    assert p.pin(reference)['sha256']==project['library']['sha256']
    source=PROVIDER.read_bytes();original=reference.read_bytes()
    oldsections={(g['name'],s['name']):s for g in p.segments(original)for s in g['sections']if s['fileoff']and s['flags']&255 not in(1,12)}
    newsections={(g['name'],s['name']):s for g in p.segments(source)for s in g['sections']if s['fileoff']and s['flags']&255 not in(1,12)}
    assert set(oldsections)==set(newsections)
    for key,old in oldsections.items():
        new=newsections[key];assert old['size']==new['size']and original[old['fileoff']:old['fileoff']+old['size']]==source[new['fileoff']:new['fileoff']+new['size']],key
    assert len(newsections)==6
    for command,at,size in p.commands(source):
        if command==0x80000033:off,length=struct.unpack_from('<II',source,at+8)
    exports={r['symbol']:r for r in p.export_trie(source[off:off+length])}
    assert set(exports)=={SYMBOL,'_swift_getTypeByMangledNameInContext2'}
    assert not any(r['flags']&8 for r in exports.values())
    # The original caller's exact byte contract is ff metadata state and raw
    # null context/arguments, a shape present in the adapter's historical test.
    rawpath=RAWBASE/'raw/Virtualization';raw=rawpath.read_bytes();section=next(s for g in p.segments(raw)for s in g['sections']if s['name']=='__text')
    caller=0x2260f78e4;pos=section['fileoff']+caller-section['address'];window=raw[pos-40:pos+16]
    assert struct.unpack_from('<3I',window,28)==(0x52801fe0,0xd2800003,0xd2800004)
    branch=struct.unpack_from('<I',window,40)[0];assert branch&0xfc000000==0x94000000
    delta=(branch&0x3ffffff)<<2
    if delta&0x8000000:delta-=0x10000000
    assert caller+delta==0x228050800
    sourceplan=json.loads(SOURCE.read_text());frontend=Path(sourceplan['frontendCandidate']['path']);before=frontend.read_bytes()
    data=bytearray(before);parsed=p.vz_reader.parse(before);at=parsed['imports'][705]['at']
    word=struct.unpack_from('<I',data,at)[0];struct.pack_into('<I',data,at,(word&~255)|58);after=bytes(data)
    row=verify(before,after);target=out/'VZ27.state2-oldhost-entry.mac.inert.macho-data';target.write_bytes(after)
    providerout=out/'VM27SwiftLookup.unchanged-ios-provider.inert.macho-data';providerout.write_bytes(source)
    cases=[]
    for name,pos,mask in[('weak State2 import',at+1,1),('wrong State2 ordinal',at,1),('wrong State2 addend',at+4,1),
                          ('genuine instruction',section['fileoff'],1),('chained PAC word',3092448+7,128),('dependency header',16,1)]:
        changed=bytearray(after);changed[pos]^=mask;rejected=False
        try:verify(before,bytes(changed))
        except(AssertionError,ValueError,struct.error):rejected=True
        assert rejected,name;cases.append(dict(name=name,rejected=True))
    check=subprocess.run(['xcrun','dyld_info','-validate_only',str(target)],capture_output=True);assert check.returncode==0,check.stderr
    report=dict(schema='Genuine old-host guarded State2 entry route inert data v1',sourceCandidate=p.pin(SOURCE),frontendSource=sourceplan['frontendCandidate'],frontendCandidate=p.pin(target),
                unchangedRuntimeProvider=dict(intendedLoadPath='@loader_path/VM27SwiftLookup.dylib',source=p.pin(PROVIDER),candidate=p.pin(providerout),exports=exports),
                referenceProjectBuild=p.pin(PROJECT),exactSixFileBackedProviderSectionsMatchReference=True,
                originalVZCaller=dict(source=p.pin(rawpath),callPC=caller,exactWindow=window.hex(),state=255,context=None,genericArguments=None),
                route=dict(index=705,at=at,symbol=SYMBOL,oldOrdinal=36,newOrdinal=58,strong=True),
                negativeControls=cases,dyldValidationExit=check.returncode,externalFiveArgumentSwiftCCAndPACContractPreserved=True,
                compatibilityScope='old-host entry authentication and native State lookup delegation; parser equivalence is not claimed',
                fullSwift27ParserEquivalent=False,allOriginalVZTypesProvenResolvable=False,conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,
                fullCurrentLoadGraphProven=False,metadataCompatibilityProven=False,nativeExecuted=False,deviceOperations=0,originalVZLoaded=False,full27Backend=False)
    p.save(out/'candidate.json',report)
    files=[Path(__file__),SOURCE,PROVIDER,PROJECT,reference,rawpath,frontend,target,providerout,out/'candidate.json']
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),negativeControls=len(cases),fiveArgumentOldHostEntryOnly=True)))


if __name__=='__main__':main()
