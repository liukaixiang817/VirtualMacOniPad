#!/usr/bin/env python3
"""Route the exact consuming specialization in a new inert VZ data candidate."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
spec=importlib.util.spec_from_file_location('array_genuine_route',ROOT/'VirtualMac/scripts/development/prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
SOURCE=NODE/'vz-cxx-six-strong-data-v2/candidate.json'
BUILD=NODE/'swift-arraybuffer-consume-data-build-v2/candidate.json'
ABI=NODE/'swift-arraybuffer-consume-original-abi-v3/audit.json'
SYMBOL='_$ss12_ArrayBufferV20_consumeAndCreateNew14bufferIsUnique15minimumCapacity13growForAppendAByxGSb_SiSbtFyXl_Ts5'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    assert p.pin(SOURCE)['sha256']=='790e8ec7c466a90b963ea44603947ecb69b8f3e3204a2e37595bebd7ef4bb2b0'
    assert p.pin(BUILD)['sha256']=='71e91244b53029d7fb3ec5057e3cfa50a3bf7f83c3cfa2855396a1c4146d746f'
    assert p.pin(ABI)['sha256']=='c46aa26a4aa6ea60610814fe492d5c332c608082fac616ae8fa6c59a10bfdcea'
    for folder in(SOURCE.parent,BUILD.parent,ABI.parent):
        for row in json.loads((folder/'freeze.json').read_text())['files']:assert p.pin(Path(row['path']))==row
    source=json.loads(SOURCE.read_text());build=json.loads(BUILD.read_text());abi=json.loads(ABI.read_text())
    assert abi['originalCallerABICompatible']and abi['ownedBufferArgumentAndResult']and abi['noReceiverSwiftself']
    role=next(r for r in build['roles']if r['role']=='ios');assert role['allCurrentNativeStrongDependenciesResolved']
    provider=Path(role['provider']['path']);raw=provider.read_bytes();assert p.pin(provider)==role['provider']
    assert set(role['exports'])=={SYMBOL}and not any(c==0x1d for c,q,z in p.commands(raw))
    providerout=out/'AB.unchanged-unsigned-ios-provider.inert.macho-data';providerout.write_bytes(raw)
    beforepath=Path(source['frontendCandidate']['path']);before=beforepath.read_bytes();assert p.pin(beforepath)==source['frontendCandidate']
    old=p.vz_reader.parse(before);data=bytearray(before)
    assert len(old['deps'])==61 and old['deps'][-1]['name']=='@loader_path/CP'
    ordinal=p.append_dependency(data,'@loader_path/AB');assert ordinal==62
    matches=[r for r in old['imports']if r['name']==SYMBOL];assert len(matches)==1
    row=matches[0];assert row['ordinal']==36 and not row['weak'];word=struct.unpack_from('<I',data,row['at'])[0]
    struct.pack_into('<I',data,row['at'],(word&~255)|62)
    after=bytes(data);new=p.vz_reader.parse(after)
    assert old['words']==new['words']and old['nlists']==new['nlists']
    for a,b in zip(old['imports'],new['imports'],strict=True):assert b==({**a,'ordinal':62}if a['name']==SYMBOL else a)
    assert len(new['imports'])==1056 and sum(not r['weak']for r in new['imports'])==1011
    whitelist=set(range(16,24))|set(range(32+struct.unpack_from('<I',before,20)[0],32+struct.unpack_from('<I',before,20)[0]+40))|{row['at']}
    assert all(i in whitelist for i,(a,b)in enumerate(zip(before,after))if a!=b)
    target=out/'VZ27.cxx-six-and-arraybuffer-consume.mac.inert.macho-data';target.write_bytes(after)
    result=subprocess.run(['xcrun','dyld_info','-validate_only',str(target)],capture_output=True);assert result.returncode==0,result.stderr
    (out/'dyld.stdout').write_bytes(result.stdout);(out/'dyld.stderr').write_bytes(result.stderr)
    report=dict(schema='Real consuming AnyObject ArrayBuffer private VZ inert route v1',sourceCandidate=p.pin(SOURCE),sourceBuild=p.pin(BUILD),
                originalCallerABIAudit=p.pin(ABI),frontendSource=source['frontendCandidate'],frontendCandidate=p.pin(target),
                unchangedRuntimeProvider=dict(alias='AB',intendedLoadPath='@loader_path/AB',source=role['provider'],candidate=p.pin(providerout),exports=role['exports']),
                route=dict(index=row['index'],at=row['at'],symbol=SYMBOL,oldOrdinal=36,newOrdinal=62,strong=True),
                exactConsumedBufferArgumentAndOwnedResultABI=True,allOriginalInstructionMetadataWitnessAuthAndNlistBytesPreserved=True,
                strongImportsPreserved=1011,importCount=1056,dyldValidationExit=result.returncode,
                conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,stockTransitiveClosureProven=False,
                fullCurrentLoadGraphProven=False,fullMetadataSchema=False,codeSigned=False,nativeIOSExecuted=False,deviceOperations=0,
                originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    p.save(out/'candidate.json',report)
    files=[Path(__file__),SOURCE,BUILD,ABI,beforepath,target,provider,providerout,out/'candidate.json']
    p.save(out/'freeze.json',dict(files=[p.pin(path)for path in files],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),strongImportOrdinal=62)))


if __name__=='__main__':main()
