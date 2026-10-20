#!/usr/bin/env python3
"""Route real array implementations through actual UH reexports; inert only."""
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
from compiler_image import commands,segments,imports,chain_entries,export_trie
NODE=p.NODE
UH=NODE/'universalhid-oldhost-contiguousbytes-adapted-data-v1/candidate.json'
KIT=NODE/'universalhid-genuine-type-metadata-data-v2/candidate.json'
FRONTEND=NODE/'universalhid-exact-owner-private-route-v5/candidate.json'
RESERVE=NODE/'vmm-contiguousarray-reserve-contract-v1/build-v6/candidate.json'


def exports(buf):
    for cmd,at,size in commands(buf):
        if cmd==0x80000033:off,z=struct.unpack_from('<II',buf,at+8);break
    else:raise AssertionError('exports required')
    return {r['symbol']:r for r in export_trie(buf[off:off+z])}


def add_true_reexport(data,path):
    ordinal=p.append_dependency(data,path)
    dep=p.dependencies(data)[ordinal-1]
    struct.pack_into('<I',data,dep['at'],0x8000001f)
    return ordinal


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--native-audit',type=Path,required=True)
    ap.add_argument('--abi-audit',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    auditpath=args.native_audit.resolve();audit=json.loads(auditpath.read_text())
    assert audit['all26StrongProviderImportsResolved'] and audit['current25HeaderExactlyMatchesArchived']
    for row in json.loads((auditpath.parent/'freeze.json').read_text())['files']:assert p.pin(Path(row['path']))==row
    abi=args.abi_audit.resolve();assert p.pin(abi)['sha256']=='39db5376349d44c6b1d1ae14c12158d49bcfca023980bb931e35bc60fc8dca4a'
    abiproof=json.loads(abi.read_text());assert abiproof['arrayProviderABICompatible']
    array=json.loads(RESERVE.read_text());role=next(r for r in array['roles']if r['role']=='ios')
    runtime=[];owners={}
    for alias,plan in [('AR',role['unchangedSiblingProvider']),('R',role['provider'])]:
        source=Path(plan['path']);assert p.pin(source)=={k:plan[k]for k in('path','bytes','sha256')}
        raw=source.read_bytes();declared=exports(raw);assert set(declared)==set(plan['exports'])
        dest=out/(alias+'.unchanged-ios-provider.inert.macho-data');dest.write_bytes(raw)
        runtime.append(dict(alias=alias,intendedLoadPath='@loader_path/'+alias,source=p.pin(source),candidate=p.pin(dest),exports=declared))
        for name in declared:assert name not in owners;owners[name]=alias
    assert len(owners)==9
    uh=json.loads(UH.read_text());kit=json.loads(KIT.read_text())['providers'][1]
    vz=json.loads(FRONTEND.read_text())['frontendCandidate']
    plans=[('UniversalHID',uh['providerCandidate'],False),('UniversalHIDKit',kit['candidate'],False),('Virtualization',vz,True)]
    results=[]
    for name,source,vzflag in plans:
        assert p.pin(Path(source['path']))==source;before=Path(source['path']).read_bytes();data=bytearray(before)
        if vzflag:
            oldparsed=p.vz_reader.parse(before);rows=oldparsed['imports'];oldordinal=36
        else:rows=imports(before)['imports'];oldordinal=8
        if name=='UniversalHID':
            ordinals={alias:add_true_reexport(data,'@loader_path/'+alias)for alias in('AR','R')}
            assert ordinals=={'AR':20,'R':21}
        else:
            ordinal=1 if name=='UniversalHIDKit'else 7
            assert p.dependencies(data)[ordinal-1]['path']=='@loader_path/UniversalHID27.dylib'
            ordinals={'AR':ordinal,'R':ordinal}
        selected=[]
        for r in rows:
            if r['name'] not in owners:continue
            assert r['ordinal']==oldordinal and not r['weak']
            at=r['at']if vzflag else r['command'];word=struct.unpack_from('<I',data,at)[0]
            ordinal=ordinals[owners[r['name']]];struct.pack_into('<I',data,at,(word&~255)|ordinal)
            selected.append(dict(index=r['index'],symbol=r['name'],at=at,oldOrdinal=oldordinal,newOrdinal=ordinal,
                actualProviderAlias=owners[r['name']],realReexportThroughUH=name!='UniversalHID'))
        assert len(selected)==(6 if name=='UniversalHIDKit'else 9)
        after=bytes(data)
        if vzflag:
            parsed=p.vz_reader.parse(after);assert oldparsed['words']==parsed['words'] and oldparsed['nlists']==parsed['nlists']
            actualrows=parsed['imports']
        else:
            assert list(chain_entries(before))==list(chain_entries(after));actualrows=imports(after)['imports']
        desired={r['index']:r['newOrdinal']for r in selected}
        for a,b in zip(rows,actualrows,strict=True):
            expected={**a,'ordinal':desired.get(a['index'],a['ordinal'])};assert b==expected
        for g in segments(before):
            for s in g['sections']:
                if not s['fileoff']or s['flags']&255 in(1,12):continue
                assert before[s['fileoff']:s['fileoff']+s['size']]==after[s['fileoff']:s['fileoff']+s['size']],(name,s['name'])
        target=out/(name+'27.real-array-reexports.mac.inert.macho-data');target.write_bytes(after)
        r=subprocess.run(['xcrun','dyld_info','-validate_only',str(target)],capture_output=True,text=True);assert r.returncode==0,r.stderr
        results.append(dict(name=name,source=source,candidate=p.pin(target),arrayImportRoutes=selected,
            allInstructionMetadataWitnessPACBytesPreserved=True,dyldValidationExit=r.returncode))
    result=dict(schema='Real array specialization strong reexports through genuine UH inert v1',
        nativeProviderDependencyAudit=p.pin(auditpath),originalCallerABIAudit=p.pin(abi),sourceUH=p.pin(UH),sourceKit=p.pin(KIT),sourceFrontend=p.pin(FRONTEND),
        unchangedRuntimeProviders=runtime,images=results,exactArrayStrongImportsRouted=24,
        genuineOriginalProviderMetadataWitnessCodePreservedFromSources=True,privateActualReexports=True,
        conformanceMetadataAdapted=True,completeOriginal27MetadataPreserved=False,
        stockTransitiveClosureProven=False,fullMetadataSchema=False,allCurrentProvidersDeclared=False,
        nativeExecuted=False,codeSigned=False,deviceOperations=0,originalVZLoaded=False,originalVMMExecuted=False,full27Backend=False)
    p.save(out/'candidate.json',result)
    files=[Path(__file__),UH,KIT,FRONTEND,RESERVE,auditpath,abi,out/'candidate.json']
    files += [Path(r[k]['path'])for r in results for k in('source','candidate')]
    files += [Path(r[k]['path'])for r in runtime for k in('source','candidate')]
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),routedStrongImports=24)))


if __name__=='__main__':main()
