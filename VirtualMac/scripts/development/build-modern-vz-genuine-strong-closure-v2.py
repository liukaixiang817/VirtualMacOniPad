#!/usr/bin/env python3
"""Restore 165 native-evidenced original VZ cache owner requirements locally.

Frozen v1 and all earlier inputs remain unchanged. No dlopen, deployment, API,
VM or GPU operation occurs. The six failed cache imports remain diagnostic
flat/weak and --require-complete exits 78 without a new VZ binary. A new exact
SkyLight owner dependency is explicit, and remains unavailable on the iPad.
"""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE=N/'vz-genuine-strong-closure-design-v1'
OWNER=N/'vz-cache-only-owner-oracle-v1'
READER=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py'
EXPECTED_REVIEW='d0a036c8117226d266c0ad71161f5c65688471f5873e9fbd0b1c736b8d00863d'
EXPECTED_OWNER_FREEZE='1a3d25e7703534b9c06752463b01085f557de69af4271dd288e71aedd7e17a38'


def pin(p):
    assert p.is_file() and not p.is_symlink()
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def dependencies(reader,b):
    rows=[]
    for cmd,at,size in reader.commands(b):
        if cmd in (12,0x80000018,0x8000001f,0x80000023):
            no=struct.unpack_from('<I',b,at+8)[0]
            rows.append(dict(ordinal=len(rows)+1,command=cmd,fileoff=at,bytes=size,path=reader.cstring(b,at+no,at+size)))
    return rows


def add_owner(reader,b,path):
    old=dependencies(reader,b);assert len(old)==52 and all(d['path']!=path for d in old)
    count,size=struct.unpack_from('<II',b,16);at=32+size
    first=min(sec['fileoff'] for seg in reader.segments(b) for sec in seg['sections'] if sec['fileoff'] and sec['size'] and sec['flags']&255 not in (1,12,18))
    encoded=path.encode()+b'\0';command_size=(24+len(encoded)+7)&~7
    assert at+command_size<=first and not any(b[at:at+command_size]),'no unused header capacity'
    record=struct.pack('<6I',12,command_size,24,0,0,0)+encoded
    b[at:at+command_size]=record+bytes(command_size-len(record))
    struct.pack_into('<II',b,16,count+1,size+command_size)
    after=dependencies(reader,b)
    assert after[:52]==old and len(after)==53 and after[-1]['path']==path
    return dict(ordinal=53,path=path,command=12,fileoff=at,bytes=command_size,original52CommandsAndOrdinalsUnchanged=True,providerAvailableOnIPad=False,nativeOriginalOwnerOnly=True)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',required=True,type=pathlib.Path)
    ap.add_argument('--require-complete',action='store_true')
    args=ap.parse_args();out=args.output.resolve()
    assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    assert pin(OWNER/'review.json')['sha256']==EXPECTED_REVIEW
    assert pin(OWNER/'freeze.json')['sha256']==EXPECTED_OWNER_FREEZE
    freezes=[BASE/'freeze.json',OWNER/'freeze.json'];inputs=[pin(pathlib.Path(__file__).resolve())]
    for freeze in freezes:
        inputs.append(pin(freeze))
        for record in json.loads(freeze.read_text())['files']:
            p=pathlib.Path(record['path']);assert pin(p)==record;inputs.append(record)
    inputs=list({p['path']:p for p in inputs}.values())
    spec=importlib.util.spec_from_file_location('pinned_reader',READER)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    report=json.loads((OWNER/'review.json').read_text())
    assert report['nativePID']==4883 and report['nativeWait']==0 and report['sourceReadChecks']==3330
    assert report['exactCacheExportAndNativeDlsymUnique']==165
    assert report['diagnosticFailureIndexes']==[14,15,20,22,40,490]
    assert report['originalWeakBitsRecovered'] is False and report['full27'] is False
    original=BASE/'build-v1/bundle/VZ27.original-imports-partial.ios.dylib'
    assert pin(original)['sha256']=='6f8054ba21bb74bcbd904d37d7658d5104f9e070bc6adf956a9db9d1049c943d'
    old=original.read_bytes();b=bytearray(old)
    before_imports=reader.imports(old)['imports'];assert len(before_imports)==1056
    before_chains=list(reader.chain_entries(old))
    changes=[]
    for row in report['restoredCacheImports']:
        entry=before_imports[row['index']]
        assert entry['name']==row['symbol'] and entry['ordinal']==-2 and entry['weak']
        assert row['nativeSourceProof'] is True and row['nativeDlsymExactTarget'] is True
        ordinal=row['ownerOrdinal'];assert type(ordinal) is int and 1<=ordinal<=53
        word=struct.unpack_from('<I',b,entry['command'])[0]
        after=word & ~0x1ff | ordinal
        struct.pack_into('<I',b,entry['command'],after)
        changes.append(dict(index=row['index'],symbol=entry['name'],ordinal=ordinal,originalTarget=row['target'],physicalOwner=row['physicalOwner'],originalRoute=row['originalRoute'],newDirectOwnerDependency=row['newDirectOwnerDependency'],fileoff=entry['command'],beforeWord=word,afterWord=after,originalWeakBitKnown=False,applicationRequirement='strong exact nonnull original owner required; no historic weak-bit claim'))
    assert len(changes)==165
    added=add_owner(reader,b,report['newExactOwnerDependency']['path'])
    after_imports=reader.imports(b)['imports']
    unknown=[x for x in after_imports if x['ordinal']==-2]
    assert sorted(x['index'] for x in unknown)==[14,15,20,22,40,490] and all(x['weak'] for x in unknown)
    assert sum(not x['weak'] for x in after_imports)==1006 and sum(x['weak'] and x['ordinal']>0 for x in after_imports)==44
    unchanged_names=all(a['name']==z['name'] for a,z in zip(before_imports,after_imports));assert unchanged_names
    assert [(s['fileoff'],s['word']) for s in before_chains]==[(s['fileoff'],s['word']) for s in reader.chain_entries(b)]
    ledger=dict(originalNlistRowsRestoredInFrozenV1=839,cacheRowsRestoredFromExactNativeOwner=changes,newExactOwnerDependency=added,diagnosticFlatImportsUnresolved=unknown,originalLegitimateWeakImportsPreserved=44,ownerEvidence=pin(OWNER/'review.json'),nativeOwnerEvidenceOnly=True,actualRelocatedVZCalls=0,relocatedVZLoaded=False,originalVMMExecuted=False,guestInstructions=0,completeStrongVZClosure=False,full27=False)
    save(out/'import-ledger.json',ledger);save(out/'inputs.json',inputs)
    if args.require_complete:
        save(out/'blocked.json',dict(reason='six exact unresolved cache import gates plus iPad SkyLight/provider closure remain',indexes=[14,15,20,22,40,490],diagnosticFlatImportsRemaining=6,binaryEmitted=False,deviceOperations=0,full27=False))
        return 78
    bundle=out/'bundle';bundle.mkdir();staged=[]
    for source in sorted((BASE/'build-v1/bundle').glob('*.dylib')):
        if source==original:continue
        destination=bundle/source.name;shutil.copy2(source,destination);assert pin(destination)['sha256']==pin(source)['sha256'];staged.append(pin(destination))
    binary=bundle/'VZ27.exact-owner-partial.ios.dylib';binary.write_bytes(b)
    processes=[]
    for label,argv in [('sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)]),('strict',['codesign','--verify','--strict',str(binary)]),('dyld',['xcrun','dyld_info','-validate_only',str(binary)]),('identity',['codesign','-d','--verbose=4',str(binary)])]:
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE);so,se=p.communicate(timeout=30)
        (out/(label+'.stdout')).write_bytes(so);(out/(label+'.stderr')).write_bytes(se)
        processes.append(dict(label=label,pid=p.pid,wait=p.returncode,command=argv));save(out/'processes.json',processes);assert p.returncode==0,se.decode()
    final=binary.read_bytes();fi=reader.imports(final)['imports'];assert fi==reader.imports(b)['imports']
    assert [(s['fileoff'],s['word']) for s in before_chains]==[(s['fileoff'],s['word']) for s in reader.chain_entries(final)]
    finaldeps=dependencies(reader,final);assert len(finaldeps)==53 and finaldeps[:52]==dependencies(reader,old)
    sections=[]
    for seg in reader.segments(old):
        for sec in seg['sections']:
            off,size=sec['fileoff'],sec['size']
            if size and off and sec['flags']&255 not in (1,12,18):
                assert old[off:off+size]==final[off:off+size]
                sections.append(dict(segment=seg['name'],section=sec['name'],fileoff=off,bytes=size,sha256=hashlib.sha256(final[off:off+size]).hexdigest()))
    assert len(sections)==46
    for record in inputs:assert pin(pathlib.Path(record['path']))==record
    candidate=dict(scope='new-local-exact-owner-partial-six-failure-gates-preserved',binary=pin(binary),stagedPrivateLibraries=staged,originalVZUUID=report['originalVZUUID'],originalNlistRowsRestored=839,cacheRowsRestoredFromExactNativeOwner=165,chainedImportRows=1056,strongImportRows=1006,originalLegitimateWeakRows=44,diagnosticFlatImportsRemaining=6,diagnosticFailureIndexes=[14,15,20,22,40,490],ownerEvidence=pin(OWNER/'review.json'),newExactOwnerDependency=added,original52DependenciesAndAllExistingOrdinalsUnchanged=True,originalWeakBitsOfCacheRowsRecovered=False,allChainWordsAndPACUnchanged=True,seventeenOriginalDA7d4cRequirementsPreserved=True,allNonemptyFileBackedSectionsUnchanged=sections,allOriginalInstructionAndRelativeMetadataBytesUnchanged=True,privateDIKitOriginalLoadProvenAtPID=47088,privateDIKitFunctionalAPIsNotInferred=True,compiledAndSignedOnly=True,nativeLoaded=False,functionCallsAllowed=False,completeStrongVZClosure=False,completeMacOS27Backend=False,originalVMMExecuted=False,guestInstructions=0,deviceOperations=False,systemModified=False)
    save(out/'candidate.json',candidate)
    print(json.dumps(dict(binary=str(binary),strongImportRows=1006,diagnosticFlatImportsRemaining=6,exactNativeOwnerRows=165,full27=False)))
    return 0


if __name__=='__main__':raise SystemExit(main())
