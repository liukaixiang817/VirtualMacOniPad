#!/usr/bin/env python3
"""Audit true original VZ consumers of six imports; never load/call/deploy.

Uses only the six real payload segments in the original cache image header.
DyldExtractor's synthetic EXTRA_OBJC address range is not original ownership.
Every cache-only import must retain a real original VZ consumer proof.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
OWNER=N/'vz-cache-only-owner-oracle-v1'
CACHE=pathlib.Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')
SOURCE=N/'vz-genuine-strong-closure-design-v2/build-v1/bundle/VZ27.exact-owner-partial.ios.dylib'
VTABLES={14:'__ZTVN10__cxxabiv120__si_class_type_infoE',15:'__ZTVN10__cxxabiv117__class_type_infoE',20:'__ZTVN10__cxxabiv121__vmi_class_type_infoE',22:'__ZTVN10__cxxabiv123__fundamental_type_infoE'}


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    spec=importlib.util.spec_from_file_location('original_reader',D/'compiler_image.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    spec=importlib.util.spec_from_file_location('pinned_export_reader',R/'VirtualMac/scripts/development/prepare-modern-vz-cache-owner-oracle.py');er=importlib.util.module_from_spec(spec);spec.loader.exec_module(er)
    from DyldExtractor.dyld.dyld_context import DyldContext
    from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info,dyld_cache_slide_info5
    from DyldExtractor.converter.slide_info import decodeV5Pointer
    b=SOURCE.read_bytes();assert pin(SOURCE)['sha256']=='fbb3031b8ea906953705eedad1d294e51e611c3cddad4b6fdc50b6bcf00eb8c5'
    old_oracle=json.loads((OWNER/'offline-v3/offline-oracle.json').read_text())
    latest=json.loads((OWNER/'offline-v5/offline-oracle.json').read_text())
    saved=json.loads((D/'virtualization27-stack-audit-v1/Virtualization-symbols.a2s.batch.json').read_text())['symbols']
    raw=(D/'virtualization27-stack-audit-v1/raw/Virtualization').read_bytes()
    layout=json.loads((D/'virtualization27-stack-audit-v1/reconstructed-macos/Virtualization.layout.json').read_text())
    deltas=[[int(v,16) for v in row] for row in layout['deltas']]
    chains=list(reader.chain_entries(b));true_imports=[];rtti=[];empty=[];resolver=None;cache_inputs=[]
    with CACHE.open('rb') as f:
        context=DyldContext(f);assert bytes(context.header.uuid).hex()==old_oracle['mainCacheUUID'];subs=context.addSubCaches(CACHE)
        files={id(context):str(CACHE)}
        for co,cf in zip(context._subCaches,subs):files[id(co)]=str(pathlib.Path(cf.name).resolve())
        def read(va,n):
            cv=context.convertAddr(va);assert cv is not None
            off,co=cv;assert n<=4096 and off+n<=len(co.file)
            return co.getBytes(off,n)
        def header(va):
            initial=read(va,32);size=struct.unpack_from('<I',initial,20)[0];assert size<0x100000
            off,co=context.convertAddr(va);h=co.getBytes(off,32+size)
            uuid=[h[a+8:a+24].hex() for c,a,s in reader.commands(h) if c==27];assert len(uuid)==1
            return h,uuid[0]
        hz,uz=header(0x225f36000);assert uz=='418efc4809d93606918eb6f95baeffdc'
        true_segments=[s for s in reader.segments(hz) if s['name']!='__LINKEDIT'];assert len(true_segments)==6
        assert all(s['name']!='__EXTRA_OBJC' for s in true_segments)
        owned=lambda va:any(s['address']<=va<s['address']+s['size'] for s in true_segments)
        own_sections=[(s['name'],q) for s in true_segments for q in s['sections']]
        def new_address(old):
            matches=[old+d for lo,hi,d in deltas if lo<=old<hi];assert len(matches)==1
            return matches[0]
        def decode_slot(va):
            mm,co=next((m,o) for m,o in context.mappings if m.address<=va<m.address+m.size)
            mi=co.mappings.index((mm,co));ext=dyld_cache_mapping_and_slide_info(co.file,co.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
            si=dyld_cache_slide_info5(co.file,ext.slideInfoFileOffset);assert si.version==5
            page=(va-ext.address)//si.page_size;start=co.readFormat('<H',ext.slideInfoFileOffset+len(si)+page*2)[0];assert start!=65535
            pageoff=ext.fileOffset+page*si.page_size;cursor=pageoff+start;wanted=ext.fileOffset+va-ext.address;steps=0
            while True:
                assert pageoff<=cursor<=pageoff+si.page_size-8
                word=co.readFormat('<Q',cursor)[0];t,auth,key,div,ad,delta=decodeV5Pointer(word,si.value_add);steps+=1;assert steps<=si.page_size//8
                if cursor==wanted:break
                assert delta and cursor<wanted;cursor+=delta
            return dict(slot=va,target=t&0x00ffffffffffffff,auth=auth,key=key,diversity=div,addressDiversity=ad,word=word,chainMembershipVerified=True,cacheFile=files[id(co)],cacheUUID=bytes(co.header.uuid).hex(),cacheOffset=cursor)
        cppbase=next(c['physicalOwner']['base'] for row in old_oracle['imports'] for c in row['candidates'] if row['index']==14)
        hc,uc=header(cppbase);assert uc=='a21743ee6e1c3e7497ea7af793de4bdf'
        le=next(s for s in reader.segments(hc) if s['name']=='__LINKEDIT');_,lc=context.convertAddr(le['address'])
        ec=next(struct.unpack_from('<II',hc,a+8) for c,a,s in reader.commands(hc) if c==0x80000033)
        cache_exports=er.exports(lc.getBytes(*ec))

        # Independently record the original code PCs for the legacy GOT scan.
        scanner=D/'generated-collect-got.py';text=scanner.read_text()
        old='if not inimg(tt): targets[tt] = is_add'
        assert text.count(old)==1
        text=text.replace(old,'if not inimg(tt):\n                            targets[tt] = is_add\n                            source_pcs.setdefault(tt, []).append(ins.address)')
        tree=ast.parse(text);assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef)
        ns={'struct':struct,'source_pcs':{},'parse_segments':lambda z:([(s['name'],s['address'],s['size'],s['fileoff'],s['filesize'],s['command']) for s in reader.segments(z)],None,None),'a2s_batch':lambda aa:{a:tuple(saved.get(hex(a),(None,None))) for a in aa}}
        exec(compile(tree,str(scanner),'exec'),ns);ns['collect_got_refs'](raw,str(CACHE))
        got_sources=ns['source_pcs']
        def raw_word(pc):
            matches=[s for s in reader.segments(raw) if s['address']<=pc<=s['address']+s['filesize']-4];assert len(matches)==1
            s=matches[0];return struct.unpack_from('<I',raw,s['fileoff']+pc-s['address'])[0]
        for row in old_oracle['imports']:
            candidates=[]
            for c in row['candidates']:
                proofs=[]
                for p in c['proofs']:
                    if p['kind']=='originalVZSlideInfo5Member' and owned(p['slot']):proofs.append(p)
                    elif p['kind']=='originalVZExternalBranchInstruction' and owned(p['originalInstructionPC']):
                        assert struct.unpack('<I',read(p['originalInstructionPC'],4))[0]==int(p['rawInstructionWord'],16);proofs.append(p)
                    elif p['kind']=='originalVZCodeExternalGOTReference':
                        pcs=[pc for pc in got_sources.get(p['slot'],[]) if owned(pc) and raw_word(pc)==struct.unpack('<I',read(pc,4))[0]]
                        assert pcs,'external GOT lacks a true original code consumer'
                        proofs.append(dict(**p,verifiedOriginalConsumerPCs=pcs))
                assert proofs,'cache-only import candidate needs at least one genuine original consumer'
                candidates.append(dict(target=c['target'],physicalOwner=c['physicalOwner'],proofs=proofs,excludedAdjacentOrSyntheticProofs=len(c['proofs'])-len(proofs)))
            true_imports.append(dict(index=row['index'],symbol=row['symbol'],candidates=candidates))
            if row['index'] in VTABLES:
                export=cache_exports[VTABLES[row['index']]];assert not export['flags']&8 and export['flags']&3==0
                start=cppbase+export['rawValue'];target=start+16
                assert all(c['target']==target for c in candidates)
                sites=[]
                for c in candidates:
                    for p in c['proofs']:
                        assert p['kind']=='originalVZSlideInfo5Member' and p['auth']==1 and p['key']==2 and p['diversity']==0 and p['addressDiversity']==0
                        va=new_address(p['slot']);entry=next(e for e in chains if e['address']==va)
                        assert entry['import_index']==row['index'] and entry['auth'] and entry['word']>>49&3==2 and entry['word']>>32&65535==0 and entry['word']>>48&1==0
                        name_pointer=decode_slot(p['slot']+8);assert not name_pointer['auth']
                        name=read(name_pointer['target'],512).split(b'\0')[0];assert name and len(name)<512
                        if row['index']==14:object_size=24
                        elif row['index']==15:object_size=16
                        elif row['index']==20:
                            flags,base_count=struct.unpack('<II',read(p['slot']+16,8));assert 1<=base_count<=64
                            object_size=24+16*base_count
                        else:object_size=16
                        sites.append(dict(originalVA=p['slot'],newVA=va,fileoff=entry['fileoff'],originalCacheVptrContract=p,newBindWord=entry['word'],typeName=name.decode(),namePointer=name_pointer,minimumObjectBytes=object_size,vmiBaseCount=base_count if row['index']==20 else None,vmiFlags=flags if row['index']==20 else None,consumerKind='ItaniumCxxTypeInfoVptr'))
                assert len(sites)==len(row['chainSites'])
                rtti.append(dict(index=row['index'],converterSymbol=row['symbol'],exactDataExport=VTABLES[row['index']],originalOwner='/usr/lib/libc++abi.dylib',originalOwnerUUID=uc,exportVA=start,addressPointVA=target,addend=16,authKey=2,discriminator=0,addressDiversity=0,sites=sites))
            if row['index']==40:
                assert read(candidates[0]['target'],1)==b'\0'
                for p in candidates[0]['proofs']:
                    assert p['kind']=='originalVZSlideInfo5Member' and p['auth']==0
                    va=new_address(p['slot']);entry=next(e for e in chains if e['address']==va)
                    assert entry['import_index']==40 and not entry['auth']
                    # objc_ivar_t: offset*, name*, type*, uint32 alignment,size.
                    alignment,size=struct.unpack('<II',read(p['slot']+8,8));assert alignment==3 and size==8
                    nameptr=decode_slot(p['slot']-8);name=read(nameptr['target'],512).split(b'\0')[0];assert name
                    empty.append(dict(originalVA=p['slot'],newVA=va,fileoff=entry['fileoff'],word=entry['word'],consumerKind='objc_ivar_t.typeEncoding',ivarName=name.decode(),alignmentExponent=alignment,ivarBytes=size,originalTarget=p['target'],originalFirstByte=0,PAC=False))
            if row['index']==490:
                newrow=next(rr for rr in latest['imports'] if rr['index']==490);cc=newrow['candidates'][0]
                assert cc['exactExportResolverChain'] is not None and cc['target']!=candidates[0]['target']
                resolver=dict(index=490,symbol=row['symbol'],ABI='int(const char*,const char*)',originalBranches=candidates[0]['proofs'],oldNativeComparedTarget=candidates[0]['target'],newOfflineDecodedTarget=cc['target'],newTargetPhysicalOwner=cc['physicalOwner'],exactStubChain=cc['exactStubChain'],exactExportResolverChain=cc['exactExportResolverChain'],newTargetNativeValidated=False,originalVZConsumerExecuted=False)
        for filename,co in sorted({files[id(co)]:co for _,co in context.mappings}.items()):
            st=pathlib.Path(filename).stat();cache_inputs.append(dict(path=filename,bytes=st.st_size,mtime_ns=st.st_mtime_ns,uuid=bytes(co.header.uuid).hex()))
        for sf in subs:sf.close()
    assert len(true_imports)==171 and sum(len(r['sites']) for r in rtti)==418 and len(empty)==5
    own=json.loads((OWNER/'review.json').read_text());assert own['exactCacheExportAndNativeDlsymUnique']==165
    actualindexes={r['index'] for r in own['restoredCacheImports']};assert len(actualindexes)==165 and actualindexes<={r['index'] for r in true_imports}
    result=dict(originalVZUUID=uz,originalVZPayloadSegments=true_segments,syntheticExtraObjcIsOriginalCacheOwner=False,all171HaveGenuineOriginalConsumer=True,native165OwnerTargetsRemainSupported=True,cacheOnlyImportsWithTrueConsumers=true_imports,rttiDataContracts=rtti,trueOriginalRTTIVptrConsumers=418,emptyStringContracts=empty,trueOriginalEmptyStringConsumers=5,legacyEmptyStringCount281IncludedAdjacentCacheObjects=True,strcmpResolverContract=resolver,legacyNative3330IsTotalReadChecksNotAllOriginalVZConsumers=True,cacheInputs=cache_inputs,originalConsumerExecutionProven=False,actualVZCalls=0,originalVMMExecuted=False,guestInstructions=0,full27=False,deviceOperations=0,systemModified=False)
    save(out/'contract.json',result)
    sources=[pathlib.Path(__file__).resolve(),SOURCE,OWNER/'offline-v3/offline-oracle.json',OWNER/'offline-v5/offline-oracle.json',OWNER/'review.json',D/'compiler_image.py',D/'generated-collect-got.py',D/'virtualization27-stack-audit-v1/raw/Virtualization',D/'virtualization27-stack-audit-v1/reconstructed-macos/Virtualization.layout.json',R/'VirtualMac/scripts/development/prepare-modern-diskimages2-rtti-data.py',R/'VirtualMac/vz/host/modern_runtime_compat.mm']
    save(out/'inputs.json',[pin(p) for p in sources]);print(json.dumps(dict(trueImports=171,actualNativeOwner165StillValid=True,RTTIConsumers=418,emptyStringConsumers=5,full27=False)))


if __name__=='__main__':main()
