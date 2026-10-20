#!/usr/bin/env python3
"""Build a bounded, read-only native Mac oracle for original VZ cache imports.

Only parses immutable Mach-O/cache bytes. Does not load an image, execute a VZ
API, alter a cache, deploy to iPad, or change any frozen candidate. Generated
collector may dlopen only the UUID-pinned stock Mac framework and read proven
original fixup locations/targets. It never uses a nearest symbol as ownership.
"""
import argparse
import ast
import collections
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
D = R / "DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler"
CACHE = pathlib.Path("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e")
RAW = D / "virtualization27-stack-audit-v1/raw/Virtualization"
SAVED = D / "virtualization27-stack-audit-v1/Virtualization-symbols.a2s.batch.json"
LEDGER = N / "vz-genuine-strong-closure-design-v1/build-v1/import-ledger.json"
UUID = "418efc4809d93606918eb6f95baeffdc"
CACHE_UUID = "c284a291b68b3d0da1a03f866f87efdc"
VZ_PATH = "/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization"


def pin(path):
    b = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def exports(blob):
    """Read exact trie terminal, including reexports/resolvers; never nearest."""
    def uleb(at):
        value, shift = 0, 0
        while True:
            assert at < len(blob) and shift <= 63
            b = blob[at]; at += 1; value |= (b & 127) << shift
            if not b & 128:
                return value, at
            shift += 7
    stack, seen, rows = [(0, "")], set(), {}
    while stack:
        at, name = stack.pop()
        assert at not in seen and at < len(blob)
        seen.add(at)
        size, body = uleb(at); end = body + size
        assert end < len(blob)
        if size:
            flags, cursor = uleb(body); value, cursor = uleb(cursor)
            row = dict(flags=flags, rawValue=value)
            if flags & 8:
                stop = blob.find(b"\0", cursor, end)
                assert stop >= cursor
                row.update(reexportOrdinal=value, importName=blob[cursor:stop].decode())
            elif flags & 16:
                row['resolver'], cursor = uleb(cursor)
            rows[name] = row
        count = blob[end]; cursor = end + 1
        for _ in range(count):
            stop = blob.find(b"\0", cursor)
            assert stop >= cursor
            edge = blob[cursor:stop].decode(); target, cursor = uleb(stop + 1)
            stack.append((target, name + edge))
        assert len(seen) < 1000000
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    args = ap.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    out.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location('vz_original_reader', D / 'compiler_image.py')
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    from DyldExtractor.dyld.dyld_context import DyldContext
    from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info, dyld_cache_slide_info5
    from DyldExtractor.converter.slide_info import decodeV5Pointer
    raw = RAW.read_bytes()
    assert pin(RAW)['sha256'] == 'ec4bbc11af44a0c04a56269397274c90265a51568fe50e4e94123dd5eaa82f04'
    raw_uuid = [raw[a+8:a+24].hex() for c,a,s in reader.commands(raw) if c == 27]
    assert raw_uuid == [UUID]
    original_segments = reader.segments(raw)
    in_vz = lambda va: any(s['address'] <= va < s['address'] + s['size'] for s in original_segments)
    saved = json.loads(SAVED.read_text()); assert saved['uuid'] == CACHE_UUID
    symbols = saved['symbols']
    unresolved = json.loads(LEDGER.read_text())['diagnosticFlatImportsUnresolved']
    assert len(unresolved) == 171
    desired = {r['symbol'] for r in unresolved}

    # Replay only the pinned read-only reference scanner. Its symbol lookup uses
    # the saved batch; no subprocess, cache-writing a2s, or reconstructor runs.
    scanner = D / 'generated-collect-got.py'
    namespace = {'struct': struct}
    namespace['parse_segments'] = lambda b: ([(s['name'],s['address'],s['size'],s['fileoff'],s['filesize'],s['command']) for s in reader.segments(b)],None,None)
    namespace['a2s_batch'] = lambda aa: {a: tuple(symbols.get(hex(a),(None,None))) for a in aa}
    tree = ast.parse(scanner.read_text()); assert len(tree.body) == 1 and isinstance(tree.body[0],ast.FunctionDef)
    exec(compile(tree,str(scanner),'exec'),namespace)
    got_refs = namespace['collect_got_refs'](raw,str(CACHE))

    with CACHE.open('rb') as main_file:
        context = DyldContext(main_file)
        assert bytes(context.header.uuid).hex() == CACHE_UUID
        subs = context.addSubCaches(CACHE)
        owners = {id(context):str(CACHE)}
        for sub,f in zip(context._subCaches,subs): owners[id(sub)] = str(pathlib.Path(f.name).resolve())
        cache_pins = []
        for file_name,owner in sorted({owners[id(o)]:o for _,o in context.mappings}.items()):
            st = pathlib.Path(file_name).stat()
            cache_pins.append(dict(path=file_name,bytes=st.st_size,mtime_ns=st.st_mtime_ns,uuid=bytes(owner.header.uuid).hex()))
        decoded, original_fixups = {}, []

        def walk(mapping,owner,page):
            mi = owner.mappings.index((mapping,owner))
            ext = dyld_cache_mapping_and_slide_info(owner.file,owner.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
            if not ext.slideInfoFileOffset: return []
            si = dyld_cache_slide_info5(owner.file,ext.slideInfoFileOffset)
            assert si.version == 5 and si.page_size in (4096,16384)
            start = owner.readFormat('<H',ext.slideInfoFileOffset+len(si)+2*page)[0]
            if start == 0xffff: return []
            pageoff = ext.fileOffset+page*si.page_size; cursor=pageoff+start; rows=[]
            while True:
                assert pageoff <= cursor <= pageoff+si.page_size-8 and (cursor-pageoff)%8==0
                word = owner.readFormat('<Q',cursor)[0]
                target,auth,key,div,ad,delta = decodeV5Pointer(word,si.value_add)
                va=ext.address+cursor-ext.fileOffset
                row=dict(slot=va,target=target & 0x00ffffffffffffff,rawWord=hex(word),auth=auth,key=key,diversity=div,addressDiversity=ad,cacheFile=owners[id(owner)],cacheUUID=bytes(owner.header.uuid).hex(),cacheFileOffset=cursor,slideInfoVersion=5,chainMembershipVerified=True)
                decoded[va]=row;rows.append(row)
                assert len(rows)<=si.page_size//8
                if not delta:break
                cursor+=delta
            return rows

        pages=set()
        for mapping,owner in context.mappings:
            for seg in original_segments:
                lo=max(mapping.address,seg['address']);hi=min(mapping.address+mapping.size,seg['address']+seg['size'])
                if lo>=hi:continue
                mi=owner.mappings.index((mapping,owner))
                ext=dyld_cache_mapping_and_slide_info(owner.file,owner.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
                if not ext.slideInfoFileOffset:continue
                si=dyld_cache_slide_info5(owner.file,ext.slideInfoFileOffset)
                assert si.version==5
                for page in range((lo-mapping.address)//si.page_size,(hi-1-mapping.address)//si.page_size+1):
                    k=(id(owner),mi,page)
                    if k not in pages:
                        pages.add(k)
                        original_fixups += [r for r in walk(mapping,owner,page) if in_vz(r['slot'])]
        for va in got_refs:
            mapping,owner=next((m,o) for m,o in context.mappings if m.address<=va<m.address+m.size)
            mi=owner.mappings.index((mapping,owner))
            ext=dyld_cache_mapping_and_slide_info(owner.file,owner.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
            si=dyld_cache_slide_info5(owner.file,ext.slideInfoFileOffset)
            if va not in decoded:walk(mapping,owner,(va-mapping.address)//si.page_size)
            assert va in decoded,'external reference must be a genuine chain slot'

        # Original cache headers/segments and export bytes supply physical owner
        # and a *direct exact* export. Reexport ordinals are never RVA targets.
        images=[]
        for image in context.images:
            path=context.readString(image.pathFileOffset).rstrip(b'\0').decode()
            off,owner=context.convertAddr(image.address)
            head=owner.getBytes(off,32)
            assert struct.unpack_from('<I',head)[0]==0xfeedfacf
            size=struct.unpack_from('<I',head,20)[0];assert size<0x100000
            header=owner.getBytes(off,32+size)
            commands=list(reader.commands(header));segs=reader.segments(header)
            uuids=[header[a+8:a+24].hex() for c,a,s in commands if c==27];assert len(uuids)==1
            deps=[];dep_kinds=[];export_command=[]
            for c,a,s in commands:
                if c in (12,0x80000018,0x8000001f,0x80000023):
                    no=struct.unpack_from('<I',header,a+8)[0];deps.append(reader.cstring(header,a+no,a+s));dep_kinds.append(c)
                if c==0x80000033:export_command.append(struct.unpack_from('<II',header,a+8))
            images.append(dict(path=path,uuid=uuids[0],base=image.address,segments=[dict(name=s['name'],va=s['address'],size=s['size']) for s in segs],dependencies=deps,dependencyKinds=dep_kinds,_exportCommand=export_command,_linkedit=next((s for s in segs if s['name']=='__LINKEDIT'),None)))
        vz=[x for x in images if x['path']==VZ_PATH];assert len(vz)==1 and vz[0]['uuid']==UUID
        target_proofs=collections.defaultdict(list)
        for fixup in original_fixups:
            target_proofs[fixup['target']].append(dict(kind='originalVZSlideInfo5Member',**fixup))
        for va,(name,auth_hint) in got_refs.items():
            target_proofs[decoded[va]['target']].append(dict(kind='originalVZCodeExternalGOTReference',scannerAuthHint=auth_hint,savedSlotLabel=name,**decoded[va]))
        for seg in original_segments:
            for section in seg['sections']:
                if seg['name'] != '__TEXT' or section['name'] != '__text':continue
                for delta in range(0,section['size'],4):
                    word=struct.unpack_from('<I',raw,section['fileoff']+delta)[0]
                    if word & 0x7c000000 != 0x14000000:continue
                    imm=word & 0x03ffffff
                    if imm & 0x02000000:imm-=0x04000000
                    pc=section['address']+delta;target=pc+imm*4
                    if not in_vz(target):
                        target_proofs[target].append(dict(kind='originalVZExternalBranchInstruction',originalInstructionPC=pc,rawInstructionWord=hex(word),branchTarget=target))
        bypath={im['path']:im for im in images}

        def exact_exports(im):
            if '_exports' not in im:
                ec=im['_exportCommand'];assert len(ec)<=1
                if ec:
                    le=im['_linkedit'];assert le is not None
                    _,owner=context.convertAddr(le['address'])
                    pos,sz=ec[0];assert sz<0x1000000 and pos+sz<=len(owner.file)
                    im['_exports']=exports(owner.getBytes(pos,sz))
                else:im['_exports']={}
            return im['_exports']

        rows=[]
        def owner_routes(owner_path):
            routes=[]
            def visit(path,seen):
                if path==owner_path:return [dict(path=path,uuid=bypath[path]['uuid'],kind='exactPhysicalOwner')]
                if path in seen or path not in bypath or len(seen)>32:return None
                im=bypath[path]
                for dep,kind in zip(im['dependencies'],im['dependencyKinds']):
                    if kind!=0x8000001f:continue
                    rest=visit(dep,seen|{path})
                    if rest:return [dict(path=path,uuid=im['uuid'],kind='originalLC_REEXPORT_DYLIB',next=dep)]+rest
                return None
            for ordinal,path in enumerate(vz[0]['dependencies'],1):
                route=visit(path,set())
                if route:routes.append(dict(ordinal=ordinal,path=path,originalVZDependencyKind=vz[0]['dependencyKinds'][ordinal-1],route=route))
            return routes
        def follow_exact_stub(target):
            steps=[];seen=set()
            def read_slot(slot):
                if slot not in decoded:
                    mm,oo=next((m,o) for m,o in context.mappings if m.address<=slot<m.address+m.size)
                    mi=oo.mappings.index((mm,oo));ext=dyld_cache_mapping_and_slide_info(oo.file,oo.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
                    si=dyld_cache_slide_info5(oo.file,ext.slideInfoFileOffset)
                    walk(mm,oo,(slot-mm.address)//si.page_size)
                assert slot in decoded
                return decoded[slot]['target']
            while len(steps)<8:
                assert target not in seen,'cyclic cache stub'
                seen.add(target)
                cv=context.convertAddr(target)
                if cv is None:break
                off,co=cv
                words=co.readFormat('<IIII',off)
                adrp,consumer,branch,trap=words
                ordinary=adrp & 0x9f00001f == 0x90000010 and branch in (0xd61f0200,0xd61f0a1f)
                auth_stub=adrp & 0x9f00001f == 0x90000011 and consumer & 0xffc003ff == 0x91000231 and branch==0xf9400230 and trap==0xd71f0a11
                if not ordinary and not auth_stub:break
                imm=(((adrp>>5)&0x7ffff)<<2 | (adrp>>29)&3)<<12
                if imm & (1<<32):imm-=1<<33
                page=(target & ~0xfff)+imm
                if auth_stub:
                    slot=page+((consumer>>10)&0xfff)
                    final=read_slot(slot);kind='exactADRP_ADD_LDR_BRAA_X16_X17_chainSlot'
                elif consumer & 0xffc003ff == 0x91000210:
                    final=page+((consumer>>10)&0xfff)
                    kind='exactADRP_ADD_BR_X16'
                    # Optional trap is recorded, never relied on for target math.
                    slot=0
                elif consumer & 0xffc003ff == 0xf9400210:
                    slot=page+((consumer>>10)&0xfff)*8
                    final=read_slot(slot);kind='exactADRP_LDR_BRAAZ_X16_chainSlot' if branch==0xd61f0a1f else 'exactADRP_LDR_BR_X16_chainSlot'
                else:break
                steps.append(dict(stubVA=target,instructionWords=[hex(w) for w in words],kind=kind,slot=slot,target=final,slotContract=decoded.get(slot),cacheFile=owners[id(co)],cacheUUID=bytes(co.header.uuid).hex(),cacheFileOffset=off))
                target=final
            assert len(steps)<8,'stub chain limit'
            return target,steps
        for import_row in unresolved:
            name=import_row['symbol'];candidates=[]
            for target,proofs in target_proofs.items():
                entry=symbols.get(hex(target))
                label=entry[0] if entry else None
                named=(label is not None and label.removeprefix('__got.').removeprefix('_ptr.')==name)
                if not named:
                    named=any(p['kind']=='originalVZCodeExternalGOTReference' and p['savedSlotLabel'].removeprefix('__got.').removeprefix('_ptr.')==name for p in proofs)
                if not named:continue
                source_target=target
                target,stub_steps=follow_exact_stub(target)
                physical=[im for im in images if any(s['va']<=target<s['va']+s['size'] for s in im['segments'])]
                assert len(physical)<=1,'ambiguous original target owner'
                owner=physical[0] if physical else None;export=None;resolver_export=None
                if owner:
                    ex=exact_exports(owner).get(name)
                    if ex and not ex['flags']&8 and ex['flags']&3!=2:
                        if owner['base']+ex['rawValue']==target or ex['flags']&16 and owner['base']+ex['resolver']==target:export=ex
                        if ex['flags']&16 and any(step['stubVA'] in (owner['base']+ex['rawValue'],owner['base']+ex['resolver']) for step in stub_steps):resolver_export=ex
                candidates.append(dict(target=target,sourceTarget=source_target,exactStubChain=stub_steps,proofs=proofs,physicalOwner=dict(path=owner['path'],uuid=owner['uuid'],base=owner['base']) if owner else None,originalDependencyOwnerRoutes=owner_routes(owner['path']) if owner else [],directExactExport=export,exactExportResolverChain=resolver_export,savedTargetRecord=entry))
            rows.append(dict(**import_row,candidates=candidates,originalWeakBitKnown=False))
        images_saved=[{k:v for k,v in im.items() if not k.startswith('_')} for im in images if im['path']==VZ_PATH or any(c['physicalOwner'] and c['physicalOwner']['path']==im['path'] for row in rows for c in row['candidates'])]
        for f in subs:f.close()
    for cp in cache_pins:
        st=pathlib.Path(cp['path']).stat();assert st.st_size==cp['bytes'] and st.st_mtime_ns==cp['mtime_ns']
    result=dict(originalVZPath=VZ_PATH,originalVZUUID=UUID,mainCacheUUID=CACHE_UUID,imports=rows,cacheInputs=cache_pins,originalFixups=len(original_fixups),originalCodeExternalSlots=len(got_refs),exactOriginalProofRows=sum(bool(r['candidates']) for r in rows),directExactExportRows=sum(any(c['directExactExport'] is not None for c in r['candidates']) for r in rows),exactExportResolverChainRows=sum(any(c['exactExportResolverChain'] is not None for c in r['candidates']) for r in rows),images=images_saved,libraryLoaded=False,cacheModified=False,deviceOperations=0,originalVMMExecuted=False,actualVZCalls=0,guestInstructions=0,completeStrongVZClosure=False)
    save(out/'offline-oracle.json',result)
    save(out/'inputs.json',[pin(p) for p in (RAW,SAVED,LEDGER,scanner,D/'compiler_image.py',pathlib.Path(__file__).resolve())])
    print(json.dumps({k:result[k] for k in ('originalFixups','originalCodeExternalSlots','exactOriginalProofRows','directExactExportRows','libraryLoaded')}))


if __name__=='__main__':
    main()
