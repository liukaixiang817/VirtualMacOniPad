#!/usr/bin/env python3
"""Wire genuine frontend XPC imports to the existing owned V10 provider, inert."""
import bisect
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('frontend_xpc_f',HERE/'audit-modern-genuine-hid-current-frontier-v19.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);p,s,n=f.p,f.s,f.NODE
from macho_chained_import_records_v1 import read as import_records
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
spec=importlib.util.spec_from_file_location('frontend_xpc_h',n/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
SELECTED={752:'_xpc_connection_create',762:'_xpc_connection_set_oneshot_instance',784:'_xpc_main'}
OLD_OWNER='@loader_path/VM27VMNetUnavailable.dylib';NEW_OWNER='@loader_path/XF'

def transformed(before):
    dep=p.dependencies(before)[28]
    assert dep['ordinal']==29 and dep['path']==OLD_OWNER and dep['command']==12 and dep['size']==64
    assert struct.unpack_from('<I',before,dep['at']+8)[0]==24
    schema=import_records(before,p.commands);assert len(schema['imports'])==1056
    result=bytearray(before);begin,end=dep['at']+24,dep['at']+dep['size']
    replacement=NEW_OWNER.encode()+b'\0';assert len(replacement)<=end-begin
    result[begin:end]=replacement+bytes(end-begin-len(replacement))
    for index,name in SELECTED.items():
        row=schema['imports'][index]
        assert row['name']==name and row['ordinal']==19 and not row['weak'] and row['addend']==0
        result[row['command']]=29
    return bytes(result)

def verify(before,after):
    assert after==transformed(before)
    a,b=p.vz_reader.parse(before),p.vz_reader.parse(after)
    assert a['words']==b['words'] and a['nlists']==b['nlists'] and a['segments']==b['segments'] and a['header']==b['header']
    old,new=import_records(before,p.commands),import_records(after,p.commands)
    assert len(old['imports'])==len(new['imports'])==1056
    assert sum(not row['weak']for row in new['imports'])==1011
    assert new==dict(old,imports=[dict(row,ordinal=29)if row['index']in SELECTED else row for row in old['imports']])
    assert p.dependencies(after)==[dict(row,path=NEW_OWNER)if row['ordinal']==29 else row for row in p.dependencies(before)]
    for seg in p.segments(before):
        for section in seg['sections']:
            if section['fileoff'] and section['size'] and section['flags']&255 not in (1,12,18):
                off,length=section['fileoff'],section['size'];assert before[off:off+length]==after[off:off+length]
    changes=[i for i,(x,y)in enumerate(zip(before,after))if x!=y]
    return dict(changedWholeFileBytes=len(changes),exactChangedOffsets=changes,
        onlyFixedDependencyNameStorageAndThreeOrdinalBytesChanged=True,totalImports=1056,strongImports=1011,
        chainedWholeWordCount=len(a['words']),allChainedWordsPACAndAddendsPreserved=True,
        allSectionsCodeSwiftObjCMetadataAndNlistsPreserved=True,totalDependencyOrdinals=len(a['deps']))

def original_callers(before,out):
    parsed=p.vz_reader.parse(before);base=parsed['segments'][0]['address']
    sections=[sec for seg in parsed['segments']for sec in seg['sections']]
    text=next(row for row in sections if row['name']=='__text');stub=next(row for row in sections if row['name']=='__auth_stubs')
    slots={seg['address']+row['at']-seg['fileoff']:row for seg in parsed['segments']for row in parsed['words']
        if row['bind'] and row['index']in SELECTED and seg['fileoff']<=row['at']<seg['fileoff']+seg['filebytes']}
    assert len(slots)==3
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM);decoder.detail=True;routes={}
    for off in range(stub['at'],stub['at']+stub['bytes'],16):
        va=stub['address']+off-stub['at'];instructions=list(decoder.disasm(before[off:off+12],va))
        if len(instructions)!=3 or [row.mnemonic for row in instructions]!=['adrp','add','ldr']:continue
        if instructions[0].op_str.split(',')[0]!='x16' or not instructions[1].op_str.startswith('x16, x16,') or instructions[2].op_str!='x17, [x16]':continue
        address=instructions[0].operands[1].imm+instructions[1].operands[2].imm
        if address not in slots:continue
        word=slots[address];assert word['auth'] and struct.unpack_from('<I',before,off+12)[0]==0xd71f0a30
        routes[va]=dict(importIndex=word['index'],name=SELECTED[word['index']],slot=address,wholeAuthenticatedWord=word['word'],stubBytes=before[off:off+16].hex())
    assert len(routes)==3
    calls=[]
    for off in range(text['at'],text['at']+text['bytes'],4):
        word=struct.unpack_from('<I',before,off)[0]
        if word&0xfc000000 not in (0x14000000,0x94000000):continue
        disp=word&0x3ffffff;disp=disp-(1<<26)if disp&(1<<25)else disp;target=base+off+disp*4
        if target in routes:calls.append(dict(rva=off,branchWord=hex(word),branchIsCall=word&0xfc000000==0x94000000,route=routes[target]))
    assert len(calls)==13 and sum(row['route']['importIndex']==752 for row in calls)==9
    assert sum(row['route']['importIndex']==762 for row in calls)==3 and sum(row['route']['importIndex']==784 for row in calls)==1
    reads=[];chains=[];functions={}
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc'
        subs=cache.addSubCaches(p.CACHE)
        try:
            genuine=p.GenuineCacheExports(cache);image=genuine.image('/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization')
            assert image['UUID']=='418efc4809d93606918eb6f95baeffdc'
            def read(address,length,label):
                assert 0<length<=2*1024*1024
                offset,owner=cache.convertAddr(address);data=owner.getBytes(offset,length);assert len(data)==length
                file=out/(str(len(reads)).zfill(3)+'-'+label+'.bin');file.write_bytes(data)
                reads.append(dict(address=address,bytes=length,physicalUUID=bytes(owner.header.uuid).hex(),offset=offset,data=p.pin(file)));return data
            def pointer(slot):
                raw=read(slot,8,'original-import-slot');word=struct.unpack('<Q',raw)[0]
                mapping,owner=next((m,o)for m,o in cache.mappings if m.address<=slot<m.address+m.size)
                ix=owner.mappings.index((mapping,owner));extent=h.dyld_cache_mapping_and_slide_info(owner.file,owner.header.mappingWithSlideOffset+ix*h.dyld_cache_mapping_and_slide_info.SIZE)
                slide=h.dyld_cache_slide_info5(owner.file,extent.slideInfoFileOffset);assert slide.version==5
                page=(slot-extent.address)//slide.page_size;start=owner.readFormat('<H',extent.slideInfoFileOffset+len(slide)+page*2)[0];assert start!=65535
                pageoff=extent.fileOffset+page*slide.page_size;cursor=pageoff+start;wanted=extent.fileOffset+slot-extent.address
                for count in range(slide.page_size//8):
                    assert pageoff<=cursor<=pageoff+slide.page_size-8
                    current=owner.readFormat('<Q',cursor)[0];target,auth,key,div,address,delta=h.decodeV5Pointer(current,slide.value_add)
                    if cursor==wanted:
                        assert current==word and auth
                        record=dict(slot=slot,wholeWord=word,target=target&0x00ffffffffffffff,auth=auth,key=key,diversity=div,addressDiversity=address,actualS5ChainMember=True)
                        chains.append(record);return record
                    assert delta and cursor<wanted;cursor+=delta
                raise AssertionError('original chain membership not found')
            header_prefix=read(image['base'],32,'original-prefix');length=32+struct.unpack_from('<I',header_prefix,20)[0]
            header=read(image['base'],length,'original-commands')
            link=next(row for row in p.segments(header)if row['name']=='__LINKEDIT')
            off,length=next(struct.unpack_from('<II',header,at+8)for cmd,at,size in p.commands(header)if cmd==0x26)
            index=read(link['address']+off-link['fileoff'],length,'original-function-starts')
            starts=[];at=0;address=image['base']
            while at<len(index):
                delta,at=h.uleb(index,at)
                if not delta:break
                address+=delta;starts.append(address)
            assert starts==sorted(set(starts))and not any(index[at:])
            original_routes={}
            for call in calls:
                pc=image['base']+call['rva'];position=bisect.bisect_right(starts,pc)-1
                begin,end=starts[position:position+2];assert begin<=pc<end and end-begin<=128*1024
                if begin not in functions:
                    body=read(begin,end-begin,'original-caller-body')
                    functions[begin]=dict(begin=begin,end=end,LC26Complete=True,data=reads[-1]['data'],instructions=h.decode_body(body,begin))
                body=Path(functions[begin]['data']['path']).read_bytes();word=struct.unpack_from('<I',body,pc-begin)[0]
                assert word&0xfc000000==int(call['branchWord'],16)&0xfc000000
                disp=word&0x3ffffff;disp=disp-(1<<26)if disp&(1<<25)else disp;target=pc+disp*4
                ix=call['route']['importIndex']
                if ix not in original_routes:
                    island=read(target,16,'original-xpc-island');ins=list(decoder.disasm(island[:12],target))
                    assert [row.mnemonic for row in ins]==['adrp','add','ldr']
                    assert ins[0].op_str.split(',')[0]=='x17'and ins[1].op_str.startswith('x17, x17,')and ins[2].op_str=='x16, [x17]'
                    slot=ins[0].operands[1].imm+ins[1].operands[2].imm;chain=pointer(slot)
                    definition=genuine.resolve('/usr/lib/libSystem.B.dylib',SELECTED[ix]);assert definition and chain['target']==definition['exportAddress']
                    original_routes[ix]=dict(importIndex=ix,name=SELECTED[ix],island=target,islandBytes=island.hex(),auth=chain,definition=definition)
                assert target==original_routes[ix]['island']
                call.update(originalPC=pc,originalBranchWord=hex(word),originalFunction=functions[begin]['data'],originalFunctionStart=begin,originalFunctionEnd=end,originalIsland=target)
            main=next(row for row in calls if row['route']['importIndex']==784)
            assert main['originalFunctionStart']==0x2260c73ec and main['originalFunctionEnd']==0x2260c740c
            mainbody=Path(main['originalFunction']['path']).read_bytes()
            assert struct.unpack_from('<4I',mainbody,12)==(0xd0000010,0x91087210,0xdac123f0,0xaa1003e0)
            handler_address=list(decoder.disasm(mainbody[12:20],main['originalFunctionStart']+12))
            assert [row.mnemonic for row in handler_address]==['adrp','add']
            assert handler_address[0].op_str.split(',')[0]=='x16' and handler_address[1].op_str.startswith('x16, x16,')
            assert handler_address[0].operands[1].imm+handler_address[1].operands[2].imm==0x2260c921c
            # The original handler is a signed C function pointer in x0, not a
            # Block. Preserve this PACIZA and all original callback instructions.
            main['originalSignedCFunctionHandler']=dict(address=0x2260c921c,PACIZAWord=0xdac123f0,ABI='void (*)(xpc_connection_t)')
        finally:
            for sub in subs:sub.close()
    return dict(currentTextBytes=text['bytes'],currentImportStubs=list(routes.values()),calls=calls,
        originalUniqueRoutes=list(original_routes.values()),originalCompleteCallerFunctions=list(functions.values()),
        originalS5Words=chains,freshCacheReads=reads,functionsExecuted=0,originalVZLoaded=False)

def main():
    out=n/'vz-owned-xpc-real-reexport-data-v3';assert not out.exists();out.mkdir(mode=0o700)
    bases=[n/'vz-metal-singleton-selection-data-v3/candidate.json',n/'universalhid-current-exact-frontier-audit-v25/audit.json',n/'owned-vmm-xpc-v10-provider-build-v2/candidate.json']
    pins=[]
    for source in bases:
        for row in json.loads((source.parent/'freeze.json').read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(source.parent/'freeze.json'))
    branch,frontier,provider=[json.loads(source.read_bytes())for source in bases]
    original=branch['frontendCandidate'];assert p.pin(Path(original['path']))==original
    before=Path(original['path']).read_bytes();callers=original_callers(before,out)
    p.save(out/'original-callers.json',callers)
    old_vmnet=next(row for row in frontier['privateDefinitions']if row['path']==OLD_OWNER)['image']
    copies=[];library_dir=out/'private';library_dir.mkdir(mode=0o700)
    for row in provider['libraries']:
        file=Path(row['path']);assert p.pin(file)=={key:row[key]for key in ('path','bytes','sha256')}
        destination=library_dir/row['name'];destination.write_bytes(file.read_bytes());destination.chmod(0o600)
        assert p.pin(destination)['sha256']==row['sha256'];copies.append(dict(source=p.pin(file),candidate=p.pin(destination),wholeBytesIdentical=True))
    vmnet=library_dir/'VM27VMNetUnavailable.dylib';vmnet.write_bytes(Path(old_vmnet['path']).read_bytes());vmnet.chmod(0o600)
    assert p.pin(vmnet)['sha256']==old_vmnet['sha256'];copies.append(dict(source=old_vmnet,candidate=p.pin(vmnet),wholeBytesIdentical=True))
    source=p.ROOT/'VirtualMac/vz/host/vm27_frontend_owned_xpc_aggregate_v1.c'
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    aggregate=library_dir/'XF';obj=out/'aggregate.o';processes=[]
    def run(label,args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        processes.append(dict(label=label,argv=args,exit=r.returncode));p.save(out/'processes.json',processes)
        assert r.returncode==0,(label,r.stderr.decode());return r
    flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2']
    run('compile-aggregate',flags+['-c',source,'-o',obj])
    run('link-aggregate',flags+['-dynamiclib','-nostdlib',obj,'-Wl,-install_name,'+NEW_OWNER,'-Wl,-rpath,@loader_path',
        '-Wl,-reexport_library,'+str(vmnet),'-Wl,-reexport_library,'+str(library_dir/'VM27OriginalV10Transport.dylib'),'-Wl,-no_adhoc_codesign','-o',aggregate])
    aggraw=aggregate.read_bytes();assert not any(cmd==29 for cmd,at,size in p.commands(aggraw))
    assert not any(sec['size']for seg in p.segments(aggraw)for sec in seg['sections']if sec['name']=='__text')
    agg=f.image(p.pin(aggregate),NEW_OWNER)
    assert len(agg['dependencies'])==2 and all(row['command']==0x8000001f for row in agg['dependencies'])
    graph={NEW_OWNER:agg}
    for row in copies:
        file=Path(row['candidate']['path']);graph['@loader_path/'+file.name]=f.image(row['candidate'],'@loader_path/'+file.name)
    original_exports=set(graph[OLD_OWNER]['exports']);assert len(original_exports)==5
    expected=original_exports|set(graph['@loader_path/VM27OriginalV10Transport.dylib']['exports'])
    # ld64 whole-library LC_REEXPORT_DYLIB leaves the local trie empty.
    # Resolve each actual leaf definition through those real commands.
    assert not agg['exports'] and len(expected)==26
    for symbol in sorted(expected):
        assert f.resolve(graph,NEW_OWNER,symbol,agg)['status']=='actualDirectExport'
    proofs=[]
    for name in sorted(expected):
        proof=f.resolve(graph,NEW_OWNER,name,agg);assert proof['status']=='actualDirectExport'
        leaf=proof
        while 'nested'in leaf:leaf=leaf['nested']
        assert leaf['owner']==(OLD_OWNER if name in original_exports else '@loader_path/VM27OriginalV10Transport.dylib')
        proofs.append(dict(name=name,proof=proof))
    after=transformed(before);verification=verify(before,after)
    candidate=out/'VZ27.owned-xpc-v10.mac.inert.macho-data';candidate.write_bytes(after);candidate.chmod(0o600)
    negatives=[]
    schema=import_records(after,p.commands);chain=next(row for row in p.vz_reader.parse(before)['words']if row['auth']and row['bind']and row['index']==752)
    mutations=[('original strong bit',schema['imports'][752]['command']+1),('wrong XPC ordinal',schema['imports'][762]['command']),
        ('original import name',schema['imports'][784]['command']+2),('wrong aggregate path',p.dependencies(after)[28]['at']+24),
        ('original PAC wholeword',chain['at']+5),('original main function instruction',0x1913ec),('original Metal branch',0x161e04)]
    for name,offset in mutations:
        bad=bytearray(after);bad[offset]^=1
        try:verify(before,bytes(bad))
        except(AssertionError,ValueError):negatives.append(dict(name=name,rejected=True))
        else:raise AssertionError('accepted malformed exact frontend route')
    # The genuine linker produced an empty trie: these whole-library definitions
    # exist only through actual LC_REEXPORT_DYLIB. Changing one to LC_LOAD
    # therefore removes its definitions from this aggregate.
    bad_aggregate=copy.deepcopy(agg);bad_aggregate['dependencies'][1]['command']=12
    assert not all(row['command']==0x8000001f for row in bad_aggregate['dependencies'])
    damaged_graph=copy.deepcopy(graph);damaged_graph[NEW_OWNER]=bad_aggregate
    assert f.resolve(damaged_graph,NEW_OWNER,'_xpc_connection_create',bad_aggregate)['status']!='actualDirectExport'
    negatives.append(dict(name='ordinary dependency violates exact two-LC_REEXPORT aggregate contract',rejected=True))
    for name,operation in [
                           ('wrong exact transport leaf',lambda g:g[NEW_OWNER]['dependencies'][1].update(path='@rpath/WrongTransport.dylib')),
                           ('wrong rpath context',lambda g:g[NEW_OWNER].update(rpaths=['@loader_path/wrong'])),
                           ('removed original VMNet target',lambda g:g.pop(OLD_OWNER))]:
        damaged=copy.deepcopy(graph);operation(damaged)
        symbol='_vmnet_start_interface'if name.startswith('removed')else'_xpc_connection_create'
        assert f.resolve(damaged,NEW_OWNER,symbol,damaged[NEW_OWNER])['status']!='actualDirectExport'
        negatives.append(dict(name=name,rejected=True))
    for file in (candidate,aggregate):run('validate-'+file.name,['xcrun','dyld_info','-validate_only',file])
    header=Path(sdk)/'usr/include/xpc/xpc.h';decl=header.read_text()
    assert 'typedef void (*xpc_connection_handler_t)(xpc_connection_t connection);'in decl and 'xpc_main(xpc_connection_handler_t handler);'in decl
    p.save(out/'candidate.json',dict(schema='Genuine VZ frontend three-XPC true owned V10 reexport route v3',
        sourceFrontend=original,frontendCandidate=p.pin(candidate),frontendAggregate=p.pin(aggregate),
        unchangedVMNetProvider=old_vmnet,unchangedOwnedV10ProviderGraph=p.pin(bases[2]),wholeCopiedProviders=copies,
        route=dict(reusedDependencyOrdinal=29,originalPath=OLD_OWNER,newPath=NEW_OWNER,actualStrongImports=SELECTED),
        verification=verification,actualOriginalCallers=p.pin(out/'original-callers.json'),originalCallbackABIHeader=p.pin(header),
        trueWholeLibraryReexportDefinitions=proofs,aggregateLocalExports=0,aggregateReexportedDefinitions=len(proofs),negativeControls=negatives,
        preservesOriginalVMNetUnsupportedContract=True,guestNetworkingAndSSHForwardingImplemented=False,
        factoryAbsentFailsENOTCONN=True,unpreparedOriginalMainExits78=True,nativePeerAndCodeIdentityGatesUnchanged=True,
        actualParentFactoryInstalled=False,originalParentConsumerLifecycleIntegrated=False,trustedOriginalPreMainCallerIntegrated=False,
        originalVMMV9ToV10ProductRouteStillRequired=True,remainingSkyLight12AndUHK4Unclosed=True,
        completeCurrentStrongLoadGraph=False,originalVZLoaded=False,originalVZCallerExecuted=False,
        originalVMMExecuted=False,providerGraphExecuted=False,productionAppModified=False,
        codeSigningCalls=0,deviceOperations=0,nativeCPUCalls=0,guestInstructions=0,full27Backend=False))
    pins += [p.pin(Path(__file__)),p.pin(source),p.pin(header)]
    for failure_version in (1,2):
        pins += [p.pin(file)for file in (n/('vz-owned-xpc-real-reexport-data-v'+str(failure_version))).rglob('*')if file.is_file()]
    pins += [p.pin(file)for file in out.rglob('*')if file.is_file()]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),verification=verification,aggregate=p.pin(aggregate))))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        out=n/'vz-owned-xpc-real-reexport-data-v3'
        if out.exists():
            p.save(out/'failure.json',dict(error=repr(exc),candidateWritten=(out/'candidate.json').exists(),deviceOperations=0))
            (out/'failed-builder.py').write_bytes(Path(__file__).read_bytes())
        raise
