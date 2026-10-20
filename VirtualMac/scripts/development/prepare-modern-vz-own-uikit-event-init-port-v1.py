#!/usr/bin/env python3
"""Explicit consumed-self mac CG event initializer port for own UIKit, inert."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('cursor_f',HERE/'audit-modern-genuine-hid-current-frontier-v20.py')
f20=importlib.util.module_from_spec(spec);spec.loader.exec_module(f20);f=f20.f;p,s,n=f.p,f.s,f.NODE
spec=importlib.util.spec_from_file_location('cursor_h',n/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
from macho_chained_import_records_v1 import read as import_records
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
SELECTED={307:'_SLEventCopyIOHIDEvent'}
NAME='_VM27NoMacEventV1';ENTRIES=((0x649e4,1000,'initWithEvent:'),)

def branch_target(pc,word):
    immediate=word&0x3ffffff;immediate-=1<<26 if immediate&1<<25 else 0
    return pc+immediate*4

def strings(raw):
    command=next(at for cmd,at,size in p.commands(raw)if cmd==0x80000034)
    cs,cz=struct.unpack_from('<II',raw,command+8);strings_offset=struct.unpack_from('<I',raw,cs+12)[0]
    rows=import_records(raw,p.commands)['imports'];result={}
    for row in rows:
        word=struct.unpack_from('<I',raw,row['command'])[0];off=cs+strings_offset+(word>>9)
        assert raw[off:off+len(row['name'])+1]==row['name'].encode()+b'\0'
        result[row['index']]=(off,len(row['name'])+1)
    return result

def stub_for(raw,index):
    parsed=p.vz_reader.parse(raw);decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM);decoder.detail=True
    section=next(sec for seg in parsed['segments']for sec in seg['sections']if sec['name']=='__auth_stubs')
    slots={seg['address']+row['at']-seg['fileoff']:row for seg in parsed['segments']for row in parsed['words']
       if row['bind']and row['index']==index and seg['fileoff']<=row['at']<seg['fileoff']+seg['filebytes']}
    assert len(slots)==1;found=[]
    for off in range(section['at'],section['at']+section['bytes'],16):
        pc=section['address']+off-section['at'];decoded=list(decoder.disasm(raw[off:off+12],pc))
        if len(decoded)!=3 or [row.mnemonic for row in decoded]!=['adrp','add','ldr']:continue
        if decoded[0].op_str.split(',')[0]!='x16' or not decoded[1].op_str.startswith('x16, x16,') or decoded[2].op_str!='x17, [x16]':continue
        address=decoded[0].operands[1].imm+decoded[1].operands[2].imm
        if address not in slots:continue
        assert struct.unpack_from('<I',raw,off+12)[0]==0xd71f0a30 and slots[address]['auth']
        found.append(dict(PC=pc,stubFileoff=off,slot=address,chain=slots[address],bytes=raw[off:off+16].hex()))
    assert len(found)==1;return found[0]

def transform(before):
    result=bytearray(before);schema=import_records(before,p.commands);ranges=strings(before)
    for index,name in SELECTED.items():
        row=schema['imports'][index];assert row['name']==name and row['ordinal']==52 and not row['weak']and row['addend']==0
        off,length=ranges[index];assert len(NAME)+1<=length
        for other,(address,count)in ranges.items():
            if other!=index:assert address+count<=off or off+length<=address
        result[off:off+length]=NAME.encode()+bytes(length-len(NAME));result[row['command']]=29
    route=stub_for(before,307);base=p.vz_reader.parse(before)['segments'][0]['address']
    for entry,length,name in ENTRIES:
        assert struct.unpack_from('<I',before,entry)[0]==0xd503237f
        delta=route['PC']-(base+entry);assert delta%4==0 and -(1<<27)<=delta<(1<<27)
        struct.pack_into('<I',result,entry,0x14000000|((delta//4)&0x3ffffff))
    return bytes(result)

def validate(before,after):
    assert after==transform(before);old,new=p.vz_reader.parse(before),p.vz_reader.parse(after)
    assert old['words']==new['words']and old['nlists']==new['nlists']and old['segments']==new['segments']and old['header']==new['header']
    assert p.dependencies(before)==p.dependencies(after)
    oldschema=import_records(before,p.commands);newschema=import_records(after,p.commands)
    assert newschema==dict(oldschema,imports=[dict(row,name=NAME,ordinal=29)if row['index']in SELECTED else row for row in oldschema['imports']])
    assert len(newschema['imports'])==1056 and sum(not row['weak']for row in newschema['imports'])==1011
    assert not any(row['name']in SELECTED.values()for row in new['nlists'])
    entry_ranges=[(entry,entry+4)for entry,length,name in ENTRIES]
    for seg in p.segments(before):
        for sec in seg['sections']:
            if not sec['fileoff']or not sec['size']or sec['flags']&255 in(1,12,18):continue
            begin,end=sec['fileoff'],sec['fileoff']+sec['size']
            expected=bytearray(before[begin:end])
            for a,b in entry_ranges:
                if begin<=a<b<=end:expected[a-begin:b-begin]=after[a:b]
            assert bytes(expected)==after[begin:end]
    remaining=[row for row in newschema['imports']if row['ordinal']==52 and not row['weak']]
    assert len(remaining)==8 and all(row['name']not in SELECTED.values()for row in remaining)
    return dict(totalImports=1056,strongImports=1011,oneMacCGEventImportReplacedByStrongConsumedSelfCapabilityPort=True,
        originalSkyLightStrongImportsRemaining=remaining,chainedWholeWordsPreserved=len(old['words']),
        allOriginalCodeExceptOneAdditionalInitializerEntryBranchPreserved=True,allOriginalObjCAndSwiftMetadataNlistsAndDependencyOrdinalsPreserved=True,
        changedBytes=sum(a!=b for a,b in zip(before,after)),onePortedInitializer=list(name for _,_,name in ENTRIES))

def original_entry_proof(before,out):
    contract=n/'vz-skylight-consumer-contract-v1/build-v3/contract.json';j=json.loads(contract.read_bytes())
    assert p.pin(contract)['sha256']=='f1fcabba053f2e1331b8750883170b939fed06dc5c026cd9393abfe7d134d86d'
    text=next(sec for seg in p.vz_reader.parse(before)['segments']for sec in seg['sections']if sec['name']=='__text')
    base=0x100000000;methods=[];cross=[];routes={stub_for(before,index)['PC']:index for index in SELECTED}
    cursor_calls=[]
    for off in range(text['at'],text['at']+text['bytes'],4):
        word=struct.unpack_from('<I',before,off)[0]
        if word&0xfc000000 not in(0x14000000,0x94000000):continue
        target=branch_target(base+off,word)
        if target in routes:cursor_calls.append(dict(pc=base+off,target=target,index=routes[target],word=word))
        for entry,length,name in ENTRIES:
            if base+entry<target<base+entry+length and not entry<=off<entry+length:
                cross.append(dict(source=off,target=target,method=name))
    assert not cross and len(cursor_calls)==1 and cursor_calls[0]['index']==307
    assert all(any(entry<=row['pc']-base<entry+length for entry,length,name in ENTRIES)for row in cursor_calls)
    rebases=[]
    for row in p.vz_reader.parse(before)['words']:
        if row['bind']:continue
        word=row['word'];target=base+(word&0xffffffff)if row['auth']else(word&((1<<43)-1))|(((word>>43)&255)<<56)
        for entry,length,name in ENTRIES:
            if base+entry<target<base+entry+length:rebases.append(dict(row,target=target,method=name))
    assert not rebases
    with p.CACHE.open('rb')as stream:
        cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
        try:
            for entry,length,name in ENTRIES:
                original_pc=0x225f36000+entry
                old=next(row for row in j['originalBoundedConsumerHelperBodies']if row['functionStart']==original_pc)
                assert old['functionEnd']==original_pc+length
                objc=old['exactObjCIMPMatches'];assert len(objc)==1 and objc[0]['selector']==name and objc[0]['typeEncoding']=='@24@0:8@16'and objc[0]['className']=='_VZScrollWheelEvent'
                offset,owner=cache.convertAddr(original_pc);body=owner.getBytes(offset,length);file=out/(name.replace(':','_')+'.original.bin');file.write_bytes(body)
                assert p.pin(file)['sha256']==old['sha256'] and struct.unpack_from('<I',body)[0]==0xd503237f
                method_entry=objc[0]['methodEntryVA'];off,own=cache.convertAddr(method_entry);metadata=own.getBytes(off,12)
                assert method_entry+8+struct.unpack_from('<i',metadata,8)[0]==original_pc
                mfile=out/(name.replace(':','_')+'.original-method-entry.bin');mfile.write_bytes(metadata)
                current_method=method_entry-0x225f36000
                current_meta=before[current_method:current_method+12]
                assert base+current_method+8+struct.unpack_from('<i',current_meta,8)[0]==base+entry
                methods.append(dict(selector=name,originalIMP=original_pc,currentIMP=base+entry,ABI='@24@0:8@16',consumedInitializerSelf=True,originalBody=p.pin(file),
                    originalMetadata=p.pin(mfile),unchangedCurrentMetadataBytes=current_meta.hex(),currentMetadataOffset=current_method,
                    originalCompleteLC26Body=True,originalObjCIMP=objc[0]))
        finally:
            for sub in subs:sub.close()
    return dict(methods=methods,exactOriginalContract=p.pin(contract),allDirectCursorCalls=cursor_calls,
       externalDirectBranchesIntoMethodInteriors=cross,chainedRebasesIntoInteriors=rebases,
       genericIndirectInteriorEntrypointExhaustivelyProven=False,originalMethodsExecuted=0)

def main():
    out=n/'vz-own-uikit-event-init-source-port-data-v1';assert not out.exists();out.mkdir(mode=0o700)
    previous=n/'vz-own-uikit-cursor-source-port-data-v2/candidate.json';manifest=json.loads(previous.read_bytes());pins=[]
    for freeze in (previous.parent/'freeze.json',n/'uikit-input-current-definitions-readonly-v1/freeze.json'):
        for row in json.loads(freeze.read_bytes())['files']:
            assert p.pin(Path(row['path']))==row;pins.append(row)
        pins.append(p.pin(freeze))
    source=manifest['frontendCandidate'];assert p.pin(Path(source['path']))==source
    before=Path(source['path']).read_bytes();proof=original_entry_proof(before,out);p.save(out/'original-entry-proof.json',proof)
    paths=[p.ROOT/'VirtualMac/vz/host'/name for name in ('vm27_no_mac_event_init_port_v1.h','vm27_no_mac_event_init_port_v1.m','test-vm27-no-mac-event-init-port-v1.m','vm27_frontend_owned_xpc_aggregate_v1.c')]
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip();runs=[]
    def run(label,args):
        r=subprocess.run(list(map(str,args)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        runs.append(dict(label=label,argv=list(map(str,args)),exit=r.returncode));p.save(out/'processes.json',runs)
        assert r.returncode==0,(label,r.stderr.decode());return r
    for mode,options in(('normal',[]),('san',['-fsanitize=address,undefined'])):
        exe=out/('fixture-mac-'+mode)
        run('build-'+mode,['xcrun','clang','-O2','-fobjc-arc','-Wall','-Wextra','-Werror',*options,paths[1],paths[2],'-framework','Foundation','-o',exe])
        r=run('run-'+mode,[exe]);result=json.loads(r.stdout)
        assert result==dict(checks=896,failures=0,initializationRejects=128,ownedSelfReleases=128,VZLoads=0,VZCalls=0)
    directory=out/'private';directory.mkdir();copies=[]
    for row in manifest['wholeCopiedPreviousProviders']+[dict(candidate=manifest['explicitCapabilityProvider'])]:
        original=Path(row['candidate']['path']);assert p.pin(original)==row['candidate']
        dest=directory/original.name;dest.write_bytes(original.read_bytes());copies.append(dict(source=row['candidate'],candidate=p.pin(dest),wholeBytesIdentical=True))
    provider=directory/'VM27NoMacEventInitPort.dylib'
    flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fobjc-arc','-Wall','-Wextra','-Werror']
    run('build-ios-provider',flags+['-dynamiclib',paths[1],'-framework','Foundation','-Wl,-install_name,@rpath/VM27NoMacEventInitPort.dylib','-Wl,-no_adhoc_codesign','-o',provider])
    aggregate=directory/'XF'
    run('build-ios-aggregate',flags+['-dynamiclib','-nostdlib',paths[3],'-Wl,-install_name,@loader_path/XF','-Wl,-rpath,@loader_path',
        '-Wl,-reexport_library,'+str(directory/'VM27VMNetUnavailable.dylib'),
        '-Wl,-reexport_library,'+str(directory/'VM27OriginalV10Transport.dylib'),'-Wl,-reexport_library,'+str(directory/'VM27NoMacCursorPort.dylib'),'-Wl,-reexport_library,'+str(provider),'-Wl,-no_adhoc_codesign','-o',aggregate])
    graph={'@loader_path/'+file.name:f.image(p.pin(file),'@loader_path/'+file.name)for file in directory.iterdir()}
    agg=graph['@loader_path/XF'];assert not agg['exports']and len(agg['dependencies'])==4 and all(row['command']==0x8000001f for row in agg['dependencies'])
    assert list(graph['@loader_path/VM27NoMacEventInitPort.dylib']['exports'])==[NAME]
    assert not any(sec['size']for seg in p.segments(aggregate.read_bytes())for sec in seg['sections']if sec['name']=='__text')
    retained=[]
    for oldproof in manifest['previousTwentyFourReexportDefinitionsPreserved']+[dict(name='_VM27NoMacV1')]:
        symbol=oldproof['name'];new=f.resolve(graph,'@loader_path/XF',symbol,agg);assert new['status']=='actualDirectExport'
        retained.append(dict(name=symbol,proof=new))
    port=f.resolve(graph,'@loader_path/XF',NAME,agg);assert port['status']=='actualDirectExport'
    # Reuse actual current tables through the frozen 36-owner join. The product
    # needs only Foundation/ObjC/libSystem/CoreFoundation; no guessed UIKit API.
    native=s.primary.captured_images()
    for group in('system','stock-extra','cxx-leaf'):s.join_capture(native,group,n/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in('dyld-leaf','xpc-leaf'):s.join_capture(native,group,n/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    f.join_kernel(s,native)
    for fn in(f.join_hid_extra,f.join_swift_two,f.join_eight,f.join_three,f.join_trace,f.join_unwind,f.join_compiler,f.join_crypto):fn(s,native)
    assert len(native)==36
    raw=provider.read_bytes();deps={row['ordinal']:row['path']for row in p.dependencies(raw)};native_proofs=[]
    for row in import_records(raw,p.commands)['imports']:
        assert row['ordinal']>0 and not row['weak'];resolved=s.primary.resolve(native,deps[row['ordinal']],row['name']);assert resolved['status']=='actualDirectExport'
        native_proofs.append(dict(row,owner=deps[row['ordinal']],definition=resolved))
    after=transform(before);verification=validate(before,after)
    candidate=out/'VZ27.own-uikit-no-mac-event-init.mac.inert.macho-data';candidate.write_bytes(after);candidate.chmod(0o600)
    negatives=[]
    for name,offset in [('consumed initializer entry',ENTRIES[0][0]),('preserved genuine six-argument initializer',0x6494c),('old method metadata',proof['methods'][0]['currentMetadataOffset']),
                        ('original PAC word',stub_for(before,307)['chain']['at']+7),('new strong ordinal',import_records(after,p.commands)['imports'][307]['command']),
                        ('new import name',strings(before)[307][0]),('unmodified genuine VZ sender',0x5c770)]:
        bad=bytearray(after);bad[offset]^=1
        try:validate(before,bytes(bad))
        except(AssertionError,ValueError):negatives.append(dict(name=name,rejected=True))
        else:raise AssertionError('damaged exact profile port accepted')
    for name,operation in [('removed explicit port provider',lambda g:g.pop('@loader_path/VM27NoMacEventInitPort.dylib')),
                           ('ordinary load cannot reexport explicit port',lambda g:g['@loader_path/XF']['dependencies'][3].update(command=12))]:
        damaged=copy.deepcopy(graph);operation(damaged);assert f.resolve(damaged,'@loader_path/XF',NAME,damaged['@loader_path/XF'])['status']!='actualDirectExport'
        negatives.append(dict(name=name,rejected=True))
    for file in(candidate,provider,aggregate):run('validate-'+file.name,['xcrun','dyld_info','-validate_only',file])
    p.save(out/'candidate.json',dict(schema='Independent own UIKit consumed-self mac CG event initializer entry port v1',
        sourceFrontend=source,frontendCandidate=p.pin(candidate),frontendAggregate=p.pin(aggregate),explicitCapabilityProvider=p.pin(provider),
        sourceFiles=[p.pin(file)for file in paths],wholeCopiedPreviousProviders=copies,originalEntryProof=p.pin(out/'original-entry-proof.json'),
        verification=verification,previousTwentyFiveReexportDefinitionsPreserved=retained,newExplicitCapabilityDefinition=port,
        capabilityProviderCurrentStrongImports=native_proofs,negativeControls=negatives,
        originalMacArtifactPreserved=True,originalMacCursorPortWholeBytesPreserved=True,originalMacCGEventInitializerExplicitlyUnsupported=True,originalSixArgumentInitializerPreserved=True,fakeSLSOrNSEventClassesOrExportsProvided=False,
        originalVZSenderFramesAndVMExecutorPreserved=True,ownUIKitInputCandidatePreserved=True,
        originalMethodsExecuted=False,originalVZLoaded=False,actualIOSCapabilityPortExecuted=False,completeCurrentStrongLoadGraph=False,
        actualParentFactoryInstalled=False,originalParentConsumerLifecycleIntegrated=False,
        originalVMMV9ToV10ProductRouteStillRequired=True,originalReceiverExecuted=False,
        providerSigningCalls=0,deviceOperations=0,nativeCPUCalls=0,guestInstructions=0,full27Backend=False))
    pins += [p.pin(Path(__file__))]+[p.pin(file)for file in paths]
    pins += [p.pin(file)for file in out.rglob('*')if file.is_file()]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),verification=verification,provider=p.pin(provider),currentStrongImports=len(native_proofs))))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        out=n/'vz-own-uikit-event-init-source-port-data-v1'
        if out.exists():
            p.save(out/'failure.json',dict(error=repr(exc),candidateWritten=(out/'candidate.json').exists(),deviceOperations=0))
            (out/'failed-builder.py').write_bytes(Path(__file__).read_bytes())
        raise
