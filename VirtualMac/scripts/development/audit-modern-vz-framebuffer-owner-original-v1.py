#!/usr/bin/env python3
"""Bounded genuine27 VM queue and framebuffer method profile, no execution.

Parser inherited byte-for-byte except selected classes/function extent and
output description from frozen Mac-ingress v3. Does not load original VZ.
"""
import argparse
import bisect
import hashlib
import json
import pathlib
import struct
import sys
import capstone

sys.dont_write_bytecode=True
from vz_import_addend_image import commands,segments
from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info,dyld_cache_slide_info5
from DyldExtractor.converter.slide_info import decodeV5Pointer
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CACHE=pathlib.Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')
RAW=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw/Virtualization'


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--contract',required=True,type=pathlib.Path);ap.add_argument('--expected-contract-sha256',required=True);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args()
    assert pin(args.contract)['sha256']==args.expected_contract_sha256
    c=json.loads(args.contract.read_text());assert c['all171HaveGenuineOriginalConsumer'] is True and len(c['originalVZPayloadSegments'])==6
    raw=RAW.read_bytes();assert pin(RAW)['sha256']=='ec4bbc11af44a0c04a56269397274c90265a51568fe50e4e94123dd5eaa82f04'
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);md.skipdata=True
    source_segments=c['originalVZPayloadSegments'];source_sections=[q for g in source_segments for q in g['sections']]
    text=next(q for q in source_sections if q['name']=='__text')
    def owned(va,n=8):return any(g['address']<=va and va+n<=g['address']+g['size'] for g in source_segments)
    def rawread(va,n):
        matches=[g for g in segments(raw) if g['address']<=va and va+n<=g['address']+g['filesize']];assert len(matches)==1
        g=matches[0];off=g['fileoff']+va-g['address'];return raw[off:off+n]
    start,size=next(struct.unpack_from('<II',raw,a+8) for cmd,a,z in commands(raw) if cmd==0x26)
    encoded=raw[start:start+size];at=0;offset=0;functions=[]
    while at<len(encoded):
        value=0;shift=0
        while True:
            assert at<len(encoded) and shift<=63;byte=encoded[at];at+=1;value|=(byte&127)<<shift
            if not byte&128:break
            shift+=7
        if not value:assert not any(encoded[at:]);break
        offset+=value;va=source_segments[0]['address']+offset
        assert text['address']<=va<text['address']+text['size'];functions.append(va)
    assert functions and len(functions)<20000 and len(set(functions))==len(functions)
    original_methods={};class_names={};category_evidence=[];strings={};pointer_contracts=[];seen_classes=set();seen_methodlists=set();method_errors=[];own_input_classes=[]
    selected_class_names={'VZVirtualMachine','VZGraphicsDevice','VZMacGraphicsDevice','_VZMacGraphicsDevice','_VZFramebuffer','_VZFramebufferView','_VZFramebufferLayer','_VZDisplayPresenter','VZGraphicsDisplay','VZMacGraphicsDisplay','VZVirtualMachineView','_VZVirtualMachineAccessor','_VZVirtualMachineAccessorManager','_VZVirtualMachineViewAdaptorInternal'}
    def selected_class(name):return name in selected_class_names or name.startswith('_VZ')and('Framebuffer' in name or 'GraphicsDevice' in name)
    with CACHE.open('rb') as f:
        context=DyldContext(f);assert bytes(context.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=context.addSubCaches(CACHE)
        def read(va,n):
            assert 0<n<=65536;cv=context.convertAddr(va);assert cv is not None;off,co=cv;assert off+n<=len(co.file)
            return co.getBytes(off,n)
        def string(va,allow_empty=False,max_bytes=512):
            if va not in strings:
                b=read(va,max_bytes).split(b'\0',1);assert len(b)==2 and len(b[0])<max_bytes;strings[va]=b[0].decode()
            assert allow_empty or strings[va]
            return strings[va]
        def pointer(slot):
            mm,co=next((m,o) for m,o in context.mappings if m.address<=slot<m.address+m.size)
            mi=co.mappings.index((mm,co));ext=dyld_cache_mapping_and_slide_info(co.file,co.header.mappingWithSlideOffset+mi*dyld_cache_mapping_and_slide_info.SIZE)
            si=dyld_cache_slide_info5(co.file,ext.slideInfoFileOffset);assert si.version==5
            page=(slot-ext.address)//si.page_size;start=co.readFormat('<H',ext.slideInfoFileOffset+len(si)+page*2)[0]
            # A real NULL is not part of a rebase chain. Never interpret other
            # unchained words as pointers or invent a missing relocation.
            if read(slot,8)==bytes(8):return 0
            assert start!=65535;pageoff=ext.fileOffset+page*si.page_size;cursor=pageoff+start;wanted=ext.fileOffset+slot-ext.address;steps=0
            while True:
                assert pageoff<=cursor<=pageoff+si.page_size-8;word=co.readFormat('<Q',cursor)[0]
                target,auth,key,div,ad,delta=decodeV5Pointer(word,si.value_add);steps+=1;assert steps<=si.page_size//8
                if cursor==wanted:break
                assert delta and cursor<wanted;cursor+=delta
            target&=0x00ffffffffffffff;pointer_contracts.append(dict(slot=slot,target=target,auth=auth,key=key,diversity=div,addressDiversity=ad,chainMember=True));return target
        base=source_segments[0]['address'];header=read(base,32);hs=struct.unpack_from('<I',header,20)[0];assert hs<0x100000
        off,co=context.convertAddr(base);header=co.getBytes(off,32+hs)
        assert [header[a+8:a+24].hex() for cmd,a,z in commands(header) if cmd==27]==[c['originalVZUUID']]
        assert [g for g in segments(header) if g['name']!='__LINKEDIT']==source_segments
        objc=next(t['physicalOwner'] for row in c['cacheOnlyImportsWithTrueConsumers'] for t in row['candidates'] if t['physicalOwner']['path']=='/usr/lib/libobjc.A.dylib')
        obase=objc['base'];oh=read(obase,32);osize=struct.unpack_from('<I',oh,20)[0];assert osize<0x100000
        off,co=context.convertAddr(obase);oh=co.getBytes(off,32+osize)
        assert [oh[a+8:a+24].hex() for cmd,a,z in commands(oh) if cmd==27]==[objc['uuid']]
        opt=next(q for g in segments(oh) for q in g['sections'] if q['name']=='__objc_opt_ro')
        selector_offset=struct.unpack('<q',read(opt['address']+40,8))[0];assert selector_offset
        selector_base=opt['address']+selector_offset;assert context.convertAddr(selector_base) is not None
        def methodlist(ml,cls,meta):
            if not ml:return
            assert owned(ml,8);key=(ml,cls,meta)
            if key in seen_methodlists:return
            seen_methodlists.add(key);flags,count=struct.unpack('<II',read(ml,8));assert count<=4096
            stride=flags&0xfffc
            if flags&0x80000000:
                assert stride==12 and owned(ml,8+stride*count)
                direct=bool(flags&0x40000000)
                for i in range(count):
                    entry=ml+8+i*stride;name,typ,imp=struct.unpack('<iii',read(entry,12));np=selector_base+name if direct else pointer(entry+name)
                    tp=selector_base+typ if flags&0x20000000 else entry+4+typ
                    name=string(np)
                    try:typ=string(tp,True,4096)
                    except (AssertionError,UnicodeDecodeError):
                        method_errors.append(dict(className=cls,flags=hex(flags),entry=hex(entry),name=name,typeOffset=typ,typeTarget=hex(tp),typeEncodingVerified=False,error='encoding exceeds bounded 4096-byte UTF-8 parser'))
                        typ=None
                    target=entry+8+imp
                    assert text['address']<=target<text['address']+text['size']
                    original_methods.setdefault(target,[]).append(dict(className=cls,classmethod=meta,selector=name,typeEncoding=typ,typeEncodingVerified=typ is not None,listVA=ml,methodEntryVA=entry,IMP=target,sourceOwnerOriginalSix=True,relative=True))
            else:
                assert stride==24 and owned(ml,8+stride*count)
                for i in range(count):
                    entry=ml+8+i*stride;name=string(pointer(entry));typ=string(pointer(entry+8),True,4096);target=pointer(entry+16)
                    assert text['address']<=target<text['address']+text['size']
                    original_methods.setdefault(target,[]).append(dict(className=cls,classmethod=meta,selector=name,typeEncoding=typ,typeEncodingVerified=True,listVA=ml,methodEntryVA=entry,IMP=target,sourceOwnerOriginalSix=True,relative=False))
        def methods(raw,cls,meta):
            if not raw:return
            if raw&1:
                lol=raw&~7;assert owned(lol,8);entsize,count=struct.unpack('<II',read(lol,8));assert count<=512
                for i in range(count):
                    entry=lol+8+i*8;assert owned(entry);v=struct.unpack('<q',read(entry,8))[0];methodlist(entry+(v>>16),cls,meta)
            else:methodlist(raw&~7,cls,meta)
        def classinfo(cls,meta=False):
            if not cls or not owned(cls,40):return
            if cls in seen_classes:return
            seen_classes.add(cls);ro=pointer(cls+32)&~7;assert owned(ro,72)
            name=string(pointer(ro+24));class_names[cls]=name;methods(pointer(ro+32),name,meta)
            if not meta and selected_class(name):
                flags,start,size=struct.unpack('<III',read(ro,12));ivars=pointer(ro+48);iv=[]
                if ivars:
                    stride,count=struct.unpack('<II',read(ivars,8));assert stride==32 and count<=128
                    for index in range(count):
                        entry=ivars+8+index*stride;offset_slot=pointer(entry);ivar_name=string(pointer(entry+8));ivar_type=string(pointer(entry+16),max_bytes=65536);alignment,ivar_size=struct.unpack('<II',read(entry+24,8))
                        iv.append(dict(name=ivar_name,type=ivar_type,offsetSlot=offset_slot,offset=struct.unpack('<I',read(offset_slot,4))[0],alignment=alignment,size=ivar_size,originalEntry=entry))
                own_input_classes.append(dict(name=name,classVA=cls,roVA=ro,flags=flags,instanceStart=start,instanceSize=size,superclass=pointer(cls+8),ivars=iv))
            if not meta:classinfo(pointer(cls),True)
        section=next(q for q in source_sections if q['name']=='__objc_classlist');assert section['size']%8==0
        for i in range(section['size']//8):classinfo(pointer(section['address']+i*8))
        for cats in (q for q in source_sections if q['name'] in ('__objc_catlist','__objc_nlcatlist')):
            assert cats['size']%8==0
            for i in range(cats['size']//8):
                cat=pointer(cats['address']+i*8);assert owned(cat,48)
                cls=pointer(cat+8);name=class_names.get(cls)
                if not name or not selected_class(name):continue
                cn=string(pointer(cat));im=pointer(cat+16);cm=pointer(cat+24)
                category_evidence.append(dict(categoryVA=cat,classVA=cls,className=name,categoryName=cn,instanceMethodList=im,classMethodList=cm))
                methods(im,name,False);methods(cm,name,True)
        rows=[]
        for row in c['cacheOnlyImportsWithTrueConsumers']:
            if not 304<=row['index']<=317:continue
            calls=[]
            for candidate in row['candidates']:
                for p in candidate['proofs']:
                    assert p['kind']=='originalVZExternalBranchInstruction';pc=p['originalInstructionPC'];assert text['address']<=pc<text['address']+text['size']
                    assert read(pc,4)==rawread(pc,4) and struct.unpack('<I',read(pc,4))[0]==int(p['rawInstructionWord'],16)
                    fi=bisect.bisect_right(functions,pc)-1;assert fi>=0;fst=functions[fi];end=functions[fi+1] if fi+1<len(functions) else text['address']+text['size'];assert fst<=pc<end
                    wstart=max(fst,pc-48);wend=min(end,pc+52);window=read(wstart,wend-wstart);assert window==rawread(wstart,wend-wstart)
                    decoded=list(md.disasm(window,wstart));assert sum(i.size for i in decoded)==len(window) and all(i.size==4 for i in decoded)
                    instructions=[dict(pc=i.address,word=hex(struct.unpack('<I',i.bytes)[0]),mnemonic=i.mnemonic,operands=i.op_str,decoded=i.id!=0) for i in decoded]
                    branch=next(i for i in instructions if i['pc']==pc);assert branch['mnemonic']=='bl' and branch['word']==p['rawInstructionWord']
                    owner=original_methods.get(fst,[])
                    calls.append(dict(originalPC=pc,branchWord=p['rawInstructionWord'],stubTarget=p['branchTarget'],originalFunctionStart=fst,originalFunctionEnd=end,exactObjCIMPMatches=owner,unmatchedMethodNotGuessed=not bool(owner),instructionWindow=instructions))
            rows.append(dict(index=row['index'],symbol=row['symbol'],physicalOwner=row['candidates'][0]['physicalOwner'],actualConsumerCalls=calls))
        helper_starts=set()
        # Notify caller materializes this callback's original PC into x16 before
        # the explicit PAC word. It must be a real function-start entry.
        callback=0x22616bd54;assert callback in functions
        helper_starts.update(base+rva for rva in (0x18b4bc,0x1899d4,0x18de24,0x485a0,0x44ce4,0x11d6b0,0x11d9b8,0x12e2cc,0x47464,0x476d8,0x49264,0x49394,0x230530,0x2302b4,0x2308c8))
        visitors=[dict(slot=slot,target=pointer(slot)) for slot in (0x27acd6b58,0x27acd6b60)]
        helper_starts.update(row['target'] for row in visitors)
        selected_input_methods=[row for rows in original_methods.values() for row in rows if selected_class(row['className'])]
        helper_starts.update(row['IMP']for row in selected_input_methods if row['className']!='VZVirtualMachine' or row['selector'] in ('initWithConfiguration:','initWithConfiguration:queue:','queue','_graphicsDevices','graphicsDevices','_keyboards','_pointingDevices','startWithCompletionHandler:','stopWithCompletionHandler:','_createAccessorFromAccessorManagerForTestingWithOptions:','_createAccessorEndpointWithOptions:'))
        helper_bodies=[]
        for address in sorted(helper_starts):
            fi=bisect.bisect_left(functions,address);assert functions[fi]==address
            end=functions[fi+1] if fi+1<len(functions) else text['address']+text['size'];assert 0<end-address<=65536
            body=read(address,end-address);archived_body=rawread(address,end-address);archived_equal=body==archived_body;archived_differences=[dict(offset=index,genuine=actual,archived=archived_body[index])for index,actual in enumerate(body)if actual!=archived_body[index]]
            decoded=list(md.disasm(body,address));assert sum(i.size for i in decoded)==len(body) and all(i.size==4 for i in decoded)
            helper_bodies.append(dict(archivedExtractionWholeBytesIdentical=archived_equal,archivedExtractionDifferences=archived_differences,functionStart=address,functionEnd=end,bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),exactObjCIMPMatches=original_methods.get(address,[]),instructions=[dict(pc=i.address,word=hex(struct.unpack('<I',i.bytes)[0]),mnemonic=i.mnemonic,operands=i.op_str,decoded=i.id!=0) for i in decoded]))
        key=0x27acde6c0;assert owned(key,32);chars=pointer(key+16);length=struct.unpack('<Q',read(key+24,8))[0];assert 0<length<512
        keybytes=read(chars,length+1);assert keybytes[-1]==0
        dictionary_key=dict(constantObjectVA=key,plainBytesPointer=chars,declaredLength=length,utf8=keybytes[:-1].decode(),exactRuntimeCFStringTypeNotVerified=True)
        # Resolve actual objc_msgSend selector islands, not guessed labels.
        import importlib.util
        es=importlib.util.spec_from_file_location('actual_exports',pathlib.Path(__file__).with_name('prepare-modern-universalhid-provider-data-v1.py'))
        exports_module=importlib.util.module_from_spec(es);es.loader.exec_module(exports_module)
        oracle=exports_module.GenuineCacheExports(context)
        physical=[oracle.resolve(path,'_objc_msgSend')for path in oracle.paths if path.startswith('/usr/lib/objc/libobjcMsgSend')]
        matches=[row for row in physical if row and row['exportAddress']==0x228000800]
        assert len(matches)==1;msgsend_proof=matches[0]
        msgsend=msgsend_proof['exportAddress']
        for body in helper_bodies:
            resolved=[]
            for insn in body['instructions']:
                word=int(insn['word'],16)
                if word&0xfc000000!=0x94000000:continue
                delta=(word&0x3ffffff)<<2
                if delta&0x8000000:delta-=0x10000000
                target=insn['pc']+delta
                if owned(target,16):continue
                stub=read(target,16);a,b,w,trap=struct.unpack('<4I',stub)
                if a&0x9f00001f!=0x90000001 or b&0xffc003ff!=0x91000021 or w&0xfc000000!=0x14000000:continue
                pages=((a>>5)&0x7ffff)<<2|((a>>29)&3)
                if pages&0x100000:pages-=0x200000
                selector_va=(target&~4095)+(pages<<12)+((b>>10)&4095)
                tail=(w&0x3ffffff)<<2
                if tail&0x8000000:tail-=0x10000000
                assert target+8+tail==msgsend
                resolved.append(dict(callPC=insn['pc'],stubVA=target,stubBytes=stub.hex(),selectorVA=selector_va,selector=string(selector_va),actualObjcMsgSendExportVA=msgsend))
            body['resolvedObjCMsgSendSelectors']=resolved
        for sf in subs:sf.close()
    assert len(rows)==14
    result=dict(originalVZUUID=c['originalVZUUID'],originalSegments=6,imports14=rows,ownInputClasses=own_input_classes,selectedOriginalInputMethods=selected_input_methods,macIngressOuterAsyncExceptionPolicyVerified=False,originalFunctionStarts=len(functions),exactOriginalObjCMethodIMPs=len(original_methods),originalClassesTraversed=len(seen_classes),originalObjcOwner=objc,originalSelectorBase=selector_base,sourcePointerContracts=pointer_contracts,originalBoundedConsumerHelperBodies=helper_bodies,notifyCallbackOriginalPC=callback,displayDictionaryKeyPlainBytes=dictionary_key,methodErrors=method_errors,methodEncodingErrorsDoNotSupplyABI=True,sourceSyntheticExtraObjectsAccepted=False,allCallInstructionsDecodedOrExplicitRaw=True,functionsCalled=0,actualVZCalls=0,originalVMMExecuted=False,guestInstructions=0,SkyLightProviderImplemented=False,SkyLightFunctionalityVerified=False,originalConsumersExecuted=False,full27=False,deviceOperations=0,systemModified=False)
    result['actualObjcMsgSendDefinition']=msgsend_proof;result['selectedCategories']=category_evidence;result['vmOrAccessorVariantVisitors']=visitors;result['schema']='Bounded genuine27 VM queue and framebuffer method profile readonly v1';result['currentUIKitDisplayConnected']=False;result['originalVZLoaded']=False;result['framebufferMemoryLayoutCompatibilityAssumed']=False
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    (out/'contract.json').write_text(json.dumps(result,indent=2)+'\n');(out/'original-cache-header.bin').write_bytes(header)
    (out/'inputs.json').write_text(json.dumps([pin(p) for p in (args.contract,RAW,pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('vz_import_addend_image.py'),R/'VirtualMac/vz/host/NSViewShim.m',R/'VirtualMac/vz/uncache.py',R/'DeviceDiagnostics/2026-10-02-macos27-backend/toolchain/venv/lib/python3.14/site-packages/DyldExtractor/converter/objc_fixer.py')],indent=2)+'\n')
    print(json.dumps(dict(imports14=len(rows),calls=sum(len(r['actualConsumerCalls']) for r in rows),classes=len(seen_classes),exactMethodIMPs=len(original_methods),functionsCalled=0,full27=False)))


if __name__=='__main__':main()
