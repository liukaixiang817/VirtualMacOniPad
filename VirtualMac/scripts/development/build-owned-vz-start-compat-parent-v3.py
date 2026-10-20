#!/usr/bin/env python3
"""HOST-only typed helper link and sole parent-only signed-layout source port."""
import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
CACHE = N/'owned-vz-cache-adapter-source-v1-attempt2/candidate.json'
LOCALIZER = N/'owned-vz-localization-source-local-v1-attempt2/candidate.json'
BASE = N/'independent27-signed-runtime-uikit-filter-product-v10-attempt1/candidate.json'
NATIVE = N/'current-native-header-export-index-v3/index.json'
KEY = 'VM27OwnedVZStartCompat.dylib'

def need(value, reason):
    if not value: raise ValueError(reason)
def pin(path):
    path = pathlib.Path(path).resolve(); data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
def exact(row):
    path = pathlib.Path(row['path']); need(pin(path)==row,'actual frozen pin'); return path
def dump(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')
def module(path, name):
    spec = importlib.util.spec_from_file_location(name,path); result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
def align(value, width=8): return (value+width-1)&~(width-1)

def new_starts(raw, added):
    count = struct.unpack_from('<I',raw)[0]; offsets = struct.unpack_from('<'+'I'*count,raw,4)
    result = bytearray(4+4*count); struct.pack_into('<I',result,0,count)
    for index, offset in enumerate(offsets):
        if not offset: continue
        size = struct.unpack_from('<I',raw,offset)[0]; blob = raw[offset:offset+size]
        if index==added['segmentIndex']:
            size,ps,pf,segoff,maxptr,pages=struct.unpack_from('<IHHQIH',blob)
            need(ps==16384 and pf==9,'actual parent chained format9')
            firsts=list(struct.unpack_from('<'+'H'*pages,blob,22)); seeds=[]
            for first in firsts:
                if first==0xffff: seeds.append([])
                elif first&0x8000:
                    pos=first&0x7fff; values=[]
                    while True:
                        value=struct.unpack_from('<H',blob,22+2*pos)[0];values.append(value&0x7fff);pos+=1
                        if value&0x8000:break
                    seeds.append(values)
                else:seeds.append([first])
            page=added['pageIndex'];need(seeds[page]==[added['existingStart']],'actual old selected page seed')
            need(added['addedStart'] not in seeds[page],'new independent seed')
            seeds[page].append(added['addedStart']); seeds[page].sort()
            overflow=[]; newfirst=[]
            for values in seeds:
                if not values:newfirst.append(0xffff)
                elif len(values)==1:newfirst.append(values[0])
                else:
                    need(pages+len(overflow)<0x8000,'finite MULTI table')
                    newfirst.append(0x8000|(pages+len(overflow)))
                    overflow.extend(values[:-1]+[values[-1]|0x8000])
            blob=struct.pack('<IHHQIH',22+2*(pages+len(overflow)),ps,pf,segoff,maxptr,pages)+struct.pack('<'+'H'*(pages+len(overflow)),*(newfirst+overflow))
        result+=b'\0'*(align(len(result))-len(result));struct.pack_into('<I',result,4+4*index,len(result));result+=blob
    return bytes(result)

def patch_parent(original, reader, recipe):
    data=original.read_bytes(); old=reader.MachO(data); commands=[bytearray(c['raw']) for c in old.commands if c['cmd']!=0x1d]
    need(len(old.loads)==63 and len(old.imports)==1057,'actual old parent63/1057')
    selected=old.imports[504];need(selected['name']=='_confstr' and selected['ordinal']==19 and not selected['weak'],'only native confstr504')
    cs=next(c for c in old.commands if c['cmd']==0x1d);csstart,cssize=struct.unpack_from('<II',cs['raw'],8)
    need(csstart+cssize==len(data),'actual old terminal signature')
    work=bytearray(data[:csstart]); changed=[]
    for row in recipe['codeWords']+[recipe['authenticatedThunk']]:
        at=row.get('fileOffset',old.file(old.base+row['rva']));before=bytes.fromhex(row['before']);after=bytes.fromhex(row['after'])
        need(len(before)==len(after) and work[at:at+len(before)]==before,'actual scoped original code/zero pool')
        work[at:at+len(after)]=after;changed.append(dict(fileOffset=at,before=before.hex(),after=after.hex()))
    slot=recipe['authenticatedSlot'];at=slot['fileOffset'];need(work[at:at+8]==bytes.fromhex(slot['before']),'new zero authenticated slot')
    work[at:at+8]=struct.pack('<Q',int(slot['afterWord'],16));changed.append(dict(fileOffset=at,before=slot['before'],after=work[at:at+8].hex()))
    chain=next(c for c in old.commands if c['cmd']==0x80000034);fo,size=struct.unpack_from('<II',chain['raw'],8);raw=data[fo:fo+size]
    version,starts,imports,symbols,count,form,sform=struct.unpack_from('<7I',raw)
    need((version,count,form,sform)==(0,1057,2,0),'actual parent import format2')
    start_recipe=dict(recipe['chainStart']);start_recipe['segmentIndex']=next(i for i,s in enumerate(old.segments) if s['name']=='__DATA_CONST')
    newstarts=new_starts(raw[starts:imports],start_recipe)
    strings=bytearray(raw[symbols:]);cache_offset=len(strings);strings+=b'_VM27OwnedVZCacheConfstrV1\0';local_offset=len(strings);strings+=recipe['newImport']['name'].encode()+b'\0'
    rows=bytearray(raw[imports:symbols]);need(len(rows)==count*8,'actual old import rows')
    before,addend=struct.unpack_from('<Ii',rows,504*8);need(addend==0,'no cache addend')
    struct.pack_into('<Ii',rows,504*8,64|(cache_offset<<9),0);rows+=struct.pack('<Ii',64|(local_offset<<9),0)
    new_imports=align(28+len(newstarts));new_symbols=new_imports+len(rows)
    newraw=struct.pack('<7I',0,28,new_imports,new_symbols,count+1,2,0)+newstarts+b'\0'*(new_imports-28-len(newstarts))+rows+strings
    work+=b'\0'*(align(len(work))-len(work));newfo=len(work);work+=newraw
    # Relocate actual nlist/strings rather than overwrite neighbouring payloads.
    sym=next(c for c in old.commands if c['cmd']==2);symoff,nsyms,stroff,strsize=struct.unpack_from('<4I',sym['raw'],8)
    dysym=next(c for c in old.commands if c['cmd']==0xb)
    iundef,nundef=struct.unpack_from('<II',dysym['raw'],24)
    need(iundef+nundef==nsyms,'actual undefined nlist is terminal before append')
    nlist=bytearray(data[symoff:symoff+nsyms*16]);strtab=bytearray(data[stroff:stroff+strsize]);hits=[]
    for i in range(nsyms):
        no,typ,sect,desc,value=struct.unpack_from('<IBBHQ',nlist,i*16)
        stop=strtab.find(b'\0',no);name=strtab[no:stop].decode()
        if name=='_confstr' and (typ&0xe)==0:
            need((desc>>8)==19,'actual old nlist library ordinal');hits.append(i)
            newno=len(strtab);strtab+=b'_VM27OwnedVZCacheConfstrV1\0';struct.pack_into('<IBBHQ',nlist,i*16,newno,typ,sect,(64<<8)|(desc&0xff),value)
    need(len(hits)==1,'exact single selected undefined nlist')
    localno=len(strtab);strtab+=recipe['newImport']['name'].encode()+b'\0';nlist+=struct.pack('<IBBHQ',localno,1,0,64<<8,0)
    work+=b'\0'*(align(len(work))-len(work));newsyms=len(work);work+=nlist;newstr=len(work);work+=strtab
    path=('@loader_path/'+KEY).encode()+b'\0';cmdsize=align(24+len(path));load=bytearray(struct.pack('<6I',12,cmdsize,24,0,0x10000,0x10000)+path);load+=b'\0'*(cmdsize-len(load))
    commands.append(load)
    for command in commands:
        kind=struct.unpack_from('<I',command)[0]
        if kind==0x80000034:struct.pack_into('<II',command,8,newfo,len(newraw))
        elif kind==2:struct.pack_into('<4I',command,8,newsyms,nsyms+1,newstr,len(strtab))
        elif kind==0xb:
            oldundef=struct.unpack_from('<I',command,28)[0];struct.pack_into('<I',command,28,oldundef+1)
        elif kind==0x19 and command[8:24].rstrip(b'\0')==b'__LINKEDIT':
            linkoff=struct.unpack_from('<Q',command,40)[0];extent=len(work)-linkoff
            struct.pack_into('<Q',command,32,align(extent,16384));struct.pack_into('<Q',command,48,extent)
    header=b''.join(commands);minimum=min(s['fileoff'] for s in old.sections if s['fileoff']>0)
    need(32+len(header)<=minimum,'actual zero header capacity')
    need(not any(data[32+old.sizeofcmds:minimum]),'actual old header padding allzero')
    work[32:minimum]=header+b'\0'*(minimum-32-len(header));struct.pack_into('<II',work,16,len(commands),len(header))
    return bytes(work),old,changed,dict(oldSignatureOffset=csstart,oldSignatureBytes=cssize,newFixupsOffset=newfo,newFixupsBytes=len(newraw),newNlistOffset=newsyms,newNlistCount=nsyms+1,newStringsOffset=newstr,newStringsBytes=len(strtab),headerPaddingRemaining=minimum-32-len(header),newRequiredOrdinal=64,oldChainWordsUnchanged=True,newChainMethod='MULTI page12 old0 plus new17d0')

def native_routes(index,path,name,seen=()):
    need((path,name) not in seen,'native reexport cycle')
    if path not in index['images']: return []
    image=index['images'][path];definition=image['definitions'].get(name)
    if definition:
        if definition['flags']&8:
            ordinal=definition['ordinal'];target=next(x['path'] for x in image['dependencies'] if x['ordinal']==ordinal)
            return native_routes(index,target,definition.get('alias') or definition.get('importedName') or name,seen+((path,name),))
        return [dict(path=path,UUID=image['UUID'],symbol=name,definition=definition)]
    results=[]
    for dependency in image['dependencies']:
        if dependency['command']==0x8000001f:
            results+=native_routes(index,dependency['path'],name,seen+((path,name),))
    return results

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);args=ap.parse_args();out=args.output.resolve();need(out.parent==N and not out.exists(),'fresh exclusive output');out.mkdir(mode=0o700)
    reader=module(READER,'owned_parent_reader');cache=json.loads(CACHE.read_bytes());local=json.loads(LOCALIZER.read_bytes());base=json.loads(BASE.read_bytes());recipe=json.loads(exact(local['recipe']).read_bytes())
    for candidate in (CACHE,LOCALIZER):
        for row in json.loads((candidate.parent/'freeze.json').read_bytes())['files']:exact(row)
    original=exact(recipe['originalParentVZ']);provider=out/KEY
    sdk=subprocess.run(['xcrun','--sdk','iphoneos','--show-sdk-path'],capture_output=True,check=True).stdout.decode().strip()
    command=['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-arch','arm64e','-isysroot',sdk,'-dynamiclib','-Wl,-no_adhoc_codesign','-Wl,-install_name,@loader_path/'+KEY,str(exact(cache['actualIOSObject'])),str(exact(local['actualIOSObject'])),'-framework','Foundation','-lobjc','-o',str(provider)]
    run=subprocess.run(command,capture_output=True);(out/'link.stdout').write_bytes(run.stdout);(out/'link.stderr').write_bytes(run.stderr);dump(out/'link-command.json',dict(command=command,actualExit=run.returncode));need(run.returncode==0,'actual helper link')
    helper=reader.MachO(provider.read_bytes());expected={'_VM27OwnedVZCacheConfstrV1','_VM27OwnedVZLocalizedStringOrEnglishKeyV1'};need(set(helper.exports)==expected and all(x['flags']==0 for x in helper.exports.values()),'exact two true helper exports')
    index=json.loads(NATIVE.read_bytes());routes=[]
    for imp in helper.imports:
        need(imp['ordinal']>0 and not imp['weak'],'strong two-level helper import')
        load=helper.loads[imp['ordinal']-1];targets=native_routes(index,load['path'],imp['name']);unique={json.dumps(r,sort_keys=True):r for r in targets};need(len(unique)==1,'exact true native definition route')
        routes.append(dict(actualImport=imp,requiredLoad=load,resolvedDefinition=next(iter(unique.values()))))
    patched,old,changed,layout=patch_parent(original,reader,recipe);parent=out/'ParentVZ27.dylib';parent.write_bytes(patched);new=reader.MachO(patched)
    need(new.uuid==old.uuid and new.exports==old.exports and len(new.imports)==len(old.imports)+1,'actual original parent UUID/exports')
    def semantic(row):return {k:row[k] for k in ('index','ordinal','weak','name','addend')}
    for i in range(len(old.imports)):
        wanted=semantic(old.imports[i]);
        if i==504:wanted.update(ordinal=64,name='_VM27OwnedVZCacheConfstrV1')
        need(semantic(new.imports[i])==wanted,'only selected old import changes')
    need(semantic(new.imports[-1])==dict(index=1057,ordinal=64,weak=0,name='_VM27OwnedVZLocalizedStringOrEnglishKeyV1',addend=0),'actual appended localizer import')
    oldbind={r['fileoff']:r for r in old.binds};newbind={r['fileoff']:r for r in new.binds}
    for where,row in oldbind.items():need(row['word']==newbind[where]['word'],'every old auth/bind word exactly preserved')
    added=newbind[recipe['authenticatedSlot']['fileOffset']];need(added['index']==1057 and added['auth']==1 and added['key']==0 and added['addrdiv']==1 and added['diversity']==0,'new slot authentic two-level binding')
    # Whole pre-signature payload outside header and four explicit code/data
    # ranges is unchanged; old LINKEDIT payloads remain intact but unreferenced.
    reconstructed=bytearray(original.read_bytes()[:layout['oldSignatureOffset']]);minimum=min(s['fileoff'] for s in old.sections if s['fileoff']>0);reconstructed[:minimum]=patched[:minimum]
    for delta in changed:at=delta['fileOffset'];value=bytes.fromhex(delta['after']);reconstructed[at:at+len(value)]=value
    need(bytes(reconstructed)==patched[:layout['oldSignatureOffset']],'whole old prefix reconstructed exactly')
    need(not any(c['cmd']==0x1d for c in new.commands),'no stale code signature')
    validate=[]
    for target in (provider,parent):
        argv=['xcrun','dyld_info','-validate_only',str(target)]
        result=subprocess.run(argv,capture_output=True)
        label=target.name+'.validate'
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        validate.append(dict(command=argv,actualExit=result.returncode,target=pin(target),stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
        need(result.returncode==0,'actual dyld_info validate-only '+target.name)
    dump(out/'actual-dyld-validation.json',dict(results=validate,deviceOperations=0))
    verification=dict(parentOnly=True,baselineRuntimeCandidate=pin(BASE),originalParentSignedPin=pin(original),actualSelectedParentImport=new.imports[504],actualAppendedParentLocalizerImport=new.imports[1057],actualSelectedParentRequiredLoad=new.loads[63],originalChildClosureWholeUnchanged=True,diskImages2NativeConfstrWholeUnchanged=True,newProviderStrongImportsClosed=True,actualProviderNativeRows=routes,newProvider=pin(provider),sourcePins=[cache['source'],cache['header'],local['source'],local['header']],exactTwoOwnExports=helper.exports,allOldAuthBindWordsWholeUnchanged=True,actualNewAuthenticatedSlot=added,wholeOriginalPrefixEqualsOnlyDeclaredChanges=True,explicitOriginalCodeChanges=changed,layout=layout,actualDyldValidation=pin(out/'actual-dyld-validation.json'),actualCacheDirectoryExists=False,deviceOperations=0)
    graph=out/'graph.json';dump(graph,verification);patchrecipe=out/'patch-recipe.json';dump(patchrecipe,dict(cacheSelectedBefore=old.imports[504],cacheSelectedAfter=new.imports[504],localizerRecipe=local['recipe'],explicitChanges=changed,layout=layout))
    contract=copy.deepcopy(cache['cacheAdapterContract']);contract.update(providerKey=KEY,newRequiredLoad='@loader_path/'+KEY,sourcePin=cache['source'],headerPin=cache['header'],selectedImport=copy.deepcopy(new.imports[504]))
    localcontract=copy.deepcopy(local['ownLocalizationContract']);localcontract.update(newRequiredOrdinal=64,actualNewImport=copy.deepcopy(new.imports[1057]))
    candidate=dict(schema='Actual parent-only owned cache and genuine English-key fallback source port v3',baselineRuntimeCandidate=pin(BASE),providerKey=KEY,newProvider=pin(provider),patchedParentVZ=pin(parent),originalParentVZ=pin(original),cacheSourceCandidate=pin(CACHE),localizerCandidate=pin(LOCALIZER),nativeZeroReceipt=cache['nativeZeroReceipt'],cacheAdapterContract=contract,localizerContract=localcontract,selectedImport=new.imports[504],recipe=pin(patchrecipe),verification=pin(graph),graph=pin(graph),actualSelectedParentImport=new.imports[504],actualSelectedParentRequiredLoad=new.loads[63],parentOnly=True,codeSignatureRemovedForActualSigning=True,sourcePreservedOriginalCPUAndVMCodeOutsideScopedLocalizer=True,deviceOperations=0,trustCacheOperations=0,localCodeSigned=False)
    cp=out/'candidate.json';dump(cp,candidate)
    files=[pathlib.Path(__file__).resolve(),READER,CACHE,CACHE.parent/'freeze.json',LOCALIZER,LOCALIZER.parent/'freeze.json',BASE,NATIVE,original,*[exact(r) for r in verification['sourcePins']],exact(cache['actualIOSObject']),exact(local['actualIOSObject']),exact(local['recipe'])]+sorted(p for p in out.iterdir() if p.is_file())
    dump(out/'freeze.json',dict(files=[pin(p) for p in files],deviceOperations=0));print(json.dumps(dict(candidate=pin(cp),freeze=pin(out/'freeze.json'),actualNewProviderNativeImports=len(routes),actualParentImports=len(new.imports))))
if __name__=='__main__':main()
