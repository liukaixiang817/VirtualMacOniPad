#!/usr/bin/env python3
"""NEW static three-import route; never loads/signs/executes original VMM.

Reuse ordinal54 for a real zero-instruction aggregate. CheckIn90 stays54.
Only create/setoneshot/main change15->54; all original indexes/PAC/code survive.
Actual trusted caller invoking V2 Prepare before original Main remains pending.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE = N / 'vmm-client-services-original-route-v1/build-v1/VMM27.client-services-route.inert.macho-data'
SOURCE_SHA = '2c6cd1c869cd8dd95a2a41677a75bdf595b796ca5181f3ba9bc4a53ddde19bca'
READER = R / 'VirtualMac/scripts/development/vz_import_addend_image.py'
COMPILER_READER = N.parent / '2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py'
CHAIN_LAYOUT_HEADER = Path('/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.1.sdk/usr/include/mach-o/fixup-chains.h')
OLD_PATH = '@loader_path/VM27HeadlessCheckIn.dylib'
NEW_PATH = '@loader_path/VM27StartupV9.dylib'
SELECTED = {472: '_xpc_connection_create', 480: '_xpc_connection_set_oneshot_instance', 502: '_xpc_main'}
def sha(b): return hashlib.sha256(b).hexdigest()
def pin(p):
    b = p.read_bytes(); return dict(path=str(p.resolve()), bytes=len(b), sha256=sha(b))
def module(p, name):
    s = importlib.util.spec_from_file_location(name, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
M = module(READER, 'owned_v9_pure_macho')
def chains(b):
    """Bounded USERLAND24 format12 reader; SDK ordinal24/next11/stride8.

    Unlike the old VZ-only format9 helper, original VMM uses 24-bit bind indexes.
    No chain is rewritten. Unsupported multi-start/format variants are rejected.
    """
    info=M.imports(b); start=info['data']+info['header'][1]; end=info['data']+info['size']
    assert start+4<=end
    count=struct.unpack_from('<I',b,start)[0]; segments=M.segments(b)
    assert count==len(segments) and start+4+count*4<=end
    result=[]
    for index,segment in enumerate(segments):
        rel=struct.unpack_from('<I',b,start+4+index*4)[0]
        if not rel:continue
        at=start+rel; assert at+22<=end
        size,pageSize,fmt,segmentOffset,maxptr,pageCount=struct.unpack_from('<IHHQIH',b,at)
        assert fmt==12 and pageSize in (4096,16384) and size>=22+pageCount*2 and at+size<=end
        for page in range(pageCount):
            pageStart=struct.unpack_from('<H',b,at+22+page*2)[0]
            if pageStart==0xffff:continue
            assert not pageStart&0x8000 and pageStart<pageSize
            offset=segment['fileoff']+page*pageSize+pageStart
            pageEnd=min(segment['fileoff']+(page+1)*pageSize,segment['fileoff']+segment['filesize'])
            visited=set()
            while True:
                assert offset%8==0 and offset not in visited and offset+8<=pageEnd<=len(b)
                visited.add(offset);word=struct.unpack_from('<Q',b,offset)[0];bind=bool(word&(1<<62));auth=bool(word&(1<<63))
                ordinal=word&0xffffff if bind else None
                if bind:assert (word>>24)&255==0 and ordinal<len(info['imports'])
                result.append(dict(fileOffset=offset,word=word,bind=bind,auth=auth,importIndex=ordinal,format=fmt))
                delta=((word>>51)&0x7ff)*8
                if not delta:break
                offset+=delta
    return result
def nlists(b):
    rows = [(at,z) for c,at,z in M.commands(b) if c==2]; assert len(rows)==1
    symoff,count,stroff,strsize=struct.unpack_from('<4I',b,rows[0][0]+8)
    assert symoff+count*16<=len(b) and stroff+strsize<=len(b)
    result=[]
    for i in range(count):
        at=symoff+i*16; string,kind,sect,desc,value=struct.unpack_from('<IBBHQ',b,at)
        assert string<strsize
        result.append(dict(index=i,at=at,name=M.cstring(b,stroff+string,stroff+strsize),kind=kind,section=sect,descriptor=desc,value=value))
    return result
def metadata(b):
    assert len(b)>=32 and struct.unpack_from('<I',b)[0]==0xfeedfacf
    result=dict(header=list(struct.unpack_from('<8I',b)), dependencies=[],ID=None,rpaths=[],sections=[],exports=[],build=[],UUID=None,signatures=[])
    for c,at,z in M.commands(b):
        if c in (12,0x80000018,0x8000001f,0x80000023,13):
            off,stamp,cur,compat=struct.unpack_from('<4I',b,at+8); assert 24<=off<z
            row=dict(command=c,at=at,bytes=z,path=M.cstring(b,at+off,at+z),timestamp=stamp,currentVersion=cur,compatibilityVersion=compat)
            if c==13: assert result['ID'] is None; result['ID']=row
            else: row['ordinal']=len(result['dependencies'])+1; result['dependencies'].append(row)
        elif c==0x8000001c:
            off=struct.unpack_from('<I',b,at+8)[0]; result['rpaths'].append(M.cstring(b,at+off,at+z))
        elif c==0x1b: assert z==24; result['UUID']=b[at+8:at+24].hex()
        elif c==0x32: result['build']=list(struct.unpack_from('<4I',b,at+8))
        elif c==0x1d: result['signatures'].append(list(struct.unpack_from('<2I',b,at+8)))
        elif c==0x80000033:
            data,size=struct.unpack_from('<2I',b,at+8); assert data+size<=len(b); result['exports']=M.export_trie(b[data:data+size]) if size else []
    for segment in M.segments(b):
        for s in segment['sections']:
            result['sections'].append(dict(segment=segment['name'],name=s['name'],bytes=s['size'],fileoff=s['fileoff'],flags=s['flags']))
    return result
def graph_validate(directory):
    manifest=json.loads((directory/'candidate.json').read_text()); assert manifest['schema']=='NEW unsigned iOS V9 owned-startup provider graph v1'
    assert manifest['noOriginalImagesExecuted'] and not manifest['deviceOperations'] and not manifest['providerGraphExecuted']
    images={}
    for row in manifest['libraries']:
        p=directory/'ios'/row['name']; st=p.lstat(); b=p.read_bytes()
        assert stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_nlink==1 and (st.st_mode&0o777)==0o600
        assert len(b)==row['bytes'] and sha(b)==row['sha256']; images[row['name']]=metadata(b)
        if row['oldByteExactCopy']:
            actual=Path(row['source']); assert pin(actual)['sha256']==row['sha256'] and actual.read_bytes()==b
        else: assert not images[row['name']]['signatures']
    assert len(images)==13
    aggregate=images['VM27StartupV9.dylib']; assert aggregate['header'][3]==6 and aggregate['ID']['compatibilityVersion']==65536
    assert all(x['bytes']==0 for x in aggregate['sections'] if x['name']=='__text')
    assert not any(x['bytes'] for x in aggregate['sections'] if x['name'] in ('__mod_init_func','__init_offsets','__interpose','__objc_nlclslist','__objc_nlcatlist'))
    reexports=[x for x in aggregate['dependencies'] if x['command']==0x8000001f]
    assert {x['path'] for x in reexports}=={'@rpath/VM27OriginalV9Transport.dylib','@rpath/VM27OwnedStartupV2.dylib','@rpath/VM27HeadlessCheckIn.dylib'}
    for name,image in images.items():
        assert image['header'][1]==0x100000c and image['header'][2]&0xffffff==2 and image['header'][3]==6
        assert image['build'][0]==2
        assert not any(x['bytes'] for x in image['sections'] if x['name'] in ('__mod_init_func','__init_offsets','__interpose'))
        for dep in image['dependencies']:
            if dep['path'].startswith(('@rpath/','@loader_path/')):
                child=images[Path(dep['path']).name]; assert child['ID']['compatibilityVersion']>=dep['compatibilityVersion']
    v9=images['VM27OriginalV9Transport.dylib']; coord=images['VM27OwnedStartupV2.dylib']
    assert set(SELECTED.values())<={x['symbol'] for x in v9['exports']}
    assert '_xpc_connection_get_instance' in {x['symbol'] for x in v9['exports']}
    assert 'VM27ClientRegistration.dylib' in {Path(x['path']).name for x in v9['dependencies']}
    assert 'VM27HeadlessCheckIn.dylib' in {Path(x['path']).name for x in coord['dependencies']}
    assert 'VM27OriginalV9Transport.dylib' in {Path(x['path']).name for x in coord['dependencies']}
    assert {'VM27ClientRegistration.dylib','VM27PrivateProcessTitle.dylib'}=={Path(x['path']).name for x in images['VM27ClientServices.dylib']['dependencies'] if x['command']==0x8000001f}
    assert '__LSApplicationCheckIn' in {x['symbol'] for x in images['VM27HeadlessCheckIn.dylib']['exports']}
    assert 'VM27ClientRegistration.dylib' not in {Path(x['path']).name for x in coord['dependencies']} # accesses shared registration through V9 only
    return manifest,images
def transform(source):
    assert sha(source)==SOURCE_SHA and len(source)==5195312
    m=metadata(source); assert len(m['dependencies'])==54 and struct.unpack_from('<2I',source,16)==(70,8496)
    dep=m['dependencies'][53]; assert dep['command']==12 and dep['bytes']==64 and dep['path']==OLD_PATH
    assert (dep['timestamp'],dep['currentVersion'],dep['compatibilityVersion'])==(2,65536,65536)
    pathStart=dep['at']+24; assert len(NEW_PATH.encode())+1<=dep['bytes']-24
    target=bytearray(source); target[pathStart:dep['at']+dep['bytes']]=NEW_PATH.encode()+bytes(dep['bytes']-24-len(NEW_PATH.encode()))
    imports=M.imports(source)['imports']; assert len(imports)==1203
    assert imports[90]['name']=='__LSApplicationCheckIn' and imports[90]['ordinal']==54 and not imports[90]['weak'] and not imports[90]['addend']
    symbols=nlists(source); changes=[]
    for index,name in SELECTED.items():
        row=imports[index]; assert row['name']==name and row['ordinal']==15 and not row['weak'] and row['addend']==0
        matches=[x for x in symbols if x['name']==name]; assert len(matches)==1
        entry=matches[0]; assert entry['kind']&0x0e==0 and entry['descriptor']>>8==15
        original=struct.unpack_from('<I',source,row['command'])[0]; struct.pack_into('<I',target,row['command'],(original&~255)|54)
        struct.pack_into('<H',target,entry['at']+6,(entry['descriptor']&255)|(54<<8))
        changes.append(dict(importIndex=index,symbol=name,importOffset=row['command'],nlistIndex=entry['index'],nlistDescriptorOffset=entry['at']+6,oldOrdinal=15,newOrdinal=54,oldNlistDescriptor=entry['descriptor']))
    return bytes(target),dict(dependencyOrdinal=54,dependencyOffset=dep['at'],dependencyBytes=64,pathStart=pathStart,pathEnd=dep['at']+64,oldPath=OLD_PATH,newPath=NEW_PATH,imports=changes)
def verify(source,target,record):
    expected,expectedRecord=transform(source); assert target==expected and record==expectedRecord
    a,b=metadata(source),metadata(target); ai,bi=M.imports(source)['imports'],M.imports(target)['imports']
    assert a['header']==b['header'] and a['sections']==b['sections'] and a['signatures']==b['signatures'] and a['UUID']==b['UUID']
    assert len(a['dependencies'])==len(b['dependencies'])==54
    for i in range(54): assert b['dependencies'][i]==(dict(a['dependencies'][i],path=NEW_PATH) if i==53 else a['dependencies'][i])
    for i,row in enumerate(ai): assert bi[i]==(dict(row,ordinal=54) if i in SELECTED else row)
    an,bn=nlists(source),nlists(target); selectedNlists={x['nlistIndex'] for x in record['imports']}
    for i,row in enumerate(an): assert bn[i]==(dict(row,descriptor=(row['descriptor']&255)|(54<<8)) if i in selectedNlists else row)
    ac,bc=chains(source),chains(target); assert ac==bc
    allowed=set(range(record['pathStart'],record['pathEnd']))
    for row in record['imports']: allowed.update([row['importOffset'],row['nlistDescriptorOffset']+1])
    changed=[i for i,(x,y) in enumerate(zip(source,target)) if x!=y]; assert set(changed)<=allowed
    assert len([i for i in changed if i>=8528])==6
    # All source bytes outside the precise path field and six ordinal bytes equal.
    return dict(changedByteOffsets=changed,allowedByteOffsets=sorted(allowed),changedAfterOriginalTextStart=6,wholeFileOutsideAllowedExact=True,originalCodeDataAndAuthenticatedChainsExact=True,chainWords=len(ac),selectedImports=list(SELECTED),importCount=1203,strongImportCount=sum(not x['weak'] for x in ai),originalCheckInImport90Unchanged=True,originalClientServicesOrdinal5Unchanged=True,dependencyCount=54,headerCountsOffsetsAndLoadCommandSizeExact=True,signatureStale=True,executed=False)
def inverse(source,target,record):
    verify(source,target,record); restored=bytearray(target)
    restored[record['pathStart']:record['pathEnd']]=source[record['pathStart']:record['pathEnd']]
    for row in record['imports']:
        restored[row['importOffset']]=15; struct.pack_into('<H',restored,row['nlistDescriptorOffset'],row['oldNlistDescriptor'])
    assert bytes(restored)==source and sha(restored)==SOURCE_SHA; return bytes(restored)
def main():
    assert sys.flags.optimize==0
    ap=argparse.ArgumentParser(); ap.add_argument('--provider-graph',type=Path,required=True); ap.add_argument('--output',type=Path,required=True); args=ap.parse_args()
    graph=args.provider_graph.resolve(); manifest,images=graph_validate(graph)
    out=args.output.resolve(); out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=SOURCE.read_bytes(); target,record=transform(source); proof=verify(source,target,record)
    original=out/'roundtrip-source.inert.macho-data'; original.write_bytes(inverse(source,target,record)); original.chmod(0o600)
    binary=out/'VMM27.owned-xpc-v9-route.inert.macho-data'; binary.write_bytes(target); binary.chmod(0o600)
    bad=[]
    controls=[('original-instruction',8528),('header-count',16),('header-size',20),('other-dependency-path',4344),('new-provider-path',record['pathStart']),('unselected-import90',M.imports(source)['imports'][90]['command'])]
    controls += [(f"selected-import-{x['importIndex']}",x['importOffset']) for x in record['imports']]
    controls += [(f"selected-nlist-{x['nlistIndex']}",x['nlistDescriptorOffset']) for x in record['imports']]
    controls += [('authenticated-chain-word',next(x['fileOffset'] for x in chains(source) if x['auth'] and x['bind']))]
    for label,at in controls:
        damaged=bytearray(target); damaged[at]^=1
        try: inverse(source,bytes(damaged),record)
        except (AssertionError,ValueError,IndexError,struct.error,UnicodeError): bad.append(dict(name=label,fileOffset=at,rejected=True))
        else: raise AssertionError(label+' accepted')
    processes=[]
    for label,option in [('metadata','-validate_only'),('imports','-imports'),('dependencies','-linked_dylibs')]:
        argv=['/usr/bin/xcrun','dyld_info',option,str(binary)]; child=subprocess.run(argv,capture_output=True,timeout=25)
        (out/(label+'.argv.json')).write_text(json.dumps(argv,indent=2)+'\n'); (out/(label+'.stdout')).write_bytes(child.stdout); (out/(label+'.stderr')).write_bytes(child.stderr)
        processes.append(dict(label=label,argv=argv,exit=child.returncode)); assert child.returncode==0 and not child.stderr
    c=dict(schema='NEW original-VMM 3-XPC same-CheckIn static route v1',builder=pin(Path(__file__)),pureReader=pin(READER),compilerPureReader=pin(COMPILER_READER),format12SDKLayout=pin(CHAIN_LAYOUT_HEADER),source=pin(SOURCE),binary=pin(binary),roundtripSource=pin(original),providerGraphManifest=pin(graph/'candidate.json'),providerGraphFreeze=pin(graph/'freeze.json'),transform=record,verification=proof,negativeControls=bad,metadataProcesses=processes,originalVMMExecuted=False,providerGraphExecuted=False,deviceOperations=False,signingCalls=0,guestInstructions=0,full27Backend=False,originalMainAndEntryBytesUnchanged=True,coordinatorPrepareAutomaticallyInvoked=False,trustedPreMainCallerIntegrated=False,originalHandlerNativeRoleGateValidated=False,completeStrongLoadClosureValidated=False,remainingStrictLargeKernelCDHashResultGap=True)
    (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n'); (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(out.iterdir()) if p.is_file()]),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),binary=pin(binary),controls=len(bad),noOriginalExecution=True)))
if __name__=='__main__': main()
