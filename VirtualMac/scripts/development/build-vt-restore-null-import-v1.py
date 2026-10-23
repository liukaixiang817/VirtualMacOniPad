#!/usr/bin/env python3
"""Bind the genuine restore-only weak VT call to the owned availability gate."""
from pathlib import Path
import importlib.util,json,struct,subprocess,copy
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
O=N/'native-vt-restore-md-v27-attempt3'
spec=importlib.util.spec_from_file_location('rt',Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py'));rt=importlib.util.module_from_spec(spec);spec.loader.exec_module(rt)
pin=rt.pin

def patch_child(source,dest):
    raw=source.read_bytes();m=rt.m.MachO(raw)
    assert m.uuid=='4a6a588d1afd30f5a64d6304eb79be0b'
    oldname='_VTParavirtualizationHostSessionCreateTerminateAllSessionsMessage';newname='_VM27OwnedVTCreateTerminateMessageV2'
    rows=[r for r in m.imports if r['name']==oldname];assert len(rows)==1
    row=rows[0];index=row['index'];assert row['weak']==1 and not row['addend']
    assert m.loads[2]['path']=='@loader_path/MD' and m.loads[2]['cmd']==12
    binds=[r for r in m.binds if r['index']==index];assert len(binds)==1 and binds[0]['fileoff']==0x4c62c0
    assert binds[0]['auth']==1 and binds[0]['key']==0 and binds[0]['addrdiv']==1 and binds[0]['diversity']==0
    signature=next(c for c in m.commands if c['cmd']==0x1d);cs,size=struct.unpack_from('<II',signature['raw'],8);assert cs+size==len(raw)
    fix=next(c for c in m.commands if c['cmd']==0x80000034);off,size=struct.unpack_from('<II',fix['raw'],8)
    fx=bytearray(raw[off:off+size]);version,starts,imports,symbols,count,fmt,sfmt=struct.unpack_from('<7I',fx)
    assert version==0 and count==len(m.imports) and fmt==2 and sfmt==0
    entry=imports+8*index;word,addend=struct.unpack_from('<Ii',fx,entry)
    assert (word&255)==row['ordinal'] and ((word>>8)&1)==1 and addend==0
    at=len(fx)-symbols;assert at<(1<<23)
    struct.pack_into('<I',fx,entry,(at<<9)|3);fx.extend(newname.encode()+b'\0')
    output=bytearray(raw[:cs]);align=lambda x:(x+7)&~7
    output.extend(b'\0'*(align(len(output))-len(output)));newfix=len(output);output.extend(fx)
    sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strings,stringsize=struct.unpack_from('<4I',sym['raw'],8)
    tab=bytearray(raw[sy:sy+16*ns]);oldstrings=raw[strings:strings+stringsize];found=0
    for i in range(ns):
        strx,typ,sect,desc,value=struct.unpack_from('<IBBHQ',tab,16*i)
        name=oldstrings[strx:oldstrings.find(b'\0',strx)].decode()
        if name==oldname:
            assert typ==1 and sect==0 and value==0 and (desc&0x40);found+=1
            struct.pack_into('<IBBHQ',tab,16*i,len(oldstrings),typ,sect,(desc&0xff&~0x40)|(3<<8),value)
    assert found==1
    output.extend(b'\0'*(align(len(output))-len(output)));newsym=len(output);output.extend(tab)
    newstr=len(output);output.extend(oldstrings+newname.encode()+b'\0');commands=[]
    for cmd in m.commands:
        if cmd['cmd']==0x1d:continue
        data=bytearray(cmd['raw'])
        if cmd['cmd']==0x80000034:struct.pack_into('<II',data,8,newfix,len(fx))
        if cmd['cmd']==2:struct.pack_into('<4I',data,8,newsym,ns,newstr,len(oldstrings)+len(newname)+1)
        if cmd['cmd']==0x19 and data[8:24].rstrip(b'\0')==b'__LINKEDIT':
            fileoff=struct.unpack_from('<Q',data,40)[0];extent=len(output)-fileoff
            struct.pack_into('<Q',data,32,(extent+16383)&~16383);struct.pack_into('<Q',data,48,extent)
        commands.append(bytes(data))
    header=b''.join(commands);assert len(header)<=m.sizeofcmds
    output[32:32+m.sizeofcmds]=header+b'\0'*(m.sizeofcmds-len(header));struct.pack_into('<II',output,16,len(commands),len(header))
    q=rt.m.MachO(output);assert q.uuid==m.uuid and q.exports==m.exports
    assert [(x['path'],x['cmd'])for x in q.loads]==[(x['path'],x['cmd'])for x in m.loads]
    assert len(q.imports)==len(m.imports)
    for before,after in zip(m.imports,q.imports,strict=True):
        if before['index']==index:assert after['name']==newname and after['ordinal']==3 and not after['weak'] and not after['addend']
        else:assert all(before[k]==after[k]for k in ['index','ordinal','weak','name','addend'])
    assert m.binds==q.binds or all(a['word']==b['word'] and a['fileoff']==b['fileoff'] for a,b in zip(m.binds,q.binds,strict=True))
    for sec in m.sections:
        at,size=sec['fileoff'],sec['size']
        if at and size and sec['flags']&255 not in (1,12,18):assert output[at:at+size]==raw[at:at+size]
    dest.write_bytes(output)
    return dict(original=pin(source),patched=pin(dest),originalImport=row,newImport=q.imports[index],authSlotRVA=0x4c62c0,allOriginalSectionsAndAuthWordsWhole=True,onlyOneImportMetadataRowRebound=True)

def main():
    O.mkdir(mode=0o700);commands=[]
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=90)
        (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));rt.save(O/'commands.json',commands)
        assert not p.returncode,p.stderr.decode()
    oldpath=N/'independent27-signed-runtime-hibernate-fatal-v173-attempt1/candidate.json';old=json.loads(oldpath.read_bytes())
    import plistlib
    rows={r['id']:r for r in plistlib.loads(Path(old['manifest']['path']).read_bytes())['files']};root=Path(old['runtimeRoot'])
    recipe=json.loads((N/'native-hibernate-fatal-md-v26-attempt1/commands.json').read_bytes())
    args=json.loads((N/'owned-vt-host-unavailable-source-port-v1-attempt1/compile.json').read_bytes())['command'][:]
    source=S/'vm27_owned_vt_host_unavailable_v2.c';obj=O/'VT.o';args[args.index('-c')+1]=str(source);args[args.index('-o')+1]=str(obj);args[args.index('-miphoneos-version-min=16.1')]='-miphoneos-version-min=15.0';run('compile-vt',args)
    args=next(r['argv'][:]for r in recipe if r['label']=='link-md');vtold=[x for x in args if x.endswith('vm27_owned_vt_host_unavailable_v1.o')];assert len(vtold)==1;args[args.index(vtold[0])]=str(obj)
    exportsarg=next(x for x in args if x.startswith('-Wl,-exported_symbols_list,'));oldexports=Path(exportsarg.split(',',2)[2]);exports=O/'exports.txt';exports.write_text(oldexports.read_text().rstrip()+'\n_VM27OwnedVTCreateTerminateMessageV2\n')
    args[args.index(exportsarg)]='-Wl,-exported_symbols_list,'+str(exports);md=O/'MD';args[args.index('-o')+1]=str(md);run('link-md',args)
    args=next(r['argv'][:]for r in recipe if r['label']=='normalize-md');args[-1]=str(md);run('normalize-md',args)
    oldMD=rt.image_profile((root/rows['child:MD']['path']).read_bytes(),'MD');newMD=rt.image_profile(md.read_bytes(),'MD')
    assert newMD.imports==oldMD.imports and newMD.loads==oldMD.loads
    assert set(newMD.exports)==set(oldMD.exports)|{'_VM27OwnedVTCreateTerminateMessageV2'}
    child=O/'com.apple.Virtualization.VirtualMachine';proof=patch_child(root/rows['child:main']['path'] if 'child:main'in rows else root/rows[plistlib.loads(Path(old['manifest']['path']).read_bytes())['childEntryContract']['childID']]['path'],child)
    run('validate-md',['xcrun','dyld_info','-validate_only',md]);run('validate-child',['xcrun','dyld_info','-validate_only',child])
    prior=json.loads((N/'native-hibernate-fatal-md-v26-attempt1/candidate.json').read_bytes())
    sources=prior['sources']+[pin(source),pin(S/'vm27_owned_vt_host_unavailable_v1.c'),pin(__file__),pin(obj)]
    result=dict(schema='MD27 same native availability gate for restore-only terminate-all weak import',baseline=pin(oldpath),md=pin(md),patchedChild=pin(child),childImportBinding=proof,sources=sources,
        comparisons=[dict(provider='child:MD',addedImports=[],addedExports=['_VM27OwnedVTCreateTerminateMessageV2'],actualImports=newMD.imports,actualLoads=newMD.loads,actualExports=newMD.exports)],
        serializedStateFormatUnchanged=True,CPU98GIC19GPU24Whole=True,deviceOperations=0)
    rt.save(O/'candidate.json',result);print(json.dumps(pin(O/'candidate.json')))
if __name__=='__main__':main()
