#!/usr/bin/env python3
"""Independent bounded reconstruction and incremental graph review, HOST only."""
import argparse, hashlib, importlib.util, json, pathlib, struct, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CHILD='com.apple.Virtualization.VirtualMachine'
NEW='_VM27SandboxInitWithOwnedCompilerV1'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--candidate',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
    o=a.output.resolve();assert o.is_relative_to(N)and not o.exists()
    c=json.loads(a.candidate.read_bytes());directory=a.candidate.parent
    for row in json.loads((directory/'freeze.json').read_bytes())['files']:
        assert pin(row['path'])=={k:row[k]for k in('path','bytes','sha256')},row
    prior=pathlib.Path(c['baseStage']['path']);assert pin(prior)==c['baseStage'];base=json.loads(prior.read_bytes())
    reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    assert pin(reader)['sha256']=='64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'
    spec=importlib.util.spec_from_file_location('stage_peer_reader',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    old={x['key']:x for x in base['stagedImages']};now={x['key']:x for x in c['stagedImages']}
    newkeys={'VM27GenuineSandboxCompiler27.dylib','VM27GenuineMatch27.dylib',
             'VM27SandboxCompilerImportsCompatV1.dylib','VM27SandboxInitOwnedCompilerV1.dylib'}
    assert len(old)==73 and len(now)==77 and set(now)==set(old)|newkeys
    unchanged=[]
    for key,row in now.items():
        assert pin(row['staged']['path'])==row['staged']
        if key in old and key!=CHILD:
            assert pathlib.Path(row['staged']['path']).read_bytes()==pathlib.Path(old[key]['staged']['path']).read_bytes()
            unchanged.append(key)
        elif key in newkeys:
            assert pathlib.Path(row['staged']['path']).read_bytes()==pathlib.Path(row['source']['path']).read_bytes()
    assert len(unchanged)==72
    before=pathlib.Path(old[CHILD]['staged']['path']).read_bytes()
    actual=pathlib.Path(now[CHILD]['staged']['path']).read_bytes()
    im=m.MachO(before);out=m.MachO(actual)
    assert im.uuid==out.uuid=='4a6a588d1afd30f5a64d6304eb79be0b'
    # Construct expected output from original bytes and LP64 Mach-O fields,
    # without invoking the author merger or its change_child function.
    end=32+struct.unpack_from('<I',before,20)[0]
    dependency=b'@loader_path/VM27SandboxInitOwnedCompilerV1.dylib\0'
    lcsize=(24+len(dependency)+7)&~7
    assert lcsize==80 and not any(before[end:end+lcsize])
    first=min(s['fileoff']for s in im.sections if s['fileoff']and s['size']and s['flags']&255 not in(1,12,18))
    assert end+lcsize<=first
    cmd=next(x for x in im.commands if x['cmd']==0x80000034)
    off,length=struct.unpack_from('<II',before,cmd['at']+8)
    payload=before[off:off+length];v,starts,imports,names,count,form,fmt=struct.unpack_from('<7I',payload)
    assert(v,form,fmt)==(0,2,0)and count==len(im.imports)
    imp=im.imports[428];assert imp['name']=='_sandbox_init_with_parameters'and imp['ordinal']==15 and not imp['weak']and imp['addend']==0
    table=bytearray(payload);word=struct.unpack_from('<I',table,imports+428*8)[0]
    struct.pack_into('<I',table,imports+428*8,((len(table)-names)<<9)|(word&0x100)|57)
    table.extend(NEW.encode()+b'\0')
    expected=bytearray(before)
    expected[end:end+lcsize]=struct.pack('<6I',12,lcsize,24,0,0,0)+dependency+bytes(lcsize-24-len(dependency))
    struct.pack_into('<II',expected,16,im.ncmds+1,im.sizeofcmds+lcsize)
    appended=(len(expected)+15)&~15;expected.extend(bytes(appended-len(expected)));expected.extend(table)
    struct.pack_into('<II',expected,cmd['at']+8,appended,len(table))
    le=next(x for x in im.commands if x['cmd']==0x19 and before[x['at']+8:x['at']+24].rstrip(b'\0')==b'__LINKEDIT')
    leoff=struct.unpack_from('<Q',before,le['at']+40)[0]
    struct.pack_into('<Q',expected,le['at']+32,(len(expected)-leoff+16383)&~16383)
    struct.pack_into('<Q',expected,le['at']+48,len(expected)-leoff)
    assert bytes(expected)==actual and actual[off:off+length]==payload
    assert im.sections==out.sections and im.exports==out.exports and im.loads==out.loads[:-1]
    binds=[dict(b,name=NEW if b['index']==428 else b['name'])for b in im.binds]
    assert binds==out.binds
    for s in im.sections:
        at,z=s['fileoff'],s['size']
        if at and z and s['flags']&255 not in(1,12,18):assert before[at:at+z]==actual[at:at+z]
    for x,y in zip(im.imports,out.imports):
        wanted=dict(x,at=y['at'])
        if x['index']==428:wanted.update(name=NEW,ordinal=57)
        assert wanted==y
    for resource in c['genuineSandboxResources']:
        assert pin(resource['local']['path'])==resource['local']
        assert pathlib.Path(resource['local']['path']).read_bytes()==pathlib.Path(resource['source']['path']).read_bytes()
        assert resource['runtimeRelativePath']=='child-flat/'+resource['childFlatRelativePath']
        assert resource['childFlatRelativePath'].startswith('VMM.bundle/Contents/XPCServices/'+CHILD+'.xpc/Contents/Resources/')
    proof=json.loads((directory/'verification.json').read_bytes())
    baselinepath=pathlib.Path(proof['inheritedExactPreviousVerification']['path'])
    assert pin(baselinepath)==proof['inheritedExactPreviousVerification'];baseline=json.loads(baselinepath.read_bytes())
    images={CHILD:out}
    def image(key):
        if key not in images:images[key]=m.MachO(pathlib.Path(now[key]['staged']['path']).read_bytes())
        return images[key]
    index=N/'current-native-header-export-index-v3/index.json'
    assert pin(index)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    native=json.loads(index.read_bytes())['images'];used=set()
    def location(path):
        if path in native:return('native',path)
        if path.startswith('@loader_path/')and path[13:]in now:return('own',path[13:])
        raise KeyError(path)
    def resolve(kind,key,symbol,seen=()):
        assert(kind,key,symbol)not in seen;seen=(*seen,(kind,key,symbol))
        obj=native[key]if kind=='native'else image(key)
        if kind=='native':used.add(key)
        exports=obj['definitions']if kind=='native'else obj.exports
        deps=obj['dependencies']if kind=='native'else[dict(ordinal=d['ordinal'],path=d['path'],command=d['cmd'])for d in obj.loads]
        d=exports.get(symbol)
        if d is not None:
            if d['flags']&8:
                p=next(x for x in deps if x['ordinal']==d['ordinal'])
                return resolve(*location(p['path']),d.get('alias',d.get('importedName',''))or symbol,seen)
            return dict(kind=kind,path=key,symbol=symbol,UUID=obj['UUID']if kind=='native'else obj.uuid,actualExport=d)
        for dep in deps:
            if dep['command']==0x8000001f:
                try:return resolve(*location(dep['path']),symbol,seen)
                except KeyError:pass
        raise KeyError((kind,key,symbol))
    increment=json.loads((directory/'incremental-229-definition-rows.json').read_bytes());assert len(increment)==229
    actualrows=[]
    for row in increment:
        key=row['importer'];x=row['actualImport'];assert image(key).imports[x['index']]==x
        dep=next(d for d in image(key).loads if d['ordinal']==x['ordinal'])
        result=resolve(*location(dep['path']),x['name'])
        final=row['resolution']['route'][-1]
        assert all(result[k]==final[k]for k in('kind','path','symbol','UUID','actualExport')),(result,final)
        actualrows.append(dict(importer=key,index=x['index'],symbol=x['name'],final=result))
    previous={(r['importer'],r['actualImport']['index']):r for r in baseline['actualStrongImportRows']}
    joined={(r['importer'],r['actualImport']['index']):r for r in proof['actualStrongImportRows']}
    assert len(previous)==5432 and len(joined)==5660
    for identity,row in previous.items():
        current=joined[identity]
        if identity==(CHILD,428):assert current==increment[0]
        else:
            expected=json.loads(json.dumps(row))
            if identity[0]==CHILD:expected['actualImport']=out.imports[identity[1]]
            assert expected==current
    assert all(joined[(r['importer'],r['actualImport']['index'])]==r for r in increment)
    assert len(proof['actualNativeWeakDefinitionRows'])==13 and proof['actualStrongImports']==5673
    for resource in c['genuineSandboxResources']:assert resource['mode']==0o600
    assert c['HELDUntilActualNativeApplyAndOracle']and not c['readyForDeviceExecution']
    findings=[]
    if c['fixedOwnedCompilerDlopenPath'].endswith('/child-flat/VM27GenuineSandboxCompiler27.dylib'):
        findings.append(dict(id='dynamic-compiler-package-path',priority=1,
            detail='The adapter fixed dlopen path is child-flat root, while the genuine runtime assembler copies every child dependency into the XPC Contents/MacOS directory. A new adapter/Stage version must align with that actual packaging path. No runtime execution has occurred.'))
    o.mkdir()
    inputs=[pin(pathlib.Path(__file__)),pin(a.candidate),pin(directory/'freeze.json'),pin(directory/'verification.json'),pin(directory/'incremental-229-definition-rows.json'),pin(prior),pin(baselinepath),pin(reader),pin(index)]
    for key in sorted(used):
        for name in('actualCompleteCommands','actualCompleteExportSource'):
            p=native[key].get(name)
            if isinstance(p,dict)and'path'in p:
                q=pin(p['path']);assert all(q[k]==p[k]for k in('path','bytes','sha256'));inputs.append(q)
    report=dict(schema='Independent HELD sandbox stage finite reconstruction and229 incremental resolution peer',
        finiteLocalScopePassed=not findings,finiteOriginalByteDeltaAnd229ClosurePassed=True,findings=findings,
        stageCandidate=pin(a.candidate),stageFreeze=pin(directory/'freeze.json'),actualImages=77,
        originalOther72ImagesWholeByteUnchanged=True,newFourImagesExactInputs=True,
        actualChildWholeOutputIndependentlyReconstructed=True,originalBackedSectionsAndPACWordsPreserved=True,
        actualSelectedImportIndex=428,actualSelectedOrdinal=57,actualRequiredLoadBytes=80,
        actualHeaderEnd=end+lcsize,firstOriginalSection=first,actualIncrementalResolvedImports=229,
        inheritedPrevious5432NormalDefinitionsNotReResolved=True,joinedNormalStrongImports=5660,
        inheritedNativeWeakDefinitions=13,joinedStrongDefinitionsIncludingWeak=5673,
        nativeApplyCompatibilityVerified=False,HELD=True,readyForDeviceExecution=False,
        deviceOperations=0,signingExecuted=False,actualNativeApplyExecuted=False,
        actualFiniteImportRows=actualrows,inputs=inputs)
    save(o/'review.json',report);save(o/'freeze.json',dict(files=inputs+[pin(o/'review.json')]))
    print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=findings)))
if __name__=='__main__':main()
