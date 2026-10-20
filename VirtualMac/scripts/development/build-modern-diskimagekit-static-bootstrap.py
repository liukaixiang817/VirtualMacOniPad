#!/usr/bin/env python3
"""Build isolated two-phase DIKit27 loader and Mac oracle; no device work.

This changes the single StaticArray CN import into a deliberately invalid private
sentinel. All original non-CN strong dependencies remain required. The internal
loader completes real Swift metadata and authenticates/repairs three ISA slots
before returning a DIKit handle. This is new private compatibility semantics.
"""
import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import shutil
import struct
import subprocess
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parents[3]
    host=root/'VirtualMac/vz/host'
    diagnostics=root/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(root/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'))
    from compiler_image import commands,segments,imports,chain_entries
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    logs=[]
    def run(label,argv,expected=0,timeout=60):
        argv=list(map(str,argv));result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
        logs.append({'label':label,'argv':argv,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        (out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
        assert result.returncode==expected,(label,result.returncode,result.stderr,result.stdout)
        return result
    def sign(path):
        run('sign-'+path.name,['codesign','--force','--sign','-','--timestamp=none',path])
        run('strict-'+path.name,['codesign','--verify','--strict',path])
        run('dyld-'+path.name,['xcrun','dyld_info','-validate_only','-imports','-inits',path])
    def remove_signature(b):
        cmdlist=list(commands(b));sig=next(at for cmd,at,n in cmdlist if cmd==0x1d)
        signatureOffset=struct.unpack_from('<I',b,sig+8)[0];b=b[:signatureOffset]
        oldEnd=32+struct.unpack_from('<I',b,20)[0]
        kept=[bytes(b[at:at+n])for cmd,at,n in cmdlist if cmd!=0x1d];joined=b''.join(kept)
        b[32:oldEnd]=joined+bytes(oldEnd-32-len(joined));struct.pack_into('<II',b,16,len(kept),len(joined))
        return b
    def resize_linkedit(b):
        for cmd,at,n in commands(b):
            if cmd==0x19 and bytes(b[at+8:at+24]).split(b'\0')[0]==b'__LINKEDIT':
                start=struct.unpack_from('<Q',b,at+40)[0];size=len(b)-start
                struct.pack_into('<Q',b,at+32,(size+16383)&~16383);struct.pack_into('<Q',b,at+48,size)
    oldCN='_$ss20__StaticArrayStorageCN';newCN='_VM27StaticArrayUninitializedISA'
    arrayManifest=json.loads((diagnostics/'swift-anyobject-array-build-v5/manifest.json').read_text())
    arrayNames={'_'+q for q in arrayManifest['exports']}
    assert len(arrayNames)==8
    lookupNames={'_swift_getTypeByMangledNameInContext2','_swift_getTypeByMangledNameInContextInMetadataState2'}
    lookupSource=root/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-lookup-wrapper-native-candidate-v1/candidate/lookup_wrapper.ios.dylib'
    assert sha(lookupSource)=='d9b1f6d932a035a68de125c0523b902c5248680899b83576c77fdc3f12180914'
    frozen=diagnostics/'diskimagekit-scoped-cvw-image-v9'
    freeze=json.loads((frozen/'manifest.json').read_text())
    original=json.loads((diagnostics/'diskimagekit-contract-v1/original-identity-imports-initializers.json').read_text())
    authSource=diagnostics/'diskimagekit-bootstrap-requirement-auth-oracle-v1/original-got-contract.json'
    authRows=[q for q in json.loads(authSource.read_text())if q['labels']==['resilientRequirement']]
    assert len(authRows)==20 and all(q['auth']==1 and q['key']==2 and q['diversity']=='0x7d4c'and q['addressDiversity']==1 for q in authRows)
    files=[];routes=[];inputs=[];macRun={}
    sourceFiles=[host/'modern_swift_static_array_bootstrap.cpp',host/'modern_swift_static_array_bootstrap.h',host/'modern_swift_static_array_bootstrap_probe.cpp',host/'modern_swift_static_array_dik_fixture.swift',pathlib.Path(__file__)]
    inputs.extend({'path':str(p),'sha256':sha(p)}for p in sourceFiles)
    inputs.append({'path':str(authSource),'sha256':sha(authSource)})
    (out/'bootstrap-exports.txt').write_text('_VM27StaticArrayUninitializedISA\n_VM27StaticArrayBootstrapLoad\n')
    for role,target,sdkname in [('mac','arm64e-apple-macos13.0','macosx'),('ios','arm64e-apple-ios16.1','iphoneos')]:
        directory=out/role;directory.mkdir()
        source=frozen/role/'DiskImageKit27.dylib';assert sha(source)==next(q['sha256']for q in freeze['files']if q['role']==role)
        before=source.read_bytes();b=remove_signature(bytearray(before));oldImports=imports(before)['imports'];info=imports(b)
        oldChains=list(chain_entries(before));requirementRepairs=[]
        for row in authRows:
            site=next(q for q in oldChains if q['address']==row['newSlotVA'])
            assert site['symbol']==row['symbol']and site['bind']and not site['auth']and (site['word']>>32&0x7ffff)==0
            repaired=site['word']|(1<<63)|(0x7d4c<<32)|(1<<48)|(2<<49)
            struct.pack_into('<Q',b,site['fileoff'],repaired)
            requirementRepairs.append({'symbol':row['symbol'],'originalCacheSlot':row['originalSlotVA'],'candidateFileoff':site['fileoff'],'candidateRVA':site['address']-0x100000000,'beforeWord':site['word'],'afterWord':repaired,'key':2,'diversity':0x7d4c,'addressDiversity':True})
        pool=bytearray(b[info['data']+info['header'][3]:info['data']+info['size']])
        words=bytearray(b[info['data']+info['header'][2]:info['data']+info['header'][2]+len(oldImports)*4])
        newDeps=['@loader_path/VM27StaticArrayBootstrap.dylib','@loader_path/VM27AnyObjectArray.dylib']
        if role=='ios':newDeps.append('@loader_path/VM27SwiftLookup.dylib')
        oldLoads=[(cmd,at,n)for cmd,at,n in commands(b)if cmd in(12,0x80000018,0x8000001f,0x80000023)];assert len(oldLoads)==13
        changed=[]
        for row in oldImports:
            afterName=row['name'];ordinal=row['ordinal']
            if row['name']==oldCN:afterName=newCN;ordinal=14
            elif row['name']in arrayNames:ordinal=15
            elif role=='ios' and row['name']in lookupNames:ordinal=16
            if afterName!=row['name']or ordinal!=row['ordinal']:
                assert row['ordinal']==5 and not row['weak']
                offset=len(pool);pool+=afterName.encode()+b'\0'
                struct.pack_into('<I',words,row['index']*4,(offset<<9)|ordinal)
                changed.append({'symbolBefore':row['name'],'symbolAfter':afterName,'index':row['index'],'beforeOrdinal':5,'afterOrdinal':ordinal,'strong':True})
        assert sum(q['symbolBefore']==oldCN for q in changed)==1
        assert sum(q['symbolBefore']in arrayNames for q in changed)==8
        if role=='ios':assert sum(q['symbolBefore']in lookupNames for q in changed)==2
        prefix=bytearray(b[info['data']:info['data']+info['header'][2]])
        struct.pack_into('<I',prefix,12,len(prefix)+len(words))
        blob=prefix+words+pool
        # Keep imported symbol-table spelling consistent with the new private
        # CN semantics without moving any original code or data section.
        symcmd=next(at for cmd,at,n in commands(b)if cmd==2)
        symoff,nsyms,stroff,strsize=struct.unpack_from('<4I',b,symcmd+8)
        strings=bytearray(b[stroff:stroff+strsize]);newStr=len(strings);strings+=newCN.encode()+b'\0';renamed=0
        for i in range(nsyms):
            at=symoff+i*16;strx,typ,section,desc,value=struct.unpack_from('<IBBHQ',b,at)
            name=bytes(strings[strx:strings.find(b'\0',strx)]).decode()
            if name==oldCN and not(typ&0xe):struct.pack_into('<I',b,at,newStr);struct.pack_into('<H',b,at+6,(desc&255)|(14<<8));renamed+=1
        # StaticArray CN is an optimized-cache fixup import, not an original
        # nlist row in this exact image. No invented original ordinal is claimed.
        assert renamed==0
        for row in changed:
            if row['symbolBefore']==oldCN:continue
            for i in range(nsyms):
                at=symoff+i*16;strx,typ,section,desc,value=struct.unpack_from('<IBBHQ',b,at)
                name=bytes(strings[strx:strings.find(b'\0',strx)]).decode()
                if name==row['symbolBefore'] and not(typ&0xe):struct.pack_into('<H',b,at+6,(desc&255)|(row['afterOrdinal']<<8))
        if renamed:
            newStringOffset=len(b);b+=strings;struct.pack_into('<II',b,symcmd+16,newStringOffset,len(strings))
        newFixupOffset=len(b);b+=blob
        fixupcmd=next(at for cmd,at,n in commands(b)if cmd==0x80000034);struct.pack_into('<II',b,fixupcmd+8,newFixupOffset,len(blob))
        # No section or instruction moves. Three unused zero-length ObjC
        # string-section headers supply header space for positive providers.
        # All N_SECT indexes are precisely adjusted to the remaining sections.
        emptyNames={b'__objc_classname',b'__objc_methname',b'__objc_methtype'}
        cmdlist=[];oldSection=0;newSection=0;sectionMap={};removed=[]
        for cmd,at,n in commands(b):
            raw=bytearray(b[at:at+n])
            if cmd==0x19:
                count=struct.unpack_from('<I',raw,64)[0];kept=[]
                for i in range(count):
                    s=bytes(raw[72+i*80:72+(i+1)*80]);oldSection+=1
                    name=s[:16].split(b'\0')[0]
                    if name in emptyNames:
                        assert bytes(raw[8:24]).split(b'\0')[0]==b'__TEXT' and struct.unpack_from('<Q',s,40)[0]==0
                        removed.append(name.decode());continue
                    newSection+=1;sectionMap[oldSection]=newSection;kept.append(s)
                raw=raw[:72]+b''.join(kept);struct.pack_into('<I',raw,4,len(raw));struct.pack_into('<I',raw,64,len(kept))
            cmdlist.append(bytes(raw))
        assert set(removed)=={x.decode()for x in emptyNames}and len(removed)==3
        for i in range(nsyms):
            at=symoff+i*16;typ=b[at+4];index=b[at+5]
            if not(typ&0xe0)and (typ&0xe)==0xe:
                assert index in sectionMap;b[at+5]=sectionMap[index]
        oldEnd=32+struct.unpack_from('<I',b,20)[0]
        for name in newDeps:
            text=name.encode()+b'\0';size=(24+len(text)+7)&~7
            cmdlist.append(struct.pack('<6I',12,size,24,0,0,0)+text+bytes(size-24-len(text)))
        joined=b''.join(cmdlist);first=min(s['fileoff']for g in segments(before)for s in g['sections']if s['fileoff']and s['size'])
        assert 32+len(joined)<=first and not any(b[oldEnd:first])
        b[32:first]=joined+bytes(first-32-len(joined));struct.pack_into('<II',b,16,len(cmdlist),len(joined));resize_linkedit(b)
        image=directory/'DiskImageKit27.dylib';image.write_bytes(b);sign(image)
        after=image.read_bytes();newImports=imports(after)['imports'];newSites=list(chain_entries(after));oldSites=list(chain_entries(before))
        assert len(newSites)==len(oldSites)and len(newImports)==len(oldImports)
        for old,new in zip(oldSites,newSites):
            repair=next((q for q in requirementRepairs if q['candidateFileoff']==old['fileoff']),None)
            assert old['fileoff']==new['fileoff']and new['word']==(repair['afterWord']if repair else old['word'])
        code=[]
        for g in segments(before):
            for s in g['sections']:
                if s['flags']&0x80000000:
                    assert before[s['fileoff']:s['fileoff']+s['size']]==after[s['fileoff']:s['fileoff']+s['size']]
                    code.append({'section':s['name'],'sha256':hashlib.sha256(after[s['fileoff']:s['fileoff']+s['size']]).hexdigest()})
        required={q['name']for q in original['nlistImports']if not q['weak']and q['name']!=oldCN}|{q['name']for q in newImports if not q['weak']}
        header='// Exact original non-CN plus current candidate strong imports.\nstatic constexpr const char *RequiredImports[]={\n'+''.join(' '+json.dumps(q[1:])+',\n'for q in sorted(required))+'};\n'
        header+='struct VM27RequirementBinding { uintptr_t offset; const char *symbol; };\nstatic constexpr VM27RequirementBinding RequirementBindings[]={\n'+''.join(' {'+hex(q['candidateRVA'])+', '+json.dumps(q['symbol'][1:])+'},\n'for q in requirementRepairs)+'};\n'
        for name in ['diskimagekit_required_imports.h','diskimagekit_bootstrap_required_imports.h']:(directory/name).write_text(header)
        for oldName,newName in [('VM27DIKCVW.dylib','VM27DIKCVW.dylib')]:shutil.copy2(frozen/role/oldName,directory/newName)
        shutil.copy2(diagnostics/'swift-anyobject-array-build-v5'/role/'VM27AnyObjectArray.dylib',directory/'VM27AnyObjectArray.dylib')
        shutil.copy2(diagnostics/'static-array-metadata-build-v8'/role/'VM27StaticArrayMetadata.dylib',directory/'VM27StaticArrayMetadata.dylib')
        if role=='ios':shutil.copy2(lookupSource,directory/'VM27SwiftLookup.dylib')
        factory=directory/'VM27StaticArrayMetadata.dylib'
        fm=json.loads((diagnostics/'static-array-metadata-build-v8/manifest.json').read_text());factoryUUID=next(q['uuid']for q in fm['files']if q['path'].endswith('/'+role+'/VM27StaticArrayMetadata.dylib'))
        sdk=run(role+'-sdk',['xcrun','--sdk',sdkname,'--show-sdk-path']).stdout.strip()
        common=['xcrun','--sdk',sdkname,'clang++','-target',target,'-isysroot',sdk,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-memory-operations','-fno-typed-cxx-new-delete','-I'+str(directory),'-I'+str(host)]
        provider=directory/'VM27StaticArrayBootstrap.dylib'
        defines=['-DVM27_DIKit_SHA="'+sha(image)+'"','-DVM27_FACTORY_SHA="'+sha(factory)+'"','-DVM27_FACTORY_UUID="'+factoryUUID+'"']
        run(role+'-bootstrap',common+defines+[host/'modern_swift_static_array_bootstrap.cpp','-dynamiclib','-lobjc','-Wl,-install_name,@rpath/VM27StaticArrayBootstrap.dylib','-Wl,-exported_symbols_list,'+str(out/'bootstrap-exports.txt'),'-o',provider]);sign(provider)
        probeDefines=[]
        if role=='mac':
            fixture=directory/'DIKitStaticArrayFixture.dylib'
            run('mac-fixture',['xcrun','swiftc','-target','arm64e-apple-macos27.0','-sdk',sdk,'-module-cache-path',out/'fixture-module-cache','-O','-parse-as-library','-module-name','VM27DIKitArrayFixture',host/'modern_swift_static_array_dik_fixture.swift','-emit-library','-o',fixture])
            fixtureBytes=bytearray(fixture.read_bytes());replaced=0
            for cmd,at,n in commands(fixtureBytes):
                if cmd==12:
                    p=struct.unpack_from('<I',fixtureBytes,at+8)[0];path=bytes(fixtureBytes[at+p:at+n]).split(b'\0')[0].decode()
                    if path.endswith('/DiskImageKit.framework/Versions/A/DiskImageKit'):
                        path=b'@loader_path/DiskImageKit27.dylib\0';assert len(path)<=n-p;fixtureBytes[at+p:at+n]=path+bytes(n-p-len(path));replaced+=1
            assert replaced==1;fixture.write_bytes(fixtureBytes);sign(fixture)
            fixtureUUID=next(fixture.read_bytes()[at+8:at+24].hex()for cmd,at,n in commands(fixture.read_bytes())if cmd==27)
            probeDefines=['-DVM27_FIXTURE_UUID=\"'+fixtureUUID+'\"']
        probe=out/('dik27-bootstrap-'+role)
        run(role+'-probe',common+probeDefines+[host/'modern_swift_static_array_bootstrap_probe.cpp',provider,'-lobjc','-Wl,-rpath,@executable_path/'+role,'-o',probe])
        if role=='ios':
            rights={'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True}
            ent=out/'Probe.entitlements';ent.write_bytes(plistlib.dumps(rights))
            run('ios-sign',['codesign','--force','--sign','-','--timestamp=none','--entitlements',ent,probe])
            assert plistlib.loads(run('ios-rights',['codesign','-d','--entitlements',':-',probe]).stdout.encode())==rights
            run('ios-strict',['codesign','--verify','--strict',probe])
        else:sign(probe)
        routes.append({'role':role,'newPositiveRoutes':changed,'removedOnlyThreeZeroLengthSectionHeaders':removed,'nlistSectionIndexesExactlyReindexed':True,'allNonemptySectionAddressesOffsetsBytesPreserved':True,'allOtherImportRowsUnchanged':all((a['name'],a['ordinal'],a['weak'])==(z['name'],z['ordinal'],z['weak'])for a,z in zip(oldImports,newImports)if not any(q['index']==a['index']for q in changed)),
            'twentyOriginalCacheRequirementPACContractsRestored':requirementRepairs,'everyOtherOriginalBindWordIncludingPACUnchanged':True,'instructionSections':code,'requiredCount':len(required)})
        if role=='mac':
            for label,flag in [('mac-bootstrap',[]),('mac-metadata',['--metadata']),('mac-rollback-1',['--rollback-after=1']),('mac-rollback-2',['--rollback-after=2']),('mac-rollback-3',['--rollback-after=3'])]:
                z=run(label,[probe,image,factory,directory/'VM27DIKCVW.dylib',*flag],timeout=15)
                data=[json.loads(line)for line in z.stdout.splitlines()if line.startswith('{')]
                macRun[label]=data
                first=data[0];assert first['authenticatedBefore']==3 and first['protectionRestored']==1 and first['requirementBindingsAuthenticated']==20
                if 'rollback' in label:assert first['rollbackAuthenticated']==3 and first['handlePublished']==0
                else:assert first['authenticatedAfter']==3 and first['handlePublished']==1
            z=run('mac-array-fixture',[probe,image,factory,directory/'VM27DIKCVW.dylib','--array-fixture',fixture],timeout=15)
            macRun['mac-array-fixture']=[json.loads(line)for line in z.stdout.splitlines()if line.startswith('{')]
            assert macRun['mac-array-fixture'][-1]['checks']==4608 and macRun['mac-array-fixture'][-1]['failures']==0
    for p in [*out.glob('dik27-bootstrap-*'),*out.glob('*/*.dylib')]:
        signature=run('identity-'+p.name,['codesign','-dvvv',p]).stderr;b=p.read_bytes();uuid=next(b[at+8:at+24].hex()for cmd,at,n in commands(b)if cmd==27)
        files.append({'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p),'CDHash':re.search('CDHash=([0-9a-f]{40})',signature)[1],'uuid':uuid})
    assert all(sha(pathlib.Path(q['path']))==q['sha256']for q in inputs)
    manifest={'files':files,'inputs':inputs,'routes':routes,'nativeMac':macRun,'actualIOSRun':False,
        'genuineDIKitUUID':'652b07a998be31d298d7ffcaf14aca5e','originalCNProvided':False,
        'privateOneCNCompatibilitySemantics':'invalid sentinel followed by three real completed-metadata ISA bindings before handle publication',
        'originalOtherStrongDependenciesRetained':True,'pageScope':'one owned __AUTH_CONST page; original current and maximum protection restored',
        'actualPACAuthentication':'DA address-diverse 0x6ae1 before/after/rollback; direct raw-pointer equality after authentication',
        'modernDI2FunctionalProviderStillRequiredOnIOS':True,'completeOriginalClosure':False,
        'fullSwift27Runtime':False,'fullVZ27Backend':False,'productionModified':False}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'files':files,'nativeMac':macRun,'actualIOSRun':False,'completeOriginalClosure':False},indent=2))


if __name__=='__main__':main()
