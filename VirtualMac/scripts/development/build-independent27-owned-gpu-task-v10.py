#!/usr/bin/env python3
"""Root-only ordered native GPU event signal plus bounded genuine render-PSO errors; one Metal unit and four GPU13 objects."""
import argparse, hashlib, importlib.util, json, pathlib, plistlib, shutil, struct, subprocess, sys, tempfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
PLAN = N/'owned-gpu-task-ordered-event-rps-source-v8-attempt1/source-plan.json'
PLAN_SHA = 'd8d19f31ee8ba0f20909d42a41396148399f6fa96d5bd0de5c5cf9e142a43aad'
PREVIOUS=N/'owned-gpu-task-iosurface-shared-source-port-v7-attempt1'
PREVIOUS_SHA='7c0293b04e19a705a54b5b4bd37e116cb5a4782a8839f312e7063873520153b1'
PREVIOUS_FREEZE_SHA='9f458451d5b1c8da36615526d456384a08792553c19edac20e61620a841ba7a4'
BASE = pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp = importlib.util.spec_from_file_location('gpu_task_signature_primitives', BASE)
base = importlib.util.module_from_spec(sp); sp.loader.exec_module(base)
M = base.m.MachO
pin, save, need = base.pin, base.save, base.need
TARGET = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
CHILD = 'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS'
GPU = 'gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc'
EXE = 'com.apple.gpusw.ParavirtualizedGraphicsGPUTask'
COMPAT = 'VM27OwnedGPUTaskCompatV1.dylib'
PROVIDERS = ('VM27CxxABICompat.dylib', 'VM27AllocatorProvider.dylib',
             'VM27OwnedAppStartupV3.dylib', 'VM27PrivateEndpoint.dylib')

def exact(row):
    need(pin(row['path']) == {k:row[k] for k in ('path','bytes','sha256')}, 'exact source '+row['path'])
    return pathlib.Path(row['path'])

def branch(a, b, link=False):
    need((b-a)%4 == 0 and -(1<<27) <= b-a < (1<<27), 'bounded ARM64 branch')
    return (0x94000000 if link else 0x14000000) | (((b-a)//4)&0x3ffffff)

def commands(raw):
    at=32
    for _ in range(struct.unpack_from('<I',raw,16)[0]):
        c,z=struct.unpack_from('<II',raw,at); yield c,at,z; at+=z

def port(raw):
    """Preserve native body except nine exact BL/entry words and one authenticated-chain next field."""
    before=M(raw); need(len(before.imports)==186, 'all186 native imports, not old17 subset')
    words={0xa7bc:0xd503237f, 0x2a6ac:0x94010885,
           0x6c8c0:0x90000161, 0x6c8c4:0xf941b021, 0x6c8c8:0xb0000131,
           0x2a484:0x94011267, 0x2a4a8:0x94011286, 0x2a4cc:0x94011295,
           0x4ea20:0x940078a8, 0x2d438:0x9400f77a,
           0x41110:0x9400ae74, 0x41b04:0x9400abff}
    # Decode original words rather than assuming assembler display spelling.
    need(struct.unpack_from('<I',raw,0xa7bc)[0]==words[0xa7bc], 'exact original main entry')
    need(struct.unpack_from('<I',raw,0x2a6ac)[0]==words[0x2a6ac], 'exact native default-library BL')
    need(branch(0xa7bc,0x68d1c)==0x14017958, 'reviewed main branch')
    callers=lambda target: [i for s in before.sections if s['name']=='__text'
        for i in range(s['fileoff'],s['fileoff']+s['size'],4)
        if (w:=struct.unpack_from('<I',raw,i)[0])&0xfc000000==0x94000000 and
        i+(((w&0x3ffffff)-(1<<26) if w&(1<<25) else w&0x3ffffff)<<2)==target]
    need(callers(0x68d1c)==[0xa870] and callers(0x689dc)==[0xa810] and
         callers(0x6c8c0)==[0x2a6ac], 'sole original sandbox/confstr/specialized-library callers')
    # Existing imported C bool(uint64_t) stub preserves x0, w0 and caller LR.
    need(callers(0x68abc)==[0x56ce0], 'sole original RGB classifier caller')
    need(struct.unpack_from('<4I',raw,0x68abc)==(0xb0000151,0x912d2231,0xf9400230,0xd71f0a11) and
         (struct.unpack_from('<Q',raw,0x91b48)[0]&0xffff)==17 and
         next(row for row in before.imports if row['index']==17)['name']=='_isRGBPixelFormat',
         'exact original RGB authenticated import stub and index17 binding')
    capabilities=[dict(callRVA=0x2a484,returnRVA=0x2a488,originalTarget=0x6ee20,selector='supportsBufferWithAddressRanges'),
                  dict(callRVA=0x2a4a8,returnRVA=0x2a4ac,originalTarget=0x6eec0,selector='supportsHeapWithAddressRanges'),
                  dict(callRVA=0x2a4cc,returnRVA=0x2a4d0,originalTarget=0x6ef20,selector='supportsResourceDetachBacking')]
    for route in capabilities:
        site=route['callRVA']; word=struct.unpack_from('<I',raw,site)[0]
        need(word==words[site] and branch(site,route['originalTarget'],True)==word and
             struct.unpack_from('<I',raw,site-4)[0]==0xf87c6900, 'exact native device getter BL/input')
        route.update(originalBLWord=hex(word),actualBLWord=hex(branch(site,0x68abc,True)),actualTarget=0x68abc)
    need(struct.unpack_from('<I',raw,0x2a09c)[0]==0x9400fb71, 'original allowLibrariesFromOtherPlatforms BL remains native')
    # Sole original mkdir caller is in the already bypassed, never-entered native main.
    need(callers(0x68b6c)==[0xa884] and
         next(row for row in before.imports if row['index']==122)['name']=='_mkdir' and
         struct.unpack_from('<Q',raw,0x91e90)[0]&0xffff==122 and
         struct.unpack_from('<4I',raw,0x68b6c)==(0xb0000151,0x913a4231,0xf9400230,0xd71f0a11),
         'exact unused native main mkdir import122/stub/authslot')
    for sec in before.sections:
        if sec['name']!='__text':continue
        for site in range(sec['fileoff'],sec['fileoff']+sec['size'],4):
            word=struct.unpack_from('<I',raw,site)[0]
            if word&0x7c000000==0x14000000:
                imm=word&0x3ffffff; imm=imm-(1<<26) if imm&(1<<25) else imm
                target=site+(imm<<2)
                need(not (0xa7bc<target<0xa91c and not 0xa7bc<=site<0xa91c),'no external direct branch enters bypassed native main body')
    need(struct.unpack_from('<5I',raw,0x4ea10)==(0x79414be4,0xaa1703e0,0xaa1403e2,0xaa1603e3,0x940078a8),
         'actual crash exact device/descriptor/IOSurface/plane argument preparation')
    # First two specialized-stub instructions preserve the genuine selector.
    need(all(struct.unpack_from('<I',raw,p)[0]==words[p] for p in (0x6c8c0,0x6c8c4,0x6c8c8)),
         'exact original selector ADRP/LDR and specialized-stub tail')
    new_calls={0x2d438:0x6b200,0x41110:0x8e640,0x41b04:0x8e640}
    need(all(struct.unpack_from('<I',raw,site)[0]==words[site] for site in new_calls),'exact original scheduled and ordinary/tile PSO BL words')
    need(struct.unpack_from('<4I',raw,0x2d42c)==(0xaa1803e0,0xaa1903e2,0xaa1a03e3,0x9400f77a) and
         struct.unpack_from('<I',raw,0x2d440)[0]==0x9400ef08,'real event/value and following native commit remain whole')
    need(struct.unpack_from('<6I',raw,0x410f8)==(0xf90053ff,0x910283e5,0xaa1503e0,0xaa1703e2,0xd2800003,0xd2800004) and
         struct.unpack_from('<6I',raw,0x41aec)==(0xf90053ff,0x910283e5,0xaa1403e0,0xaa1603e2,0xd2800003,0xd2800004),'both original native six-arg PSO preparations include genuine initialized error slots')
    for name,fo,fs,prot in ((b'__TEXT',0,0x90000,5),(b'__DATA_CONST',0x90000,0x4000,3)):
        cmd=next(at for c,at,z in commands(raw)if c==0x19 and raw[at+8:at+24].rstrip(b'\0')==name)
        need(struct.unpack_from('<QQ',raw,cmd+40)==(fo,fs) and struct.unpack_from('<II',raw,cmd+56)==(prot,prot),'actual mapped padding segment/protection')
    need(raw[0x8e640:0x8e650]==bytes(16) and raw[0x920e8:0x920f8]==bytes(16),'two bounded original zero padding intervals')
    need(all(not (sec['fileoff'] and sec['size'] and sec['fileoff']<0x8e650 and sec['fileoff']+sec['size']>0x8e640)for sec in before.sections),'new tail stub outside all native backed sections')
    out=bytearray(raw)
    for c,at,z in commands(out):
        if c==0x32: struct.pack_into('<III',out,at+8,2,0x100100,0x100100)
    fix=next((at for c,at,z in commands(out) if c==0x80000034),None)
    need(fix is not None, 'one active native chained fixups')
    start,length=struct.unpack_from('<II',out,fix+8); payload=bytearray(out[start:start+length])
    ver,starts,imports,symbols,count,fmt,compression=struct.unpack_from('<7I',payload)
    need(ver==compression==0 and fmt==2 and count==186, 'exact native addend32 import schema before append')
    stride={1:4,2:8,3:16}[fmt]; metal=next(x['ordinal'] for x in before.loads if '/Metal.framework/' in x['path'] or pathlib.PurePosixPath(x['path']).name==COMPAT)
    need(struct.unpack_from('<3I',raw,0x1190)==(0xf9400680,0x9100a281,0x94019f01), 'exact native shmem decoder arguments and call remain whole')
    need(next(row for row in before.imports if row['index']==136)['name']=='_xpc_shmem_map','exact native shmem map import136')
    need(metal==2, 'same exact original native Metal/compat load ordinal2')
    renamed={'_sandbox_init_with_parameters':'_VM27OwnedGPUTaskMainV1',
             '_confstr':'_VM27OwnedGPUTaskDefaultLibraryV1',
             '_xpc_shmem_map':'_VM27OwnedGPUTaskShmemMapV1',
             '_mkdir':'_VM27OwnedGPUTaskNewTextureIOSurfaceV1'}
    routed=[]
    for row in before.imports:
        name=row['name']; at=imports+row['index']*stride
        word=struct.unpack_from('<Q' if fmt==3 else '<I',payload,at)[0]
        if name in renamed:
            no=len(payload)-symbols; payload.extend(renamed[name].encode()+b'\0')
            shift=32 if fmt==3 else 9; word=(word&((1<<shift)-1)) | (no<<shift)
        if name in renamed or name.startswith('__ZNSt3__18to_chars') or name in (
            '_malloc_type_malloc','_malloc_type_realloc','__ZnwmSt19__type_descriptor_t',
            '__ZnamSt19__type_descriptor_t','__ZdlPvSt19__type_descriptor_t','__ZdaPvSt19__type_descriptor_t',
            '_OBJC_CLASS_$_MTLResourceAddressRangeArray','_MTLCopyDeviceForRegistryID','_isRGBPixelFormat'):
            mask=65535 if fmt==3 else 255; word=(word&~mask)|metal
            routed.append(dict(original=name,actual=renamed.get(name,name),ordinal=metal))
        struct.pack_into('<Q' if fmt==3 else '<I',payload,at,word)
    # Retain the complete existing import table; append one proper six-argument observer.
    observer_name='_VM27OwnedGPUTaskCreateRenderPipelineV1'
    observer_name_offset=len(payload)-symbols;payload.extend(observer_name.encode()+b'\0')
    need(observer_name_offset<(1<<23),'bounded native import name field')
    payload.extend(bytes((-len(payload))%8));new_imports=len(payload)
    payload.extend(payload[imports:imports+count*stride])
    payload.extend(struct.pack('<Ii',(observer_name_offset<<9)|metal,0))
    struct.pack_into('<I',payload,8,new_imports);struct.pack_into('<I',payload,16,187)
    # Extend the existing DataConst page's terminal chain by one genuine IA/address-diversified bind.
    segment_info=struct.unpack_from('<I',payload,starts+4+2*4)[0]
    page_info=starts+segment_info
    need(struct.unpack_from('<HHQ',payload,page_info+4)==(0x4000,12,0x90000) and
         struct.unpack_from('<HH',payload,page_info+20)==(1,0),'actual DataConst single page starts descriptor')
    cursor=0x90000
    for _ in range(2048):
        need(0x90000<=cursor<=0x93ff8,'existing pointer chain stays in its actual page')
        word=struct.unpack_from('<Q',raw,cursor)[0];step=(word>>51)&0x7ff
        if not step:break
        cursor+=step*8
    else:need(False,'finite original pointer chain terminates')
    need(cursor==0x920e0 and word==0xc0010000000000b6,'exact original terminal auth bind182 with next0')
    struct.pack_into('<Q',out,0x920e0,word|(2<<51))
    struct.pack_into('<Q',out,0x920f0,0xc0010000000000ba)
    # The ordinary C import tail stub preserves x0..x5 and LR. Its slot modifier is x17.
    struct.pack_into('<4I',out,0x8e640,0x90000031,0x9103c231,0xf9400230,0xd71f0a11)
    out.extend(bytes((-len(out))%8)); newat=len(out); out.extend(payload)
    struct.pack_into('<II',out,fix+8,newat,len(payload))
    for c,at,z in commands(out):
        if c==0x19 and out[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT':
            fo=struct.unpack_from('<Q',out,at+40)[0]; size=len(out)-fo
            struct.pack_into('<Q',out,at+32,(size+0x3fff)&~0x3fff);struct.pack_into('<Q',out,at+48,size)
    struct.pack_into('<I',out,0xa7bc,branch(0xa7bc,0x68d1c))
    struct.pack_into('<I',out,0x6c8c8,branch(0x6c8c8,0x689dc))
    for route in capabilities:
        struct.pack_into('<I',out,route['callRVA'],branch(route['callRVA'],0x68abc,True))
    struct.pack_into('<I',out,0x4ea20,branch(0x4ea20,0x68b6c,True))
    for site,target in new_calls.items():struct.pack_into('<I',out,site,branch(site,target,True))
    after=M(out); need(len(after.imports)==187 and after.uuid==before.uuid, 'all186 native rows retained plus one typed observer import')
    need(after.imports[-1]['index']==186 and after.imports[-1]['name']==observer_name and after.imports[-1]['ordinal']==2 and after.imports[-1]['addend']==after.imports[-1]['weak']==0,'actual appended observer import semantics')
    added_bind=next(row for row in after.binds if row['fileoff']==0x920f0)
    need(added_bind['index']==186 and added_bind['auth']==added_bind['addrdiv']==1 and added_bind['key']==added_bind['diversity']==0,'actual new IA address-diversified bind resolves observer186')
    for sec in before.sections:
        a,z=sec['fileoff'],sec['size']
        if not a or not z: continue
        expected=bytearray(raw[a:a+z])
        for pos in (0xa7bc,0x6c8c8,0x2a484,0x2a4a8,0x2a4cc,0x4ea20,0x2d438,0x41110,0x41b04):
            if a<=pos<a+z:expected[pos-a:pos-a+4]=out[pos:pos+4]
        if a<=0x920e0<a+z:expected[0x920e0-a:0x920e8-a]=out[0x920e0:0x920e8]
        need(bytes(expected)==out[a:a+z], 'all native backed business sections whole except nine reviewed words and one chain next field')
    return out,dict(nativeImports=187,originalNativeImportRowsRetained=186,routedImports=routed,mainBranchWord=hex(branch(0xa7bc,0x68d1c)),
        libraryTailBranchWord=hex(branch(0x6c8c8,0x689dc)),nativeDefaultLibraryBLWhole=True,
        selectorLoadsWhole=True,allOtherNativeBackedSectionsWhole=False,
        allNativeBusinessSectionsWholeExceptNineWordsAndAuthChainNext=True,
        exactChangedInstructionWordCount=9,nativeFeatureQueryRoutes=capabilities,
        originalRGBClassifierCallWhole=True,allowLibrariesFromOtherPlatformsNativeBLWhole=True,
        nativeShmemMapImportRenamedOnly=True,nativeShmemMapCallAndCompareAndThrowWhole=True,
        nativeIOSurfaceTextureAllocation=dict(callRVA=0x4ea20,returnRVA=0x4ea24,originalWord=hex(words[0x4ea20]),
            actualWord=hex(branch(0x4ea20,0x68b6c,True)),targetCStubRVA=0x68b6c,reusedUnusedImportIndex=122,
            correctStandaloneFiveArgumentABI=True,originalNativeTextureAndSurfaceValidatorsWhole=True),
        nativeOrderedEventSignal=dict(callRVA=0x2d438,returnRVA=0x2d43c,actualTarget=0x6b200,conservativeGPUSignalNotSchedulingEquivalent=True,originalCommitWhole=True),
        nativeRenderPipelineObserver=dict(callRVAs=[0x41110,0x41b04],returnRVAs=[0x41114,0x41b08],stubRVA=0x8e640,slotRVA=0x920f0,importIndex=186,properSixArgumentABI=True),
        actualAddedImport=after.imports[-1],actualAddedAuthenticatedBind=added_bind,
        actualNewStubAndSlotPadding=[dict(fileoff=p,oldHex=raw[p:p+n].hex(),newHex=out[p:p+n].hex())for p,n in ((0x8e640,16),(0x920f0,8),(0x920e0,8))])

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runtime-candidate',required=True,type=pathlib.Path)
    ap.add_argument('--native-index',type=pathlib.Path,default=N/'current-native-header-export-index-v3/index.json')
    ap.add_argument('--entitlements',required=True,type=pathlib.Path)
    ap.add_argument('--output',required=True,type=pathlib.Path)
    a=ap.parse_args(); out=a.output.resolve(); need(out.parent==N and not out.exists(),'fresh HOST-only output')
    need(pin(PLAN)['sha256']==PLAN_SHA,'final Root-reviewed server plan')
    plan=json.loads(PLAN.read_bytes())
    evidence_keys=('baselineCanonicalMainSelectionSourcePlan','baselineMetalSource','sourceDelta','metalSourceDelta',
                   'nativeFeatureCallsiteProof','actualNativeDeviceCapabilitiesReceipt','actualNativeDeviceCapabilitiesStdout','actualNativeCrossPlatformLibraryReceipt',
                   'nativeShmemMapCallsiteProof','baselineCompiledGPUTaskProduct','baselineCompiledGPUTaskFreeze','baselineCompiledGPUTaskSourcePlan',
                   'nativeIOSurfaceTextureCallsiteProof','actualGPUEntitlements','existingPVGUnifiedStorageSource',
                   'nativeEventRPSCallsiteProof','actualNormal117ErrorExcerpt','officialPublicSignalEventABI')
    inputs=[exact(x) for x in plan['sourceFiles']+plan['frozenReuse']+[plan[k]for k in evidence_keys]]
    need(plan['actualChangedCompileUnits']==[2] and plan['inheritedWholeCompileUnits']==[0,1,3,4],'exact one-unit plan')
    need(pin(PREVIOUS/'candidate.json')['sha256']==PREVIOUS_SHA and pin(PREVIOUS/'freeze.json')['sha256']==PREVIOUS_FREEZE_SHA,'actual successful GPU13 compile/link/sign baseline')
    previous=json.loads((PREVIOUS/'candidate.json').read_bytes());previous_frozen=base.frozen_rows(PREVIOUS/'freeze.json')
    need(previous_frozen[str(PREVIOUS/'candidate.json')]==pin(PREVIOUS/'candidate.json'),'frozen successful GPU13 candidate')
    need(previous['actualIOSCompileStrictLinkDyldAndSigningPassed']is True,'actual GPU13 successful build evidence')
    previous_plan=json.loads(exact(previous['sourcePlan']).read_bytes())
    for key in ('profileTemplate','actualNativeTask','nativeMetadata','actualDefaultMetallib'):
        need(plan[key]==previous_plan[key],'unchanged native task/resource/profile '+key);exact(plan[key])
    previous_commands_pin=pin(PREVIOUS/'commands.json');need(previous_frozen[str(PREVIOUS/'commands.json')]==previous_commands_pin,'frozen actual GPU13 commands')
    previous_commands=json.loads((PREVIOUS/'commands.json').read_bytes())
    native=exact(plan['actualNativeTask']); info=exact(plan['nativeMetadata']); profile=exact(plan['profileTemplate'])
    runtime=json.loads(a.runtime_candidate.read_bytes()); rt=pathlib.Path(runtime['runtimeRoot'])
    manifest=plistlib.loads(pathlib.Path(runtime['manifest']['path']).read_bytes()); rows=manifest['files']
    for name in PROVIDERS:
        path=rt/CHILD/name; r=next(x for x in rows if x['path']==str(path.relative_to(rt)))
        need(pin(path)['sha256']==r['sha256'],'actual whole Runtime86 provider '+name)
    ent=plistlib.loads(a.entitlements.read_bytes())
    previous_task_signature=next(row for row in previous['signedFiles'] if row['actualSignedFile']==previous['task'])
    need(len(ent)==9 and ent==previous_task_signature['embeddedEntitlements'] and pin(a.entitlements)==plan['actualGPUEntitlements'],'exact current GPU13 Task9 entitlements unchanged')
    need(ent.get('com.apple.private.security.no-sandbox') is True,'real required no-sandbox entitlement')
    need(ent.get('com.apple.private.virtualization.plugin') is True, 'same real scoped plugin requirement used by the parent consumer')
    need(not any('hypervisor' in x.lower() or ('virtualization' in x.lower() and x != 'com.apple.private.virtualization.plugin') for x in ent),'GPU task has plugin identity only and no CPU/HV permission')
    out.mkdir(mode=0o700); log=[]
    def run(label,argv):
        argv=list(map(str,argv)); r=subprocess.run(argv,capture_output=True,timeout=180)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        log.append(dict(label=label,argv=argv,exit=r.returncode));save(out/'commands.json',log)
        need(r.returncode==0,label+': '+r.stderr.decode(errors='replace')[-4000:]); return r
    root=out/'gpu-task-flat'; xpc=root/'GPUTask.bundle/Contents/XPCServices'/ (EXE+'.xpc')
    contents=xpc/'Contents'; mac=contents/'MacOS'; mac.mkdir(parents=True); (contents/'Resources').mkdir()
    task=mac/EXE; compat=mac/COMPAT
    build=out/'objects';build.mkdir(); objects=[]
    flags=['-target','arm64e-apple-ios16.1','-O2','-fno-strict-aliasing','-fno-objc-arc','-fblocks',
           '-fptrauth-abi-version=0','-fno-typed-cxx-new-delete','-I',str(S),'-Wno-deprecated-declarations']
    units=[S/'vm27_owned_gpu_task_server_v3.m',S/'vm27_owned_gpu_parent_inspection_v1.c',
           S/'vm27_owned_gpu_task_metal_v6.m',profile,S/'modern_runtime_compat.mm']
    runtime_source=pin(S/'modern_runtime_compat.mm')
    need(all(pin(units[i])==previous['sourceFiles'][i] for i in (0,1,3,4)),'all four inherited compilation source pins whole')
    inherited_objects=[]
    for i,source in enumerate(units):
        if i==2:
            obj=build/(str(i)+'-'+source.stem+'.o');objects.append(obj)
            run('compile-'+str(i),['xcrun','--sdk','iphoneos','clang',*flags,'-c',source,'-o',obj])
            continue
        row=previous['actualIOSObjects'][i];obj=pathlib.Path(row['path'])
        need(previous_frozen.get(str(obj))==row and pin(obj)==row,'actual GPU13 frozen object at unchanged unit index')
        objects.append(obj);inherited_objects.append(row)
    need(len(objects)==5 and len(inherited_objects)==4,'only Metal6 compiles; four actual GPU13 objects inherited directly')
    run('link-compat',['xcrun','--sdk','iphoneos','clang++',*flags,'-dynamiclib','-Wl,-undefined,error',
        '-Wl,-no_adhoc_codesign','-Wl,-headerpad_max_install_names','-install_name',TARGET+'/'+GPU+'/Contents/MacOS/'+COMPAT,
        *objects,'-framework','Foundation','-framework','Security','-framework','CoreFoundation','-Wl,-reexport_framework,Metal',
        '-Wl,-reexport_library,'+str(rt/CHILD/PROVIDERS[0]),'-Wl,-reexport_library,'+str(rt/CHILD/PROVIDERS[1]),
        rt/CHILD/PROVIDERS[2],rt/CHILD/PROVIDERS[3],'-o',compat])
    cm=M(compat.read_bytes())
    for dep in cm.loads:
        name=pathlib.PurePosixPath(dep['path']).name
        if name in PROVIDERS:
            run('compat-path-'+name,['install_name_tool','-change',dep['path'],TARGET+'/'+CHILD+'/'+name,compat])
    task.write_bytes(native.read_bytes());task.chmod(0o700)
    run('remove-original-signature',['codesign','--remove-signature',task])
    # Let Apple's load-command editor operate before moving the active fixup payload.
    tm=M(task.read_bytes())
    for dep in tm.loads:
        old=dep['path']; new=old
        for name,ver in [('Foundation','C'),('CoreFoundation','A'),('IOSurface','A')]:
            new=new.replace('/'+name+'.framework/Versions/'+ver+'/'+name,'/'+name+'.framework/'+name)
        if '/Metal.framework/' in old:new='@loader_path/'+COMPAT
        if old!=new:run('task-path-'+str(dep['ordinal']),['install_name_tool','-change',old,new,task])
    original=task.read_bytes(); raw,portproof=port(original); task.write_bytes(raw)
    # Preserve source metadata semantics while making its actual platform honest.
    metadata=plistlib.loads(info.read_bytes());metadata.update(CFBundleSupportedPlatforms=['iPhoneOS'],MinimumOSVersion='16.1',DTPlatformName='iphoneos')
    for key in ('LSMinimumSystemVersion','DTPlatformVersion','DTSDKName','DTSDKBuild','DTPlatformBuild','BuildMachineOSBuild'):
        metadata.pop(key,None)
    ip=contents/'Info.plist';ip.write_bytes(plistlib.dumps(metadata,sort_keys=True))
    outer=root/'GPUTask.bundle/Contents/Info.plist';outer.write_bytes(plistlib.dumps(dict(CFBundleIdentifier='org.lkx.VirtualMacIndependent27.GPUTask',CFBundlePackageType='BNDL',CFBundleVersion='1',CFBundleSupportedPlatforms=['iPhoneOS']),sort_keys=True))
    shader=contents/'Resources/default.metallib';shutil.copyfile(exact(plan['actualDefaultMetallib']),shader);shader.chmod(0o600)
    # All original186 imports plus newly linked shim imports, with exact provider/reexport definitions.
    native_index=json.loads(a.native_index.read_bytes())['images']; images={str(task):M(task.read_bytes()),str(compat):M(compat.read_bytes())}
    mapped={TARGET+'/'+GPU+'/Contents/MacOS/'+EXE:str(task),TARGET+'/'+GPU+'/Contents/MacOS/'+COMPAT:str(compat)}
    def local(path,owner):
        if path.startswith('@loader_path/'):
            return str(pathlib.Path(owner).parent/path[len('@loader_path/'):])
        if path.startswith(TARGET+'/child-flat/'):return str(rt/path[len(TARGET+'/'):])
        return mapped.get(path,path)
    def canon(path):
        if path in native_index:return path
        return path.replace('/Versions/A/','/').replace('/Versions/C/','/')
    def resolve(path,name,seen=()):
        key=(path,name)
        if key in seen or len(seen)>64:return None
        path=canon(path); seen=seen+(key,)
        if path in native_index:
            im=native_index[path]; ex=im['definitions'].get(name); deps=im['dependencies']
            if ex is not None:
                if ex['flags']&8:
                    dep=next(d for d in deps if d['ordinal']==ex['ordinal'])
                    return resolve(dep['path'],ex.get('alias') or ex.get('importedName') or name,seen)
                return dict(kind='actualCapturedNativeDefinition',path=path,UUID=im['UUID'],symbol=name,definition=ex)
            for dep in deps:
                if dep['command']==0x8000001f:
                    got=resolve(dep['path'],name,seen)
                    if got:return got
            return None
        p=pathlib.Path(path)
        if not p.is_file():return None
        if path not in images:images[path]=M(p.read_bytes())
        im=images[path];ex=im.exports.get(name)
        if ex is not None:
            if ex['flags']&8:
                dep=next(d for d in im.loads if d['ordinal']==ex['ordinal'])
                return resolve(local(dep['path'],path),ex.get('importedName') or name,seen)
            return dict(kind='actualMachODefinition',file=pin(p),UUID=im.uuid,symbol=name,definition=ex)
        for dep in im.loads:
            if dep['cmd']==0x8000001f:
                got=resolve(local(dep['path'],path),name,seen)
                if got:return got
        return None
    proofs=[]
    for path in (task,compat):
        im=images[str(path)]
        for row in im.imports:
            if row['ordinal']>0:
                dep=next(d for d in im.loads if d['ordinal']==row['ordinal']); owner=local(dep['path'],str(path)); found=resolve(owner,row['name'])
            else:
                owner='special-namespace:'+str(row['ordinal']);found=resolve(str(path),row['name'])
                if not found:
                    for system in ('/usr/lib/libc++.1.dylib','/usr/lib/libc++abi.dylib','/usr/lib/libSystem.B.dylib'):
                        found=resolve(system,row['name'])
                        if found:break
            proofs.append(dict(image=pin(path),actualImport=row,owner=owner,actualDefinition=found,specialNamespaceRuntimeBindingExecuted=False))
    save(out/'actual-import-closure.json',dict(originalNativeImportRows=186,actualTaskImportRows=187,additionalTaskObserverImport=portproof['actualAddedImport'],rows=proofs,unresolved=[x for x in proofs if not x['actualDefinition'] and not x['actualImport']['weak']]))
    need(all(x['actualDefinition'] or x['actualImport']['weak'] for x in proofs),'complete actual original186+shim strong definition closure; see actual-import-closure.json')
    for path,label in ((compat,'compat'),(task,'task')):
        run('validate-'+label,['xcrun','dyld_info','-validate_only',path])
    run('sign-compat',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.gputask.compat',compat])
    run('verify-compat',['codesign','--verify','--strict',compat])
    # Sign outside the Documents file provider, which attaches FinderInfo to bundles.
    # Only this generated temporary copy has its extended attributes removed.
    with tempfile.TemporaryDirectory(prefix='vm27-owned-gputask-sign-',dir='/private/tmp') as signing:
        staged=pathlib.Path(signing)/(EXE+'.xpc')
        shutil.copytree(xpc,staged,copy_function=shutil.copyfile)
        (staged/'Contents/MacOS'/EXE).chmod(0o755)
        (staged/'Contents/MacOS'/COMPAT).chmod(0o755)
        run('clear-temporary-own-bundle-attributes',['/usr/bin/xattr','-cr',staged])
        run('sign-task-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier',EXE,'--entitlements',a.entitlements,'--generate-entitlement-der',staged])
        run('verify-task-xpc',['codesign','--verify','--strict',staged])
        for signedfile in staged.rglob('*'):
            if signedfile.is_file():
                destination=xpc/signedfile.relative_to(staged)
                destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(signedfile,destination)
    cr=contents/'_CodeSignature/CodeResources'; signed=[]
    for path in (compat,task):
        im=M(path.read_bytes()); external={1:ip.read_bytes(),3:cr.read_bytes()} if path==task else None
        signed.append(dict(actualSignedFile=pin(path),**base.signature(path.read_bytes(),im.uuid,external)))
    need(pin(S/'modern_runtime_compat.mm')==runtime_source,'runtime container source whole')
    result=dict(schema='NativeGPUTaskOwnedEntryProductV1',runtimeRoot=str(root),task=pin(task),compat=pin(compat),
        taskInfo=pin(ip),outerBundleInfo=pin(outer),taskCodeResources=pin(cr),defaultMetallib=pin(shader),
        sourcePlan=pin(PLAN),nativeTaskSource=pin(native),nativeTaskPort=portproof,sourceFiles=[pin(x) for x in units],
        frozenReuseProviders=[pin(rt/CHILD/x) for x in PROVIDERS],signedFiles=signed,
        actualImportClosure=pin(out/'actual-import-closure.json'),actualNativeImports186=False,actualNativeImports187=True,
        actualOriginal186TaskImportRowsRetained=True,actualCurrentTaskImportRows=187,
        baselineCompiledGPUTaskProduct=pin(PREVIOUS/'candidate.json'),actualChangedObjects=[pin(objects[2])],inheritedWholeObjects=inherited_objects,
        actualNewCompilations=1,actualWholeInheritedObjects=4,actualChangedCompileUnits=[2],actualIOSObjects=[pin(obj)for obj in objects],
        inheritedSuccessfulCompileCommands=previous_commands_pin,allFourInheritedSourcePinsWhole=True,
        actualIOSCompileStrictLinkDyldAndSigningPassed=True,sandboxProfileApplied=False,
        noUndefinedDynamicLookup=True,deviceOperations=0,actualTaskExecuted=False)
    save(out/'candidate.json',result)
    files=[pin(p) for p in out.rglob('*') if p.is_file()]+[pin(__file__),pin(BASE),pin(PLAN),pin(a.native_index),pin(a.runtime_candidate),pin(a.entitlements),runtime_source,*[pin(x) for x in inputs],pin(PREVIOUS/'candidate.json'),pin(PREVIOUS/'freeze.json'),previous_commands_pin,previous['sourcePlan'],*previous['sourceFiles'],*inherited_objects]
    save(out/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),task=pin(task),compat=pin(compat),freeze=pin(out/'freeze.json'))))

if __name__=='__main__':main()
