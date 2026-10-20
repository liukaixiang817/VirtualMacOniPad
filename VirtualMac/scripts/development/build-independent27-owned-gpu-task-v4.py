#!/usr/bin/env python3
"""Root-only actual native GPUTask port/link/sign. No fixture or device action."""
import argparse, hashlib, importlib.util, json, pathlib, plistlib, shutil, struct, subprocess, sys, tempfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
PLAN = N/'owned-gpu-task-server-source-v1-attempt1/source-plan.json'
PLAN_SHA = '978ffb0412c00800cbe0afaf0bb693385f6364a2d251391e3201f1b9a4198ae9'
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
    """Preserve all original sections except two exact instruction words."""
    before=M(raw); need(len(before.imports)==186, 'all186 native imports, not old17 subset')
    words={0xa7bc:0xd503237f, 0x2a6ac:0x94010885,
           0x6c8c0:0x90000161, 0x6c8c4:0xf941b021, 0x6c8c8:0xb0000131}
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
    # First two specialized-stub instructions preserve the genuine selector.
    need(all(struct.unpack_from('<I',raw,p)[0]==words[p] for p in (0x6c8c0,0x6c8c4,0x6c8c8)),
         'exact original selector ADRP/LDR and specialized-stub tail')
    out=bytearray(raw)
    for c,at,z in commands(out):
        if c==0x32: struct.pack_into('<III',out,at+8,2,0x100100,0x100100)
    fix=next((at for c,at,z in commands(out) if c==0x80000034),None)
    need(fix is not None, 'one active native chained fixups')
    start,length=struct.unpack_from('<II',out,fix+8); payload=bytearray(out[start:start+length])
    ver,starts,imports,symbols,count,fmt,compression=struct.unpack_from('<7I',payload)
    need(ver==compression==0 and fmt in (1,2,3) and count==186, 'actual native fixups schema')
    stride={1:4,2:8,3:16}[fmt]; metal=next(x['ordinal'] for x in before.loads if '/Metal.framework/' in x['path'] or pathlib.PurePosixPath(x['path']).name==COMPAT)
    renamed={'_sandbox_init_with_parameters':'_VM27OwnedGPUTaskMainV1',
             '_confstr':'_VM27OwnedGPUTaskDefaultLibraryV1'}
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
    out.extend(bytes((-len(out))%8)); newat=len(out); out.extend(payload)
    struct.pack_into('<II',out,fix+8,newat,len(payload))
    for c,at,z in commands(out):
        if c==0x19 and out[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT':
            fo=struct.unpack_from('<Q',out,at+40)[0]; size=len(out)-fo
            struct.pack_into('<Q',out,at+32,(size+0x3fff)&~0x3fff);struct.pack_into('<Q',out,at+48,size)
    struct.pack_into('<I',out,0xa7bc,branch(0xa7bc,0x68d1c))
    struct.pack_into('<I',out,0x6c8c8,branch(0x6c8c8,0x689dc))
    after=M(out); need(len(after.imports)==186 and after.uuid==before.uuid, 'all native import rows and UUID retained')
    for sec in before.sections:
        a,z=sec['fileoff'],sec['size']
        if not a or not z: continue
        expected=bytearray(raw[a:a+z])
        for pos in (0xa7bc,0x6c8c8):
            if a<=pos<a+z:expected[pos-a:pos-a+4]=out[pos:pos+4]
        need(bytes(expected)==out[a:a+z], 'all native backed business sections whole except two reviewed words')
    return out,dict(nativeImports=186,routedImports=routed,mainBranchWord=hex(branch(0xa7bc,0x68d1c)),
        libraryTailBranchWord=hex(branch(0x6c8c8,0x689dc)),nativeDefaultLibraryBLWhole=True,
        selectorLoadsWhole=True,allOtherNativeBackedSectionsWhole=True)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runtime-candidate',required=True,type=pathlib.Path)
    ap.add_argument('--native-index',type=pathlib.Path,default=N/'current-native-header-export-index-v3/index.json')
    ap.add_argument('--entitlements',required=True,type=pathlib.Path)
    ap.add_argument('--output',required=True,type=pathlib.Path)
    a=ap.parse_args(); out=a.output.resolve(); need(out.parent==N and not out.exists(),'fresh HOST-only output')
    need(pin(PLAN)['sha256']==PLAN_SHA,'final Root-reviewed server plan')
    plan=json.loads(PLAN.read_bytes())
    inputs=[exact(x) for x in plan['sourceFiles']+plan['frozenReuse']]
    native=exact(plan['actualNativeTask']); info=exact(plan['nativeMetadata']); profile=exact(plan['profileTemplate'])
    runtime=json.loads(a.runtime_candidate.read_bytes()); rt=pathlib.Path(runtime['runtimeRoot'])
    manifest=plistlib.loads(pathlib.Path(runtime['manifest']['path']).read_bytes()); rows=manifest['files']
    for name in PROVIDERS:
        path=rt/CHILD/name; r=next(x for x in rows if x['path']==str(path.relative_to(rt)))
        need(pin(path)['sha256']==r['sha256'],'actual whole Runtime86 provider '+name)
    ent=plistlib.loads(a.entitlements.read_bytes()); need(ent.get('com.apple.private.security.no-sandbox') is True,'real required no-sandbox entitlement')
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
    units=[S/'vm27_owned_gpu_task_server_v1.m',S/'vm27_owned_gpu_parent_inspection_v1.c',
           S/'vm27_owned_gpu_task_metal_v1.m',profile,S/'modern_runtime_compat.mm']
    runtime_source=pin(S/'modern_runtime_compat.mm')
    for i,source in enumerate(units):
        obj=build/(str(i)+'-'+source.stem+'.o'); objects.append(obj)
        compiler='clang++' if source.suffix=='.mm' else 'clang'
        run('compile-'+str(i),['xcrun','--sdk','iphoneos',compiler,*flags,*(['-std=c++17'] if compiler=='clang++' else []),'-c',source,'-o',obj])
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
    save(out/'actual-import-closure.json',dict(originalNativeImportRows=186,rows=proofs,unresolved=[x for x in proofs if not x['actualDefinition'] and not x['actualImport']['weak']]))
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
        actualImportClosure=pin(out/'actual-import-closure.json'),actualNativeImports186=True,
        actualIOSCompileStrictLinkDyldAndSigningPassed=True,sandboxProfileApplied=False,
        noUndefinedDynamicLookup=True,deviceOperations=0,actualTaskExecuted=False)
    save(out/'candidate.json',result)
    files=[pin(p) for p in out.rglob('*') if p.is_file()]+[pin(__file__),pin(BASE),pin(PLAN),pin(a.native_index),pin(a.runtime_candidate),pin(a.entitlements),runtime_source,*[pin(x) for x in inputs]]
    save(out/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),task=pin(task),compat=pin(compat),freeze=pin(out/'freeze.json'))))

if __name__=='__main__':main()
