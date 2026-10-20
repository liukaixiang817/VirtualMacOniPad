#!/usr/bin/env python3
"""Assemble and locally sign a real, zero-unresolved independent27 product.

Inputs must be actual frozen stage and definition verification files. The
private temporary tree is the only signing target. No device, trust cache,
installation, execution of an iOS image or default/fixture anchor is used.
"""
import argparse, collections, hashlib, importlib.util, json, os, pathlib
import plistlib, shutil, stat, struct, subprocess, sys, tempfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
spec = importlib.util.spec_from_file_location('signed_product_macho', READER)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
TARGET_ROOT = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
CHILD = 'com.apple.Virtualization.VirtualMachine'
CHILD_UUID = '4a6a588d1afd30f5a64d6304eb79be0b'
VZ_UUID = '418efc4809d93606918eb6f95baeffdc'
PARENT_ROOTS = ('VM27HVVMProduction.dylib', 'VM27OwnedAppStartupV3.dylib',
                'UniversalHIDKit27.dylib', 'VZ27.dylib')
PREMAIN = 'VM27OwnedAppChildPreMainV3.dylib'
PROFILE_SHA256 = '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504'
PROFILE_BYTES = 32301
PROFILE_NAME = CHILD + '.sb'
FORBIDDEN = ('VZHostCompat', 'ModernCPURuntimeCompat', 'VM27StartupV9',
             'VM27OwnedAppStartupV2', 'VM27OwnedAppChildPreMainV2',
             'OriginalV9Transport', 'OwnedStartupV2')

def need(v, why):
    if not v: raise ValueError(why)
def digest(b): return hashlib.sha256(b).digest()
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=digest(b).hex())
def save(p, v): p.write_text(json.dumps(v, indent=2, ensure_ascii=False)+'\n')
def relative(s):
    return isinstance(s, str) and 0 < len(s) <= 1024 and not s.startswith('/') and all(
        x and x not in ('.', '..') and not any(ord(c) < 32 for c in x) for x in s.split('/'))
def regular_bytes(p):
    p = pathlib.Path(p); before = p.lstat()
    need(stat.S_ISREG(before.st_mode), 'regular input, no symlink: '+str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd); chunks = []; remaining = a.st_size
        while remaining:
            b = os.read(fd, min(remaining, 1024*1024)); need(b, 'complete stable input'); chunks.append(b);remaining-=len(b)
        need(not os.read(fd, 1), 'input grew while reading'); b = os.fstat(fd)
        need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns) ==
             (b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns), 'input changed while reading')
        need((before.st_dev,before.st_ino)==(a.st_dev,a.st_ino), 'input inode changed')
        return b''.join(chunks)
    finally: os.close(fd)
def copy_regular(source, target, executable=True):
    data = regular_bytes(source); target.parent.mkdir(parents=True, exist_ok=True)
    need(not target.exists() and not target.is_symlink(), 'fresh destination')
    with target.open('xb') as f: f.write(data)
    target.chmod(0o700 if executable else 0o600)
    return data

def image_profile(data, label):
    im = m.MachO(data)
    need(struct.unpack_from('<I', data, 4)[0] == 0x100000c, 'true arm64 CPU '+label)
    need(struct.unpack_from('<I', data, 8)[0] & 0xffffff == 2, 'true arm64e ABI '+label)
    versions = [struct.unpack_from('<4I', data, c['at']+8) for c in im.commands if c['cmd'] == 0x32]
    need(len(versions) == 1 and versions[0][0] == 2 and 0 < versions[0][1] <= 0x100100,
         'actual iOS declaration compatible with iOS16.1: '+label)
    need(not any(c['cmd'] in (0x24,0x25,0x2f,0x30) for c in im.commands), 'ambiguous legacy version declaration')
    need(not any(x in label for x in FORBIDDEN), 'forbidden old runtime '+label)
    for c in im.loads: need(not any(x in c['path'] for x in FORBIDDEN), 'forbidden load '+c['path'])
    return im

def be32(b, p):
    need(0 <= p <= len(b)-4, 'big-endian word bound'); return struct.unpack_from('>I', b, p)[0]
def signature(data, expected_uuid, external=None):
    """Mirror Runtime1's actual primary SHA256 pages and all special slots."""
    im=m.MachO(data); need(im.uuid==expected_uuid,'signed actual UUID')
    cmds=[c for c in im.commands if c['cmd']==0x1d];need(len(cmds)==1,'one actual LC_CODE_SIGNATURE')
    start,size=struct.unpack_from('<II',data,cmds[0]['at']+8)
    need(12<=size and start+size<=len(data),'actual signature file range')
    blob=data[start:start+size]; length,count=be32(blob,4),be32(blob,8)
    need(be32(blob,0)==0xfade0cc0 and 12<=length<=size and count<=64 and 12+8*count<=length,'actual superblob')
    slots={}
    for i in range(count):
        typ,off=struct.unpack_from('>II',blob,12+8*i);need(off+8<=length and typ not in slots,'unique signature slot')
        n=be32(blob,off+4);need(n>=8 and off+n<=length,'actual slot extent');slots[typ]=blob[off:off+n]
    cd=slots.get(0,b'');need(len(cd)>=44,'actual primary CodeDirectory')
    version,hash_at,special,code,limit=[be32(cd,p)for p in (8,16,24,28,32)]
    hash_size,hash_type,page=cd[36],cd[37],cd[39]
    need(be32(cd,0)==0xfade0c02 and be32(cd,4)==len(cd) and version>=0x20001 and
         hash_size==32 and hash_type==2 and 0<page<=16 and limit<=start and special<=64 and
         hash_at>=special*32 and hash_at+code*32<=len(cd) and code==(limit+(1<<page)-1)>>page,
         'actual primary SHA256 CodeDirectory shape')
    if version>=0x20300:
        need(len(cd)>=64 and be32(cd,56)==0 and be32(cd,60) in (0,limit),'Runtime1-supported extended code limit')
    for i in range(code):
        a=i<<page;need(digest(data[a:min(a+(1<<page),limit)])==cd[hash_at+32*i:hash_at+32*(i+1)],
                      'actual signed code page '+str(i))
    external=external or {};special_rows=[]
    for i in range(1,special+1):
        expected=cd[hash_at-32*i:hash_at-32*(i-1)];value=slots.get(i)
        if i in external:
            need(value is None,'no ambiguous embedded/external slot');value=external[i]
        if value is not None: need(digest(value)==expected,'actual special slot '+str(i))
        else: need(not any(expected),'missing nonzero special slot '+str(i))
        special_rows.append(dict(slot=i,present=value is not None,external=i in external,sha256=expected.hex()))
    entitlements=None
    if 5 in slots:
        need(be32(slots[5],0)==0xfade7171,'actual XML entitlements blob')
        entitlements=plistlib.loads(slots[5][8:])
    return dict(uuid=im.uuid, cdhash=digest(cd).hex()[:40], primaryCodeDirectorySHA256=digest(cd).hex(),
        primaryHashType=hash_type,actualCodePages=code,pageShift=page,codeLimit=limit,
        actualSpecialSlots=special_rows,embeddedEntitlements=entitlements,
        signatureFileOffset=start,signatureBytes=size,allPrimaryPagesAndSpecialSlotsVerified=True)

def read_inputs(stage_path, verification_path):
    raw=regular_bytes(stage_path);stage=json.loads(raw);proof_raw=regular_bytes(verification_path);proof=json.loads(proof_raw)
    need(proof.get('unresolvedStrongImportRows')==[] and proof.get('remainingActualStrongSymbols')==0,
         'actual zero-unresolved strong-import proof required')
    need(proof.get('finalStrongDefinitionGraphClosed') is True,'actual finalized strong graph required')
    need(not proof.get('requiredSelectedLoadGaps',[]) and
         (proof.get('allSelectedFirstLoadImagePathsAvailable') is True or proof.get('allRequiredSelectedFirstLoadsAvailable') is True),
         'actual required first-load proof')
    need(isinstance(stage.get('stagedImages'),list) and 0<len(stage['stagedImages'])<=128,'finite actual stage')
    files={};images={}
    for row in stage['stagedImages']:
        key=row['key'];need(relative(key) and '/' not in key and key not in files,'unique flat key')
        source=pathlib.Path(row['staged']['path']);data=regular_bytes(source)
        need(dict(path=str(source.resolve()),bytes=len(data),sha256=digest(data).hex())==row['staged'],'actual staged pin '+key)
        files[key]=row['staged'];images[key]=image_profile(data,key)
    aliases=stage.get('canonicalAliases',{})
    def canonical(k):
        k=aliases.get(k,k);need(k in files,'selected root '+k);return k
    roots=[canonical(k)for k in PARENT_ROOTS];child=canonical(CHILD);premain=canonical(PREMAIN)
    # Actual proof must join the same immutable image pins, not a stale list.
    proof_pins={r['path']:r for r in proof.get('sources',[])if isinstance(r,dict) and 'sha256'in r}
    need(proof_pins.get(str(stage_path.resolve()))==pin(stage_path),'proof is anchored to actual stage candidate')
    # Verification v2 anchors the stage candidate itself; that exact candidate
    # contains every image pin checked above. An additional direct image pin,
    # when present, must also agree. Do not invent a different proof schema.
    for row in files.values():
        if row['path'] in proof_pins: need(proof_pins[row['path']]==row,'same direct proof image pin')
    actual_rows=proof.get('actualStrongImportRows');need(isinstance(actual_rows,list),'actual import rows required')
    seen=set()
    for row in actual_rows:
        key=row['importer'];imp=row['actualImport'];need(key in images,'actual proof importer')
        need(images[key].imports[imp['index']]==imp and not imp['weak'],'same actual import record')
        need(row['resolution']['resolved'] is True,'actual resolved import');seen.add((key,imp['index']))
    weak_rows=proof.get('actualNativeWeakDefinitionRows',proof.get('actualNativeWeakDefinitions',[]))
    for row in weak_rows:
        key=row['importer'];imp=row['actualImport'];need(images[key].imports[imp['index']]==imp,'same weak-lookup record')
        res=row.get('actualDefinition',row.get('resolution'))
        need(imp['ordinal']==-3 and not imp['weak'] and imp['addend']==0 and res['resolved'] is True,
             'real captured native weak coalescing definition')
        need(res['route'][-1]['actualExport']['flags'] & 4,'true native weak export flag')
        seen.add((key,imp['index']))
    need(seen=={(k,r['index'])for k,im in images.items()for r in im.imports if not r['weak']},'every actual strong import joined')
    native_path=N/'current-native-header-export-index-v3/index.json';native=json.loads(regular_bytes(native_path))['images']
    need(proof_pins.get(str(native_path.resolve()))==pin(native_path),'captured current native index proof')
    def closure(start):
        queue=collections.deque(start);found=set()
        while queue:
            key=queue.popleft()
            if key in found:continue
            found.add(key)
            for dep in images[key].loads:
                p=dep['path']
                if p.startswith('@loader_path/'):
                    to=p[len('@loader_path/'):];need(to in images,'actual relative dependency '+p);queue.append(to)
                else:
                    if p not in native:
                        load=next((r for r in proof['actualLoadRows']if r['importer']==key and r['ordinal']==dep['ordinal']),None)
                        need(dep['cmd']==0x80000018 and load and load['required'] is False and
                             not any(not r['weak']and r['ordinal']==dep['ordinal']for r in images[key].imports),
                             'only actual captured native or proved nonrequired weak dependencies '+p)
        return found
    firmware=stage.get('firmwareResources',[])
    need(len(firmware)==5,'actual five firmware resources required')
    expected_firmware={'AVPBooter.vmapple2.bin','AVPBooter.vresearch1.bin','AVPSEPBooter.vresearch1.bin','VZG11.fd','VZG21.fd'}
    need({r['relativePath']for r in firmware}=={'Firmware27/'+n for n in expected_firmware},'exact genuine firmware layout')
    for resource in firmware:
        data=regular_bytes(resource['local']['path'])
        need(pin(resource['local']['path'])==resource['local'] and resource['kind']=='resource' and resource['role']=='firmware',
             'actual frozen firmware source')
        need(resource['hostMachO'] is False and resource['addsTrustCacheHash'] is False,'data resources only')
    dynamic=stage.get('explicitRequiredDynamicChildImages',[])
    need(set(dynamic)=={'VM27GenuineSandboxCompiler27.dylib','VM27GenuineMatch27.dylib','VM27SandboxCompilerImportsCompatV1.dylib'} and len(dynamic)==3, 'three genuine dynamic compiler dependencies explicitly packaged')
    parent=closure(roots);children=closure([child,premain]+dynamic)
    need(premain not in parent and child not in parent and not any('ChildPreMain'in k for k in parent),
         'child-only constructor absent from actual parent closure')
    need(all(struct.unpack_from('<I',images[k].data,12)[0]==6 for k in parent),'parent only actual dylibs')
    need(images[child].uuid==CHILD_UUID and struct.unpack_from('<I',images[child].data,12)[0]==2,'actual original child main')
    need(images[roots[3]].uuid==VZ_UUID,'actual original VZ class image')
    need(struct.unpack_from('<I',images[child].data,images[child].file(images[child].base+0x2e9d4c))[0]==0x9404a45a,
         'original setup BL2e9d4c untouched')
    entries=[]
    for key,symbol in [(roots[0],'hv_vm_config_create'),(roots[1],'VM27OwnedAppParentStartWithScopedPolicyV2'),
                       (roots[1],'VM27OwnedAppParentCopyStateV1'),(roots[3],'OBJC_CLASS_$_VZVirtualMachine')]:
        e=images[key].exports.get('_'+symbol);need(e and e['flags']==0 and 'address'in e,'actual direct strong export '+symbol)
        entries.append(dict(key=key,symbol=symbol,rva=e['address']))
    return dict(stage=stage,firmware=firmware,proof=proof,proofRaw=proof_raw,files=files,images=images,parent=parent,child=children,
        roots=roots,main=child,premain=premain,entries=entries,nativeIndex=pin(native_path),
        setupBLFileOffset=images[child].file(images[child].base+0x2e9d4c))

def assemble(inputs,o):
    commands=[]
    def run(label,args):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=60)
        (o/(label+'.stdout')).write_bytes(result.stdout);(o/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=args,exit=result.returncode));save(o/'commands.json',commands)
        need(result.returncode==0,label+': '+result.stderr.decode(errors='replace'));return result.stdout
    parent_ent=plistlib.loads(regular_bytes(S/'VirtualMac.entitlements'));child_ent=dict(parent_ent)
    removed={k:child_ent.pop(k)for k in ('com.apple.private.tcc.allow','com.apple.virtualization.avp.videotoolbox')if k in child_ent}
    # The unchanged received-message LWCR requires this exact Boolean on
    # the owned child before its first configuration request. Preserve the
    # parent App contract and every other copied child entitlement.
    need('com.apple.private.virtualization.plugin' not in child_ent,
         'the prior genuine child contract lacks the required plugin key')
    child_ent['com.apple.private.virtualization.plugin'] = True
    for k in ('platform-application','com.apple.private.hypervisor','com.apple.private.security.no-sandbox',
              'com.apple.security.virtualization','com.apple.private.virtualization',
              'com.apple.private.virtualization.plugin'):
        need(child_ent.get(k) is True,'actual child required entitlement '+k)
    save(o/'entitlement-contract.json',dict(parentAppEntitlements=pin(S/'VirtualMac.entitlements'),
        childEntitlements=child_ent,removedIrrelevantMicrophoneAndAVP=removed,childEntitlementsAreAuthorization=False,
        localSignOnly=True,deviceOperations=0))
    ent_path=o/'child.entitlements.plist';ent_path.write_bytes(plistlib.dumps(child_ent,sort_keys=True))
    with tempfile.TemporaryDirectory(prefix='vm27-signed-runtime-',dir='/private/tmp')as work:
        work=pathlib.Path(work);runtime=work/'runtime';runtime.mkdir(mode=0o700)
        registry='child-flat';bundle=registry+'/VMM.bundle'
        service=bundle+'/Contents/XPCServices/'+CHILD+'.xpc';contents=service+'/Contents';macos=contents+'/MacOS'
        xpc=runtime/service;relative_paths={};source_snapshots={}
        for role,keys,prefix in [('parent',inputs['parent'],'parent-flat'),('child',inputs['child'],macos)]:
            for key in sorted(keys):
                rel=prefix+'/'+key;destination=runtime/rel
                source_snapshots[(role,key)]=copy_regular(inputs['files'][key]['path'],destination)
                relative_paths[(role,key)]=rel
        parent_info=dict(CFBundleIdentifier='org.lkx.VirtualMacIndependent27.VMMHostBundleV1',CFBundleName='VMM',
            CFBundlePackageType='BNDL',CFBundleVersion='1',CFBundleSupportedPlatforms=['iPhoneOS'])
        child_info=dict(CFBundleIdentifier=CHILD,CFBundleExecutable=inputs['main'],CFBundleName=CHILD,
            CFBundlePackageType='XPC!',CFBundleVersion='1',CFBundleSupportedPlatforms=['iPhoneOS'],
            XPCService=dict(RunLoopType='dispatch_main',ServiceType='Application'))
        info_paths={'parent-info':bundle+'/Contents/Info.plist','child-info':contents+'/Info.plist'}
        for key,relative_path in info_paths.items():
            p=runtime/relative_path;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(plistlib.dumps(parent_info if key=='parent-info'else child_info,fmt=plistlib.FMT_BINARY,sort_keys=True));p.chmod(0o600)
        profile_relative = contents + '/Resources/' + PROFILE_NAME
        profile_destination = runtime / profile_relative
        copied_profile = copy_regular(inputs['sandboxProfile']['path'], profile_destination, executable=False)
        need(len(copied_profile) == PROFILE_BYTES and digest(copied_profile).hex() == PROFILE_SHA256,
             'exact genuine macOS27 original sandbox resource')
        imported_resources=[]
        for resource in inputs['sandboxImports']:
            relative_path=contents+'/'+resource['relativePath']
            need(resource['runtimeRelativePath']==relative_path,'actual imported profile runtime path')
            copied=copy_regular(resource['local']['path'],runtime/relative_path,executable=False)
            need(digest(copied).hex()==resource['local']['sha256'] and len(copied)==resource['local']['bytes'],'genuine imported profile bytes')
            imported_resources.append((resource,relative_path,copied))
        for p in runtime.rglob('*'):
            need(not p.is_symlink(),'no symlinks in signing product')
            if p.is_dir():p.chmod(0o700)
        signatures={}
        for (role,key),rel in sorted(relative_paths.items()):
            if role=='child'and key==inputs['main']:continue
            path=runtime/rel;label=role+'-'+key
            run('sign-'+label,['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256',
                '--identifier','org.lkx.VirtualMacIndependent27.'+role+'.'+key,path])
            run('verify-'+label,['codesign','--verify','--strict',path])
            signatures[(role,key)]=signature(regular_bytes(path),inputs['images'][key].uuid)
        run('sign-child-xpc',['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256',
            '--identifier',CHILD,'--entitlements',ent_path,'--generate-entitlement-der',xpc])
        run('verify-child-xpc',['codesign','--verify','--strict',xpc])
        resources_path=contents+'/_CodeSignature/CodeResources';resources=regular_bytes(runtime/resources_path)
        sealed = plistlib.loads(resources)
        seal = sealed.get('files2', {}).get('Resources/' + PROFILE_NAME)
        need(isinstance(seal, dict) and seal.get('hash2') == digest(copied_profile) and
             not seal.get('optional', False) and not seal.get('omit', False),
             'actual new resource has mandatory SHA256 CodeResources seal')
        for resource,relative_path,copied in imported_resources:
            seal=sealed.get('files2',{}).get(resource['relativePath'])
            need(isinstance(seal,dict) and seal.get('hash2')==digest(copied) and not seal.get('optional',False) and not seal.get('omit',False),'mandatory SHA256 seal of actual imported profile')
        actual_child=regular_bytes(runtime/relative_paths[('child',inputs['main'])])
        need(len(actual_child)<=8*1024*1024,'actual child main bounded by8MiB')
        child_signature=signature(actual_child,CHILD_UUID,{1:regular_bytes(runtime/info_paths['child-info']),3:resources})
        need(child_signature['embeddedEntitlements']==child_ent,'actual child embedded entitlements match input')
        need({r['slot']for r in child_signature['actualSpecialSlots']if r['external']}=={1,3},'actual external Info1/CodeResources3')
        signatures[('child',inputs['main'])]=child_signature
        # Signing may change signature geometry and its load-command records;
        # every actual code/data section, import, chain/PAC and UUID stays real.
        for (role,key),before in source_snapshots.items():
            after=regular_bytes(runtime/relative_paths[(role,key)]);old=inputs['images'][key];new=image_profile(after,key)
            need(new.uuid==old.uuid and new.sections==old.sections and new.imports==old.imports and new.binds==old.binds and
                 new.exports==old.exports,'signing preserves actual code identity, imports and chain words '+key)
            for section in old.sections:
                at,z=section['fileoff'],section['size']
                if at and z and section['flags']&255 not in (1,12,18):
                    need(before[at:at+z]==after[at:at+z],'signing preserves actual section bytes '+key+' '+section['name'])
        proof_path='Independent27ActualDependencyProof.json'
        (runtime/proof_path).write_bytes(inputs['proofRaw']);(runtime/proof_path).chmod(0o600)
        rows=[];ids={}
        for (role,key),rel in sorted(relative_paths.items()):
            sig=signatures[(role,key)];p=runtime/rel;identity=role+':'+key;ids[(role,key)]=identity
            row=dict(id=identity,path=rel,kind='mach-o',role='child'if(role=='child'and key==inputs['main'])else
                ('frontend'if(role=='parent'and key in inputs['roots'])else'dependency'),
                bytes=p.stat().st_size,sha256=pin(p)['sha256'],uuid=sig['uuid'],cdhash=sig['cdhash'])
            if role=='child'and key==inputs['main']:row['signatureSlots']={'1':'child-info','3':'child-coderesources'}
            rows.append(row)
        for key,rel in list(info_paths.items())+[('child-coderesources',resources_path),('dependency-proof',proof_path),
                                             ('child-sandbox-profile',profile_relative)]:
            p=runtime/rel;rows.append(dict(id=key,path=rel,kind='resource',role='proof'if key=='dependency-proof'else'registration',
                bytes=p.stat().st_size,sha256=pin(p)['sha256']))
        for resource,relative_path,copied in imported_resources:
            p=runtime/relative_path
            rows.append(dict(id=resource['id'],path=relative_path,kind='resource',role='registration',bytes=p.stat().st_size,sha256=pin(p)['sha256']))
        for resource in inputs['firmware']:
            rel=resource['relativePath'];p=runtime/rel;p.parent.mkdir(mode=0o700,exist_ok=True)
            shutil.copyfile(resource['local']['path'],p);p.chmod(0o600)
            need(pin(p)['sha256']==resource['local']['sha256'] and p.stat().st_size==resource['local']['bytes'],'actual copied firmware')
            rows.append(dict(id=resource['id'],path=rel,kind='resource',role='firmware',bytes=p.stat().st_size,sha256=pin(p)['sha256']))
        load_order=[ids[('parent',key)]for key in inputs['roots']]
        entries=[dict(fileID=ids[('parent',e['key'])],symbol=e['symbol'],rva=e['rva'])for e in inputs['entries']]
        provider=ids[('parent',inputs['roots'][0])];child_id=ids[('child',inputs['main'])]
        setup=next(e['rva']for e in entries if e['symbol']=='hv_vm_config_create')
        manifest=dict(schema=1,runtimeVersion=27,files=rows,loadOrder=load_order,entries=entries,
            dependencyProofID='dependency-proof',childEntryContract=dict(providerID=provider,childID=child_id,
                mainUUID=CHILD_UUID,symbol='hv_vm_config_create',setupBLFileOffset=inputs['setupBLFileOffset'],
                setupBLWord=0x9404a45a,providerEntryRVA=setup),
            parentBootstrapContract=dict(registryRoot=registry,immediateBundle=bundle,serviceIdentifier=CHILD,
                executableName=inputs['main'],childID=child_id,providerID=ids[('parent',inputs['roots'][1])]))
        need(len(rows)<=256,'Runtime3 file bound256');need(len(manifest['parentBootstrapContract'])==6,'Runtime3 exact6key contract')
        raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);need(0<len(raw)<=512*1024,'Runtime3 manifest512KiBbound')
        manifest_name='VM27IndependentRuntimeManifestV1.plist';(runtime/manifest_name).write_bytes(raw);(runtime/manifest_name).chmod(0o600)
        anchor=o/'vm27_independent_runtime_product_anchor_v1.c'
        anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\n'
            'const uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x)for x in digest(raw))+'};\n'
            'const size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
        # A real-product read-only preflight with the real anchor. Only the
        # host's unavailable iPad sysctl profile is admitted for this Mac test;
        # no generated Mach-O fixture/default anchor, dlopen or spawn is used.
        probe=o/'actual-product-preflight.m';probe.write_text('#import "vm27_independent_app_runtime_v1.h"\n'
            '#include <stdio.h>\nint main(int n,const char**v){@autoreleasepool{if(n!=2)return 2;NSError*e=nil;'
            'BOOL ok=VM27IndependentAppRuntimePreflightV1([NSString stringWithUTF8String:v[1]],&e);'
            'if(!ok)fprintf(stderr,"%s\\n",e.localizedDescription.UTF8String);return ok?0:1;}}\n')
        exe=o/'actual-product-preflight'
        run('compile-actual-product-preflight',['xcrun','--sdk','macosx','clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror',
            '-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-I',S,probe,S/'vm27_independent_app_runtime_v4.m',S/'vm27_actual_executable_image_v1.c',anchor,'-framework','Foundation','-o',exe])
        run('run-actual-product-preflight',[exe,runtime])
        anchor_obj=o/'vm27_independent_runtime_product_anchor_v1.ios.o'
        run('compile-actual-anchor-ios',['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-I',S,'-Wall','-Wextra','-Werror',
            '-c',anchor,'-o',anchor_obj])
        destination=o/'runtime';need(not destination.exists(),'fresh finalized runtime')
        shutil.copytree(runtime,destination,symlinks=False)
        for p in destination.rglob('*'):
            need(not p.is_symlink() and (p.is_dir() or stat.S_ISREG(p.lstat().st_mode)),'final regular product')
            if p.is_dir():p.chmod(0o700)
        # Reinspect copied final bytes; receipt paths never point at removed tmp.
        receipt=[]
        for (role,key),rel in sorted(relative_paths.items()):
            extern={1:regular_bytes(destination/info_paths['child-info']),3:regular_bytes(destination/resources_path)}if(role,key)==('child',inputs['main'])else None
            sig=signature(regular_bytes(destination/rel),inputs['images'][key].uuid,extern)
            receipt.append(dict(role=role,key=key,relativePath=rel,actualSignedFile=pin(destination/rel),**sig))
        save(o/'signature-verification.json',dict(actualSignedFiles=receipt,allCodeDirectoriesPrimarySHA256=True,
            allCodePagesAndSpecialSlotsActuallyVerified=True,childExternalSlots={'1':info_paths['child-info'],'3':resources_path},
            onlyPrivateTmpFilesSigned=True,actualIOSImagesExecuted=False,deviceOperations=0))
        save(o/'manifest.json',manifest)
        return dict(runtimeRoot=str(destination),canonicalDeviceRoot=TARGET_ROOT,manifest=pin(destination/manifest_name),
            anchorSource=pin(anchor),anchorIOSObject=pin(anchor_obj),actualProductPreflightPassed=True,
            fixtureMachOOrDefaultAnchorUsed=False,parentImages=len(inputs['parent']),childImages=len(inputs['child']),
            files=len(rows),loadOrder=load_order,entries=entries,signatureVerification=pin(o/'signature-verification.json'),
            genuineSandboxResource=pin(destination/profile_relative),
            genuineSandboxResourceManifestID='child-sandbox-profile',
            genuineImportedSandboxResources=[pin(destination/relative_path) for resource,relative_path,copied in imported_resources],
            explicitActualDynamicCompilerImages=inputs['stage']['explicitRequiredDynamicChildImages'],
            sandboxInitializationExecuted=False,sandboxCompatibilityVerified=False,
            futureInstallerOwnership=dict(uid=501,mode='0700',allDirectoriesRegular=True,deviceInstallPerformed=False),
            finalAppMainNotInManifest=True,finalAppSelfInspectionMaximumBytes=2*1024*1024,
            childMainMaximumBytes=8*1024*1024,localCodeSigned=True,trustCacheOperations=0,
            actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False)

def verify_runtime6_to_runtime8_delta(inputs,result,baseline_path,output):
    baseline=json.loads(regular_bytes(baseline_path))
    need(baseline.get('files')==148 and baseline.get('localCodeSigned') is True,'frozen actual Runtime6 baseline')
    freeze_path=baseline_path.parent/'freeze.json'
    frozen={r['path']:r for r in json.loads(regular_bytes(freeze_path))['files']}
    need(frozen.get(str(baseline_path.resolve()))==pin(baseline_path),'baseline candidate actual freeze')
    old_manifest=plistlib.loads(regular_bytes(baseline['manifest']['path']))
    new_manifest=plistlib.loads(regular_bytes(result['manifest']['path']))
    need(pin(baseline['manifest']['path'])==baseline['manifest'],'baseline manifest actual bytes')
    old_rows={r['id']:r for r in old_manifest['files']};new_rows={r['id']:r for r in new_manifest['files']}
    added_images={'child:'+x for x in ('VM27GenuineSandboxCompiler27.dylib','VM27GenuineMatch27.dylib','VM27SandboxCompilerImportsCompatV1.dylib','VM27SandboxInitOwnedCompilerV1.dylib')}
    added_resources={'child-sandbox-profile','child-sandbox-system-import','child-sandbox-dyld-import'}
    need(set(new_rows)==set(old_rows)|added_images|added_resources and len(new_rows)==155,'exact four new child images and three genuine profiles')
    child_id=new_manifest['childEntryContract']['childID']
    allowed={child_id,'child-coderesources','dependency-proof'}
    old_root=pathlib.Path(baseline['runtimeRoot']);new_root=pathlib.Path(result['runtimeRoot'])
    unchanged=[];changed=[]
    for identity,old in old_rows.items():
        new=new_rows[identity];old_path=old_root/old['path'];new_path=new_root/new['path'];old_pin=pin(old_path);new_pin=pin(new_path)
        need(frozen.get(str(old_path.resolve()))==old_pin and old_pin['bytes']==old['bytes'] and old_pin['sha256']==old['sha256'],'frozen actual baseline '+identity)
        need(new_pin['bytes']==new['bytes'] and new_pin['sha256']==new['sha256'],'actual new manifest '+identity)
        need(old['path']==new['path'] and old['kind']==new['kind'] and old['role']==new['role'],'same exact old identity')
        if identity not in allowed:
            need(old==new and regular_bytes(old_path)==regular_bytes(new_path),'every other old file wholebyte unchanged '+identity)
            unchanged.append(dict(id=identity,before=old_pin,after=new_pin,signedImage=old['kind']=='mach-o'))
        else:
            need(old_pin['sha256']!=new_pin['sha256'],'actual changed metadata/resource proof '+identity)
            changed.append(dict(id=identity,before=old_pin,after=new_pin))
    need(sum(x['signedImage'] for x in unchanged)==138,'138 old signed images wholebyte unchanged')
    before=regular_bytes(old_root/old_rows[child_id]['path']);after=regular_bytes(new_root/new_rows[child_id]['path'])
    old=m.MachO(before);new=m.MachO(after)
    need(old.uuid==new.uuid==CHILD_UUID and old.sections==new.sections and old.binds==new.binds and old.exports==new.exports,'original child section identity, chained PAC words, UUID and exports unchanged')
    for section in old.sections:
        at,size=section['fileoff'],section['size']
        if at and size and section['flags']&255 not in (1,12,18):need(before[at:at+size]==after[at:at+size],'actual original child code/pool section unchanged '+section['name'])
    need(len(old.imports)==len(new.imports),'same original child runtime import count')
    for a,z in zip(old.imports,new.imports):
        a={k:v for k,v in a.items() if k!='at'};z={k:v for k,v in z.items() if k!='at'}
        if a['index']==428:
            need(a['name']=='_sandbox_init_with_parameters' and a['ordinal']==15 and a['addend']==0 and not a['weak'],'true original native init import')
            need(z['name']=='_VM27SandboxInitWithOwnedCompilerV1' and z['ordinal']==57 and z['addend']==0 and not z['weak'],'only strong owned compiler init binding')
        else:need(a==z,'every other child import semantically identical')
    need(new.loads[:-1]==old.loads and new.loads[-1]['path']=='@loader_path/VM27SandboxInitOwnedCompilerV1.dylib' and new.loads[-1]['cmd']==12 and new.loads[-1]['ordinal']==57,'one required typed adapter dependency')
    old_sig=signature(before,CHILD_UUID,{1:regular_bytes(old_root/old_rows['child-info']['path']),3:regular_bytes(old_root/old_rows['child-coderesources']['path'])})
    new_sig=signature(after,CHILD_UUID,{1:regular_bytes(new_root/new_rows['child-info']['path']),3:regular_bytes(new_root/new_rows['child-coderesources']['path'])})
    need(old_sig['embeddedEntitlements']==new_sig['embeddedEntitlements'] and len(new_sig['embeddedEntitlements'])==13,'original exact thirteen child entitlements unchanged')
    old_slots={x['slot']:x for x in old_sig['actualSpecialSlots']};new_slots={x['slot']:x for x in new_sig['actualSpecialSlots']}
    need(set(old_slots)==set(new_slots) and all(old_slots[k]==new_slots[k] for k in old_slots if k!=3) and old_slots[3]['sha256']!=new_slots[3]['sha256'],'only mandatory bundle resource special slot changed')
    old_seal=plistlib.loads(regular_bytes(old_root/old_rows['child-coderesources']['path']));new_seal=plistlib.loads(regular_bytes(new_root/new_rows['child-coderesources']['path']))
    prefix='child-flat/VMM.bundle/Contents/XPCServices/'+CHILD+'.xpc/Contents/'
    strip_keys={new_rows[x]['path'][len(prefix):] for x in added_images|added_resources}
    need(all(new_rows[x]['path'].startswith(prefix) for x in added_images|added_resources),'all additions inside own child Contents')
    stripped=dict(new_seal)
    for bank in ('files','files2'):
        stripped[bank]={k:v for k,v in new_seal.get(bank,{}).items() if k not in strip_keys}
    need(stripped==old_seal,'all old nested bundle resource seal records unchanged')
    for k in old_manifest:
        if k!='files':need(old_manifest[k]==new_manifest[k],'unchanged entry/bootstrap contracts and real load order')
    report=dict(schema='Actual Runtime6 to Runtime8 compiler/resource metadata finite delta v1',passed=True,findings=[],baselineCandidate=pin(baseline_path),baselineFreeze=pin(freeze_path),actualStage=inputs['stagePin'],actualDefinitionGraph=inputs['graphPin'],oldFiles=148,newFiles=155,actualSignedImages=143,unchangedSignedImages=138,unchangedFiles=unchanged,changedOldFiles=changed,addedFiles=[new_rows[x] for x in sorted(added_images|added_resources)],originalMainAndAllBackedSectionsUnchanged=True,allChainedPACCodedPointerWordsUnchanged=True,onlyChildInitRuntimeImport428Retargeted=True,allRequiredDynamicCompilerImagesPackaged=True,oldEntryContractsUnchanged=True,actualIOSExecution=False,guestBooted=False,deviceOperations=0)
    save(output/'runtime6-to-runtime8-delta.json',report)
    return pin(output/'runtime6-to-runtime8-delta.json')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--stage-candidate',required=True,type=pathlib.Path)
    ap.add_argument('--verification',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path)
    ap.add_argument('--genuine-sandbox-profile',required=True,type=pathlib.Path)
    ap.add_argument('--sandbox-profile-proof',required=True,type=pathlib.Path)
    ap.add_argument('--baseline-runtime-candidate',required=True,type=pathlib.Path)
    ap.add_argument('--check-inputs-only',action='store_true');args=ap.parse_args()
    o=args.output.resolve();need(o.parent==N.resolve() and not o.exists(),'fresh diagnostics output')
    inputs=read_inputs(args.stage_candidate.resolve(),args.verification.resolve())
    profile = regular_bytes(args.genuine_sandbox_profile)
    profile_pin = pin(args.genuine_sandbox_profile)
    need(len(profile) == PROFILE_BYTES and digest(profile).hex() == PROFILE_SHA256, 'exact original macOS27 sandbox source')
    profile_proof = json.loads(regular_bytes(args.sandbox_profile_proof))
    need(any(r == profile_pin for r in profile_proof.get('files', [])), 'genuine system profile joined to frozen source proof')
    resources=inputs['stage'].get('genuineSandboxResources',[])
    need(len(resources)==3 and {x['id'] for x in resources}=={'child-sandbox-profile','child-sandbox-system-import','child-sandbox-dyld-import'},'exact three original sandbox resources in stage')
    expected={'child-sandbox-profile':(32301,PROFILE_SHA256,'Resources/'+PROFILE_NAME),'child-sandbox-system-import':(12041,'180a0356611b5de7a7db84b800ed47a1d2f15ec884d0fb960445366ededac7c8','Resources/SandboxProfiles27/system.sb'),'child-sandbox-dyld-import':(3152,'bdfc2354c683c8fb95a39e63fbc8610e9739b0256c89ab880564edefbe73a5ce','Resources/SandboxProfiles27/dyld-support.sb')}
    for resource in resources:
        size,sha,path=expected[resource['id']]
        need(resource['relativePath']==path and resource['relativePathBase']=='original child XPC Contents' and resource['kind']=='resource' and resource['mode']==0o600,'exact genuine compiler import resource contract')
        need(pin(resource['local']['path'])==resource['local'] and resource['local']['bytes']==size and resource['local']['sha256']==sha,'actual original macOS27 resource bytes')
    need(next(x['local'] for x in resources if x['id']=='child-sandbox-profile')==profile_pin,'original main profile joins frozen proof and stage')
    inputs['sandboxImports']=[x for x in resources if x['id']!='child-sandbox-profile']
    inputs.update(sandboxProfile=profile_pin,sandboxProfileProof=pin(args.sandbox_profile_proof),
        stagePin=pin(args.stage_candidate),graphPin=pin(args.verification))
    o.mkdir(mode=0o700)
    admission=dict(schema='Actual zero-import independent27 runtime product admission v1',
        actualStage=pin(args.stage_candidate),actualVerification=pin(args.verification),currentNativeIndex=inputs['nativeIndex'],
        parentClosure=sorted(inputs['parent']),childClosure=sorted(inputs['child']),actualEntries=inputs['entries'],
        childConstructorAbsentFromParent=True,trueIOS16_1CompatibleDeclarations=True,deviceOperations=0)
    save(o/'admission.json',admission)
    if args.check_inputs_only:
        print(json.dumps(dict(admission=pin(o/'admission.json'),signed=False,deviceOperations=0)));return
    try:
        result=assemble(inputs,o)
        result['runtime6DeltaVerification'] = verify_runtime6_to_runtime8_delta(inputs,result,args.baseline_runtime_candidate.resolve(),o)
        need(pin(args.genuine_sandbox_profile) == inputs['sandboxProfile'], 'genuine source unchanged after signing')
        for row in inputs['files'].values():need(pin(row['path'])==row,'frozen source unchanged after signing')
        result.update(schema='Actual signed independent27 Runtime8 genuine compiler and sandbox resources product v6',admission=pin(o/'admission.json'),
            builder=pin(__file__),sources=[pin(READER),pin(S/'VirtualMac.entitlements'),pin(S/'vm27_independent_app_runtime_v4.m'),
                pin(S/'vm27_actual_executable_image_v1.c'),pin(S/'vm27_actual_executable_image_v1.h'),
                pin(S/'vm27_independent_app_runtime_v2.m'),pin(S/'vm27_independent_app_runtime_v1.m'),
                pin(S/'vm27_independent_app_runtime_anchor_v1.h')],deviceOperations=0)
        save(o/'candidate.json',result)
        files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(args.stage_candidate),pin(args.verification)]
        files+=result['sources']+list(inputs['files'].values())+[r['local']for r in inputs['firmware']]
        files += [x['local'] for x in inputs['sandboxImports']]
        files += [inputs['sandboxProfile'],inputs['sandboxProfileProof'],pin(args.baseline_runtime_candidate),
                  pin(args.baseline_runtime_candidate.parent/'freeze.json'),pin(pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v4.py'))]
        for r in inputs['firmware']:need(pin(r['local']['path'])==r['local'],'frozen firmware unchanged after signing')
        save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0,trustCacheOperations=0,
            frozenInputsUnchanged=True,localSigningOnly=True))
        print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
    except Exception as error:
        save(o/'failure.json',dict(error=repr(error),deviceOperations=0,trustCacheOperations=0));raise
if __name__=='__main__':main()
