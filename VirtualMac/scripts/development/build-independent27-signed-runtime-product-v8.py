#!/usr/bin/env python3
"""Assemble Runtime8 with explicit owned platform preparation, not sandbox application.

Inherited genuine resource/signature machinery is kept from frozen builder V5.

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
OWN_API = '_VM27OwnedPlatformLaunchPrepareV1'
RUNTIME_CHILD_CONTENTS = 'child-flat/VMM.bundle/Contents/XPCServices/' + CHILD + '.xpc/Contents'
COMPILER_FUTURE_KEYS = {'VM27GenuineSandboxCompiler27.dylib', 'VM27GenuineMatch27.dylib',
    'VM27SandboxCompilerImportsCompatV1.dylib', 'VM27SandboxInitOwnedCompilerV1.dylib'}
BASE_BUILDER = pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v5.py')
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
    parent=closure(roots);children=closure([child,premain])
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
            sandboxInitializationExecuted=False,sandboxCompatibilityVerified=False,
            futureInstallerOwnership=dict(uid=501,mode='0700',allDirectoriesRegular=True,deviceInstallPerformed=False),
            finalAppMainNotInManifest=True,finalAppSelfInspectionMaximumBytes=2*1024*1024,
            childMainMaximumBytes=8*1024*1024,localCodeSigned=True,trustCacheOperations=0,
            actualChildSpawnExecuted=False,guestBoot=False,independent27Complete=False)

def frozen_rows(freeze_path):
    freeze = json.loads(regular_bytes(freeze_path))
    rows = freeze.get('files', freeze.get('pins'))
    need(isinstance(rows, list) and rows, 'actual source/output freeze required')
    found = {}
    for row in rows:
        exact = {k:row[k] for k in ('path', 'bytes', 'sha256')}
        need(exact['path'] not in found or found[exact['path']] == exact, 'no ambiguous freeze pins')
        found[exact['path']] = exact
    return found

def actual_frozen(row, rows, why):
    exact = {k:row[k] for k in ('path', 'bytes', 'sha256')}
    need(rows.get(exact['path']) == exact and pin(exact['path']) == exact, why)
    return exact

def own_platform_preparation_admission(inputs, stage_path, verification_path, profile_pin, profile_proof_path):
    """Read real Stage13/producer records before any signing or product output."""
    stage = inputs['stage']
    freeze_path = stage_path.parent / 'freeze.json'
    rows = frozen_rows(freeze_path)
    actual_frozen(pin(stage_path), rows, 'actual Stage13 candidate frozen')
    actual_frozen(pin(verification_path), rows, 'actual Stage13 joined graph frozen')
    need(pathlib.Path(profile_proof_path).resolve() == freeze_path.resolve(), 'profile proof is actual Stage13 freeze')
    need(len(inputs['files']) == 73 and len(inputs['parent']) + len(inputs['child']) == 139,
         'actual original73 images and139 signed role copies')
    need(not (set(inputs['files']) & COMPILER_FUTURE_KEYS), 'future compiler/adapter images are excluded')
    need(stage.get('actualAddedImages') == [] and stage.get('actualAddedChildLoadCommands') == 0,
         'no new images or child load commands')
    need(stage.get('actualOnlyReplacedImages') == [CHILD, PREMAIN] and
         stage.get('actualOther71ImagesByteIdentical') is True and
         stage.get('actualUnchangedOtherImages') == 71, 'only original child and existing premain changed')
    contract = stage.get('ownPlatformPrepContract')
    need(isinstance(contract, dict), 'explicit ownPlatformPrepContract required')
    expected = dict(symbol=OWN_API, requiredChildOrdinal=55, originalImportIndex=428,
        requiredFlags=3, requiredParametersNULL=True,
        profileCanonicalPath=TARGET_ROOT + '/' + RUNTIME_CHILD_CONTENTS + '/Resources/' + PROFILE_NAME,
        profileBytes=PROFILE_BYTES, profileSHA256=PROFILE_SHA256, nativeSandboxApplyUnavailable=45,
        sandboxProfileApplied=False, genuineConstructorOwnerRequired=True,
        actualSelfIdentityAndNativeEntitlementsRequired=True, nativeApplyInvoked=False,
        compilerProductionDependenciesRequired=False, preparedMeansOnlyOwnedPlatformLaunchChecksPassed=True,
        securityIsolationProfileDeferred=True, UID=501, EUID=501, requiredNativeCSFlags=0x04000001,
        requiredTrueNativeEntitlements=['platform-application', 'com.apple.private.security.no-container',
                                      'com.apple.private.security.no-sandbox'])
    for key, value in expected.items():
        need(type(contract.get(key)) is type(value) and contract.get(key) == value,
             'exact owned preparation contract: ' + key)
    need(stage.get('sandboxProfileApplied') is False and stage.get('nativeSandboxApplyUnavailable') == 45 and
         stage.get('nativeSandboxInitSuccessFabricated') is False, 'actual unavailable sandbox is not success')
    provider_pin = stage['ownPlatformLaunchProviderCandidate']
    actual_frozen(provider_pin, rows, 'actual premain source provider joined')
    provider = json.loads(regular_bytes(provider_pin['path']))
    need(provider.get('ownPlatformPrepContract') == contract, 'same real producer preparation contract')
    need(provider.get('passed') is True and provider.get('findings') == [] and
         provider.get('existingPermissionOnly') is True and provider.get('actualNativeGrantCalls') == 0 and
         provider.get('nativeSandboxApplyCalls') == 0 and provider.get('nativeCompilerCalls') == 0 and
         provider.get('fixtureHooksForbiddenOnIOS') is True and
         provider.get('childConstructorNativeVMOperations') == 0, 'real provider finite role and zero grant/apply/VM contract')
    provider_freeze_path = pathlib.Path(provider_pin['path']).parent / 'freeze.json'
    provider_rows = frozen_rows(provider_freeze_path)
    actual_frozen(provider_pin, provider_rows, 'producer candidate frozen')
    actual_frozen(provider['childOnlyPreMain'], provider_rows, 'producer premain image frozen')
    implementation = contract.get('sourcePin')
    need(isinstance(implementation, dict), 'exact typed preparation sourcePin required')
    actual_frozen(implementation, provider_rows, 'actual preparation implementation source frozen')
    need(implementation['path'] != provider['childOnlyPreMain']['path'], 'implementation is a source, not image flag')
    receipt = contract.get('nativeApplyReceipt')
    need(isinstance(receipt, dict) and receipt.get('bytes') == 1430 and
         receipt.get('sha256') == 'e576ac0b4c690c1e5e0ccce1269762900b055c968742f7477ada1aa3185a5e37',
         'exact actual self-only native apply observation')
    actual_frozen(receipt, provider_rows, 'actual native ENOTSUP observation frozen with producer')
    need(b'APPLY_RESULT count=1 return=-1 errno=45' in regular_bytes(receipt['path']),
         'actual diagnostic apply once returned ENOTSUP; no policy accepted')
    resources = stage.get('genuineSandboxResources')
    need(isinstance(resources, list) and len(resources) == 1, 'only genuine Main sandbox resource')
    resource = resources[0]
    need(resource['id'] == 'child-sandbox-profile' and resource['local'] == profile_pin and
         resource['runtimeRelativePath'] == RUNTIME_CHILD_CONTENTS + '/Resources/' + PROFILE_NAME and
         resource['hostMachO'] is False and resource['addsTrustCacheHash'] is False,
         'exact Stage13 Main resource and actual assembly path')
    actual_frozen(profile_pin, rows, 'actual Stage13 local profile frozen')
    for image_pin in inputs['files'].values():
        actual_frozen(image_pin, rows, 'actual selected Stage13 image frozen')
    child = inputs['images'][inputs['main']]
    imp = child.imports[428]
    need(imp['name'] == OWN_API and imp['ordinal'] == 55 and imp['weak'] == 0 and imp['addend'] == 0,
         'true selected import428 names own platform API')
    load = next(row for row in child.loads if row['ordinal'] == 55)
    need(load['cmd'] == 12 and load['path'] == '@loader_path/' + PREMAIN, 'existing required premain55')
    export = inputs['images'][inputs['premain']].exports.get(OWN_API)
    need(export and export['flags'] == 0 and 'address' in export, 'actual own preparation export in premain')
    base_pin = stage['baseStage']
    actual_frozen(base_pin, rows, 'real original Stage10 candidate frozen')
    base = json.loads(regular_bytes(base_pin['path']))
    original = {r['key']:r['staged'] for r in base['stagedImages']}
    need(set(original) == set(inputs['files']), 'same original73 source image keys')
    old_child = m.MachO(regular_bytes(original[CHILD]['path']))
    need(old_child.imports[428]['name'] == '_sandbox_init_with_parameters' and
         old_child.imports[428]['ordinal'] == 15, 'true original selected sandbox import')
    need(old_child.loads == child.loads and old_child.sections == child.sections and
         old_child.exports == child.exports and old_child.uuid == child.uuid and
         old_child.ncmds == child.ncmds and old_child.sizeofcmds == child.sizeofcmds,
         'all original child loads/sections/exports/UUID/header lengths preserved')
    need(len(old_child.imports) == len(child.imports), 'no new child import records')
    for old, new in zip(old_child.imports, child.imports):
        want = dict(old, at=new['at'])
        if old['index'] == 428:
            want.update(name=OWN_API, ordinal=55)
        need(want == new, 'only import428 name/ordinal semantics change')
    need(child.binds == [dict(row, name=OWN_API if row['index'] == 428 else row['name'])
                         for row in old_child.binds], 'all original chain words/slots/PAC fields preserved')
    for section in old_child.sections:
        at, length = section['fileoff'], section['size']
        if at and length and section['flags'] & 255 not in (1,12,18):
            need(old_child.data[at:at+length] == child.data[at:at+length], 'all original VMM backed sections unchanged')
    for key, old_pin in original.items():
        actual_frozen(old_pin, rows, 'original Stage10 image pin')
        if key not in (CHILD, PREMAIN):
            need(regular_bytes(old_pin['path']) == regular_bytes(inputs['files'][key]['path']), 'other71 actual wholebyte identity')
    inputs.update(ownPlatformPrepContract=contract, ownPlatformProvider=provider_pin,
        ownPlatformProviderFreeze=pin(provider_freeze_path), ownPlatformImplementation=implementation,
        nativeApplyObservation=receipt,
        stageFreeze=pin(freeze_path), originalStage=base_pin)
    return dict(mode='explicit-owned-platform-preparation', contract=contract,
        actualProducer=provider_pin, implementationSource=implementation, nativeApplyObservation=receipt,
        productionOpaqueCompilerObjectApplied=False, stageFreeze=pin(freeze_path),
        originalStage=base_pin, selectedImport=imp, requiredExistingLoad=load,
        actualOriginalImages=73, actualSignedRoleCopies=139, originalOther71WholebytesUnchanged=True,
        originalAllVMMBackedSectionsAndPACUnchanged=True, childLoadsWholeEqual=True,
        sandboxProfileApplied=False, sandboxApplied=False, nativeSandboxApplyUnavailable=45,
        nativeSandboxInitSuccessFabricated=False, nativeApplyInvoked=False,
        runtimeAuthorizationAndIdentityChecksPreserved=True, childConstructorAbsentFromParent=True,
        compilerFutureDependenciesIncluded=False, deviceOperations=0)

def verify_runtime6_delta(inputs, result, baseline_path, output):
    baseline = json.loads(regular_bytes(baseline_path))
    need(baseline.get('files') == 148 and baseline.get('localCodeSigned') is True,
         'actual frozen Runtime6 signed baseline')
    baseline_freeze_path = baseline_path.parent / 'freeze.json'
    frozen = frozen_rows(baseline_freeze_path)
    actual_frozen(pin(baseline_path), frozen, 'baseline candidate frozen')
    actual_frozen(baseline['manifest'], frozen, 'baseline manifest frozen actual bytes')
    old_manifest = plistlib.loads(regular_bytes(baseline['manifest']['path']))
    new_manifest = plistlib.loads(regular_bytes(result['manifest']['path']))
    old_rows = {r['id']:r for r in old_manifest['files']}
    new_rows = {r['id']:r for r in new_manifest['files']}
    need(set(new_rows) == set(old_rows) | {'child-sandbox-profile'} and len(new_rows) == 149,
         'only genuine Main resource manifest addition')
    need(sum(r['kind'] == 'mach-o' for r in old_rows.values()) == 139 and
         sum(r['kind'] == 'mach-o' for r in new_rows.values()) == 139, 'exact139 original signed images')
    child_id = new_manifest['childEntryContract']['childID']
    premain_id = 'child:' + PREMAIN
    allowed = {child_id, premain_id, 'child-coderesources', 'dependency-proof'}
    need(len(allowed) == 4 and allowed <= set(old_rows), 'four exact old changed rows')
    old_root = pathlib.Path(baseline['runtimeRoot']); new_root = pathlib.Path(result['runtimeRoot'])
    unchanged, changes = [], []
    for identity, old in old_rows.items():
        old_path = old_root / old['path']; new = new_rows[identity]; new_path = new_root / new['path']
        old_pin = actual_frozen(pin(old_path), frozen, 'actual frozen baseline file ' + identity)
        new_pin = pin(new_path)
        need(old_pin['bytes'] == old['bytes'] and old_pin['sha256'] == old['sha256'] and
             new_pin['bytes'] == new['bytes'] and new_pin['sha256'] == new['sha256'], 'real manifest file hashes')
        if identity not in allowed:
            need(old == new and regular_bytes(old_path) == regular_bytes(new_path),
                 'all other signed images/resource bits unchanged: ' + identity)
            unchanged.append(dict(id=identity, before=old_pin, after=new_pin, signedImage=old['kind'] == 'mach-o'))
        else:
            need(old['path'] == new['path'] and old['kind'] == new['kind'] and old['role'] == new['role'],
                 'changed file identity unchanged')
            need(old_pin['sha256'] != new_pin['sha256'], 'actual new intended file delta: ' + identity)
            changes.append(dict(id=identity, before=old_pin, after=new_pin))
    need(len(changes) == 4 and sum(r['signedImage'] for r in unchanged) == 137,
         'exact four old changes and137 wholebyte unchanged signed images')
    before_child = regular_bytes(old_root / old_rows[child_id]['path'])
    after_child = regular_bytes(new_root / new_rows[child_id]['path'])
    old_child, new_child = m.MachO(before_child), m.MachO(after_child)
    need(new_child.uuid == old_child.uuid == CHILD_UUID and new_child.loads == old_child.loads and
         new_child.exports == old_child.exports and new_child.sections == old_child.sections,
         'original Main loads/UUID/exports/section metadata preserved')
    need(len(new_child.imports) == len(old_child.imports), 'same original import count')
    for old, new in zip(old_child.imports, new_child.imports):
        expected = dict(old, at=new['at'])
        if old['index'] == 428:
            need(old['name'] == '_sandbox_init_with_parameters' and old['ordinal'] == 15, 'original import428')
            expected.update(name=OWN_API, ordinal=55)
        need(new == expected, 'only selected child import428 semantics change')
    need(new_child.binds == [dict(row, name=OWN_API if row['index'] == 428 else row['name'])
                             for row in old_child.binds], 'binds retain actual rawwords/auth/slot/key/diversity')
    for section in old_child.sections:
        at, length = section['fileoff'], section['size']
        if at and length and section['flags'] & 255 not in (1,12,18):
            need(before_child[at:at+length] == after_child[at:at+length], 'original Main real backed sections unchanged')
    old_sym = next(c for c in old_child.commands if c['cmd'] == 2)
    new_sym = next(c for c in new_child.commands if c['cmd'] == 2)
    need(old_sym['raw'] == new_sym['raw'], 'original symbol-table load command unchanged')
    symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', before_child, old_sym['at'] + 8)
    need(before_child[symoff:symoff+16*nsyms] == after_child[symoff:symoff+16*nsyms] and
         before_child[stroff:stroff+strsize] == after_child[stroff:stroff+strsize], 'original nlist/stringtable bytes unchanged')
    old_signature = signature(before_child, CHILD_UUID, {
        1:regular_bytes(old_root/old_rows['child-info']['path']),
        3:regular_bytes(old_root/old_rows['child-coderesources']['path'])})
    new_signature = signature(after_child, CHILD_UUID, {
        1:regular_bytes(new_root/new_rows['child-info']['path']),
        3:regular_bytes(new_root/new_rows['child-coderesources']['path'])})
    need(old_signature['embeddedEntitlements'] == new_signature['embeddedEntitlements'] and
         len(new_signature['embeddedEntitlements']) == 13 and
         new_signature['embeddedEntitlements']['com.apple.private.virtualization.plugin'] is True,
         'child original thirteen genuine XML entitlements unchanged')
    old_slots = {r['slot']:r for r in old_signature['actualSpecialSlots']}
    new_slots = {r['slot']:r for r in new_signature['actualSpecialSlots']}
    need(set(old_slots) == set(new_slots) and all(old_slots[k] == new_slots[k] for k in old_slots if k != 3) and
         old_slots[3]['sha256'] != new_slots[3]['sha256'], 'only resource special slot3 changes; XML/DER/Info retained')
    old_premain = regular_bytes(old_root/old_rows[premain_id]['path'])
    new_premain = regular_bytes(new_root/new_rows[premain_id]['path'])
    before_premain_sig = signature(old_premain, old_rows[premain_id]['uuid'])
    after_premain_sig = signature(new_premain, new_rows[premain_id]['uuid'])
    need(before_premain_sig['embeddedEntitlements'] is None and after_premain_sig['embeddedEntitlements'] is None,
         'premain adds no entitlement grant')
    old_seal = plistlib.loads(regular_bytes(old_root/old_rows['child-coderesources']['path']))
    new_seal = plistlib.loads(regular_bytes(new_root/new_rows['child-coderesources']['path']))
    resource_key = 'Resources/' + PROFILE_NAME
    nested_key = 'MacOS/' + PREMAIN
    need(resource_key not in old_seal.get('files2', {}), 'baseline genuinely lacks Main resource')
    need(new_seal.get('files2', {}).get(resource_key) == {'hash2':bytes.fromhex(PROFILE_SHA256)},
         'real mandatory resource SHA256 seal')
    for seal, sig in ((old_seal, before_premain_sig), (new_seal, after_premain_sig)):
        cdhash = sig['cdhash']
        need(seal.get('files2', {}).get(nested_key) == {
            'cdhash':bytes.fromhex(cdhash), 'requirement':'cdhash H"' + cdhash + '"'},
             'exact nested premain seal derived from its real signed CodeDirectory')
        need(nested_key not in seal.get('files', {}), 'no ambiguous legacy nested code resource')
    stripped = dict(new_seal)
    for bank in ('files', 'files2'):
        stripped[bank] = dict(new_seal.get(bank, {})); stripped[bank].pop(resource_key, None)
    stripped['files2'][nested_key] = old_seal['files2'][nested_key]
    need(stripped == old_seal, 'CodeResources only adds Main resource and changes actual premain seal')
    for key in old_manifest:
        if key != 'files':
            need(new_manifest[key] == old_manifest[key], 'all runtime entry contracts/load order unchanged')
    report = dict(schema='Actual Runtime6 to Runtime8 explicit owned preparation finite delta v1',
        baselineCandidate=pin(baseline_path), baselineFreeze=pin(baseline_freeze_path),
        actualStage=inputs['stagePin'], originalStage=inputs['originalStage'], actualDefinitionGraph=inputs['graphPin'],
        ownPlatformPrepContract=inputs['ownPlatformPrepContract'], ownPlatformProvider=inputs['ownPlatformProvider'],
        genuineProfileSource=inputs['sandboxProfile'], genuineProfileProof=inputs['sandboxProfileProof'],
        resourceAdded=new_rows['child-sandbox-profile'], actualOldInventory=148, actualNewInventory=149,
        actualSignedImages=139, wholebyteUnchangedSignedImages=137, unchangedFiles=unchanged, changedFiles=changes,
        beforeChildSignature=old_signature, afterChildSignature=new_signature,
        beforePreMainSignature=before_premain_sig, afterPreMainSignature=after_premain_sig,
        infoPlistsAndThirteenEntitlementsWholeContractUnchanged=True,
        originalMainBackedSectionsAndPACUnchanged=True, originalMainAllCodePagesUnchanged=False,
        originalChildLoadsWholeEqual=True, noNewImageOrChildLoadCommand=True,
        onlySelectedImport428NamesOwnedPreparation=True, nativeSandboxInitSuccessFabricated=False,
        mode='explicit-owned-platform-preparation', sandboxApplied=False, sandboxProfileApplied=False,
        nativeSandboxApplyUnavailable=45, nativeApplyInvoked=False,
        actualOwnedPlatformPreparationExecuted=False, guestBoot=False, deviceOperations=0,
        trustCacheOperations=0, findings=[], finiteLocalScopePassed=True)
    save(output/'runtime6-to-runtime8-delta.json', report)
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
    need(any({k:r[k] for k in ('path','bytes','sha256')} == profile_pin for r in profile_proof.get('files', [])), 'genuine system profile joined to frozen source proof')
    inputs.update(sandboxProfile=profile_pin,sandboxProfileProof=pin(args.sandbox_profile_proof),
        stagePin=pin(args.stage_candidate),graphPin=pin(args.verification))
    platform_admission = own_platform_preparation_admission(inputs,args.stage_candidate.resolve(),
        args.verification.resolve(),profile_pin,args.sandbox_profile_proof.resolve())
    baseline_path = args.baseline_runtime_candidate.resolve()
    baseline_pin = pin(baseline_path)
    need(baseline_pin['bytes'] == 5466 and baseline_pin['sha256'] ==
         '50f88b5ccfcb37cd67aa3b7fd07131d3a7a4b9f0d8147a52baeb05ccdec584eb',
         'exact actual signed Runtime6 baseline candidate')
    baseline = json.loads(regular_bytes(baseline_path))
    baseline_freeze_path = baseline_path.parent / 'freeze.json'
    baseline_rows = frozen_rows(baseline_freeze_path)
    actual_frozen(baseline_pin, baseline_rows, 'actual Runtime6 candidate frozen before signing')
    actual_frozen(baseline['manifest'], baseline_rows, 'actual Runtime6 manifest frozen before signing')
    baseline_manifest = plistlib.loads(regular_bytes(baseline['manifest']['path']))
    need(baseline.get('files') == 148 and baseline.get('localCodeSigned') is True and
         len(baseline_manifest['files']) == 148 and
         len({row['id'] for row in baseline_manifest['files']}) == 148 and
         sum(row['kind'] == 'mach-o' for row in baseline_manifest['files']) == 139,
         'actual Runtime6 baseline148 rows/139 signed images')
    baseline_admission = dict(candidate=baseline_pin, freeze=pin(baseline_freeze_path),
        manifest=baseline['manifest'], actualRows=148, actualSignedImages=139,
        oldCodePagesReverified=False, postSigningDeltaRequires137SignedWholebyteIdentity=True)
    o.mkdir(mode=0o700)
    admission=dict(schema='Actual independent27 Runtime8 owned preparation admission v1',
        ownedPlatformPreparation=platform_admission, actualRuntime6Baseline=baseline_admission, sandboxApplied=False, sandboxProfileApplied=False,
        nativeSandboxApplyUnavailable=45, nativeSandboxInitSuccessFabricated=False,
        actualStage=pin(args.stage_candidate),actualVerification=pin(args.verification),currentNativeIndex=inputs['nativeIndex'],
        parentClosure=sorted(inputs['parent']),childClosure=sorted(inputs['child']),actualEntries=inputs['entries'],
        childConstructorAbsentFromParent=True,trueIOS16_1CompatibleDeclarations=True,deviceOperations=0)
    save(o/'admission.json',admission)
    if args.check_inputs_only:
        print(json.dumps(dict(admission=pin(o/'admission.json'),signed=False,deviceOperations=0)));return
    try:
        result=assemble(inputs,o)
        result['runtime6DeltaVerification'] = verify_runtime6_delta(inputs,result,args.baseline_runtime_candidate.resolve(),o)
        need(pin(args.genuine_sandbox_profile) == inputs['sandboxProfile'], 'genuine source unchanged after signing')
        for row in inputs['files'].values():need(pin(row['path'])==row,'frozen source unchanged after signing')
        result.update(schema='Actual signed independent27 Runtime8 owned platform preparation product v8',
            ownPlatformPrepContract=inputs['ownPlatformPrepContract'], mode='explicit-owned-platform-preparation',
            sandboxApplied=False,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,
            nativeSandboxInitSuccessFabricated=False,actualOwnedPlatformPreparationExecuted=False,admission=pin(o/'admission.json'),
            builder=pin(__file__),sources=[pin(READER),pin(S/'VirtualMac.entitlements'),pin(S/'vm27_independent_app_runtime_v4.m'),
                pin(S/'vm27_actual_executable_image_v1.c'),pin(S/'vm27_actual_executable_image_v1.h'),
                pin(S/'vm27_independent_app_runtime_v2.m'),pin(S/'vm27_independent_app_runtime_v1.m'),
                pin(S/'vm27_independent_app_runtime_anchor_v1.h')],deviceOperations=0)
        save(o/'candidate.json',result)
        files=[pin(p)for p in sorted(o.rglob('*'))if p.is_file()]+[pin(__file__),pin(args.stage_candidate),pin(args.verification)]
        files+=result['sources']+list(inputs['files'].values())+[r['local']for r in inputs['firmware']]
        files += [inputs['sandboxProfile'],inputs['sandboxProfileProof'],pin(args.baseline_runtime_candidate),
                  pin(args.baseline_runtime_candidate.parent/'freeze.json'),pin(BASE_BUILDER),inputs['stageFreeze'],inputs['ownPlatformProvider'],
                  inputs['ownPlatformProviderFreeze'],inputs['ownPlatformImplementation'],inputs['originalStage'],
                  inputs['nativeApplyObservation']]
        for r in inputs['firmware']:need(pin(r['local']['path'])==r['local'],'frozen firmware unchanged after signing')
        save(o/'freeze.json',dict(files=list({p['path']:p for p in files}.values()),deviceOperations=0,trustCacheOperations=0,
            frozenInputsUnchanged=True,localSigningOnly=True))
        print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),manifest=result['manifest'],anchor=result['anchorSource'])))
    except Exception as error:
        save(o/'failure.json',dict(error=repr(error),deviceOperations=0,trustCacheOperations=0));raise
if __name__=='__main__':main()
