#!/usr/bin/env python3
"""Inherit actual external-slot tests; add the exact child-only ports delta."""
import argparse, difflib, hashlib, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);out=ap.parse_args().output.resolve()
    assert out.is_relative_to(N)and not out.exists();out.mkdir();commands=[];closure={}
    parent=N/'owned-child-external-slots-source-local-v1-attempt2'
    pf=json.loads((parent/'freeze.json').read_bytes())
    for row in pf['files']:assert pin(row['path'])==row,row['path']
    pc=json.loads((parent/'candidate.json').read_bytes());assert pc['finiteLocalScopePassed']and not pc['findings']and len(pc['models'])==22
    def run(label,args):
        args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=30)
        (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));save(out/'commands.json',commands)
        assert p.returncode==0,(label,p.stdout,p.stderr);return p.stdout
    sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
    flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-fblocks','-O2','-Wall','-Wextra','-Werror','-I',S]
    sources=[S/'modern_xpc_large_private_consumer_v4.c',S/'vm27_bundle_child_inspection_v1.c',S/'modern_xpc_large_strict_identity_v2.c']
    objects=[]
    for i,p in enumerate(sources):
        obj=out/(p.stem+'.ios.o');run('compile-'+str(i),flags+['-c',p,'-o',obj]);objects.append(obj)
        deps=run('deps-'+str(i),flags+['-MM',p]).decode().replace('\\\n',' ')
        for n in shlex.split(deps.split(':',1)[1]):q=pathlib.Path(n).resolve();closure[str(q)]=pin(q)
    libraries=json.loads((N/'owned-vmm-xpc-v10-provider-build-v2/candidate.json').read_bytes())['libraries']
    selected=[row for row in libraries if row['name']in['VM27LargeRegistry.dylib','VM27ApprovedCode.dylib','VM27PrivateEndpoint.dylib','VM27LWCRPolicy.dylib']]
    for row in selected:assert pin(row['path'])=={k:row[k]for k in ['path','bytes','sha256']}
    dso=out/'VM27LargeConsumerV2.unsigned.dylib'
    run('strict-link',flags+['-dynamiclib']+objects+[r['path']for r in selected]+['-framework','CoreFoundation','-framework','Security','-Wl,-install_name,@rpath/VM27LargeConsumerV2.dylib','-Wl,-no_adhoc_codesign','-o',dso])
    run('validate',['xcrun','dyld_info','-validate_only',dso])
    new=run('exports',['xcrun','dyld_info','-exports',dso]);old=(parent/'ios-old-consumer-exports.stdout').read_bytes()
    names=lambda b:[line.split()[-1]for line in b.decode().splitlines()if'0x'in line]
    assert names(new)==names(old)and b'InheritedSpawn'not in new and b'InheritedChild'not in new and b'VM27BundleChildInspect'not in new
    run('imports',['xcrun','dyld_info','-imports',dso])
    test=S/'test-vm27-registered-child-ports-v1.c';binary=out/'actual-ports-host'
    run('host-compile',['xcrun','clang','-std=c11','-O1','-Wall','-Wextra','-Werror',test,'-o',binary])
    actual=json.loads(run('host-real-registered-ports',[binary]))
    assert actual['passed']and actual['childReaped']and actual['parentThreeSlotsUnchanged']and actual['ownParentPortsRestored']
    original=(S/'modern_xpc_large_private_consumer_v3.c').read_text();updated=sources[0].read_text()
    a=original.index('int VM27LargePrivateServiceConsumerV2Spawn(');b=original.index('\nint VM27LargePrivateServiceConsumerV2CheckMessage(',a)
    sourceBody=updated[updated.index('int VM27LargePrivateServiceConsumerV2Spawn('):]
    (out/'spawn-finite-delta.diff').write_text(''.join(difflib.unified_diff(original[a:b].splitlines(True),sourceBody.splitlines(True),fromfile='frozen3',tofile='new4')))
    # All acquired child ownership, before/after comparison and rights cleanup
    # are literally inherited from the frozen body after the diagnostic spawn.
    tail='    if (hasAttr && posix_spawnattr_destroy'
    assert original[a:b][original[a:b].index(tail):].strip()==sourceBody[sourceBody.index(tail):].strip()
    assert 'before[2] != MACH_PORT_NULL'not in sourceBody and '{before[0], before[1], inherited}'in sourceBody
    assert 'for (unsigned i = 0; unchanged && i < count; ++i) unchanged = before[i] == after[i];'in sourceBody
    # Frozen V3 is included once; its Authenticate/Create and all other APIs
    # are preserved. Only its former Spawn definition receives a hidden name.
    assert updated.count('#include "modern_xpc_large_private_consumer_v3.c"')==1
    assert pc['productionCreateThroughEndOfSourceByteIdentical']
    record=dict(schema='Actual external1/3 and child-only inherited Mach ports finite source candidate v2',
        finiteLocalScopePassed=True,findings=[],parentCandidate=pin(parent/'candidate.json'),parentFreeze=pin(parent/'freeze.json'),
        parentFreezeFilesActuallyRehashed=len(pf['files']),inheritedRealFileTestsPerMode=11,oldActualSignedChildStatus45=pc['oldActualSignedChildStatus45'],
        sourcePins=[pin(p)for p in sources+[test,pathlib.Path(__file__),S/'vm27_owned_app_child_startup_v4.c']],
        actualIncludeClosure=list(closure.values()),consumerProvider=pin(dso),objects=[pin(p)for p in objects],actualHostRegisteredPorts=actual,
        originalConsumerV2ExportNamesUnchanged=True,hiddenChildReaderNoNewPublicExport=True,
        frozenV3ExternalSlotAuthenticateAndNativeIdentityInherited=True,realChildSlot2EndpointAndParent01Preserved=True,
        fullParentThreeSlotEqualityAndAllCleanupTailByteIdentical=True,actualStartupStageDiagnosticsInherited=True,
        primarySources=[dict(url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-8792.41.9/libsyscall/wrappers/spawn/posix_spawn.c',lines='1971-1989',basis='Only appends child attributes PSPA_REGISTERED_PORTS'),
                       dict(url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-8792.41.9/bsd/kern/kern_exec.c',lines='2252-2259,2371-2422',basis='Copies send rights from current task, registers actual newly created proc_task(p)'),
                       dict(url='https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-8792.41.9/osfmk/kern/ipc_tt.c',lines='2159-2266',basis='Registered rights belong to specified task; lookup clones its actual three rights')],
        stageOrDeviceProductWritten=False,deviceOperations=0,trustCacheOperations=0,signingCalls=0,nativeVMOperations=0,
        actualUIKitParentSlot2Measured=False,actualXPCHandshakeExecuted=False,guestBoot=False,
        limitations=['Known signature-format mismatch was actually reproduced on installed-identical signed child; actual stage failure45 itself lacked stage diagnostics.',
                     'Native strict identity, parent kernel CD/entitlements, actual hello/factory and child constructor remain runtime gates.',
                     'HOST test creates only its own ordinary task rights and one test child; it does not prove iPad posix_spawn or XPC startup.',
                     'No full resource walk is performed by the inherited signed CodeResources metadata reader.'])
    save(out/'candidate.json',record)
    files={str(p.resolve()):pin(p)for p in out.rglob('*')if p.is_file()and p.name!='freeze.json'}
    for row in record['sourcePins']+record['actualIncludeClosure']:files[row['path']]=row
    for p in [parent/'candidate.json',parent/'freeze.json']:files[str(p.resolve())]=pin(p)
    for row in selected:files[row['path']]=pin(row['path'])
    save(out/'freeze.json',dict(schema='finite source2 chain and actual host-port evidence freeze',parentFreeze=pin(parent/'freeze.json'),files=list(files.values())))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),consumerProvider=pin(dso),actualHostRegisteredPorts=actual)))
if __name__=='__main__':main()
