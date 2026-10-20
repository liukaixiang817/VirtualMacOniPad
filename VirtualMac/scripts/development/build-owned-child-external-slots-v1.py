#!/usr/bin/env python3
"""Finite genuine signed-byte reader tests and inert iOS sources; no device."""
import argparse, difflib, errno, hashlib, json, os, pathlib, plistlib, shlex, shutil, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, v): p.write_text(json.dumps(v, indent=2) + '\n')
def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--output', required=True, type=pathlib.Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(N) and not out.exists(); out.mkdir()
    commands = []; closure = {}
    def run(label, args, expected=0):
        args = list(map(str, args)); p = subprocess.run(args, capture_output=True, timeout=45)
        (out/(label+'.stdout')).write_bytes(p.stdout); (out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label, argv=args, exit=p.returncode, expected=expected))
        save(out/'commands.json', commands)
        assert p.returncode == expected, (label,p.returncode,p.stdout,p.stderr)
        return p.stdout
    runtime = N/'independent27-signed-runtime-product-v3-attempt1'
    appProduct = N/'independent27-signed-app-main-identity-product-v2-attempt1'
    app = json.loads((appProduct/'candidate.json').read_bytes())
    manifest = plistlib.loads((runtime/'runtime/VM27IndependentRuntimeManifestV1.plist').read_bytes())
    child = next(row for row in manifest['files'] if row['id']=='child:com.apple.Virtualization.VirtualMachine')
    childPath = runtime/'runtime'/child['path']
    assert pin(childPath)['sha256']==child['sha256']
    assert pin(app['binary']['path'])==app['binary']
    sources = [S/'vm27_bundle_child_inspection_v1.c',S/'modern_xpc_large_private_consumer_v3.c',
               S/'vm27_owned_app_child_startup_v4.c']
    sdk = run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
    flags = ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11',
             '-fblocks','-O2','-Wall','-Wextra','-Werror','-I',S]
    objects=[]
    for i,source in enumerate(sources+[S/'modern_xpc_large_strict_identity_v2.c']):
        obj=out/(source.stem+'.ios.o');run('ios-compile-'+str(i),flags+['-c',source,'-o',obj]);objects.append(obj)
        deps=run('ios-deps-'+str(i),flags+['-MM',source]).decode().replace('\\\n',' ')
        for name in shlex.split(deps.split(':',1)[1]):
            p=pathlib.Path(name).resolve();closure[str(p)]=pin(p)
    prior=N/'owned-vmm-xpc-v10-provider-build-v2';provider=json.loads((prior/'candidate.json').read_bytes())
    libraries={x['name']:x for x in provider['libraries']}
    dependencies=[libraries[n]for n in ['VM27LargeRegistry.dylib','VM27ApprovedCode.dylib',
                                         'VM27PrivateEndpoint.dylib','VM27LWCRPolicy.dylib']]
    for row in dependencies: assert pin(row['path'])=={k:row[k]for k in ['path','bytes','sha256']}
    consumer=out/'VM27LargeConsumerV2.unsigned.dylib'
    run('ios-actual-consumer-link',flags+['-dynamiclib',objects[0],objects[1],objects[3]]+
        [x['path']for x in dependencies]+['-framework','CoreFoundation','-framework','Security',
        '-Wl,-install_name,@rpath/VM27LargeConsumerV2.dylib','-Wl,-no_adhoc_codesign','-o',consumer])
    run('ios-actual-consumer-validate',['xcrun','dyld_info','-validate_only',consumer])
    newExports=run('ios-actual-consumer-exports',['xcrun','dyld_info','-exports',consumer])
    oldExports=run('ios-old-consumer-exports',['xcrun','dyld_info','-exports',libraries['VM27LargeConsumerV2.dylib']['path']])
    def names(raw): return [line.split()[-1]for line in raw.decode().splitlines()if '0x' in line]
    assert names(newExports)==names(oldExports)
    assert b'VM27BundleChildInspect'not in newExports and b'InheritedChild'not in newExports
    run('ios-actual-consumer-imports',['xcrun','dyld_info','-imports',consumer])
    oldC=(S/'modern_xpc_large_private_consumer_v2.c').read_text()
    newC=sources[1].read_text()
    assert oldC[oldC.index('int VM27LargePrivateServiceConsumerV2Create'):]==newC[newC.index('int VM27LargePrivateServiceConsumerV2Create'):]
    (out/'consumer-exact-delta.diff').write_text(''.join(difflib.unified_diff(oldC.splitlines(True),newC.splitlines(True),fromfile='frozen-v2',tofile='new-v3')))
    base=['xcrun','clang','-std=c11','-fblocks','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-O1','-g','-I',S]
    oldProbe=N/'owned-child-enotsup-host-localization-v1-attempt1/actual-inspector.c'
    oldBinary=out/'host-old-inspector'
    run('old-inspector-compile',base+[oldProbe,S/'modern_xpc_approved_code.c',S/'modern_xpc_lwcr_policy.c',
                                    '-framework','CoreFoundation','-framework','Security','-o',oldBinary])
    oldResult=json.loads(run('old-actual-signed-child', [oldBinary,childPath]))
    assert oldResult['actualProductionInspectorStatus']==45
    copy=out/'fixture.xpc';(copy/'Contents/MacOS').mkdir(parents=True);(copy/'Contents/_CodeSignature').mkdir()
    srcContents=childPath.parent.parent
    relative=['Contents/MacOS/com.apple.Virtualization.VirtualMachine','Contents/Info.plist','Contents/_CodeSignature/CodeResources']
    for rel in relative:
        source=srcContents/pathlib.Path(rel).relative_to('Contents');shutil.copy2(source,copy/rel)
    executable=copy/relative[0]; info=copy/relative[1]; resources=copy/relative[2]
    originals={p:p.read_bytes()for p in [executable,info,resources]}
    originalsMode={p:p.stat().st_mode&0o777 for p in originals}
    args=[child['sha256'],child['cdhash'],child['uuid'],app['app'],'VirtualMacIndependent27',
          app['binary']['sha256'],app['actualSignature']['cdhash']]
    results=[]
    for san in [False,True]:
        kind='san'if san else'normal'; binary=out/('host-new-'+kind)
        extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer']if san else[]
        run(kind+'-compile',base+[S/'test-vm27-bundle-child-inspection-v1.c',sources[0],
            S/'vm27_bundle_parent_inspection_v1.c','-framework','CoreFoundation','-framework','Security',
            '-Wl,-dead_strip','-o',binary]+extra)
        def check(name,path=executable,status=0,selected=args):
            raw=run(kind+'-'+name,[binary,path]+selected,status);record=json.loads(raw)
            assert record['actualConsumerAuthenticateStatus']==status and record['actualParentInspectStatus']==0
            assert record['parentCodePagesVerified']and record['parentExternalInfoVerified']and record['parentExternalResourcesVerified']
            assert not record['wholeResourceWalkClaimed'];results.append(dict(mode=kind,case=name,**record))
        check('genuine-installed-child',childPath)
        check('genuine-copied-child')
        for name,p in [('changed-info',info),('changed-resources',resources),('changed-codepage',executable)]:
            data=bytearray(originals[p]);at=65536 if p==executable else len(data)//2;data[at]^=1;p.write_bytes(data)
            check(name,status=errno.EBADMSG);p.write_bytes(originals[p])
        check('wrong-reviewed-sha',status=errno.EACCES,selected=['0'*64]+args[1:])
        check('wrong-reviewed-cd',status=errno.EACCES,selected=[args[0],'0'*40]+args[2:])
        resources.unlink();check('missing-resources',status=errno.ENOENT);resources.write_bytes(originals[resources]);resources.chmod(originalsMode[resources])
        resources.unlink();resources.symlink_to(info);check('symlink-resources',status=errno.ELOOP);resources.unlink();resources.write_bytes(originals[resources]);resources.chmod(originalsMode[resources])
        resources.chmod(0o666);check('writable-resources',status=errno.EACCES);resources.chmod(originalsMode[resources])
        executable.chmod(0o600);check('nonexecutable-child',status=errno.EACCES);executable.chmod(originalsMode[executable])
    for p,b in originals.items():assert p.read_bytes()==b and p.stat().st_mode&0o777==originalsMode[p]
    sourcePins=[pin(p)for p in sources+[S/'vm27_bundle_child_inspection_v1.h',S/'test-vm27-bundle-child-inspection-v1.c',pathlib.Path(__file__)]]
    record=dict(schema='True installed child external1/3 reader finite source candidate v1',
        finiteLocalScopePassed=True,findings=[],oldActualSignedChildStatus45=oldResult,
        actualInstalledChild=pin(childPath),actualInstalledApp=app['binary'],sourcePins=sourcePins,
        actualIncludeClosure=list(closure.values()),objects=[pin(p)for p in objects],
        consumerProvider=pin(consumer),originalConsumerAPINamesUnchanged=True,
        productionCreateThroughEndOfSourceByteIdentical=True,slot2GateUnchanged=True,
        startupDiagnosticOnlyFrozenV3Composition=True,models=results,
        actualAppParentFlatBundleInspectionPassed=True,actualChildContentsInspectionPassed=True,
        codePagesAndEmbedded2_5_7AndRealExternal1_3Required=True,
        genuineParentV10Path='FlatBundle -> VM27BundleParentInspectV1, unchanged',
        inactiveRawReaderPaths=['V10 ParentFile only CodeOnlyDiagnostic, not production FlatBundle','LargeOriginalParent only historical largeTransport, not current V10'],
        oldRawInspectBytesStillRejectsExternalSlots=True,originalStrictNativeIdentityUnchanged=True,
        oldExplicitApprovedModeStillRejectsExternalSlots=True,wholeCodeResourcesWalkPerformed=False,
        deviceOperations=0,signingCalls=0,trustCacheOperations=0,nativeVMOperations=0,
        actualXPCHandshakeExecuted=False,guestBoot=False,
        limitations=['CodeResources seal metadata is authenticated; resources it describes are not walked by this reader.',
                     'Remaining parent slot2==NULL restriction is unchanged and actual UIKit parent ports have not been measured.',
                     'Actual strict Security entitlement policy, child hello and native bootstrap remain required at runtime.'])
    save(out/'candidate.json',record)
    files={str(p.resolve()):pin(p)for p in out.rglob('*')if p.is_file()and p.name!='freeze.json'}
    for row in sourcePins+list(closure.values()):files[row['path']]=row
    for p in [runtime/'candidate.json',runtime/'freeze.json',appProduct/'candidate.json',appProduct/'freeze.json',
              prior/'candidate.json',S/'modern_xpc_approved_code.c',S/'vm27_bundle_parent_inspection_v1.c',oldProbe]:files[str(p.resolve())]=pin(p)
    for row in dependencies:files[row['path']]=pin(row['path'])
    save(out/'freeze.json',dict(schema='finite external-slot source/output closure freeze v1',files=list(files.values())))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),consumerProvider=pin(consumer),actualCasesPerMode=11)))
if __name__=='__main__':main()
