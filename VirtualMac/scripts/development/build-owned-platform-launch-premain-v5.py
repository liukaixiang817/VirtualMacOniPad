#!/usr/bin/env python3
"""Build the explicit owned platform preparation; HOST-only, never sign or run it."""
import argparse, hashlib, importlib.util, json, pathlib, shlex, struct, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
S = R/'VirtualMac/vz/host'
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N/'independent27-owned-bundle-stage-v10-attempt1'
INDEX = N/'current-native-header-export-index-v3/index.json'
READER = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, value):
    with p.open('x') as f: f.write(json.dumps(value, indent=2)+'\n')
def exact(row):
    p = pathlib.Path(row['path']); assert pin(p) == {k:row[k] for k in ('path','bytes','sha256')}, str(p)
    return p
def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--output', type=pathlib.Path, required=True); a = ap.parse_args()
    o = a.output.resolve(); assert o.parent == N and not o.exists()
    assert pin(READER)['sha256'] == '64bc2db83c89a9a3fe180dc63259b0751952f7413c0f68e815bc4940afd7542b'
    assert pin(INDEX)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    stage = json.loads((BASE/'candidate.json').read_bytes())
    images = {row['key']: row for row in stage['stagedImages']}
    adapter = exact(images['VM27OwnedAppStartupV3.dylib']['staged'])
    old = exact(images['VM27OwnedAppChildPreMainV3.dylib']['staged'])
    inherited = N/'actual-executable-image-source-local-v1-attempt1/freeze.json'
    inherited_files = {row['path']:row for row in json.loads(inherited.read_bytes())['files']}
    for name in ('vm27_actual_executable_image_v1.c','vm27_actual_executable_image_v1.h','vm27_owned_app_child_premain_v4.c'):
        exact(inherited_files[str(S/name)])
    o.mkdir(mode=0o700); commands = []; closure = {}
    def run(label, argv, expected=0):
        argv = list(map(str, argv)); c = subprocess.run(argv, capture_output=True, timeout=60)
        (o/(label+'.stdout')).write_bytes(c.stdout); (o/(label+'.stderr')).write_bytes(c.stderr)
        commands.append(dict(label=label, argv=argv, exit=c.returncode)); (o/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        assert c.returncode == expected, (label,c.returncode,c.stderr.decode(errors='replace'))
        return c.stdout
    sdk = run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
    flags = ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks',
        '-std=c11','-fvisibility=hidden','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',S]
    sources = [S/'vm27_actual_executable_image_v1.c',S/'vm27_owned_app_child_premain_v5.c']; objects=[]
    for i, source in enumerate(sources):
        obj = o/(source.stem+'.o'); run('ios-compile-'+str(i), flags+['-c',source,'-o',obj]); objects.append(obj)
        dep = run('ios-deps-'+str(i),flags+['-MM',source]).decode().replace('\\\n',' ')
        for name in shlex.split(dep.split(':',1)[1]):
            p = pathlib.Path(name).resolve(); closure[str(p)] = pin(p)
    child = o/'VM27OwnedAppChildPreMainV3.unsigned.dylib'
    run('ios-child-link',flags+['-dynamiclib']+objects+[adapter,'-framework','CoreFoundation','-framework','Security',
        '-Wl,-undefined,error','-Wl,-install_name,@loader_path/VM27OwnedAppChildPreMainV3.dylib','-Wl,-no_adhoc_codesign','-o',child])
    for mode in ('validate_only','imports','exports','dependents'):
        run('ios-child-'+mode,['xcrun','dyld_info','-'+mode,child])
    run('ios-child-assembly',['xcrun','llvm-objdump','--macho','--disassemble','--symbolize-operands',child])
    spec = importlib.util.spec_from_file_location('owned_premain_macho',READER)
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    image = reader.MachO(child.read_bytes()); old_image = reader.MachO(old.read_bytes()); own = reader.MachO(adapter.read_bytes())
    assert set(image.exports) == {'_VM27OwnedPlatformLaunchPrepareV1'}
    assert struct.unpack_from('<II',image.data,4)==(0x100000c,0x80000002)
    builds = [struct.unpack_from('<III',c['raw'],8) for c in image.commands if c['cmd']==0x32]
    assert len(builds)==1 and builds[0][:2] == (2,0x100100)
    assert all(not row['weak'] and row['ordinal']>0 for row in image.imports)
    assert not any(any(x in row['name'] for x in ('sandbox_init','sandbox_apply','sandbox_compile','hv_vm_','KernelVM')) for row in image.imports)
    # Resolve the actual selected ordinals, including native whole reexports.
    native = json.loads(INDEX.read_bytes())['images']; used=set()
    def resolve(path,name,seen=()):
        if (path,name) in seen or path not in native: return None
        v=native[path]; used.add(path); seen=(*seen,(path,name)); definition=v['definitions'].get(name)
        if definition is not None:
            step=dict(image=path,UUID=v['UUID'],symbol=name,definition=definition)
            if definition['flags']&8:
                dep=next(d for d in v['dependencies'] if d['ordinal']==definition['ordinal'])
                rest=resolve(dep['path'],definition.get('alias') or name,seen)
                return None if rest is None else [dict(**step,reexportDependency=dep)]+rest
            return [step]
        for dep in v['dependencies']:
            if dep['command']==0x8000001f:
                rest=resolve(dep['path'],name,seen)
                if rest is not None:return [dict(image=path,UUID=v['UUID'],symbol=name,wholeDylibReexport=dep)]+rest
        return None
    routes=[]
    for row in image.imports:
        path=image.loads[row['ordinal']-1]['path']; name=row['name']
        if path=='@loader_path/VM27OwnedAppStartupV3.dylib':
            assert name=='_VM27OwnedAppChildBootstrapBeforeMainV3' and name in own.exports
            route=[dict(ownedProvider=pin(adapter),symbol=name,definition=own.exports[name])]
        else:
            route=resolve(path,name); assert route is not None,(path,name)
        routes.append(dict(importRow=row,requiredLoad=path,actualRoute=route))
    native_pins={}
    for path in sorted(used):
        for key in ('actualCompleteCommands','actualCompleteExportSource'):
            row=native[path][key]; row=row.get('rangePin',row)
            p=exact(row); native_pins[str(p)]=pin(p)
    save(o/'current-definitions.json',dict(passed=True,findings=[],actualStrongImports=len(routes),
        actualRoutes=routes,unresolved=[],nativeIndex=pin(INDEX),actualNativeInputs=list(native_pins.values()),deviceOperations=0))
    cpp=o/'actual-platform-prep-caller.cpp'
    cpp.write_text('#include "vm27_owned_app_child_premain_v5.h"\nextern "C" __attribute__((visibility("default"))) int actualPrep(const char *p,char **e){return VM27OwnedPlatformLaunchPrepareV1(p,3,nullptr,e);}\n')
    obj=o/'actual-platform-prep-caller.o'; typed=o/'actual-platform-prep-caller.unsigned.dylib'
    cxx=['xcrun','clang++']+flags[2:]; cxx[cxx.index('-std=c11')]='-std=c++17'
    run('ios-cpp-compile',cxx+['-c',cpp,'-o',obj])
    run('ios-cpp-link',cxx+['-dynamiclib',obj,child,'-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',typed])
    run('ios-cpp-validate',['xcrun','dyld_info','-validate_only',typed])
    run('ios-cpp-imports',['xcrun','dyld_info','-imports',typed])
    assert '_VM27OwnedPlatformLaunchPrepareV1' in (o/'ios-cpp-imports.stdout').read_text()
    # A fixture macro is rejected by the actual iOS source, not silently ignored.
    failed=run('ios-forbidden-fixture',flags+['-DVM27_OWNED_PLATFORM_PREP_TESTING=1','-c',sources[1],'-o',o/'forbidden.o'],expected=1)
    del failed
    assert 'fixture hooks are forbidden on iOS' in (o/'ios-forbidden-fixture.stderr').read_text() and not (o/'forbidden.o').exists()
    models=[]; fixture=S/'test_vm27_owned_platform_launch_prepare_v1.c'
    for san in (False,True):
        label='san' if san else 'normal'; binary=o/('host-model-'+label)
        args=['xcrun','clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-I',S,fixture,'-framework','CoreFoundation','-o',binary]
        if san:args+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        run('host-compile-'+label,args); result=json.loads(run('host-model-'+label,[binary]).splitlines()[-1])
        assert result['passed'] and result['cases']==40 and result['sandboxApplyCalls']==0; models.append(result)
    contract=dict(symbol='_VM27OwnedPlatformLaunchPrepareV1',originalImportIndex=428,requiredChildOrdinal=55,
        requiredFlags=3,requiredParametersNULL=True,profileCanonicalPath='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb',
        profileBytes=32301,profileSHA256='59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504',
        nativeSandboxApplyUnavailable=45,sandboxProfileApplied=False,genuineConstructorOwnerRequired=True,
        actualSelfIdentityAndNativeEntitlementsRequired=True,nativeApplyInvoked=False,compilerProductionDependenciesRequired=False,
        sourcePin=pin(sources[1]),headerPin=pin(S/'vm27_owned_app_child_premain_v5.h'),
        nativeApplyReceipt=pin(N/'native-sandbox-apply-compat-device-v6-arm64-execpolicy-attempt1/actual-execute/stdout'),
        preparedMeansOnlyOwnedPlatformLaunchChecksPassed=True,securityIsolationProfileDeferred=True,
        UID=501,EUID=501,requiredNativeCSFlags=0x04000001,
        requiredTrueNativeEntitlements=['platform-application','com.apple.private.security.no-container','com.apple.private.security.no-sandbox'])
    save(o/'candidate.json',dict(schema='Explicit own platform launch preparation child preMain v5',passed=True,findings=[],
        builder=pin(__file__),childOnlyPreMain=pin(child),ownPlatformPrepContract=contract,
        sourcePins=[pin(p) for p in sources+[S/'vm27_owned_app_child_premain_v5.h',fixture]],actualIncludeClosure=list(closure.values()),
        iosObjects=[pin(p) for p in objects],actualExports=image.exports,actualImports=image.imports,actualLoads=image.loads,
        actualAddedImportNames=sorted({r['name'] for r in image.imports}-{r['name'] for r in old_image.imports}),
        actualNativeDefinitionProof=pin(o/'current-definitions.json'),originalBootstrapAdapter=pin(adapter),
        priorChildOnlyPreMain=pin(old),priorCanonicalImageFreeze=pin(inherited),models=models,
        actualCXXTypedCallStrongLink=True,fixtureHooksForbiddenOnIOS=True,childConstructorInheritedRoleAndBootstrapABI=True,
        childConstructorNativeVMOperations=0,actualNativeGrantCalls=0,nativeSandboxApplyCalls=0,nativeCompilerCalls=0,
        sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,existingPermissionOnly=True,
        deviceOperations=0,signingCalls=0,guestBoot=False,readyForDeviceExecution=False,
        limitations=['Native audit/SecTask/code queries are mocked only in HOST fixtures; real iPad admission has not run.',
            'The sandbox profile remains unapplied; this preparation has no sandbox_init or sandbox_apply success contract.',
            'Actual whole child signing, selected original import428 port, parent constructor exclusion and final product manifest are downstream requirements.']))
    all_pins={str(p.resolve()):pin(p) for p in o.iterdir() if p.is_file()}
    for row in list(closure.values())+[pin(fixture),pin(__file__),pin(INDEX),pin(READER),pin(BASE/'candidate.json'),pin(inherited),pin(adapter),pin(old)]+list(native_pins.values()): all_pins[row['path']]=row
    assert all(pin(row['path'])==row for row in all_pins.values())
    save(o/'freeze.json',dict(schema='Owned platform preMain v5 true source/output freeze',files=list(all_pins.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),childOnlyPreMain=pin(child),currentDefinitions=pin(o/'current-definitions.json'),models=models)))
if __name__=='__main__':main()
