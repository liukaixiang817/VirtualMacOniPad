"""Build a real typed flags3 source adapter; keep Stage/device integration held."""
import hashlib,importlib.util,json,os,re,shlex,struct,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'VirtualMac/vz/host'
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT=NODE/'sandbox-init-owned-compiler-adapter-local-v3-attempt1'
def pin(path):
    p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
def main():
    OUT.mkdir(exist_ok=False);steps=[];inputs=[]
    def run(label,args,timeout=45):
        env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        p=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=timeout)
        (OUT/(label+'.stdout')).write_bytes(p.stdout);(OUT/(label+'.stderr')).write_bytes(p.stderr)
        steps.append(dict(label=label,arguments=list(map(str,args)),exit=p.returncode,
                          stdout=pin(OUT/(label+'.stdout')),stderr=pin(OUT/(label+'.stderr'))))
        (OUT/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
        if p.returncode:raise ValueError(label+' failed')
        return p.stdout
    try:
        reader=NODE/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
        spec=importlib.util.spec_from_file_location('actual_adapter_macho',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        compiler=NODE/'mac27-sandbox-compiler-reconstructed-host-v3-attempt1/libsandbox.1.dylib.reconstructed.mac'
        compilerImage=m.MachO(compiler.read_bytes());assert compilerImage.uuid=='648b6ec9b80a3673ac47f6f7806bb158'
        APIs={'sandbox_create_params':(0x848,'38bcb13f72f538f64686dd080e835e7dfab4c04de7543c2757b61bfd06282b87'),
              'sandbox_set_param':(0x8c4,'5866c207ee5c34b37a3f5b878b27d826b84ef8d25ad0ae8151c87e49c4f45d33'),
              'sandbox_compile_file':(0xa88,'c4e11376bc9c0584d29f248a5ab0fc96bd80ee0b1ae8302d7afc9af697e65c91'),
              'sandbox_free_profile':(0x1f0dc,'f0e47579ecf6bf9e741b661f6412a8a5f8e3166872b0c3e62261d6d4a7fb9fdd'),
              'sandbox_free_params':(0x1f128,'6ce717956e0f4cdfe1c9d558bf98ee4df63d1e3b3a239d50c7232c2aa843edd8')}
        for name,(rva,sha) in APIs.items():
            assert compilerImage.exports['_'+name]==dict(flags=0,address=rva)
            assert hashlib.sha256(compiler.read_bytes()[rva:rva+16]).hexdigest()==sha
        stage=NODE/'independent27-owned-bundle-stage-v10-attempt1/candidate.json'
        original=stage.parent/'flat/com.apple.Virtualization.VirtualMachine';image=m.MachO(original.read_bytes())
        imports=[x for x in image.imports if x['name']=='_sandbox_init_with_parameters']
        assert len(imports)==1 and imports[0]['index']==428 and imports[0]['ordinal']==15 and not imports[0]['weak'] and not imports[0]['addend']
        source=SOURCE/'vm27_sandbox_init_owned_compiler_v3.c'
        tests=SOURCE/'vm27_sandbox_init_owned_compiler_host_tests_v1.c'
        helper=SOURCE/'vm27_actual_executable_image_v1.c'
        flags=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-std=c11',
               '-Wall','-Wextra','-Werror','-fvisibility=hidden','-I',SOURCE]
        closure={Path(__file__).resolve(),source,tests,helper}
        for unit in [source,helper]:
            rule=run(unit.stem+'-dependencies',flags+['-MM',unit]).decode().split(':',1)[1].replace('\\\n',' ')
            for token in shlex.split(rule):
                p=Path(token).resolve()
                assert p.is_relative_to(SOURCE) or p.name=='SDKSettings.json',str(p)
                closure.add(p)
        blob=NODE/'mac27-vmm-sandbox-compile-only-host-v1-attempt1/compiled-profile.bin'
        inputs=[pin(p) for p in sorted(closure)]+[pin(p) for p in [reader,compiler,stage,original,blob,
            NODE/'mac27-reconstructed-sandbox-compile-only-host-v3-attempt1/report.json',
            NODE/'ipad-current-native-sandbox-code-host-audit-v1-attempt2/report.json',
            NODE/'ipad-current-native-sandbox-code-readonly-v1/system-sandbox-text.bin',
            NODE/'ipad-current-native-sandbox-code-readonly-v1/sandbox-compiler-text.bin',
            NODE/'ipad-native-sandbox-apply-binding-host-audit-v1-attempt1/report.json',
            Path('/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb'),
            Path('/System/Library/Sandbox/Profiles/system.sb'),Path('/System/Library/Sandbox/Profiles/dyld-support.sb')]]
        objects=[]
        for unit in [source,helper]:
            obj=OUT/(unit.stem+'.o');objects.append(obj);run(unit.stem+'-compile',flags+['-O1','-c',unit,'-o',obj])
        binary=OUT/'VM27SandboxInitOwnedCompilerV1.dylib'
        run('ios-link',flags+objects+['-dynamiclib','-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
            '-Wl,-install_name,@rpath/VM27SandboxInitOwnedCompilerV1.dylib','-o',binary])
        run('ios-validate',['xcrun','dyld_info','-validate_only',binary]);run('ios-imports',['xcrun','dyld_info','-imports','-dependents',binary])
        im=m.MachO(binary.read_bytes());assert set(im.exports)=={'_VM27SandboxInitWithOwnedCompilerV1'}
        assert not any(c['cmd']==0x1d for c in im.commands)
        run('ios-disassembly',['xcrun','llvm-objdump','--macho','--disassemble',binary])
        prior=NODE/'sandbox-init-owned-compiler-adapter-local-v2-attempt1'
        priorCandidate=prior/'candidate.json';priorFreeze=prior/'freeze.json'
        assert pin(priorCandidate)['sha256']=='c69fd00fff9b683ad9a892e09771400a30ffe6aa7ccd275b1ce16a82f6ad134d'
        assert pin(priorFreeze)['sha256']=='711cf4b075853d9cb56c1b4bd715b2d47c9673231ee64e6c99ab2882bcdcba22'
        for row in json.loads(priorFreeze.read_bytes())['files']:
            assert all(pin(row['path'])[k]==row[k] for k in ['path','bytes','sha256'])
        oldSource=SOURCE/'vm27_sandbox_init_owned_compiler_v2.c'
        assert source.read_bytes().replace(b'#define COMPILER CHILD "/MacOS/VM27GenuineSandboxCompiler27.dylib"',b'#define COMPILER FLAT "/VM27GenuineSandboxCompiler27.dylib"')==oldSource.read_bytes()
        actualScope=NODE/'independent27-sandbox-resource-device-v2-attempt1/scope.json'
        actual=json.loads(actualScope.read_bytes())
        prefix='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents'
        assert actual['deviceChildMain']==prefix+'/MacOS/com.apple.Virtualization.VirtualMachine'
        resource=next(x for x in actual['deltaFiles'] if x.get('newResource'))
        assert resource['devicePath']==prefix+'/Resources/com.apple.Virtualization.VirtualMachine.sb'
        assert resource['new']['bytes']==32301 and resource['new']['sha256']=='59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504'
        assert pin(resource['new']['path'])==resource['new'] and resource['mode']==0o600
        child=next(x for x in actual['files'] if x['devicePath']==actual['deviceChildMain'])
        assert pin(child['local']['path'])==child['local']
        assert m.MachO(Path(child['local']['path']).read_bytes()).uuid=='4a6a588d1afd30f5a64d6304eb79be0b'
        productionBuilder=ROOT/'VirtualMac/scripts/development/build-independent27-signed-runtime-product-v5.py'
        productionSource=productionBuilder.read_text()
        assert "('child',inputs['child'],macos)" in productionSource and "macos=contents+'/MacOS'" in productionSource
        expectedCompilerPath=prefix+'/MacOS/VM27GenuineSandboxCompiler27.dylib'
        assert expectedCompilerPath.encode() in binary.read_bytes()
        assert b'/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VM27GenuineSandboxCompiler27.dylib\0' not in binary.read_bytes()
        inputs += [pin(productionBuilder)]
        save(OUT/'actual-production-compiler-path-contract.json',dict(
            actualProductionBuilder=pin(productionBuilder),productionRolePrefixExpression="('child',inputs['child'],macos)",
            expectedFixedCompilerDlopenPath=expectedCompilerPath,actualBinaryContainsExpectedFullPath=True,
            oldWrongFlatRootCompilerPathAbsentFromActualBinary=True,duplicateRootCopyAdded=False,
            runtimeChildMacOSPlacementStaticallyProved=True,actualNewRuntimeAssembled=False,deviceOperations=0))
        actualRuntime=NODE/'independent27-signed-runtime-product-v7-attempt1/candidate.json'
        inputs += [pin(x) for x in [priorCandidate,priorFreeze,prior/'host-results.json',oldSource,actualScope,actualRuntime,resource['new']['path'],child['local']['path']]]
        save(OUT/'host-results.json',dict(schema='Owned flags3 unmodified lifecycle HOST mocks inherited from prior V2 by exact source delta',
            inheritedPriorResults=pin(prior/'host-results.json'),normalAndSanitizerAssertionsEach=100,notRerun=True,
            deltaOnlyCorrectActualChildCompilerMacOSPath=True,nativeSandboxApplyCalls=0,deviceOperations=0))
        save(OUT/'source-delta.json',dict(original=pin(oldSource),current=pin(source),
            onlySourceChange='COMPILER macro uses actual CHILD/MacOS library directory; all lifecycle, ABI, error, guard and ownership code unchanged',
            v2KnownBlockingCompilerRootPath=True,v2Preserved=True,actualScope=pin(actualScope),actualRuntime=pin(actualRuntime),
            actualOriginalExecutable=child,actualMainResource=resource,
            expectedAddedImportedResources=[prefix+'/Resources/SandboxProfiles27/system.sb',prefix+'/Resources/SandboxProfiles27/dyld-support.sb'],
            nativeApplyCompatibilityStillUnobserved=True,StageIntegrationHeld=True))
        save(OUT/'patch-recipe.json',dict(schema='Inactive exact original VMM sandbox flags3 single-import recipe v3',
            originalStage=pin(stage),originalImage=pin(original),selectedOriginalImport=imports[0],
            newSymbol='_VM27SandboxInitWithOwnedCompilerV1',newStageRequiredLoad='@loader_path/VM27SandboxInitOwnedCompilerV1.dylib',
            newProvider=pin(binary),newOrdinalMustBeDerivedByRootFinalMergedLoadList=True,
            originalMainInstructionsAndFlagsAndErrorBranchMustStayWholeBytes=True,
            originalChainedFixupPointerWordsAndPACMustStayWholeBytes=True,tableNameOnlySelectedImportRetarget=True,
            requiredGenuineCompilerPath='child-flat/'+prefix.split('/child-flat/',1)[1]+'/MacOS/VM27GenuineSandboxCompiler27.dylib',requiredGenuineMatchPath='child-flat/'+prefix.split('/child-flat/',1)[1]+'/MacOS/VM27GenuineMatch27.dylib',
            requiredAddedResources=['VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/SandboxProfiles27/system.sb','VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/SandboxProfiles27/dyld-support.sb'],actualChildRootPrefixCorrectedByRuntime7Scope=True,
            existingMainProfileBytesUnchanged=True,deviceIntegrationHeld=True,requiresActualNativeApplyCompatibilityReceiptBeforeStage=True,
            actualPatchPerformed=False))
        save(OUT/'contract.json',dict(schema='Owned flags3 adapter genuine producer and native application contract v3',
            exportedABI='int(const char *profile,uint64_t flags,const char *const parameters[],char **errorbuf)',
            flags3ExactOriginalPath=True,flags3PublicParametersNULLOnly=True,internalParamOnly='IMPORT_DIR',
            roles='actual canonical original child executable UUID4a6a588d... UID/eUID501',
            opaqueSequence=['verify actual role/resource identities','resolve fixed genuine compiler5APIs UUID648b6... and current nativeapply UUID41a96... with exact exportRVA and code SHA',
                            'create real compiler params; set only own IMPORT_DIR','compile_file(originalPath,actualParams,errorout)',
                            'read and validate actual producer prefix/data against fixed genuine producer result; never replace producer pointer',
                            'revalidate genuine resource bytes; nativeapply exactly once with actual opaque pointer','save actual return and errno including errno0; producerfree_profile and free_params','return actual apply status or clear preapply failure'],
            errorOwnership='Compiler strings remain genuine malloc-owned output for caller. NULL error output uses a real local string freed by libSystem free, as native Init does. Native errno saved before cleanup.',
            nativeInitFlowEvidence='Actual iPad Init227c: compile_file dynamically resolved then apply then same producerfree_profile/free_params; no notify. Mac apply success notify belongs to unused Mac apply API.',
            otherFlags='Verified current native Init227c passthrough retaining actual arguments/result/error; no success fallback',
            profileContentUnmodified=True,diagnosticWrapperNotUsed=True,precompiledBlobNotReplayed=True,manualSyscalls=False,
            nativeApplyCompatibilityNotYetEstablished=True,StageIntegrationHeld=True,fullVM=False,guestBooted=False))
        for row in inputs:assert pin(row['path'])==row,('input changed',row['path'])
        save(OUT/'candidate.json',dict(schema='Owned flags3 real source compiler adapter unsigned candidate v3',
            sourcePins=[pin(p) for p in sorted(closure)],inputs=inputs,binary=pin(binary),actualExport=list(im.exports),
            actualIOSArm64e161CompileLinkValidatePassed=True,onlySourceDeltaActualChildCompilerMacOSPath=True,sourceDelta=pin(OUT/'source-delta.json'),hostResults=pin(OUT/'host-results.json'),
            contract=pin(OUT/'contract.json'),recipe=pin(OUT/'patch-recipe.json'),actualNativeCompilerInvoked=False,
            actualNativeSandboxApplyInvoked=False,deviceOperations=0,sourceOwnProfileCompileLifecycleImplemented=True,actualProductionCompilerPathContract=pin(OUT/'actual-production-compiler-path-contract.json'),
            nativeSandboxCompatibilityUnproved=True,requiresIndependentPeerReview=True,StageIntegrationHeld=True,
            actualPatchedImageGenerated=False,providerSigned=False,fullVM=False,guestBooted=False,finiteLocalScopePassed=True,findings=[]))
        files=inputs+[pin(p) for p in sorted(OUT.iterdir()) if p.is_file()]
        save(OUT/'freeze.json',dict(schema='Owned flags3 compiler adapter source/unsigned HOST product freeze v3',files=files))
        print(json.dumps(dict(candidate=pin(OUT/'candidate.json'),freeze=pin(OUT/'freeze.json'),binary=pin(binary))))
    except Exception as error:
        save(OUT/'failure.json',dict(error=str(error),inputs=inputs,steps=steps,deviceOperations=0,nativeSandboxApplyCalls=0));raise
if __name__=='__main__':main()
