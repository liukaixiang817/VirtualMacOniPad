"""Build/test an alternative V3 unit locally; never loads the iOS provider."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys

sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
H=R/'VirtualMac/vz/host'
BASE=N/'kernel-context-callback-lifetime-product-v3'
PENDING=N/'native-pending-control-return-contract-v1'


def pin(p):
    b=p.read_bytes()
    return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
    assert not sys.flags.optimize
    out=args.output.resolve();assert out.is_relative_to(N)
    out.mkdir(exist_ok=False)
    source=out/'source';source.mkdir()
    inputs=[];commands=[];model_results=[]
    for folder,digest in [(BASE,'1dc624a5257e71395e7a31a99564abaeb1015582a39639f9bf9cabb0b622a338'),
                          (PENDING,'4e60b2f437cdb264cf2f6766e215b15040d5a411bba4b75186fb7fdf447a8164')]:
        assert pin(folder/'freeze.json')['sha256']==digest
        inputs.append(pin(folder/'freeze.json'))
        for row in json.loads((folder/'freeze.json').read_bytes())['files']:
            assert pin(Path(row['path']))==row
    baseline=json.loads((BASE/'candidate.json').read_bytes());inputs.append(pin(BASE/'candidate.json'))
    legacy_names=[]
    for row in baseline['sourceSnapshots']:
        p=H/Path(row['path']).name
        if p.is_file():
            assert pin(p)['sha256']==row['sha256']
            legacy_names.append(p.name);inputs.append(pin(p));(source/p.name).write_bytes(p.read_bytes())
    assert len(legacy_names)==12
    for name in ['modern_cpu_kernel_lifecycle_v3.c','modern_cpu_kernel_lifecycle_v3.h',
                 'modern_cpu_pending_interrupt_values_v1.c','modern_cpu_pending_interrupt_values_v1.h']:
        p=H/name;inputs.append(pin(p));(source/name).write_bytes(p.read_bytes())
    for name in ['modern_cpu_pending_interrupt_values_v1.c','modern_cpu_pending_interrupt_values_v1.h']:
        assert (source/name).read_bytes()==(PENDING/'candidate'/name).read_bytes()
        inputs.append(pin(PENDING/'candidate'/name))
    old=(source/'modern_cpu_kernel_lifecycle_v2.c').read_text();new=(source/'modern_cpu_kernel_lifecycle_v3.c').read_text()
    start=new.index('// These two V3 APIs');end=new.index('VZKernelStatus VZKernelCPUAccessSystemRegister',start)
    new_api_block=new[start:end]
    assert '->nativeTrap(' not in new_api_block and '->ops.readMemory' not in new_api_block and 'writeMemory' not in new_api_block
    normalized=new[:start]+new[end:]
    replacements=[
        ('#include "modern_cpu_kernel_lifecycle.h"\n#include "modern_cpu_kernel_lifecycle_v3.h"','#include "modern_cpu_kernel_lifecycle.h"'),
        ('    // Own calloc-backed IRQ/FIQ values, never native creation defaults.\n    VZCPUPendingInterruptValuesV1 pendingInterrupts;\n',''),
        ('    cpu->pendingInterrupts.schemaVersion = VZ_CPU_PENDING_VALUES_SCHEMA_V1;\n',''),
        ('        memset(&cpu->pendingInterrupts, 0, sizeof(cpu->pendingInterrupts));\n',''),
        ('    --vm->cpuHandles; Unlock(&vm->mutex);\n    memset(&cpu->pendingInterrupts, 0, sizeof(cpu->pendingInterrupts));\n    free(cpu);','    --vm->cpuHandles; Unlock(&vm->mutex); free(cpu);')]
    for needle,value in replacements:
        assert normalized.count(needle)==1,needle
        normalized=normalized.replace(needle,value,1)
    assert normalized==old, 'legacy V2 code delta is outside only private field init/cleanup and new APIs'
    (out/'source-delta-from-v2.diff').write_text(''.join(difflib.unified_diff(old.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='immutable-v2',tofile='alternative-v3')))
    tests=[R/'VirtualMac/scripts/tests'/name for name in ['test-modern-cpu-owned-pending-v3.c',
        'test-modern-cpu-owned-pending-v3.cpp','test-modern-cpu-callback-lifetime-v3.c',
        'test-modern-cpu-initialization-boundary-v2.c']]
    legacy_tests=[N/'kernel-context-profiles-product-v2/source-freeze'/name for name in
                  ['lifecycle_mock_tests.c','initialization-tests.c','system-tests.c']]
    for p in tests+legacy_tests:
        inputs.append(pin(p));(source/p.name).write_bytes(p.read_bytes())
    golden=N/'kernel-context-profiles-product-v2/source-freeze/system-golden.inc'
    inputs.append(pin(golden));(source/golden.name).write_bytes(golden.read_bytes())
    inherited_model=json.loads((BASE/'model-verification.json').read_bytes())
    inputs.append(pin(BASE/'model-verification.json'))
    for p in legacy_tests+[golden]:
        rows=[row for row in inherited_model['sourceInputs'] if row['path']==str(p.resolve())]
        assert len(rows)==1 and pin(p)==rows[0], 'immutable legacy model fixture pin'
    inputs.append(pin(Path(__file__)))
    (out/'builder-snapshot.py').write_bytes(Path(__file__).read_bytes())

    def run(label,argv,asan=False):
        argv=list(map(str,argv));env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        if asan:env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0'
        child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:stdout,stderr=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill();stdout,stderr=child.communicate();raise
        (out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
        commands.append(dict(label=label,argv=argv,exit=child.returncode,directChildPID=child.pid,reaped=True))
        assert child.returncode==0,(label,stderr.decode(errors='replace'))
        return stdout,stderr

    sdk=run('macos-sdk',['xcrun','--sdk','macosx','--show-sdk-path'])[0].decode().strip()
    common=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-pthread','-isysroot',sdk,'-I',source]
    compiled=[source/name for name in ['modern_cpu_kernel_lifecycle_v3.c','modern_cpu_pending_interrupt_values_v1.c',
                'modern_cpu_native_fields.c','modern_cpu_kernel_initialization_v2.c','modern_cpu_kernel_system_v2.c']]
    for sanitized in [False,True]:
        suffix='-sanitized' if sanitized else ''
        san=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitized else []
        for whitebox in [False,True]:
            label='owned-pending'+('-whitebox' if whitebox else '')+suffix;exe=out/label
            units=compiled[1:] if whitebox else compiled
            run(label+'-compile',common+(['-DVZ_PENDING_WHITEBOX'] if whitebox else [])+[source/tests[0].name,*units,'-o',exe]+san)
            stdout,stderr=run(label+'-run',[exe],asan=sanitized);assert not stderr
            result=json.loads(stdout);assert result['full27Backend'] is False
            assert result['checks']==(680 if whitebox else 526) and result['scenarios']==(56 if whitebox else 34)
            model_results.append(dict(model=label,result=result))
        for test in tests[2:]:
            label=test.stem+suffix;exe=out/label
            run(label+'-compile',common+[source/test.name,*compiled,'-o',exe]+san)
            stdout,stderr=run(label+'-run',[exe],asan=sanitized);assert not stderr
            if test.name=='test-modern-cpu-callback-lifetime-v3.c':
                assert stdout.endswith(b'PASS: 48 callback lifetime/release/failure/owner scenarios; local mocks only\n')
                scenarios=48
            else:
                assert stdout.endswith(b'PASS: 4 stable, 48 final-callback rejection, 2 snapshot reentry, 168 read failures; local mocks only\n')
                scenarios=222
            model_results.append(dict(model=label,stdoutSHA256=hashlib.sha256(stdout).hexdigest(),passed=True,scenarios=scenarios))
        for isa in [1,2]:
            for test in legacy_tests:
                label='legacy-'+test.stem+'-isa'+str(isa)+suffix;exe=out/label
                run(label+'-compile',common+['-DVM27_MODEL_NATIVE_ISA='+str(isa),source/test.name,*compiled,'-o',exe]+san)
                stdout,stderr=run(label+'-run',[exe],asan=sanitized);assert not stderr
                result=json.loads(stdout);assert result.get('failed',0)==0 and result.get('result','PASS')=='PASS'
                model_results.append(dict(model=label,nativeISA=isa,sanitized=sanitized,result=result))
    # A C++ caller really links and executes against the separate C objects.
    mac_objects=[]
    for unit in compiled:
        obj=out/(unit.stem+'-mac.o');run(unit.stem+'-mac-object',common+['-c',unit,'-o',obj]);mac_objects.append(obj)
    cxx=out/'cxx-model'
    run('cxx-link',['xcrun','clang++','-std=c++17','-Wall','-Wextra','-Werror','-pthread','-isysroot',sdk,'-I',source,source/tests[1].name,*mac_objects,'-o',cxx])
    run('cxx-run',[cxx])

    # The copied whole pure-value unit is hidden. Only the setter is referenced
    # by V3; unused entry/return plans must disappear from the actual library.
    ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
         '-std=c11','-Wall','-Wextra','-Werror','-pthread','-I',source]
    ios_objects=[]
    for unit in compiled:
        obj=out/(unit.stem+'-ios.o')
        hidden=['-fvisibility=hidden'] if unit.name=='modern_cpu_pending_interrupt_values_v1.c' else []
        run(unit.stem+'-ios-object',ios+hidden+['-c',unit,'-o',obj]);ios_objects.append(obj)
    candidate=out/'VM27KernelOwnedPendingV3.dylib'
    run('ios-link',ios+['-dynamiclib',*ios_objects,'-Wl,-dead_strip','-Wl,-undefined,error',
        '-Wl,-install_name,@rpath/VM27KernelOwnedPendingV3.dylib','-Wl,-current_version,3.0','-Wl,-compatibility_version,3.0','-o',candidate])
    run('adhoc-sign',['codesign','--force','--sign','-',candidate]);run('strict-sign',['codesign','--verify','--strict',candidate])
    signing=run('signature',['codesign','-d','--verbose=4',candidate])[1].decode()
    entitlements=run('entitlements',['codesign','-d','--entitlements',':-',candidate])[0]
    assert not entitlements or plistlib.loads(entitlements)=={}
    run('dyld-validate',['xcrun','dyld_info','-validate_only',candidate])
    symbols=lambda b:sorted(line.split()[-1] for line in b.decode().splitlines() if line.split())
    exports=symbols(run('exports',['xcrun','nm','-gU',candidate])[0])
    added=['_VZKernelCPUReadPendingInterruptsV3','_VZKernelCPUSetPendingInterruptV3']
    assert exports==sorted(baseline['exports']+added),(exports,baseline['exports'])
    all_symbols=run('all-symbols',['xcrun','nm','-m',candidate])[0].decode()
    assert '_VZCPUPlanControl0EntryValueV1' not in all_symbols and '_VZCPUPlanControl0ReturnValueV1' not in all_symbols
    assert 'private external' in next(line for line in all_symbols.splitlines() if '_VZCPUSetPendingInterruptValueV1' in line)
    undefined=symbols(run('undefined',['xcrun','nm','-u',candidate])[0])
    old_candidate=Path(baseline['candidate']['path']);assert pin(old_candidate)==baseline['candidate']
    old_undefined=symbols(run('old-undefined',['xcrun','nm','-u',old_candidate])[0])
    added_imports=sorted(set(undefined)-set(old_undefined));removed_imports=sorted(set(old_undefined)-set(undefined))
    assert added_imports==['___memcpy_chk'] and not removed_imports
    dependencies=run('dependencies',['otool','-L',candidate])[0].decode().splitlines()[1:]
    assert len(dependencies)==2 and any('/usr/lib/libSystem.B.dylib' in x for x in dependencies)
    assert not any(x in '\n'.join(dependencies) for x in ['Hypervisor.framework','Virtualization.framework','VirtualMac2','13.2.1'])
    assert '_VZCPU27KernelTrapRaw' not in exports+undefined
    for row in inputs:assert pin(Path(row['path']))==row
    result=dict(schema='Own CPU pending lifecycle V3 local model and iOS product v1',candidate=pin(candidate),
        sourceInputs=inputs,sourceSnapshots=[pin(p) for p in sorted(source.iterdir())],
        legacySourcePinsUnchanged=True,legacyCodeNormalizedByteExactWithV2=True,
        pureValueSourceExactWithFrozenCandidate=True,pureValueSetterHidden=True,unusedEntryReturnPlansStripped=True,
        exports=exports,addedExports=added,legacyExportsPreserved=True,undefinedImports=undefined,
        addedImports=added_imports,removedImports=removed_imports,undefinedImportSetUnchanged=False,
        newImportsLimitedToFortifiedMemcpy=True,newNativeOrFrameworkImports=False,
        externalDependenciesUnchanged=True,dependencies=dependencies,signingIdentity=signing,entitlements={},
        modelResults=model_results,CPlusPlusCLinkAndExecution=True,commands=commands,
        pendingUsesOnlyOwnCallocValues=True,pendingCallbacksOnlyCurrentThread=True,
        pendingNativeReads=0,pendingNativeWrites=0,pendingNativeCalls=0,atomicGuardBeforeCallbacks=True,
        actualOwnerTLSAndGenerationRequired=True,privateCPUAndVMAliasesRefused=True,
        pendingKernelCreationDefaultsProved=False,pendingValuesAppliedToNativeControl=False,
        nativeRunAdded=False,postReturnLeaseAdded=False,USEROrVIEWConstructed=False,
        runAllowedChanged=False,architecturalResetCompleted=False,providerLoaded=False,deviceOperations=0,
        actualNativeOperations=0,guestInstructionOracle=False,original27VMMExecuted=False,independent27GuestBooted=False,full27Backend=False)
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(candidate),manifest=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),
                         publicExports=len(exports),models=len(model_results),providerLoaded=False,deviceOperations=0)))


if __name__=='__main__':main()
