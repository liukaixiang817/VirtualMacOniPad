#!/usr/bin/env python3
"""Build an unsigned ordinary GPU leaf and test its own typed-call guards."""
import argparse,hashlib,importlib.util,json,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_stock',HERE/'audit-modern-genuine-hid-current-frontier-v15.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);s,p=f.s,f.p
from current_hid_system_three_capture_v1 import join as join_three
from macho_chained_import_records_v1 import read

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE)and not out.exists()
    host=p.ROOT/'VirtualMac/vz/host'
    provider=host/'modern_metal_device_array.m';fixture=host/'modern_metal_device_array_ipad_fixture.m'
    tests=host/'modern_metal_device_array_type_guard_tests.m'
    build=p.NODE/'metal-device-array-data-build-v4/candidate.json'
    for pin in json.loads((build.parent/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    pins=[p.pin(x)for x in (Path(__file__),provider,fixture,tests,build)]
    out.mkdir(mode=0o700);commands=[]
    def run(label,argv):
        argv=list(map(str,argv));result=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=argv,exitCode=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out/'commands.json',commands);assert result.returncode==0,(label,result.stderr.decode())
        return result
    try:
        fixtures=[]
        for sanitized in (False,True):
            label='typed-guards-asan-ubsan'if sanitized else'typed-guards-normal';exe=out/(label+'-ordinary-mac')
            flags=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0','-O2','-Wall','-Wextra','-Werror','-fno-objc-arc',
                '-DVM27_METAL_DEVICE_ARRAY_EXPORT=VM27MetalDeviceArrayFixture']
            if sanitized:flags+=['-fsanitize=address,undefined']
            run(label+'-build',flags+[provider,tests,'-framework','Metal','-framework','Foundation','-o',exe])
            result=run(label+'-execute',[exe]);assert not result.stderr
            actual=json.loads(result.stdout)
            assert actual==dict(checks=23555,failures=0,ownSyntheticObjects=6144,actualBOOLCalls=1024,
                actualSignedCharCalls=1024,wrongTypeCalls=0,nativeGPUCalls=0,systemMethodsAdded=0,deviceOperations=0)
            fixtures.append(dict(executable=p.pin(exe),actualResult=actual,allOwnTypedGuardCodeInstrumented=sanitized,
                syntheticOwnClassesOnly=True,actualNativeGPUObjectsTested=False))
        exe=out/'ordinary-metal-array.unsigned.inert.macho-data'
        flags=['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-O2','-Wall','-Wextra','-Werror','-fno-objc-arc',
            '-DVM27_METAL_DEVICE_ARRAY_EXPORT=VM27MetalDeviceArrayFixture']
        run('ios-ordinary-build',flags+[provider,fixture,'-framework','Metal','-framework','Foundation','-Wl,-no_adhoc_codesign','-o',exe])
        run('ios-dyld-validate',['xcrun','dyld_info','-validate_only',exe]);raw=exe.read_bytes()
        assert not any(cmd==0x1d for cmd,at,size in p.commands(raw))
        deps=p.dependencies(raw)
        forbidden=('Hypervisor','Virtualization','VirtualMachineMonitor','UniversalHID','ModernCPU','VM27Cxx','@loader_path/','@rpath/VM27')
        assert not any(any(token in x['path']for token in forbidden)for x in deps)
        schema=read(raw,p.commands);assert all(x['ordinal']>0 and not x['weak']for x in schema['imports'])
        assert not any(any(token in x['name']for token in ('hv_','Hypervisor','VZ','VirtualMachine','VM27Cxx','VM27Static'))for x in schema['imports'])
        images=s.primary.captured_images()
        for group in ('system','stock-extra','cxx-leaf'):
            pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
        for group in ('dyld-leaf','xpc-leaf'):
            pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
        pins+=f.join_kernel(s,images)
        for helper in (f.join_hid_extra,f.join_swift_two,f.join_eight,join_three):
            added,_=helper(s,images);pins+=added
        assert len(images)==32
        owners={x['ordinal']:x['path']for x in deps};proofs=[]
        for row in schema['imports']:
            proof=s.primary.resolve(images,owners[row['ordinal']],row['name'])
            if proof['status']!='actualDirectExport':
                assert row['name']=='__Unwind_Resume' and owners[row['ordinal']]=='/usr/lib/libSystem.B.dylib'
                assert proof['status']=='ownerHasNoDefinitionReexportsUnverified'
            proofs.append(dict(**row,dependency=owners[row['ordinal']],definition=proof))
        assert pins[:5]==[p.pin(x)for x in (Path(__file__),provider,fixture,tests,build)]
        report=dict(schema='Ordinary own-process finite Metal array iPad leaf fixture v1',
            executable=p.pin(exe),sourceInputs=pins[:5],actualDependencies=deps,actualImportRecords=schema,
            actualCurrentDefinitions=proofs,currentStockImages=32,
            positiveCurrentStrongDefinitions=sum(x['definition']['status']=='actualDirectExport'for x in proofs),
            remainingDefinitionsUnverified=[x for x in proofs if x['definition']['status']!='actualDirectExport'],
            nativeMetalUUID='8f062125748839efafda57db8cd80033',actualMacTypedGuardFixtures=fixtures,
            requestedOrdinaryIterations=64,ownProcessAlarmSeconds=40,mainMarker='VM27_ORDINARY_METAL_ARRAY_MAIN_V1',
            selectorQueries=['isLowPower','isRemovable'],getterCallsRequireActualResponseAndExactType=True,
            absentOrMismatchedGetterIsRecordedWithoutCalling=True,systemMethodsAdded=0,
            actualIPadGPUOrSelectorResults=None,actualIPadExecuted=False,codeSigned=False,
            noHVVMMVZOrPrivateProvidersInDependencies=True,independentReviewComplete=False,
            ordinaryExecutionAuthorizedByRootButNotDispatched=True,readyForDeviceExecution=False,
            originalVZCallerExecuted=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
        p.save(out/'candidate.json',report)
        pins += [p.pin(x)for x in out.rglob('*')if x.is_file()]
        p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),
            executable=p.pin(exe),strongDefinitions=report['positiveCurrentStrongDefinitions'],
            unprovedStrongDefinitions=len(report['remainingDefinitionsUnverified']))))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for path in (Path(__file__),provider,fixture,tests):(failed/path.name).write_bytes(path.read_bytes())
        p.save(out/'failure.json',dict(error=repr(error),deviceOperations=0));raise

if __name__=='__main__':main()
