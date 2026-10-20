#!/usr/bin/env python3
"""Build an inert finite native scroll source and genuine ordinary Mac fixtures."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scroll_build_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from macho_chained_import_records_v1 import read as import_records
HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=p.NODE/'processed-scroll-native-data-build-v2';assert not out.exists();out.mkdir()
    names=['modern_processed_scroll_native_v1.h','modern_processed_scroll_native_v1.c',
        'modern_processed_scroll_native_fixture_v2.c','modern_processed_scroll_sink_v1.h','modern_processed_scroll_sink_v1.m']
    inputs=[Path(__file__)]+[HOST/name for name in names]+[HOST/'modern_input_packet_v2.h',HOST/'modern_uikit_input_surface_v2.h',HOST/'modern_uikit_input_adapter_v2.h',HOST/'modern_input_packet_lease_v2.h']
    pins=list(map(p.pin,inputs));commands=[]
    def run(label,args,timeout=60):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=timeout)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=args,exit=result.returncode));p.save(out/'commands.json',commands)
        assert result.returncode==0,(label,result.stderr.decode())
        return result
    try:
        macsdk=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        ios_sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        common=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-ffp-contract=off']
        native=HOST/'modern_processed_scroll_native_v1.c';fixture=HOST/'modern_processed_scroll_native_fixture_v2.c'
        fixtures=[]
        for label,profile,san in [('normal',True,False),('sanitized',True,True),('production-reject',False,False),('production-reject-sanitized',False,True)]:
            executable=out/('mac-'+label)
            flags=common+['-target','arm64e-apple-macos13.0','-isysroot',macsdk,'-O2']
            flags+=['-DVM27_SCROLL_MAC_COMPARISON_PROFILE'] if profile else ['-DVM27_SCROLL_PRODUCTION_REJECTION_FIXTURE']
            if san:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            run('compile-mac-'+label,flags+[native,fixture,'-framework','IOKit','-framework','CoreFoundation','-lobjc','-o',executable])
            body=executable.read_bytes();deps=p.dependencies(body)
            assert not any(any(part in r['path'] for part in ('Virtualization','Hypervisor','VirtualMachineMonitor','UniversalHID')) for r in deps)
            result=run('run-mac-'+label,[executable],25);assert not result.stderr
            actual=json.loads(result.stdout);assert actual['deviceOperations']==actual['nativeHVCalls']==actual['nativeVMCalls']==0
            assert actual['realEventsCreated']==(512 if profile else 0)
            if profile:assert actual['realFinalReleases']==512 and not actual['UIKitClockOriginValidated']
            else:assert actual['productionProfileRejected']
            fixtures.append(dict(role=label,executable=p.pin(executable),dependencies=deps,result=actual,actualSourceInstrumented=san))
        ios_flags=common+['-target','arm64e-apple-ios16.1','-isysroot',ios_sdk,'-O2']
        core_obj=out/'ios-native.o';sink_obj=out/'ios-sink.o'
        run('compile-ios-native',ios_flags+['-c',native,'-o',core_obj])
        run('compile-ios-native-ir',ios_flags+['-S','-emit-llvm',native,'-o',out/'ios-native.ll'])
        sink=HOST/'modern_processed_scroll_sink_v1.m'
        run('compile-ios-sink',ios_flags+['-fobjc-arc','-c',sink,'-o',sink_obj])
        run('compile-ios-sink-ir',ios_flags+['-fobjc-arc','-S','-emit-llvm',sink,'-o',out/'ios-sink.ll'])
        provider=out/'VM27ProcessedScroll.ios.unsigned.inert.dylib'
        run('link-ios-provider',ios_flags+['-dynamiclib',core_obj,sink_obj,'-framework','Foundation','-framework','CoreFoundation','-framework','IOKit','-lobjc',
            '-Wl,-install_name,@loader_path/VM27ProcessedScroll.dylib','-Wl,-no_adhoc_codesign','-o',provider])
        ordinary=out/'VM27ProcessedScroll.ios.ordinary.unsigned.inert'
        # Root may use this own one-file fixture after separate source/sign/controller
        # review. The fixture never publishes the created events to a service.
        run('compile-ios-ordinary',ios_flags+[native,fixture,'-framework','IOKit','-framework','CoreFoundation','-lobjc','-Wl,-no_adhoc_codesign','-o',ordinary])
        for label,file in [('provider',provider),('ordinary',ordinary)]:
            run('validate-ios-'+label,['xcrun','dyld_info','-validate_only',file])
            raw=file.read_bytes();assert not any(cmd==29 for cmd,at,size in p.commands(raw))
            deps=p.dependencies(raw);imports=import_records(raw,p.commands)
            assert all(r['ordinal']>0 and not r['weak'] for r in imports['imports'])
            assert not any(any(part in r['name'] for part in ('_hv_','_VZ','_VMM','_SLEvent','_CGEvent','NSEvent','NSTouch')) for r in imports['imports'])
            p.save(out/('ios-'+label+'-imports.json'),dict(dependencies=deps,schema=imports))
        llvm=(out/'ios-native.ll').read_text();signature=next(line for line in llvm.splitlines()if line.startswith('declare ptr @IOHIDEventCreateScrollEvent('))
        assert signature.count('double')==3 and 'i64' in signature and 'i32' in signature
        assert 'llvm.round.f64' in llvm and 'contract' not in signature
        assert pins==list(map(p.pin,inputs))
        candidate=dict(schema='Finite processed UIKit pan to genuine native type6 source data v1',sourceFiles=pins,
            provider=p.pin(provider),ordinaryIOSFixture=p.pin(ordinary),ordinaryMacFixtures=fixtures,
            factoryDeclaration=signature,actualNativeImportSchema=p.pin(out/'ios-provider-imports.json'),
            productionProfile=dict(IOKitUUID='87ae25ce3bef39d9baa90d8cc15a34a0',HIDEventInstanceBytes=112,
                everyUsedIOKitFunctionAndClassUUIDRequired=True),
            genuineNativeType6FactoryUsed=True,doubleFactoryArgumentsPreserved=True,
            namedNativePhaseMapping=dict(began=1,changed=2,ended=4,cancelled=8),
            originalTimebaseMultiplyDivideAndRoundAwayImplemented=True,unrepresentableOwnDeltasRejected=True,
            ownedNativeObjectAndExplicitReleaseImplemented=True,processedScrollOnly=True,
            atomicUIKitSessionSinkCompatible=True,nativeGlobalDispatchImplemented=False,
            richCGEventFieldsImplemented=False,originalUHKConformanceImplemented=False,
            UIKitClockOriginValidated=False,actualIPadFixtureExecuted=False,iOSProviderLoaded=False,
            productionAppIntegrated=False,currentStrongDefinitionsValidated=False,independentReviewPassed=False,
            codeSigned=False,readyWritten=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False)
        p.save(out/'candidate.json',candidate)
        p.save(out/'freeze.json',dict(files=list({r['path']:r for r in pins+[p.pin(path)for path in out.iterdir()if path.is_file()]}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),provider=p.pin(provider),fixtures=fixtures)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for path in inputs:(failed/path.name).write_bytes(path.read_bytes())
        p.save(out/'failure.json',dict(reason=repr(error),sourcePins=pins,deviceOperations=0,actualIPadExecuted=False))
        raise
if __name__=='__main__':main()
