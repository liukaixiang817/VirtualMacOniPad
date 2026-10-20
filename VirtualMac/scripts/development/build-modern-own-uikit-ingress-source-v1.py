#!/usr/bin/env python3
"""Compile the copied UIKit -> genuine VZ value source path, without execution."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('own_ingress_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from macho_chained_import_records_v1 import read as import_records
HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=p.NODE/'own-uikit-genuine-input-ingress-source-build-v1';assert not out.exists();out.mkdir()
    names=['vm27_own_uikit_ingress_values_v1.h','vm27_own_uikit_ingress_values_v1.c',
        'test-vm27-own-uikit-ingress-values-v1.c','vm27_own_uikit_ingress_profile_v1.h',
        'vm27_own_uikit_ingress_profile_v1.m','vm27_own_uikit_ingress_endpoint_v1.h',
        'vm27_own_uikit_ingress_endpoint_v1.m','modern_independent_input_coordinator_v2.h',
        'modern_independent_input_coordinator_v2.m','modern_vz_processed_scroll_receiver_v1.h',
        'modern_vz_processed_scroll_receiver_v1.m','modern_vz_scroll_normalization_v1.h',
        'modern_vz_scroll_normalization_v1.c','modern_processed_scroll_native_v1.h',
        'modern_processed_scroll_native_v1.c','modern_processed_scroll_sink_v1.h',
        'modern_processed_scroll_sink_v1.m','modern_input_packet_v2.h',
        'modern_uikit_input_surface_v2.h','modern_uikit_input_adapter_v2.h',
        'modern_input_packet_lease_v2.h','VZBackendSelection.h','VZBackendSelection.m','VirtualMacApp.m']
    sources=[Path(__file__)]+[HOST/name for name in names];pins=[p.pin(file)for file in sources];runs=[]
    def run(label,args):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        runs.append(dict(label=label,argv=args,exit=result.returncode));p.save(out/'commands.json',runs)
        assert result.returncode==0,(label,result.stderr.decode());return result
    try:
        ios=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        flags=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-O2','-ffp-contract=off','-fblocks']
        fixtures=[]
        for mode in ('normal','sanitized'):
            exe=out/('own-copied-values-'+mode)
            local=flags+['-target','arm64e-apple-macos13.0','-isysroot',mac]
            if mode=='sanitized':local+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            run('compile-values-'+mode,local+[HOST/'vm27_own_uikit_ingress_values_v1.c',HOST/'test-vm27-own-uikit-ingress-values-v1.c','-o',exe])
            result=run('run-values-'+mode,[exe]);actual=json.loads(result.stdout);assert not actual['failures'] and actual['VZCalls']==0
            fixtures.append(dict(mode=mode,image=p.pin(exe),result=actual,sourceSanitized=mode=='sanitized'))
        local=flags+['-target','arm64e-apple-ios16.1','-isysroot',ios]
        units=[('values','vm27_own_uikit_ingress_values_v1.c',False),('normalization','modern_vz_scroll_normalization_v1.c',False),
            ('native-scroll','modern_processed_scroll_native_v1.c',False),('scroll-sink','modern_processed_scroll_sink_v1.m',True),
            ('genuine-scroll-receiver','modern_vz_processed_scroll_receiver_v1.m',True),
            ('own-profile','vm27_own_uikit_ingress_profile_v1.m',True),('own-endpoint','vm27_own_uikit_ingress_endpoint_v1.m',True)]
        objects=[]
        for label,name,arc in units+[('coordinator','modern_independent_input_coordinator_v2.m',True)]:
            obj=out/(label+'.o');file=HOST/name;options=local+(['-fobjc-arc']if arc else[])
            run('compile-'+label,options+['-c',file,'-o',obj]);run('ir-'+label,options+['-S','-emit-llvm',file,'-o',out/(label+'.ll')])
            if label!='coordinator':objects.append(obj)
        provider=out/'VM27OwnUIKitGenuineIngress.ios.unsigned.inert.dylib'
        run('link-provider',local+['-dynamiclib']+objects+['-framework','Foundation','-framework','CoreFoundation','-framework','CoreGraphics','-framework','IOKit','-lobjc',
            '-Wl,-install_name,@loader_path/VM27OwnUIKitGenuineIngress.dylib','-Wl,-no_adhoc_codesign','-o',provider])
        run('validate-provider',['xcrun','dyld_info','-validate_only',provider])
        raw=provider.read_bytes();schema=import_records(raw,p.commands);deps=p.dependencies(raw)
        assert not any(cmd==29 for cmd,at,size in p.commands(raw))
        assert all(row['ordinal']>0 and not row['weak']for row in schema['imports'])
        assert not any(any(token in row['path']for token in ('Virtualization','Hypervisor','VirtualMachineMonitor','UniversalHID'))for row in deps)
        assert not any(any(token in row['name']for token in ('_hv_','_VMM','_VZ','_SLEvent','_CGEvent','NSEvent','NSTouch'))for row in schema['imports'])
        p.save(out/'imports.json',dict(dependencies=deps,imports=schema))
        # Reuse the frozen current definition proof's genuinely decoded native
        # names. No new image aliases or unobserved platform exports are added.
        proof=p.NODE/'uikit-input-current-definitions-readonly-v1/audit.json';old=json.loads(proof.read_bytes())
        native_names={(row['dependency'],row['name']):row['proof']for product in old['products']for row in product['imports']}
        matched=[];unknown=[];owners={row['ordinal']:row['path']for row in deps}
        for row in schema['imports']:
            key=(owners[row['ordinal']],row['name']);record=dict(row,dependency=key[0])
            if key in native_names:record['proof']=native_names[key];matched.append(record)
            else:unknown.append(record)
        p.save(out/'current-definitions.json',dict(frozenProof=p.pin(proof),exactPreviouslyCapturedDefinitions=matched,remainingNamesNotInThisFrozenProductProof=unknown,
            allCurrentStrongDefinitionsValidated=not unknown,fullNamespaceOrTransitiveGraphValidated=False))
        contract=p.NODE/'vz-mac-ingress-callers-original-readonly-v3/contract.json';j=json.loads(contract.read_bytes())
        assert j['originalVZUUID']=='418efc4809d93606918eb6f95baeffdc'
        required={0x5a28c:('@28@0:8q16S24',80),0x64394:('@40@0:8{CGPoint=dd}16q32',120),0x58aa8:('v24@0:8@16',None),0x6460c:('v24@0:8@16',None)}
        base=0x225f36000;originals=[]
        for rva,(encoding,size)in required.items():
            body=next(row for row in j['originalBoundedConsumerHelperBodies']if row['functionStart']==base+rva)
            method=next(row for row in body['exactObjCIMPMatches']if row['typeEncoding']==encoding)
            if size:assert body['bytes']==size
            originals.append(dict(rva=rva,body=body,method=method))
        for directory in (p.NODE/'vz-mac-ingress-callers-original-readonly-v3',p.NODE/'vz-mac-ingress-callers-original-readonly-v2'):
            pins += [p.pin(file)for file in directory.iterdir()if file.is_file()]
        for directory in (proof.parent,p.NODE/'vz-processed-scroll-receiver-source-data-v5'):
            frozen=json.loads((directory/'freeze.json').read_bytes())
            for row in frozen['files']:assert p.pin(Path(row['path']))==row;pins.append(row)
            pins.append(p.pin(directory/'freeze.json'))
        assert pins[:len(sources)]==[p.pin(file)for file in sources]
        p.save(out/'candidate.json',dict(schema='Copied UIKit genuine27 key pointer scroll ingress source v1',sourceFiles=pins[:len(sources)],provider=p.pin(provider),
            actualIOSImports=p.pin(out/'imports.json'),currentDefinitions=p.pin(out/'current-definitions.json'),originalInputMethodContracts=originals,
            ownCopiedValuesFixtures=fixtures,keyboardTableReusedFromProductionApp=True,keyboardTypesDown0Up1=True,
            ownSingleContactLeftButtonPolicyExplicit=True,twoFingerPanUsesExistingGenuineSixParameterReceiver=True,
            genuineValueConstructorsAndSendersSourceConnected=True,ownEndpointAndCoordinatorSourceConnected=True,
            nativeSenderExceptionConsumptionUncertainAndAdmissionStops=True,closeReleaseFailurePropagated=True,
            originalMacViewOrCGPacketSourceRegistrationBypassed=True,originalOuterAsyncExceptionCatchPolicyValidated=False,
            realBackendMustSupplyAndProveConsumerExecutor=True,backendExecutorImplementationProvided=False,backendThreadAffinityValidated=False,
            originalVZValueObjectsExecuted=False,actualUIKitTimestampAndRuntimeValidated=False,productionAppSourceModified=False,
            backendAvailabilityGatePreserved=True,sourcePlatformAdmissionGateClosed=True,providerCodeSigned=False,providerLoaded=False,
            readyWritten=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
        pins += [p.pin(file)for file in out.iterdir()if file.is_file()]
        p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),provider=p.pin(provider),fixtures=fixtures,strong=len(schema['imports']),remainingExactDefinitionNames=len(unknown))))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for file in sources:(failed/file.name).write_bytes(file.read_bytes())
        p.save(out/'failure.json',dict(reason=repr(error),sourceFiles=pins[:len(sources)],deviceOperations=0,originalVZCalls=0));raise
if __name__=='__main__':main()
