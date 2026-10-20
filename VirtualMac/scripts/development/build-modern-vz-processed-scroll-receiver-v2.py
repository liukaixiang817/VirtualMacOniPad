#!/usr/bin/env python3
"""Compile the genuine27 receiver, executing only its own scalar normalization."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('scroll_receiver_p',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from macho_chained_import_records_v1 import read as import_records
HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=p.NODE/'vz-processed-scroll-receiver-source-data-v2'; assert not out.exists();out.mkdir()
    names=['modern_vz_processed_scroll_receiver_v1.h','modern_vz_processed_scroll_receiver_v1.m',
           'modern_vz_scroll_normalization_v1.h','modern_vz_scroll_normalization_v1.c',
           'modern_vz_scroll_normalization_fixture_v1.c','modern_processed_scroll_native_v1.h',
           'modern_processed_scroll_native_v1.c','modern_processed_scroll_sink_v1.h',
           'modern_input_packet_v2.h','modern_uikit_input_surface_v2.h','modern_uikit_input_adapter_v2.h','modern_input_packet_lease_v2.h']
    inputs=[Path(__file__)]+[HOST/name for name in names];pins=[p.pin(file)for file in inputs];commands=[]
    def run(label,args):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=args,exit=result.returncode));p.save(out/'commands.json',commands)
        assert result.returncode==0,(label,result.stderr.decode());return result
    try:
        ios=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        original_path=p.NODE/'vz-processed-scroll-entry-original-readonly-v1/audit.json'
        literals_path=p.NODE/'vz-scroll-fallback-original-literals-readonly-v2/audit.json'
        original=json.loads(original_path.read_bytes());assert original['actualImage']['UUID']=='418efc4809d93606918eb6f95baeffdc'
        branch_path=p.NODE/'vz-metal-singleton-selection-data-v3/candidate.json'
        branch=json.loads(branch_path.read_bytes());current=Path(branch['frontendCandidate']['path']);raw=current.read_bytes()
        assert p.pin(current)==branch['frontendCandidate'];assert [raw[at+8:at+24].hex()for cmd,at,size in p.commands(raw)if cmd==27]==[original['actualImage']['UUID']]
        methods=[]
        for row in original['completeFunctions']:
            if row['className']!='_VZScrollWheelEvent' and row['selector']!='sendScrollWheelEvents:':continue
            data=Path(row['data']['path']).read_bytes();assert p.pin(Path(row['data']['path']))==row['data']
            rva=row['begin']-original['actualImage']['base'];extracted=raw[rva:rva+len(data)]
            assert len(extracted)==len(data)
            differences=[]
            for offset in range(0,len(data),4):
                old=struct.unpack_from('<I',data,offset)[0];new=struct.unpack_from('<I',extracted,offset)[0]
                if old==new:continue
                if old&0xfc000000==new&0xfc000000==0x94000000:kind='existing extracted BL target relocation'
                elif old&0x9f00001f==new&0x9f00001f and old&0x9f000000==0x90000000:kind='existing extracted ADRP target relocation'
                elif old&0xffc003ff==new&0xffc003ff and old&0xffc00000==0xf9400000:kind='existing extracted LDR pointer-slot relocation'
                else:
                    assert rva==0x6494c and offset==72 and (old,new)==(0x913c0101,0xf9417d01)
                    kind='existing extraction selector ADD changed to pointer-slot LDR'
                differences.append(dict(offset=offset,originalWord=hex(old),currentWord=hex(new),classification=kind))
            if len(data)==8:assert not differences
            current_body=out/(hex(rva)+'-current-body.bin');current_body.write_bytes(extracted)
            methods.append(dict(selector=row['selector'],className=row['className'],rva=rva,bytes=len(data),typeEncoding=row['types'],
                genuineMachineBytes=row['data'],currentCandidateBytes=p.pin(current_body),existingExtractionDifferences=differences,
                getterWholeBytesEqual=len(data)==8,nonReferenceInstructionsAndOriginalPACWordsEqual=True,
                existingReferenceRelocationTargetSemanticClosureValidated=False))
        assert len(methods)==9
        assert any(row['rva']==0x6494c and row['bytes']==152 and row['typeEncoding']=='@64@0:8d16d24d32d40Q48Q56'for row in methods)
        assert any(row['rva']==0x5c770 and row['bytes']==708 for row in methods)
        for directory in (original_path.parent,literals_path.parent):
            for row in json.loads((directory/'freeze.json').read_bytes())['files']:
                assert p.pin(Path(row['path']))==row;pins.append(row)
            pins.append(p.pin(directory/'freeze.json'))
        common=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-ffp-contract=off','-O2']
        normalization=HOST/'modern_vz_scroll_normalization_v1.c';fixture=HOST/'modern_vz_scroll_normalization_fixture_v1.c'
        results=[]
        for mode in ('normal','sanitized'):
            flags=common+['-target','arm64e-apple-macos13.0','-isysroot',mac]
            if mode=='sanitized':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            exe=out/('own-normalization-'+mode)
            run('compile-'+mode,flags+[normalization,fixture,'-o',exe])
            deps=p.dependencies(exe.read_bytes());assert all(row['path']=='/usr/lib/libSystem.B.dylib'for row in deps)
            result=run('run-'+mode,[exe]);assert not result.stderr
            actual=json.loads(result.stdout);assert actual['originalVZCalls']==actual['nativeHVCalls']==actual['nativeVMCalls']==actual['deviceOperations']==0
            assert actual['acceptedPreciseFallbackCases']==8198 and actual['rejectedCases']==264
            results.append(dict(mode=mode,executable=p.pin(exe),result=actual,sourceSanitized=mode=='sanitized'))
        flags=common+['-target','arm64e-apple-ios16.1','-isysroot',ios]
        objs=[]
        for label,file,arc in [('normalization',normalization,False),('native',HOST/'modern_processed_scroll_native_v1.c',False),('receiver',HOST/'modern_vz_processed_scroll_receiver_v1.m',True)]:
            local=flags+(['-fobjc-arc']if arc else[]);obj=out/(label+'.o');objs.append(obj)
            run('compile-ios-'+label,local+['-c',file,'-o',obj])
            run('compile-ios-'+label+'-ir',local+['-S','-emit-llvm',file,'-o',out/(label+'.ll')])
        provider=out/'VM27GenuineScrollReceiver.ios.unsigned.inert.dylib'
        run('link-ios',flags+['-dynamiclib']+objs+['-framework','Foundation','-framework','CoreFoundation','-framework','IOKit','-lobjc',
            '-Wl,-install_name,@loader_path/VM27GenuineScrollReceiver.dylib','-Wl,-no_adhoc_codesign','-o',provider])
        run('validate-ios',['xcrun','dyld_info','-validate_only',provider])
        product=provider.read_bytes();imports=import_records(product,p.commands);deps=p.dependencies(product)
        assert not any(cmd==29 for cmd,at,size in p.commands(product))
        assert all(row['ordinal']>0 and not row['weak']for row in imports['imports'])
        assert not any(any(token in row['path']for token in ('Virtualization','Hypervisor','VirtualMachineMonitor','UniversalHID'))for row in deps)
        assert not any(any(token in row['name']for token in ('_hv_','_VMM','_VZ','_SLEvent','_CGEvent','NSEvent','NSTouch'))for row in imports['imports'])
        p.save(out/'ios-imports.json',dict(dependencies=deps,imports=imports))
        llvm=(out/'normalization.ll').read_text();assert llvm.count('fdiv double')==2
        receiver=(out/'receiver.ll').read_text();assert 'sendScrollWheelEvents:'in receiver and 'initWithScrollingDeltaX:'in receiver
        assert list(map(p.pin,inputs))==pins[:len(inputs)]
        p.save(out/'candidate.json',dict(schema='Genuine original27 processed-scroll receiver source candidate v1',sourceFiles=pins[:len(inputs)],
            provider=p.pin(provider),actualIOSImports=p.pin(out/'ios-imports.json'),originalMethodABIContracts=methods,
            originalGetterBodiesWholeBytesPreserved=True,originalWholeMethodBytesPreserved=False,
            existingCandidateExtractionReferenceDeltasExplicit=True,existingReferenceRelocationSemanticClosureValidated=False,
            currentGenuineVZImage=p.pin(current),originalMethodAudit=p.pin(original_path),originalLiteralAudit=p.pin(literals_path),
            ownScalarFixtures=results,original27RuntimeProfile=dict(UUID='418efc4809d93606918eb6f95baeffdc',eventInstanceBytes=56,pointingBaseInstanceBytes=32,
                constructorRVA=0x6494c,senderRVA=0x5c770,allSixGettersRVAAndEncodingChecked=True),
            genuineOriginalClassConstructorAndSenderSourceImplemented=True,ownPreciseFallbackNormalizationImplemented=True,
            hardwareAccelerationMeasured=False,richHardwareMomentumSupported=False,nativeTimestampTransferredToOriginalVZWire=False,
            serializedBackendThreadRequired=True,backendThreadAffinityProven=False,endpointConsumerImplemented=False,
            platformGateStillClosed=True,originalVZFunctionsExecuted=0,originalVZReceiverExecuted=False,
            iOSProviderLoaded=False,actualUIKitTimestampOriginValidated=False,productionAppIntegrated=False,
            currentStrongDefinitionsValidated=False,codeSigned=False,readyWritten=False,independentReviewPassed=False,
            full27Backend=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0))
        pins += [p.pin(current),p.pin(branch_path)]
        pins += [p.pin(file)for file in out.iterdir()if file.is_file()]
        p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),provider=p.pin(provider),fixtures=results)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for file in inputs:(failed/file.name).write_bytes(file.read_bytes())
        p.save(out/'failure.json',dict(reason=repr(error),sources=pins[:len(inputs)],deviceOperations=0,originalVZFunctionsExecuted=0));raise
if __name__=='__main__':main()
