#!/usr/bin/env python3
"""Build finite native IOKit double packets; execute ordinary genuine Mac comparisons."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('iokit_double_s',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p=s.p
from current_kernel_capture_v1 import join as join_kernel
from current_hid_extra_three_capture_v1 import join as join_hid_extra
from current_swift_two_capture_v1 import join as join_swift_two
from macho_chained_import_records_v1 import read as import_records
HOST=p.ROOT/'VirtualMac/vz/host'


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();assert out.is_relative_to(p.NODE) and not out.exists()
    original=p.NODE/'iokit-three-original-abi-readonly-v5/audit.json'
    native=p.NODE/'iokit-native-double-initializer-readonly-v3/audit.json'
    inputs=[Path(__file__),original,native]+[HOST/name for name in ('modern_iokit_double_event_packets.h',
        'modern_iokit_double_event_packets.c','modern_iokit_double_events.c','modern_iokit_double_events_fixture.c')]
    pins=list(map(p.pin,inputs))
    for path in (original,native):
        for pin in json.loads((path.parent/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    old=json.loads(native.read_bytes());assert old['currentNativeIOKitUUID']=='87ae25ce3bef39d9baa90d8cc15a34a0'
    assert old['actualObjectDataOffset']==104 and old['actualInitializerSelectedByBothMethodListAndAllocatorDispatch']
    assert old['exactRawType41And42ObjectsExpressibleThroughNativeAllocator'] and not old['nativeIOSExecuted']
    images=s.primary.captured_images();stock_pins=[]
    for group in ('system','stock-extra','cxx-leaf'):
        stock_pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v1/headers.json'))
    for group in ('dyld-leaf','xpc-leaf'):
        stock_pins+=s.join_capture(images,group,p.NODE/('ipad-current-cache-'+group+'-headers-v2/headers.json'))
    stock_pins+=join_kernel(s,images)
    joined,_=join_hid_extra(s,images);stock_pins+=joined
    joined,_=join_swift_two(s,images);stock_pins+=joined
    assert len(images)==22
    out.mkdir();commands=[];roles=[]
    def run(label,argv):
        result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out/'commands.json',commands)
        assert result.returncode==0,(label,result.stderr.decode())
        return result
    try:
        macsdk=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        sources=inputs[4:]
        renamed=['-DVM27_FORCE_EVENT_EXPORT=VM27ForceStageFixture','-DVM27_TOUCH_EVENT_EXPORT=VM27TouchRadiusFixture']
        for role,profile,san in [('normal-genuine-compare',True,False),('asan-ubsan-genuine-compare',True,True),
                                ('production-wrong-host-rejection',False,False),('asan-ubsan-production-wrong-host-rejection',False,True)]:
            exe=out/(role+'-ordinary-mac-fixture')
            flags=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0','-isysroot',macsdk,
                '-O2','-Wall','-Wextra','-Werror']+renamed
            flags+=['-DVM27_IOKIT_MAC_PACKET_FIXTURE']if profile else['-DVM27_PRODUCTION_REJECTION_FIXTURE']
            if san:flags+=['-fsanitize=address,undefined']
            run(role+'-build',flags+sources+['-framework','IOKit','-framework','CoreFoundation','-lobjc','-o',exe])
            deps=p.dependencies(exe.read_bytes())
            assert not any(any(word in row['path']for word in ('Hypervisor','Virtualization','VirtualMachineMonitor','UniversalHID'))for row in deps)
            result=run(role+'-execute',[exe]);actual=json.loads(result.stdout);assert not result.stderr
            if profile:
                assert actual['realEventsCreatedAndReleased']==2048 and actual['realParentOwnedChildren']==1024
                assert actual['finiteCandidateComparedToBothGenuineConstructors']and actual['allOriginalPacketBytesCompared']
                assert actual['originalIOKitUUID']=='0e4cf3e4b0c2312ab1470bd4978ef0b7'and actual['macDataOffset']==96
                assert actual['checks']>=24000 and not actual['ipadLayoutOrInitializerExecuted']
            else:
                assert actual['checks']==65 and actual['productionProfileRejectedOnRealDifferentHost']and actual['nativeEventsAllocated']==0
            roles.append(dict(role=role,executable=p.pin(exe),dependencies=deps,actualOrdinaryMacResult=actual,
                allCandidateSourceCodeInstrumented=san,explicitDifferentMacComparisonProfile=profile))
        sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        provider=out/'DE.unsigned.inert.macho-data'
        export_file=out/'exports.list'
        export_names=['_IOHIDEventCreateForceStageEvent','_IOHIDEventCreateTouchSensitiveButtonEventWithRadius']
        export_file.write_text('\n'.join(export_names)+'\n')
        flags=['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,
            '-O2','-Wall','-Wextra','-Werror','-fvisibility=hidden']
        run('ios-build',flags+['-dynamiclib']+sources[:2]+['-framework','IOKit','-framework','CoreFoundation','-lobjc',
            '-Wl,-install_name,@rpath/VM27IOKitDoubleEvents.dylib','-Wl,-exported_symbols_list,'+str(export_file),
            '-Wl,-no_adhoc_codesign','-o',provider])
        run('ios-dyld-validate',['xcrun','dyld_info','-validate_only',provider])
        raw=provider.read_bytes();assert not any(cmd==0x1d for cmd,at,size in p.commands(raw))
        assert not any(section['name']=='__mod_init_func'and section['size']for segment in p.segments(raw)for section in segment['sections'])
        offset,length=next(struct.unpack_from('<II',raw,at+8)for cmd,at,size in p.commands(raw)if cmd==0x80000033)
        definitions=s.primary.trie(raw[offset:offset+length]);assert set(definitions)==set(export_names)
        assert all(row['flags']==0 for row in definitions.values())
        deps={row['ordinal']:row['path']for row in p.dependencies(raw)}
        schema=import_records(raw,p.commands);proofs=[]
        for record in schema['imports']:
            assert record['ordinal']>0 and not record['weak']
            proof=s.primary.resolve(images,deps[record['ordinal']],record['name'])
            proofs.append(dict(**record,dependency=deps[record['ordinal']],actualCurrentNativeResolution=proof))
        assert any(row['name']=='__IOHIDEventCreate'and row['actualCurrentNativeResolution']['status']=='actualDirectExport'for row in proofs)
        ir=out/'ios-constructors.ll'
        run('ios-IR',flags+['-S','-emit-llvm',sources[1],'-o',ir])
        llvm=ir.read_text()
        signatures={name:next(line for line in llvm.splitlines()if line.startswith('define ')and '@'+name+'('in line)
            for name in ('IOHIDEventCreateForceStageEvent','IOHIDEventCreateTouchSensitiveButtonEventWithRadius')}
        force=signatures['IOHIDEventCreateForceStageEvent'];touch=signatures['IOHIDEventCreateTouchSensitiveButtonEventWithRadius']
        assert force.count('double')==5 and touch.count('double')==6 and 'swiftcc'not in force+touch
        assert re.search(r'declare ptr @_IOHIDEventCreate\(ptr[^,]*, i64[^,]*, i32[^,]*, i64[^,]*, i32[^)]*\)',llvm)
        assert re.search(r'icmp eq i64 %\w+, 112',llvm) and 'i64 104'in llvm
        assert re.search(r'@allocate_packet\([^\n]*i64 noundef 80, i32 noundef 41',llvm)
        assert re.search(r'@allocate_packet\([^\n]*i64 noundef 96, i32 noundef 42',llvm)
        uuid_line=next(line for line in llvm.splitlines()if line.startswith('@native_uuid ='))
        assert r'\87\AE%\CE;\EF9\D9\BA\A9\0D\8C\C1Z4\A0'in uuid_line
        assert pins==list(map(p.pin,inputs))
        counts={}
        for row in proofs:
            state=row['actualCurrentNativeResolution']['status'];counts[state]=counts.get(state,0)+1
        p.save(out/'candidate.json',dict(schema='Finite genuine native old-host IOKit double event provider data v1',inputs=pins,
            originalComplete27ABI=p.pin(original),currentCompleteNativeInitializerContract=p.pin(native),ordinaryMacRoles=roles,
            iosProvider=p.pin(provider),exactExports=definitions,iosIR=p.pin(ir),actualCEntrySignatures=signatures,
            actualCurrentNativeImportSchema=schema,actualCurrentNativeImports=proofs,actualCurrentNativeImportCounts=counts,
            currentNativeImages=22,nativeGenericAllocatorFiveGPABIUsed=True,
            productionProfile=dict(IOKitUUID=old['currentNativeIOKitUUID'],instanceBytes=112,ownIvarOffset=8,dataPointerOffset=104,
                exactRuntimeIvarTypeEncodingRequired=True,actualNativeAllocatorUUIDAndClassUUIDRequired=True),
            originalDoublePacketTypesSizesAndIEEEBitsPreserved=True,realNativeOwnedObjectReturned=True,
            originalType32ForceEventAliasUsed=False,originalMac96OffsetUsedInIOS=False,
            nativeIOSExecuted=False,originalHIDLoaded=False,originalVZLoaded=False,deviceOperations=0,nativeHVCalls=0,
            currentIOKitKernelNewTypeConsumerValidated=False,originalFullIOKitSemanticsPreserved=False,
            completeOriginal27MetadataPreserved=False,candidateReadyForNativeLoading=False,allNativeImportNamespaceProven=False,
            codeSigned=False,full27Backend=False))
        files=[path for path in out.rglob('*')if path.is_file()]
        p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins+stock_pins+list(map(p.pin,files))}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),provider=p.pin(provider),nativeImportCounts=counts,roles=roles)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for path in inputs:(failed/path.name).write_bytes(path.read_bytes())
        p.save(out/'failure.json',dict(error=repr(error),inputs=pins,deviceOperations=0,nativeIOSExecuted=False))
        raise


if __name__=='__main__':main()
