#!/usr/bin/env python3
"""Build exact six-word swiftcc availability entry; query genuine host dyld."""
import argparse, hashlib, importlib.util, json, re, struct, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST=ROOT/'VirtualMac/vz/host'
SYMBOL='$ss042_stdlib_isOSVersionAtLeastOrVariantVersiondE0yBi1_Bw_BwBwBwBwBwtF'
spec=importlib.util.spec_from_file_location('current_availability',ROOT/'VirtualMac/scripts/development/audit-modern-current-stock-extra-exports-v2.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
p=e.p


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE) and not out.exists();out.mkdir()
    source=HOST/'modern_swift_os_variant_availability_compat.c'
    fixture=HOST/'modern_swift_os_variant_availability_fixture.c'
    assert 'dlsym(handle, "'+SYMBOL+'")' in fixture.read_text()
    inputs=[p.pin(x)for x in(Path(__file__),source,fixture,NODE/'swift-os-or-variant-original-abi-readonly-v3/audit.json')]
    export=out/'exports.list';export.write_text('_'+SYMBOL+'\n')
    logs=[]
    def run(label,argv):
        argv=list(map(str,argv));r=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        logs.append(dict(label=label,argv=argv,exit=r.returncode,stdoutSHA256=hashlib.sha256(r.stdout).hexdigest(),stderrSHA256=hashlib.sha256(r.stderr).hexdigest()))
        p.save(out/'commands.json',logs);assert r.returncode==0,(label,r.stderr.decode());return r
    images=e.primary.captured_images()
    for group,header in[('system','system-v1'),('stock-extra','stock-extra-v1'),('cxx-leaf','cxx-leaf-v1')]:
        stem,version=header.rsplit('-',1)
        e.join_capture(images,group,NODE/('ipad-current-cache-'+stem+'-headers-'+version+'/headers.json'))
    e.join_capture(images,'dyld-leaf',NODE/'ipad-current-cache-dyld-leaf-headers-v2/headers.json')
    e.join_capture(images,'xpc-leaf',NODE/'ipad-current-cache-xpc-leaf-headers-v2/headers.json')
    availability=e.primary.resolve(images,'/usr/lib/libSystem.B.dylib','__availability_version_check')
    assert availability['status']=='actualDirectExport',availability
    assert len(images)==16
    roles=[]
    for role,target,sdk in[('mac','arm64e-apple-macos13.0','macosx'),('ios','arm64e-apple-ios16.1','iphoneos')]:
        sdkpath=run(role+'-sdk',['xcrun','--sdk',sdk,'--show-sdk-path']).stdout.decode().strip()
        interface=Path(sdkpath)/('usr/lib/swift/Swift.swiftmodule/arm64e-apple-'+('macos'if role=='mac'else 'ios')+'.swiftinterface')
        inputs.append(p.pin(interface))
        if role=='mac':assert '_stdlib_isOSVersionAtLeastOrVariantVersionAtLeast(_ major: Builtin::Word' in interface.read_text()
        base=['xcrun','--sdk',sdk,'clang','-target',target,'-isysroot',sdkpath,'-std=c11','-O2','-fvisibility=hidden','-Wall','-Wextra','-Werror',source]
        ir=out/(role+'.ll');run(role+'-ir',base+['-S','-emit-llvm','-o',ir])
        text=ir.read_text();needle='@"'+chr(92)+'01_'+SYMBOL+'"(';line=next((x for x in text.splitlines()if x.startswith('define ')and needle in x),None)
        assert line and 'swiftcc' in line and 'i1 'in line and line.count('i64 ')==6,line or 'no exact export'
        assert 'swiftself' not in line and 'swiftasync' not in line
        obj=out/(role+'.o');run(role+'-object',base+['-c','-o',obj])
        provider=out/('AV.mac.dylib'if role=='mac'else 'AV.unsigned.inert.macho-data')
        link=['xcrun','--sdk',sdk,'clang','-target',target,'-isysroot',sdkpath,obj,'-dynamiclib','-Wl,-dead_strip','-Wl,-undefined,error','-Wl,-install_name,@rpath/VM27OSVariantAvailability.dylib','-Wl,-exported_symbols_list,'+str(export),'-o',provider]
        if role=='ios':link+=['-Wl,-no_adhoc_codesign']
        run(role+'-link',link);run(role+'-dyld',['xcrun','dyld_info','-validate_only',provider])
        data=provider.read_bytes();definitions={row['symbol']:row for cmd,at,size in p.commands(data)if cmd==0x80000033 for off,n in[struct.unpack_from('<II',data,at+8)]for row in p.export_trie(data[off:off+n])}
        assert set(definitions)=={'_'+SYMBOL} and not definitions['_'+SYMBOL]['flags']&8
        imports=p.imports(data)['imports'];deps={row['ordinal']:row['path']for row in p.dependencies(data)}
        assert len(imports)==3 and {x['name']for x in imports}=={'__availability_version_check','___stack_chk_guard','___stack_chk_fail'} and all(not x['weak']and x['ordinal']>0 for x in imports)
        row=dict(role=role,provider=p.pin(provider),IRSignature=line,actualImports=imports,dependencies=deps,
                 exactSixWordSwiftCallingConvention=True,deviceExecuted=False)
        if role=='ios':
            assert not any(cmd==0x1d for cmd,at,size in p.commands(data))
            proof=[dict(symbol=x['name'],ordinal=x['ordinal'],definition=e.primary.resolve(images,deps[x['ordinal']],x['name']))for x in imports]
            assert all(x['definition']['status']=='actualDirectExport'for x in proof)
            row.update(currentStrongNativeDefinitions=proof,currentDefinitionEvidenceFrom16ActualTries=True,explicitCodeSigning=False)
        else:
            for suffix,sanitizer in[('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
                binary=out/('availability-'+suffix+'-fixture')
                run('mac-fixture-'+suffix+'-build',['xcrun','--sdk',sdk,'clang','-target',target,'-isysroot',sdkpath,'-std=c11','-O2','-Wall','-Wextra','-Werror',
                    '-DVM27_AVAILABILITY_ASM_NAME="VM27OSOrVariantVersionAtLeastFixture"',source,fixture,*sanitizer,'-o',binary])
                result=run('mac-fixture-'+suffix,[binary]);checks=json.loads(result.stdout)
                assert checks['checks']==15636 and checks['trueResults']>0 and checks['falseResults']>0
                row[suffix+'ActualSwiftCoreComparison']=checks
        roles.append(row)
    assert all(p.pin(Path(row['path']))==row for row in inputs)
    result=dict(schema='Actual six word swiftcc native availability provider data build v1',inputs=inputs,roles=roles,
                trueSystemAvailabilityQueries=True,queryPlatforms=[1,2],queryCount=2,
                versionEncoding='uint32 word truncation; major low16,minor low8,patch low8; identical genuine instructions',
                hostVersionSpoofed=False,syntheticAvailabilityResult=False,unprovenMissingAPIFallback=False,
                ABIOriginalCallerExecuted=False,originalUHLoaded=False,completeGraphProven=False,
                deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
    p.save(out/'candidate.json',result);print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),iOS=p.pin(out/'AV.unsigned.inert.macho-data'),full27Backend=False)))

if __name__=='__main__':main()
