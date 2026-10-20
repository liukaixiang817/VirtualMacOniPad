#!/usr/bin/env python3
"""Build one real consuming Swift specialization and an ordinary Mac fixture."""
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
ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST=ROOT/'VirtualMac/vz/host'
SYMBOL='$ss12_ArrayBufferV20_consumeAndCreateNew14bufferIsUnique15minimumCapacity13growForAppendAByxGSb_SiSbtFyXl_Ts5'
spec=importlib.util.spec_from_file_location('actual_array',ROOT/'VirtualMac/scripts/development/audit-modern-array-native-dependencies-v1.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
p=a.p


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    source=HOST/'modern_swift_arraybuffer_consume_compat.swift';fixture=HOST/'modern_swift_arraybuffer_consume_fixture.swift'
    inputs=[p.pin(path)for path in(Path(__file__),source,fixture)]
    exports=out/'exports.list';exports.write_text('_'+SYMBOL+'\n')
    logs=[]
    def run(label,argv,expected=True):
        r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        logs.append(dict(label=label,argv=list(map(str,argv)),exit=r.returncode,stdoutSHA256=hashlib.sha256(r.stdout).hexdigest(),stderrSHA256=hashlib.sha256(r.stderr).hexdigest()))
        p.save(out/'commands.json',logs)
        if expected:assert r.returncode==0,(label,r.stderr.decode())
        return r
    roles=[]
    for role,target,sdk in[('mac','arm64e-apple-macos13.0','macosx'),('ios','arm64e-apple-ios16.1','iphoneos')]:
        directory=out/role;directory.mkdir()
        sdkpath=run(role+'-sdk',['xcrun','--sdk',sdk,'--show-sdk-path']).stdout.decode().strip()
        interface=Path(sdkpath)/('usr/lib/swift/Swift.swiftmodule/arm64e-apple-'+('macos'if role=='mac'else 'ios')+'.swiftinterface')
        inputs.append(p.pin(interface));text=interface.read_text()
        needle='internal __consuming func _consumeAndCreateNew(bufferIsUnique:'
        at=text.index(needle);window=text[at:text.index('\n  @',at+len(needle))]
        assert 'dest.moveInitialize' in window and '_native.mutableCount = 0' in window and '_copyContents(' in window
        (out/(role+'-serialized-source.txt')).write_text(window+'\n')
        base=['xcrun','--sdk',sdk,'swiftc','-parse-as-library','-target',target,'-sdk',sdkpath,
              '-Xfrontend','-disable-access-control','-Xfrontend','-disable-layout-string-value-witnesses',
              '-Xfrontend','-disable-layout-string-value-witnesses-instantiation','-module-name','VM27ArrayBufferConsume',
              '-module-cache-path',out/(role+'-cache'),'-O',source]
        original=out/(role+'.original.ll');edited=out/(role+'.ll')
        run(role+'-ir',base+['-emit-ir','-o',original])
        ir=original.read_text();head=re.search(r'^define hidden swiftcc ptr @"'+re.escape(SYMBOL)+r'"\([^\n]*',ir,re.M)
        assert head and 'swiftself'not in head[0],head[0]if head else 'missing entry'
        assert re.search(r'\(i1 %\d+, i64 %\d+, i1 %\d+, ptr %\d+\)',head[0]),head[0]
        assert not re.search(r'^.*\b(?:call|invoke)\b.*@"'+re.escape(SYMBOL)+r'"',ir,re.M),'recursive export call'
        # Only make this correctly compiled internal member's definition public.
        newhead=head[0].replace('define hidden swiftcc','define swiftcc')
        ir=ir[:head.start()]+newhead+ir[head.end():];edited.write_text(ir)
        assert ir.replace(newhead,head[0],1)==original.read_text()
        run(role+'-module',base+['-emit-module','-emit-module-path',directory/'VM27ArrayBufferConsume.swiftmodule'])
        obj=out/(role+'.o')
        run(role+'-object',['xcrun','--sdk',sdk,'clang','-target',target,'-isysroot',sdkpath,'-x','ir','-c',edited,'-o',obj])
        provider=directory/('VM27AB.dylib'if role=='mac'else 'AB.unsigned.inert.macho-data')
        link=['xcrun','--sdk',sdk,'swiftc','-target',target,'-sdk',sdkpath,obj,'-emit-library',
              '-Xlinker','-exported_symbols_list','-Xlinker',exports,'-Xlinker','-install_name','-Xlinker','@rpath/VM27AB.dylib','-o',provider]
        if role=='ios':link+=['-Xlinker','-no_adhoc_codesign']
        run(role+'-link',link);run(role+'-dyld',['xcrun','dyld_info','-validate_only',provider])
        raw=provider.read_bytes();actualexports={r['symbol']:r for c,q,z in p.commands(raw)if c==0x80000033 for off,size in[struct.unpack_from('<II',raw,q+8)]for r in p.export_trie(raw[off:off+size])}
        assert set(actualexports)=={'_'+SYMBOL}and not actualexports['_'+SYMBOL]['flags']&8
        imp=p.imports(raw)['imports'];deps={r['ordinal']:r['path']for r in p.dependencies(raw)}
        assert all(r['ordinal']>0 and not r['weak']and r['name']!='_'+SYMBOL for r in imp)
        assert not any(x in r['name']for r in imp for x in('swift_cvw_','swift_coro','Context2','ContextInMetadataState2'))
        record=dict(role=role,provider=p.pin(provider),exports=actualexports,IRSignature=newhead,
                    visibilityOnlyChanged=True,recursiveSameSymbolCallAbsent=True,deviceExecuted=False)
        if role=='ios':
            assert not any(c==0x1d for c,q,z in p.commands(raw)),'unsigned data only'
            images=a.actual.captured_images();images.update(a.current_system_images());proof=[]
            for r in imp:
                found=a.actual.resolve(images,deps[r['ordinal']],r['name']);assert found['status']=='actualDirectExport',(r,found)
                proof.append(dict(symbol=r['name'],ordinal=r['ordinal'],dependency=deps[r['ordinal']],proof=found))
            record.update(currentNativeImports=proof,allCurrentNativeStrongDependenciesResolved=True,explicitCodeSigning=False)
        else:
            executable=out/'arraybuffer-consume-mac-fixture'
            run('mac-fixture-build',['xcrun','--sdk',sdk,'swiftc','-target',target,'-sdk',sdkpath,'-O',
                '-Xfrontend','-disable-access-control','-Xfrontend','-disable-layout-string-value-witnesses',
                '-Xfrontend','-disable-layout-string-value-witnesses-instantiation','-module-cache-path',out/'fixture-cache',
                '-I',directory,provider,'-Xlinker','-rpath','-Xlinker','@executable_path/mac',fixture,'-o',executable])
            positive=run('mac-positive',[executable]);summary=json.loads(positive.stdout)
            assert summary['failures']==0 and summary['privateCalls']==summary['stockCalls']==1920
            assert summary['actualUniqueCalls']>0 and summary['madeObjects']==summary['destroyedObjects']
            negative=run('mac-allocation-failure',[executable,'--allocation-failure'],expected=False)
            assert negative.returncode==-6 and b'failed to allocate' in negative.stderr and not negative.stdout
            record.update(ordinaryMacFixture=p.pin(executable),actualMac=summary,
                          rejectedImpossibleAllocation=dict(exit=negative.returncode,stderrSHA256=hashlib.sha256(negative.stderr).hexdigest()))
        roles.append(record)
    assert all(p.pin(Path(row['path']))==row for row in inputs)
    result=dict(schema='Real one-function ArrayBuffer consume serialized Swift data build v1',inputs=inputs,roles=roles,
                sourceBodyGeneration='actual serialized SDK body at deployment target preceding export availability',
                receiverABI='w0=unique,x1=capacity,w2=grow,x3=owned buffer; x0=owned new buffer',
                originalCallerABIIndependentlyProven=False,originalVZExecuted=False,originalVMMExecuted=False,
                nativeIOSExecuted=False,deviceOperations=0,stockTransitiveClosureProven=False,full27Backend=False)
    p.save(out/'candidate.json',result)
    files=[Path(__file__),source,fixture,out/'candidate.json',out/'commands.json',exports]
    files+=[Path(r['path'])for r in inputs]+[Path(row['provider']['path'])for row in roles]
    files+=[out/(role+suffix)for role in('mac','ios')for suffix in('.original.ll','.ll','-serialized-source.txt')]
    p.save(out/'freeze.json',dict(files=[p.pin(f)for f in files],deviceOperations=0,nativeIOSExecuted=False))
    print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),ordinaryMac=roles[0]['actualMac'],iosStrongImports=len(roles[1]['currentNativeImports']))))


if __name__=='__main__':main()
