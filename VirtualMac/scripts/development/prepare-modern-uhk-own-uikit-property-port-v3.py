#!/usr/bin/env python3
"""One real own-profile Mac property absence and dead NSEvent binding removal."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('port_u',HERE/'uhk_nsevent_property_port_v4.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
p,n=u.p,u.p.NODE;HOST=p.ROOT/'VirtualMac/vz/host'

def main():
    out=n/'uhk-own-uikit-keyboard-property-source-port-data-v3';assert not out.exists();out.mkdir()
    source=n/'universalhid-static-cn-real-reexport-data-v1/candidate.json';m=json.loads(source.read_bytes())
    kit=next(row for row in m['images']if row['name']=='UniversalHIDKit');file=Path(kit['candidate']['path']);before=file.read_bytes()
    assert p.pin(file)==kit['candidate'];after,proof=u.transform(before);verification=u.validate(before,after)
    src=HOST/'vm27_mac_keyboard_property_unavailable_v1.swift';fixture=HOST/'test-vm27-mac-keyboard-property-unavailable-v1.swift'
    pins=[p.pin(Path(__file__)),p.pin(Path(u.__file__)),p.pin(src),p.pin(fixture),p.pin(source),p.pin(file)];runs=[]
    def run(label,args,expected=0):
        args=list(map(str,args));result=subprocess.run(args,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        runs.append(dict(label=label,argv=args,exit=result.returncode));p.save(out/'commands.json',runs)
        assert result.returncode==expected,(label,result.stderr.decode());return result
    try:
        actual=n/'uhk-mac-input-four-original-readonly-v6/audit.json';original=json.loads(actual.read_bytes())
        row=next(row for row in original['functions']if row['start']==u.OLD_BASE+u.FUNCTION)
        with p.CACHE.open('rb')as stream:
            cache=p.DyldContext(stream);assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc';subs=cache.addSubCaches(p.CACHE)
            try:
                off,owner=cache.convertAddr(row['start']);body=owner.getBytes(off,136)
                assert body==Path(row['data']['path']).read_bytes();filebody=out/'genuine-original-property-body.bin';filebody.write_bytes(body)
                off,owner=cache.convertAddr(0x29fdbb068);descriptor=owner.getBytes(off,16)
                assert struct.unpack_from('<I',descriptor,12)[0]==0x20010
                oldtype=0x29fdbb068+4+struct.unpack_from('<i',descriptor,4)[0]
                off,owner=cache.convertAddr(oldtype);typename=owner.getBytes(off,8);assert typename==b'NSEvent\0'
                off,owner=cache.convertAddr(0x29fdbc740);name=owner.getBytes(off,17);assert name==b'HIDCapsLockState\0'
                (out/'genuine-original-conformance-prefix.bin').write_bytes(descriptor)
                (out/'genuine-original-class-name.bin').write_bytes(typename)
                (out/'genuine-original-property-name.bin').write_bytes(name)
            finally:
                for sub in subs:sub.close()
        modulecache=out/'module-cache';modulecache.mkdir()
        mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
        ios=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        fixtures=[]
        for mode in ('normal','sanitized'):
            exe=out/('own-property-none-'+mode);flags=['xcrun','swiftc','-module-cache-path',modulecache,'-O','-parse-as-library','-target','arm64e-apple-macos13.0','-sdk',mac]
            if mode=='sanitized':flags+=['-sanitize=address']
            run('compile-'+mode,flags+[src,fixture,'-o',exe]);result=run('run-'+mode,[exe]);j=json.loads(result.stdout)
            assert j['failures']==j['originalUHKCalls']==j['deviceOperations']==0 and j['propertyQueries']==384
            fixtures.append(dict(mode=mode,image=p.pin(exe),result=j,sourceSanitized=mode=='sanitized'))
        flags=['xcrun','swiftc','-module-cache-path',modulecache,'-O','-parse-as-library','-target','arm64e-apple-ios16.1','-sdk',ios]
        run('compile-ios-source',flags+[src,'-emit-object','-o',out/'own-property-none.ios.inert.o'])
        run('ir-ios-source',flags+[src,'-emit-ir','-o',out/'own-property-none.ios.ll'])
        run('asm-ios-source',flags+[src,'-emit-assembly','-o',out/'own-property-none.ios.s'])
        ir=(out/'own-property-none.ios.ll').read_text();assembly=(out/'own-property-none.ios.s').read_text()
        signature=next(line for line in ir.splitlines()if line.startswith('define swiftcc void @VM27MacKeyboardServicePropertyUnavailableV1('))
        assert 'ptr noalias writeonly sret(%TypSg)'in signature and 'i64 %1'in signature and 'ptr readnone captures(none) %2'in signature
        function=ir.split('define swiftcc void @VM27MacKeyboardServicePropertyUnavailableV1',1)[1].split('\n}',1)[0]
        assert 'i64 32'in function and 'llvm.memset'in function and 'ret void'in function
        assert '_VM27MacKeyboardServicePropertyUnavailableV1:'in assembly
        mutate=out/'wrong-false-property-source.swift';mutate.write_text(src.read_text().replace('return nil','return false'))
        exe=out/'wrong-false-property';run('compile-false-negative',['xcrun','swiftc','-module-cache-path',modulecache,'-O','-parse-as-library','-target','arm64e-apple-macos13.0','-sdk',mac,mutate,fixture,'-o',exe])
        result=run('run-false-negative',[exe],1);assert json.loads(result.stdout)['failures']>0
        data=out/'UniversalHIDKit27.own-uikit-keyboard-property.mac.inert.macho-data';data.write_bytes(after)
        run('validate-data',['xcrun','dyld_info','-validate_only',data])
        negatives=[]
        damage=[]
        for label,at in [('property branch',u.CLASS_READ),('original none layout',u.ABSENT),('original PAC return',u.FUNCTION+132),
            ('predecessor chain',proof['predecessor']['fileoff']),('remaining live bind',next(r['fileoff']for r in u.chain_entries(after)if r['bind']))]:
            b=bytearray(after);b[at]^=1;damage.append((label,bytes(b)))
        for label,b in damage:
            try:u.validate(before,b)
            except (AssertionError,ValueError):negatives.append(dict(name=label,refused=True))
            else:raise AssertionError(label)
        for label,at in [('conformance kind must remain actual name lookup',proof['preservedNSEventConformance']['fileoff']+12),
            ('original nil body exact',u.ABSENT),('original class chain exact',proof['chainNode']['fileoff']+7)]:
            b=bytearray(before);b[at]^=8 if 'kind'in label else 1
            try:u.reference_proof(bytes(b))
            except (AssertionError,ValueError):negatives.append(dict(name=label,refused=True))
            else:raise AssertionError(label)
        assert len(negatives)==8
        unchanged=[dict(name=row['name'],candidate=row['candidate'])for row in m['images']if row['name']!='UniversalHIDKit']
        remaining=[row for row in u.imports(after)['imports']if row['name']in ('_OBJC_CLASS_$_NSTouch','_SLEventGetDoubleValueField','_SLEventGetIntegerValueField')]
        assert len(remaining)==3
        abi=p.ROOT/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-swift-own-generic-field-native-candidate-v1/upstream/include--swift--ABI--MetadataValues.h'
        assert 'DirectObjCClassName = 0x02'in abi.read_text();pins.append(p.pin(abi))
        p.save(out/'candidate.json',dict(schema='Own UIKit unavailable Mac keyboard property source port inert v3',sourceCandidate=p.pin(source),
            sourceImage=kit['candidate'],providerCandidate=p.pin(data),unchangedGenuineProviders=unchanged,
            explicitOwnPropertyAbsenceSource=p.pin(src),genuineSwiftAnyOptionalNoneCompilerOracle=p.pin(out/'own-property-none.ios.ll'),
            originalPropertyName='HIDCapsLockState',originalPropertyBody=p.pin(filebody),verification=verification,
            ownSourceFixtures=fixtures,wrongFalsePropertyRealExecutableRejected=True,negativeControls=negatives,
            strongImportReferencesRemoved=1,remainingMacHostSpecificStrongImports=remaining,
            originalClassNameConformancePreservedWithoutFakeClass=True,originalNlistDeclarationsPreserved=True,
            removedClassSlotNotReferencedByRemainingTypedMetadataOrRelatives=True,completeOriginalHostPropertyBehaviorPreserved=False,
            actualOriginalPropertyGetterExecuted=False,originalUHKLoaded=False,nativeIOSExecuted=False,
            currentCompleteLoadGraphValidated=False,currentRuntimeClassLookupValidated=False,
            codeSigned=False,readyWritten=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,full27Backend=False))
        for directory in (source.parent,actual.parent,n/'uhk-nsevent-property-reference-proof-v1-failed',n/'uhk-nsevent-property-reference-proof-v2-failed',n/'uhk-own-uikit-keyboard-property-source-port-data-v1',n/'uhk-own-uikit-keyboard-property-source-port-data-v2'):
            if (directory/'freeze.json').exists():
                for row in json.loads((directory/'freeze.json').read_bytes())['files']:assert p.pin(Path(row['path']))==row;pins.append(row)
                pins.append(p.pin(directory/'freeze.json'))
            else:pins += [p.pin(file)for file in directory.iterdir()if file.is_file()]
        pins += [p.pin(file)for file in out.iterdir()if file.is_file()]
        p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),freeze=p.pin(out/'freeze.json'),image=p.pin(data),fixtures=fixtures,remainingMacStrong=3)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for file in (Path(__file__),Path(u.__file__),src,fixture):(failed/file.name).write_bytes(file.read_bytes())
        p.save(out/'failure.json',dict(reason=repr(error),deviceOperations=0,nativeExecuted=False));raise
if __name__=='__main__':main()
