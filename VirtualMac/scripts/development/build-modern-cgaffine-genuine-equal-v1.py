#!/usr/bin/env python3
"""Copy the exact dependency-free genuine27 transform equality leaf; no VZ load.

Original UHK passes two 48-byte transform addresses in x0/x1 and tests w0 bit0.
The exact original CoreGraphics leaf implements all six IEEE comparisons.
No function implementation, metadata, vtable, witness or success stub is made up.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hid_owner_reader',HERE/'prepare-modern-universalhid-provider-data-v1.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
from compiler_image import commands,imports,segments,chain_entries
from DyldExtractor.dyld.dyld_context import DyldContext
import capstone

ROOT=p.ROOT;NODE=p.NODE;pin=p.pin;save=p.save
NATIVE='_$sSo17CGAffineTransformV12CoreGraphicsE2eeoiySbAB_ABtFZ'
OWNER='/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics'
OWNER_UUID='b0fb9ac2e3cc31c2a90e0d38a776bae2'
ADDRESS=0x187bf3604
CALLER=0x29fdb8648
BASE=NODE/'universalhid-genuine-auth-relative-data-v1'


def run(out,label,argv):
    r=subprocess.run([str(x)for x in argv],capture_output=True,text=True)
    save(out/(label+'.json'),dict(argv=[str(x)for x in argv],exitCode=r.returncode,stdout=r.stdout,stderr=r.stderr))
    assert r.returncode==0,(label,r.stderr)
    return r


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    out=args.output.resolve();assert out.is_relative_to(NODE)and not out.exists();out.mkdir()
    with p.CACHE.open('rb')as f:
        cache=DyldContext(f);cache.addSubCaches(p.CACHE)
        assert bytes(cache.header.uuid).hex()=='c284a291b68b3d0da1a03f866f87efdc'
        exports=p.GenuineCacheExports(cache);proof=exports.resolve(OWNER,NATIVE)
        assert proof['exportAddress']==ADDRESS and proof['exportUUID']==OWNER_UUID
        off,ctx=cache.convertAddr(ADDRESS);code=bytes(ctx.getBytes(off,108))
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);md.detail=True
    dis=list(md.disasm(code,ADDRESS));assert len(dis)==27 and dis[-1].mnemonic=='ret'
    assert [i.address for i in dis if i.mnemonic=='ret']==[ADDRESS+96,ADDRESS+104]
    assert [i.mnemonic for i in dis]==(['ldr','ldr','fcmp','b.ne']*5+['ldr','ldr','fcmp','cset','ret','movz','ret'])
    assert all(i.operands[-1].imm==ADDRESS+100 for i in dis if i.mnemonic=='b.ne')
    for index in range(6):
        first,second=dis[index*4:index*4+2]
        assert first.operands[0].reg==capstone.arm64.ARM64_REG_D0
        assert second.operands[0].reg==capstone.arm64.ARM64_REG_D1
        assert first.operands[1].mem.base==capstone.arm64.ARM64_REG_X0 and first.operands[1].mem.disp==index*8
        assert second.operands[1].mem.base==capstone.arm64.ARM64_REG_X1 and second.operands[1].mem.disp==index*8
    words=struct.unpack('<27I',code)
    assembly='.text\n.p2align 2\n.globl "'+NATIVE+'"\n"'+NATIVE+'":\n'+''.join(f'  .long 0x{w:08x}\n'for w in words)
    asm=out/'genuine-transform-equal.s';asm.write_text(assembly)
    sdk=run(out,'ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.strip()
    ios=out/'VM27CGAffineEqual.ios.unsigned.dylib'
    run(out,'ios-link',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,
        '-fptrauth-abi-version=0','-dynamiclib',asm,'-Wl,-no_adhoc_codesign',
        '-Wl,-install_name,@loader_path/CGe','-o',ios])
    data=ios.read_bytes();text=next(s for g in segments(data)for s in g['sections']if s['name']=='__text')
    assert data[text['fileoff']:text['fileoff']+text['size']]==code
    run(out,'ios-dyld',['xcrun','dyld_info','-validate_only',ios])
    exports_text=run(out,'ios-exports',['xcrun','nm','-gU',ios]).stdout
    assert exports_text.count(NATIVE)==1
    assert [d['path']for d in p.dependencies(data)]==['/usr/lib/libSystem.B.dylib']
    undefined=run(out,'ios-undefined',['xcrun','nm','-u',ios]).stdout
    assert not undefined.strip()
    assert not any(cmd==0x1d for cmd,_,_ in commands(data))
    # Compile the real Swift imported-struct ABI, rather than assuming that
    # a C declaration alone proves the Swift operator calling convention.
    fixture=out/'genuine-cgaffine-caller.swift'
    fixture.write_text('import CoreGraphics\n@_cdecl("VM27CGEqualCaller")\n'
        'public func caller(_ lhs: UnsafePointer<CGAffineTransform>, '
        '_ rhs: UnsafePointer<CGAffineTransform>) -> Bool { lhs.pointee == rhs.pointee }\n')
    ir=out/'genuine-cgaffine-caller.ll'
    run(out,'ios-swift-ir',['xcrun','swiftc','-target','arm64e-apple-ios16.1','-sdk',sdk,
         '-module-cache-path',out/'ios-module-cache','-module-name','VM27GenuineCG','-Onone','-emit-ir',fixture,'-o',ir])
    llvm=ir.read_text()
    assert 'swiftcc i1 @"'+NATIVE[1:]+'"(ptr' in llvm
    # Owned local test calls only this copied pure leaf and standard CG values.
    mac=out/'VM27CGAffineEqual.mac.unsigned.dylib'
    macasm=out/'genuine-transform-equal-mac-test.s'
    macasm.write_text(assembly.replace('"'+NATIVE+'":','"'+NATIVE+'":\n.globl _VM27CopiedCGAffineEqual\n_VM27CopiedCGAffineEqual:'))
    run(out,'mac-link',['xcrun','clang','-target','arm64-apple-macos14','-dynamiclib',macasm,
                       '-Wl,-no_adhoc_codesign','-Wl,-install_name,'+str(mac),'-o',mac])
    macobject=out/'genuine-transform-equal-mac-test.o'
    run(out,'mac-object',['xcrun','clang','-target','arm64-apple-macos14','-c',macasm,'-o',macobject])
    test=out/'pure-transform-tests.swift'
    test.write_text('import CoreGraphics\n@_silgen_name("VM27CopiedCGAffineEqual")\n'
        'func originalEqual(_ lhs: CGAffineTransform, _ rhs: CGAffineTransform) -> Bool\n'
        'var checks = 0\nfunc verify(_ a:CGAffineTransform,_ b:CGAffineTransform,_ expected:Bool) { '
        'precondition(originalEqual(a,b)==expected); checks += 1 }\n'
        'let identity=CGAffineTransform.identity\nverify(identity,identity,true)\n'
        'for i in 0..<6 { var b=[1.0,0,0,1,0,0]; b[i] += 0.25; '
        'verify(identity,CGAffineTransform(a:b[0],b:b[1],c:b[2],d:b[3],tx:b[4],ty:b[5]),false) }\n'
        'for i in 0..<6 { var a=[1.0,0,0,1,0,0]; a[i] = Double.nan; '
        'let t=CGAffineTransform(a:a[0],b:a[1],c:a[2],d:a[3],tx:a[4],ty:a[5]); verify(t,t,false) }\n'
        'var zero=identity; zero.tx = -0.0; verify(identity,zero,true)\n'
        'var inf=identity; inf.a=Double.infinity; verify(inf,inf,true); '
        'var neg=inf; neg.a = -Double.infinity; verify(inf,neg,false)\n'
        'print("genuine-copy equality checks=\\(checks)")\n')
    executable=out/'pure-transform-tests'
    run(out,'mac-test-link',['xcrun','swiftc','-module-cache-path',out/'mac-module-cache','-O',test,macobject,'-o',executable])
    testresult=run(out,'mac-pure-tests',[executable])
    assert 'checks=16'in testresult.stdout
    raw=NODE/'universalhid-original-contract-v1/raw/UniversalHIDKit';b=raw.read_bytes()
    caller_section=next(s for g in segments(b)for s in g['sections']if s['address']<=CALLER<s['address']+s['size'])
    caller_off=caller_section['fileoff']+CALLER-caller_section['address']
    caller_words=list(struct.unpack_from('<4I',b,caller_off-8))
    assert caller_words==[0x910083e0,0xaa1303e1,0x940b1dde,0x37000060]
    # Route one UHK strong import to this exact copied definition in a new
    # inert candidate. Reclaim only informational LC_SOURCE_VERSION (16B)
    # to fit the 40B private load command; all section bytes/PAC stay exact.
    for row in json.loads((BASE/'freeze.json').read_text())['files']:assert pin(Path(row['path']))==row
    source=BASE/'UniversalHIDKit27.genuine-auth-relative.mac.inert.macho-data';original=source.read_bytes()
    rebuilt=bytearray(original);oldsize=struct.unpack_from('<I',rebuilt,20)[0]
    oldcmd=list(commands(rebuilt));removed=[(at,size)for cmd,at,size in oldcmd if cmd==0x2a]
    assert len(removed)==1 and removed[0][1]==16
    keep=[bytes(rebuilt[at:at+size])for cmd,at,size in oldcmd if cmd!=0x2a]
    joined=b''.join(keep);rebuilt[32:32+oldsize]=joined+b'\0'*(oldsize-len(joined))
    struct.pack_into('<II',rebuilt,16,len(keep),len(joined))
    ordinal=p.append_dependency(rebuilt,'@loader_path/CGe')
    target=next(r for r in imports(rebuilt)['imports']if r['name']==NATIVE)
    oldword=struct.unpack_from('<I',rebuilt,target['command'])[0]
    assert target['ordinal']==6 and not target['weak']
    struct.pack_into('<I',rebuilt,target['command'],(oldword&~255)|ordinal)
    assert list(chain_entries(rebuilt))==list(chain_entries(original))
    for g in segments(original):
        for s in g['sections']:
            if s['fileoff']and s['size']and s['flags']&255 not in(1,12):
                assert original[s['fileoff']:s['fileoff']+s['size']]==rebuilt[s['fileoff']:s['fileoff']+s['size']]
    routed=out/'UniversalHIDKit27.genuine-equal-route.mac.inert.macho-data';routed.write_bytes(rebuilt)
    run(out,'route-dyld',['xcrun','dyld_info','-validate_only',routed])
    report=dict(schema='Exact genuine27 CGAffine Swift equality leaf and UHK strong route v1',
        originalExport=proof,originalFunctionAddress=ADDRESS,originalFunctionBytes=108,
        originalFunctionSHA256=hashlib.sha256(code).hexdigest(),nativeCopiedCodeExactlyPreserved=True,
        iosProvider=pin(ios),originalUHKit=pin(raw),originalCallerPC=CALLER,originalCallerWords=caller_words,
        callerContract='x0 and x1 point to two 48-byte transforms; w0 bit0 is Boolean result',
        originalSource=pin(source),routedCandidate=pin(routed),changedImportIndex=target['index'],
        newStrongOrdinal=ordinal,removedInformationalSourceVersionBytes=16,
        pureOwnedMacChecks=16,swiftCallerIR=pin(ir),codeSigned=False,nativeHIDLoaded=False,
        completeMetadataSchema=False,completeTransitiveClosure=False,deviceOperations=0,full27Backend=False)
    save(out/'candidate.json',report)
    files=[Path(__file__),HERE/'prepare-modern-universalhid-provider-data-v1.py',asm,macasm,macobject,fixture,ir,test,ios,mac,raw,source,routed,out/'candidate.json']
    save(out/'freeze.json',dict(files=[pin(f)for f in files],deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),provider=pin(ios),routed=pin(routed),pureChecks=16)))


if __name__=='__main__':main()
