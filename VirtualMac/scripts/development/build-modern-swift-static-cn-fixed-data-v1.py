#!/usr/bin/env python3
"""Build real owned fixed CN data as unsigned compile-only objects.

No factory/sentinel/old metadata alias, class loading, signing, route or device
operation. mac-model has a distinct name and still uses the actual stock Base.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';HOST=R/'VirtualMac/vz/host'
def need(v,why):
    if not v:raise ValueError(why)
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def symbol(s):return '@"'+s+'"'
def ir_data(original):
    module='Swift' if original else 'VM27FixedModel';name='__StaticArrayStorage' if original else 'OwnStaticStorage'
    stem='$ss20__StaticArrayStorage' if original else '$s14VM27FixedModel16OwnStaticStorage'
    objc='_TtCs20__StaticArrayStorage' if original else '_TtC14VM27FixedModel16OwnStaticStorage'
    cn=symbol(stem+'CN');storage=symbol(stem+'CMf');desc=symbol(stem+'CMn');access=symbol(stem+'CMa');meta=symbol('OBJC_METACLASS_$'+objc)
    lines=['target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"',
        '%objc_class = type { ptr, ptr, ptr, ptr, ptr }','%ro = type { i32, i32, i32, i32, ptr, ptr, ptr, ptr, ptr, ptr, ptr }',
        '%positive = type <{ ptr, ptr, ptr, ptr, ptr, i32, i32, i32, i16, i16, i32, i32, ptr, ptr, ptr, ptr, i64, ptr, ptr, ptr, ptr, ptr, ptr }>',
        '%complete = type <{ ptr, ptr, ptr, %positive }>','%method = type <{ i32, i32 }>','%override = type <{ i32, i32, i32 }>',
        '%descriptor = type <{ i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, %method, i32, [5 x %override] }>','%response = type { ptr, i64 }',
        '@"$ss28__ContiguousArrayStorageBaseCN" = external global i8','@"$ss28__ContiguousArrayStorageBaseCMn" = external global i8','@"$sBOWV" = external global i8',
        '@"OBJC_METACLASS_$__TtCs28__ContiguousArrayStorageBase" = external global %objc_class','@"OBJC_METACLASS_$_NSObject" = external global %objc_class','@_objc_empty_cache = external global i8',
        'declare ptr @objc_opt_self(ptr)','declare swiftcc ptr @"$ss28__ContiguousArrayStorageBaseCABycfC"(ptr swiftself)',
        'declare void @_swift_stdlib_reportUnimplementedInitializer(ptr, i32, ptr, i32, i32)',
        'declare swiftcc void @VM27StaticCNDeallocator(ptr swiftself) noreturn','declare swiftcc void @VM27StaticCNModelDeallocator(ptr swiftself)','declare swiftcc ptr @VM27StaticCNDoNotCallMe(ptr swiftself) noreturn',
        'declare swiftcc void @VM27StaticCNWithUnsafeBufferOfObjects(ptr, ptr, ptr, ptr, ptr swiftself, ptr swifterror)',
        'declare swiftcc void @VM27StaticCNVerbatimNil(ptr, ptr, ptr, ptr, ptr swiftself, ptr swifterror)',
        'declare swiftcc void @VM27StaticCNNonVerbatimBuffer() noreturn','declare swiftcc void @VM27StaticCNStaticElementType() noreturn',
        'declare swiftcc i1 @VM27StaticCNCanStoreElements(ptr, ptr swiftself)']
    def cstring(label,text,section='__TEXT,__const'):
        lines.append('@'+label+' = private constant ['+str(len(text)+1)+' x i8] c"'+text+'\\00", section "'+section+'", align 1');return '@'+label
    objname=cstring('objc_name',objc,'__TEXT,__objc_classname,cstring_literals');typename=cstring('type_name',name);modname=cstring('module_name',module);fullname=cstring('full_name',module+'.'+name);initname=cstring('base_init_name','init(_doNotCallMeBase:)')
    def relative(target,source):return 'i32 trunc (i64 sub (i64 ptrtoint (ptr '+target+' to i64), i64 ptrtoint (ptr '+source+' to i64)) to i32)'
    def field(offset):return 'getelementptr (i8, ptr '+desc+', i64 '+str(offset)+')'
    def auth(label,target,slot,key,disc):
        result='@auth_'+label;lines.append(result+' = private constant { ptr, i32, i64, i64 } { ptr '+target+', i32 '+str(key)+', i64 ptrtoint (ptr '+slot+' to i64), i64 '+str(disc)+' }, section "llvm.ptrauth", align 8');return result
    def cslot(offset):return 'getelementptr (i8, ptr '+storage+', i64 '+str(24+offset)+')'
    a={}
    deallocator='@VM27StaticCNDeallocator' if original else '@VM27StaticCNModelDeallocator'
    for offset,target,key,disc in [(-16,deallocator,0,48063),(-8,symbol('$sBOWV'),2,11839),(0,meta,2,27361),(8,symbol('$ss28__ContiguousArrayStorageBaseCN'),2,46507),(32,'getelementptr (i8, ptr @class_ro, i64 2)',2,25080),(64,desc,2,44678),
        (80,symbol('$ss28__ContiguousArrayStorageBaseCABycfC'),0,41864),(88,'@VM27StaticCNWithUnsafeBufferOfObjects',0,12100),(104,'@VM27StaticCNForbiddenBaseInitializer',0,29519),(112,'@VM27StaticCNVerbatimNil',0,46600),(120,'@VM27StaticCNNonVerbatimBuffer',0,18946),(128,'@VM27StaticCNCanStoreElements',0,19820),(136,'@VM27StaticCNStaticElementType',0,43654),(144,'@VM27StaticCNDoNotCallMe',0,39982)]:a[offset]=auth('cn'+str(offset).replace('-','minus'),target,cslot(offset),key,disc)
    ma=auth('meta_isa',symbol('OBJC_METACLASS_$_NSObject'),meta,2,27361);ms=auth('meta_super',symbol('OBJC_METACLASS_$__TtCs28__ContiguousArrayStorageBase'),'getelementptr (i8, ptr '+meta+', i64 8)',2,46507);mr=auth('meta_ro','@meta_ro','getelementptr (i8, ptr '+meta+', i64 32)',2,25080)
    lines+=['@class_ro = private constant %ro { i32 128, i32 32, i32 32, i32 0, ptr null, ptr '+objname+', ptr null, ptr null, ptr null, ptr null, ptr null }, section "__DATA,__objc_const", align 8',
        '@meta_ro = private constant %ro { i32 129, i32 40, i32 40, i32 0, ptr null, ptr '+objname+', ptr null, ptr null, ptr null, ptr null, ptr null }, section "__DATA,__objc_const", align 8',
        meta+' = global %objc_class { ptr '+ma+', ptr '+ms+', ptr @_objc_empty_cache, ptr null, ptr '+mr+' }, section "__DATA,__objc_data", align 8']
    values=['ptr '+a[0],'ptr '+a[8],'ptr @_objc_empty_cache','ptr null','ptr '+a[32],'i32 2','i32 0','i32 32','i16 7','i16 0','i32 176','i32 24','ptr '+a[64],'ptr null','ptr '+a[80],'ptr '+a[88],'i64 16']+['ptr '+a[i] for i in [104,112,120,128,136,144]]
    lines+=[storage+' = internal global %complete <{ ptr null, ptr '+a[-16]+', ptr '+a[-8]+', %positive <{ '+', '.join(values)+' }> }>, section "__DATA,__objc_data,regular", align 8',
        cn+' = alias %positive, getelementptr (i8, ptr '+storage+', i64 24)',symbol('OBJC_CLASS_$'+objc)+' = alias %positive, getelementptr (i8, ptr '+storage+', i64 24)',
        '@class_list = private global ptr '+cn+', section "__DATA,__objc_classlist,regular,no_dead_strip", align 8']
    moduleRel=relative(modname,'getelementptr (i8, ptr @module_descriptor, i64 8)');lines.append('@module_descriptor = private constant <{ i32, i32, i32 }> <{ i32 0, i32 0, '+moduleRel+' }>, section "__TEXT,__constg_swiftt", align 4')
    got='@got_base_descriptor';gotAuth=auth('got_base_descriptor',symbol('$ss28__ContiguousArrayStorageBaseCMn'),got,2,44678);lines.append(got+' = private constant ptr '+gotAuth+', align 8')
    def indirect(target,offset):return 'i32 add ('+relative(target,field(offset))+', i32 1)'
    overrides=[]
    for index,(parentOff,impl) in enumerate([(60,'VM27StaticCNVerbatimNil'),(68,'VM27StaticCNNonVerbatimBuffer'),(76,'VM27StaticCNCanStoreElements'),(84,'VM27StaticCNStaticElementType'),(52,'VM27StaticCNForbiddenBaseInitializer')]):
        gotTq='@got_tq_'+str(parentOff);q=auth('got_tq_'+str(parentOff),'getelementptr (i8, ptr '+symbol('$ss28__ContiguousArrayStorageBaseCMn')+', i64 '+str(parentOff)+')',gotTq,2,26458);lines.append(gotTq+' = private constant ptr '+q+', align 8')
        at=64+index*12;overrides.append('%override <{ '+indirect(got,at)+', '+indirect(gotTq,at+4)+', '+relative('@'+impl,field(at+8))+' }>')
    # Symbolic indirect reference must authenticate the actual imported Base
    # descriptor GOT with DA2/address/ae86. Local self reference is direct.
    lines+=['@self_symbolic = private constant <{ i8, i32, i8 }> <{ i8 1, '+relative(desc,'getelementptr (i8, ptr @self_symbolic, i64 1)')+', i8 0 }>, section "__TEXT,__swift5_typeref,regular", align 2',
        '@base_symbolic = private constant <{ i8, i32, i8 }> <{ i8 2, '+relative(got,'getelementptr (i8, ptr @base_symbolic, i64 1)')+', i8 0 }>, section "__TEXT,__swift5_typeref,regular", align 2',
        '@field_descriptor = private constant <{ i32, i32, i16, i16, i32 }> <{ '+relative('@self_symbolic','@field_descriptor')+', '+relative('@base_symbolic','getelementptr (i8, ptr @field_descriptor, i64 4)')+', i16 1, i16 12, i32 0 }>, section "__TEXT,__swift5_fieldmd,regular", align 4']
    words=['i32 3221225552',relative('@module_descriptor',field(4)),relative(typename,field(8)),relative(access,field(12)),relative('@field_descriptor',field(16)),relative('@base_symbolic',field(20))]+['i32 '+str(x) for x in [3,19,1,0,18,18,1]]
    words+=['%method <{ i32 2620260353, '+relative('@VM27StaticCNDoNotCallMe',field(56))+' }>','i32 5','[5 x %override] ['+', '.join(overrides)+']']
    lines+=[desc+' = constant %descriptor <{ '+', '.join(words)+' }>, section "__TEXT,__constg_swiftt", align 4',
        'define swiftcc %response '+access+'(i64 %request) #0 {\n  %realized = call ptr @objc_opt_self(ptr '+cn+')\n  %first = insertvalue %response undef, ptr %realized, 0\n  %complete = insertvalue %response %first, i64 0, 1\n  ret %response %complete\n}',
        'define swiftcc ptr @VM27StaticCNForbiddenBaseInitializer(ptr swiftself %self) noreturn #0 {\n  call void @_swift_stdlib_reportUnimplementedInitializer(ptr '+fullname+', i32 '+str(len(module+'.'+name))+', ptr '+initname+', i32 23, i32 0)\n  unreachable\n}',
        'attributes #0 = { "frame-pointer"="non-leaf" "probe-stack"="__chkstk_darwin" "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-returns" }',
        '@llvm.used = appending global [3 x ptr] [ptr '+cn+', ptr '+desc+', ptr @class_list], section "llvm.metadata"',
        '!llvm.module.flags = !{!0, !3, !4, !5, !6, !7, !8}',
        '!0 = !{i32 6, !"ptrauth.abi-version", !1}', '!1 = !{!2}', '!2 = !{i32 0, i1 false}',
        '!3 = !{i32 1, !"Objective-C Version", i32 2}',
        '!4 = !{i32 1, !"Objective-C Image Info Version", i32 0}',
        '!5 = !{i32 1, !"Objective-C Image Info Section", !"__DATA,__objc_imageinfo,regular,no_dead_strip"}',
        '!6 = !{i32 1, !"Objective-C Class Properties", i32 64}',
        '!7 = !{i32 1, !"Objective-C Enforce ClassRO Pointer Signing", i32 16}',
        '!8 = !{i32 1, !"Swift Version", i32 7}']
    return '\n'.join(lines)+'\n'
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();out=args.output.resolve();need(not out.exists(),'output must be new');out.mkdir(parents=True)
    logs=[]
    def run(label,argv):
        argv=list(map(str,argv));r=subprocess.run(argv,capture_output=True);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);logs.append(dict(label=label,argv=argv,exit=r.returncode));(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n');need(r.returncode==0,label+' failed');return r.stdout.decode().strip()
    files=[]
    for role,sdk,target,original in [('mac-model','macosx','arm64e-apple-macos27.0',False),('ios-inert','iphoneos','arm64e-apple-ios16.1',True)]:
        sdkpath=run(role+'-sdk',['xcrun','--sdk',sdk,'--show-sdk-path']);directory=out/role;directory.mkdir();ir=directory/'FixedCN.ll';ir.write_text(ir_data(original));obj=directory/'FixedCN.o';methods=directory/'Methods.o';fatal=directory/'Fatal.o'
        run(role+'-data',['xcrun','clang','-target',target,'-isysroot',sdkpath,'-x','ir','-c',ir,'-o',obj]);run(role+'-methods',['xcrun','clang','-target',target,'-isysroot',sdkpath,'-x','ir','-c',HOST/'modern_swift_static_cn_fixed_methods_v1.ll','-o',methods]);run(role+'-fatal',['xcrun','swiftc','-target',target,'-sdk',sdkpath,'-module-cache-path',directory/'module-cache','-O','-parse-as-library','-emit-object',HOST/'modern_swift_static_cn_fixed_fatal_methods_v1.swift','-o',fatal])
        files += [pin(p) for p in [ir,obj,methods,fatal]]
    (out/'candidate.json').write_text(json.dumps(dict(schema='Genuine fixed StaticCN owned data compile-only v1',products=files,commands=logs,sourcePins=[pin(Path(__file__)),pin(HOST/'modern_swift_static_cn_fixed_methods_v1.ll'),pin(HOST/'modern_swift_static_cn_fixed_fatal_methods_v1.swift')],fullBytes=176,addressPoint=24,negativeWords=3,positiveWords=19,descriptorBytes=124,realOwnCNAddressPoint=True,oldEmptyAlias=False,factoryAlias=False,originalIOSNamePreserved=True,MacModelNameDistinct=True,dataObjectNotClassStub=True,actualObjcOptSelfAccessor=True,completeCallableMethodABIValidated=False,oldN2SubclassCompatibilityExecuted=False,originalStaticCNIdentityExecuted=False,linked=False,loaded=False,signed=False,deviceOperations=0,nativeCPUCalls=0,nativeVMCalls=0,full27Backend=False),indent=2)+'\n')
if __name__=='__main__':main()
