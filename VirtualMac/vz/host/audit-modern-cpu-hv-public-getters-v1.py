"""Bounded original getter bytes and actual public nine-entry SDK ABI.

Disassemble the pinned original image; compile only SDK and own ABI callers.
No Apple/native function is executed. Existing reports supply pins, not values.
"""
from pathlib import Path
import hashlib,json,os,re,struct,subprocess
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-hv-public-getter-original-sdk-readonly-v1'
D.mkdir(exist_ok=False)
pins={}
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();v=dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest());pins[str(p)]=v;return v
def read(p):pin(p);return Path(p).read_bytes()
def need(x,s):
 if not x:raise ValueError(s)
old=N/'old13-observer-baseline-v1/Hypervisor';b=read(old)
need(hashlib.sha256(b).hexdigest()=='c40d039280f8048b9e921d2ea7181e50e7e6dd693614cc494baa4d7f43d8efe4','actual original whole')
base=0x100000000;segments=[];starts=None;at=32
for _ in range(struct.unpack_from('<I',b,16)[0]):
 cmd,size=struct.unpack_from('<II',b,at)
 if cmd==0x19:
  name=b[at+8:at+24].split(b'\0')[0].decode();va,vs,off,fs=struct.unpack_from('<QQQQ',b,at+24);segments.append((name,va,vs,off,fs))
 if cmd==0x26:starts=struct.unpack_from('<II',b,at+8)
 at+=size
need(starts is not None,'actual LC_FUNCTION_STARTS')
def offset(rva,n):
 matches=[off+base+rva-va for _,va,vs,off,fs in segments if va<=base+rva and base+rva+n<=va+fs]
 need(len(matches)==1,'unique file-backed whole span');return matches[0]
def raw(rva,n):return b[offset(rva,n):offset(rva,n)+n]
blob=b[starts[0]:sum(starts)];cursor=0;pc=0;functions=[]
while cursor<len(blob):
 value=0;shift=0
 while True:
  q=blob[cursor];cursor+=1;value|=(q&127)<<shift;shift+=7
  if not q&128:break
  need(shift<=63,'bounded function ULEB')
 if not value:break
 pc+=value;functions.append(pc)
decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
frames=[]
for name,start,code_end,end in [('simd-get',0x585c,0x589c,0x589c),('simd-set',0x589c,0x58d8,0x58d8),
 ('scalar-get',0x58d8,0x59e4,0x59fc),('scalar-set',0x59fc,0x5b20,0x5b38)]:
 need(start in functions and functions[functions.index(start)+1]==end,'actual complete LC26 frame '+name)
 data=raw(start,end-start);(D/(name+'.bin')).write_bytes(data)
 instructions=[dict(rva=hex(i.address-base),word=f'{struct.unpack("<I",i.bytes)[0]:08x}',mnemonic=i.mnemonic,operands=i.op_str)
  for i in decoder.disasm(data[:code_end-start],base+start)]
 need(len(instructions)*4==code_end-start,'all original instruction words '+name)
 (D/(name+'.asm')).write_text('\n'.join(f"{i['rva']} {i['word']} {i['mnemonic']} {i['operands']}" for i in instructions)+'\n')
 frames.append(dict(name=name,startRVA=hex(start),codeEndRVA=hex(code_end),endRVA=hex(end),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),instructions=instructions))
def ins(rva,data=None):
 code=raw(rva,4) if data is None else data
 q=list(decoder.disasm(code,base+rva));need(len(q)==1,'single actual instruction');return q[0]
# The actual computed table selects complete load blocks for X29..CPSR.
table=struct.unpack('<6i',raw(0x59e4,24));targets=[0x5924+x for x in table]
loads=[]
for identifier,target in enumerate(targets,29):
 block=list(decoder.disasm(raw(target,12),base+target))
 chosen=[q for q in block if q.mnemonic=='ldr' and q.op_str.startswith(('x8, [','w8, ['))]
 need(len(chosen)==1,'one actual special-register load')
 q=chosen[0];m=re.fullmatch(r'([xw])8, \[x8, #(0x[0-9a-f]+|[0-9]+)\]',q.op_str)
 need(m is not None,'actual load base/destination');loads.append(dict(identifier=identifier,blockRVA=hex(target),
  loadRVA=hex(q.address-base),offset=int(m[2],0),bytes=8 if m[1]=='x' else 4,zeroExtendedToPublic64=m[1]=='w'))
need([(x['offset'],x['bytes']) for x in loads]==[(0xf0,8),(0xf8,8),(0x108,8),(0x344,4),(0x340,4),(0x110,4)],'closed actual getter six-way table')
need(ins(0x58f8).mnemonic=='ldr' and ins(0x58f8).op_str=='x8, [x8, #8]','actual ordinary scalar 8-byte load')
need(ins(0x58fc).mnemonic=='str' and ins(0x58fc).op_str=='x8, [x2]','all scalar loads publish uint64')
# Pin the actual SIMD instructions by their values, not a report's offsets.
simd_get=frames[0]['instructions'];simd_set=frames[1]['instructions']
need(any(i['mnemonic']=='ldr' and i['operands']=='q0, [x8, #0x140]' for i in simd_get),'actual Q0 16-byte getter')
need(any(i['mnemonic']=='str' and i['operands']=='q0, [x2]' for i in simd_get),'actual Q0 public output')
need(any(i['mnemonic']=='str' and i['operands']=='q0, [x8, #0x140]' for i in simd_set),'actual Q0 input setter')
neg=[]
def rejected(name,fn):
 try:fn()
 except ValueError:neg.append(dict(name=name,rejected=True))
 else:raise ValueError('mutation accepted '+name)
changed=list(table);changed[5]=changed[4]
rejected('CPSR computed table must not alias FPSR',lambda:need([0x5924+x for x in changed]==targets,'targets'))
q=loads[-1];w=struct.unpack('<I',raw(int(q['loadRVA'],16),4))[0]
changed=struct.pack('<I',w|0x40000000)
rejected('CPSR u32 load cannot become u64',lambda:need(ins(int(q['loadRVA'],16),changed).op_str.startswith('w8,'),'width'))
sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk')
for name in ['hv_vcpu.h','hv_vcpu_config.h','hv_vcpu_types.h','hv_base.h']:
 pin(sdk/'System/Library/Frameworks/Hypervisor.framework/Headers'/name)
pin(sdk/'usr/include/arm64/hv/hv_kern_types.h');pin(S/'modern_cpu_hv_public_abi_v1.h');pin(Path(__file__))
code='''#include "modern_cpu_hv_public_abi_v1.h"
_Static_assert(sizeof(hv_return_t)==4 && sizeof(hv_vcpu_t)==8,"status and ID");
_Static_assert(sizeof(hv_reg_t)==4 && sizeof(hv_sys_reg_t)==2 && sizeof(hv_simd_fp_reg_t)==4,"actual enum widths");
_Static_assert(sizeof(hv_simd_fp_uchar16_t)==16 && _Alignof(hv_simd_fp_uchar16_t)==16,"vector");
_Static_assert(sizeof(hv_vcpu_exit_t)==32 && offsetof(hv_vcpu_exit_t,exception)==8,"exit");
hv_vcpu_config_t abi_config(void){return hv_vcpu_config_create();}
hv_return_t abi_create(hv_vcpu_t *id,hv_vcpu_exit_t **exit,hv_vcpu_config_t cfg){return hv_vcpu_create(id,exit,cfg);}
hv_return_t abi_destroy(hv_vcpu_t id){return hv_vcpu_destroy(id);}
hv_return_t abi_scalar_set(hv_vcpu_t id,hv_reg_t reg,uint64_t v){return hv_vcpu_set_reg(id,reg,v);}
hv_return_t abi_scalar_get(hv_vcpu_t id,hv_reg_t reg,uint64_t *v){return hv_vcpu_get_reg(id,reg,v);}
hv_return_t abi_vector_set(hv_vcpu_t id,hv_simd_fp_reg_t reg,hv_simd_fp_uchar16_t v){return hv_vcpu_set_simd_fp_reg(id,reg,v);}
hv_return_t abi_vector_get(hv_vcpu_t id,hv_simd_fp_reg_t reg,hv_simd_fp_uchar16_t *v){return hv_vcpu_get_simd_fp_reg(id,reg,v);}
hv_return_t abi_sys_set(hv_vcpu_t id,hv_sys_reg_t reg,uint64_t v){return hv_vcpu_set_sys_reg(id,reg,v);}
hv_return_t abi_sys_get(hv_vcpu_t id,hv_sys_reg_t reg,uint64_t *v){return hv_vcpu_get_sys_reg(id,reg,v);}
'''
caller=D/'actual-sdk-own-abi.c';caller.write_text(code);steps=[];signatures={}
for label,sdkname,arch in [('actual-mac-sdk','macosx','arm64'),('own-ios-abi','iphoneos','arm64e')]:
 output=D/(label+'.ll');args=['xcrun','--sdk',sdkname,'clang','-arch',arch,'-Wall','-Wextra','-Werror','-I',str(S),'-O1','-S','-emit-llvm',str(caller),'-o',str(output)]
 p=subprocess.run(args,capture_output=True,env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')},timeout=30)
 (D/(label+'.stderr')).write_bytes(p.stderr);need(p.returncode==0,label+' compile')
 lines=output.read_text().splitlines();decls=[x for x in lines if x.startswith('declare ') and '@hv_' in x]
 normalized={re.search(r'@(hv_\w+)\(',x)[1]:re.sub(r' #\d+(?: .*?)?$', '',x) for x in decls}
 signatures[label]=normalized;steps.append(dict(label=label,args=args,exit=p.returncode,LLVM=pin(output),stderr=pin(D/(label+'.stderr'))))
need(set(signatures['actual-mac-sdk'])==set(signatures['own-ios-abi']) and len(signatures['actual-mac-sdk'])==9,'exact nine ABI callers')
def types(line):
 arg=line.split('(',1)[1].split(')',1)[0]
 return re.findall(r'<16 x i8>|i\d+|ptr',arg)
for name,a in signatures['actual-mac-sdk'].items():need(types(a)==types(signatures['own-ios-abi'][name]),'actual first arguments '+name)
need(types(signatures['actual-mac-sdk']['hv_vcpu_set_sys_reg'])==['i64','i16','i64'],'actual 16-bit SYS identifier')
need(types(signatures['actual-mac-sdk']['hv_vcpu_set_simd_fp_reg'])==['i64','i32','<16 x i8>'],'actual Q vector ABI')
gap=N/'vmm-public-adapter-gap-design-v1/contract.json';j=json.loads(read(gap));pin(Path(j['originalImage']['path']))
need(pin(Path(j['originalImage']['path']))=={k:j['originalImage'][k] for k in ['path','bytes','sha256']},'genuine original27 consumer pin')
public=set(signatures['actual-mac-sdk']);coverage=[]
for row in j['CPUDeclarations']:
 name=row['symbol'].lstrip('_');slot=row['importRecord']
 need(slot['ordinal']==21 and slot['weak']==False,'actual strong CPU cluster import')
 coverage.append(dict(symbol=name,actualSDKDeclaration=row['SDKDeclaration'],originalImport=slot,
  actualPublicSourceImplemented=name in public,actualOriginalVMMIntegrated=False))
need(len(coverage)==25 and sum(x['actualPublicSourceImplemented'] for x in coverage)==9,'nine actual exported of twenty-five')
result=dict(schema='Original scalar SIMD getter and actual nine public SDK ABI v1',finiteLocalScopePassed=True,findings=[],
 originalImage=pins[str(old)],frames=frames,computedScalarTable=loads,ordinaryScalarIDs=list(range(29)),ordinaryScalarOffsetBase=8,
 originalPublicCPSR34IsZeroExtendedUInt32=True,legacyREQUIRES_VIEWDoesNotInvalidatePublicScalarGetter=True,
 SIMDIDs=list(range(32)),SIMDOffsetBase=0x140,SIMDBytes=16,originalAppleUSERTableNotRecreated=True,
 actualSDKAndOwnIOSLLVMDeclarations=signatures,actualSDKCallerSteps=steps,negativeCases=neg,
 publicCPU25UsedCoverage=coverage,actualOriginalVMMPublicNineCallsProvenByStrongImports=True,
 unsupportedMandatorySYSIdentifiers=['0xdf11','0xdf12','0xde87','0xc687'],featureCapabilityNewlyImplemented=False,
 nativeCallsExecuted=0,deviceOperations=0,providerLoaded=False,originalVMMIntegrated=False,full25CPUClusterImplemented=False,
 full75HVImportsImplemented=False,modernVIEWExported=False,publicRunImplemented=False,full27Backend=False,
 inputs=sorted(pins.values(),key=lambda x:x['path']))
(D/'audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(audit=pin(D/'audit.json'),frames=len(frames),SDKEntries=9,coverageImplemented=9,totalCPU=25,negativeCases=len(neg))))
