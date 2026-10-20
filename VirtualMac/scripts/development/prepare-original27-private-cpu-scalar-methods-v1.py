#!/usr/bin/env python3
"""Port 112 genuine context calls in 111 functions to true owner scalar APIs.

Creates inert data only. Original virtual bindings, PAC and load metadata stay.
"""
from pathlib import Path
import argparse,hashlib,json,re,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def require(ok,message):
 if not ok:raise ValueError(message)
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);out=p.parse_args().out.resolve()
 require(out.parent==N.resolve() and not out.exists(),'fresh diagnostic output')
 parserPath=N/'vmm-public-adapter-gap-design-v1/audit.py';a=runpy.run_path(str(parserPath))
 helperPath=R/'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py';helper=runpy.run_path(str(helperPath))
 previousPath=N/'original27-routed-mandatory-fields-data-v2-attempt2/candidate.json';previous=json.loads(previousPath.read_bytes())
 source=Path(previous['candidate']['path']);require(pin(source)==previous['candidate'],'frozen routed SAVE55/RESTORE55 candidate')
 before=source.read_bytes();image=a['MachO'](before);oldPath=a['VM'];old=a['MachO'](oldPath.read_bytes())
 closurePath=N/'cpu-model4-original-context-boot-closure-v1/closure.json';closure=json.loads(closurePath.read_bytes())
 require(closure['actualVMMCandidate']==pin(source),'current actual 139 grouping')
 adapterPath=N/'vmm-private-cpu-scalar-source-local-v1-attempt1/candidate.json';adapter=json.loads(adapterPath.read_bytes())
 require(pin(adapter['provider']['path'])==adapter['provider'],'actual frozen scalar source provider')
 slot,bind=a['authenticated_stub'](image,image.raw(0x4129f4,16),0x4129f4)
 require(bind['importRecord']['name']=='_dlsym' and slot==0x4c6998,'actual authenticated original dlsym')
 _,crash=a['authenticated_stub'](image,image.raw(0x412644,16),0x412644)
 require(crash['importRecord']['name']=='__os_crash','genuine original failure helper crashes')
 require(image.raw(0x40fe48,0x60)==old.raw(0x40fe48,0x60),'original no-return error helper unchanged')
 methods=[]
 selectedGroups={'53ExistingPublicSYSFieldsGetterSetter','ExistingPrivateDBGCLAIMFieldAdapter'}
 for row in closure['residualCallers']:
  if row['group'] not in selectedGroups:continue
  start,end=int(row['functionBegin'],16),int(row['functionEnd'],16);call=int(row['callRVA'],16)
  require(image.bounds(call)==(start,end) and image.raw(start,end-start)==old.raw(start,end-start),'whole genuine private method')
  accesses=[x for x in row['genuineOriginalAccesses'] if x['offset'] in row['physicalFields']]
  require(len(accesses)==1 and accesses[0]['width']==8,'single original scalar physical access')
  write=accesses[0]['kind']=='write';field=int(accesses[0]['offset'],16)
  selector=0x6a0 if field==0x6a0 else int(row['existingPublicSYSSelectors'][hex(field)],16)
  words=struct.unpack('<'+'I'*((end-start)//4),image.raw(start,end-start))
  require(words[0]==0xd503237f,'genuine PACIBSP entry')
  at=(call-start)//4
  require(words[at-1]==0xf9406c00 and helper['target'](words[at],call)==0x4125b4,'true original this+d8 public identity load')
  if write:require(words[at-2]==0xaa0103f3,'true original X1 scalar value saved in X19')
  accessAt=int(accesses[0]['instructionRVA'],16)
  access=struct.unpack('<I',image.raw(accessAt,4))[0]
  base=(access>>5)&31
  if write:require(access==(0xf9000000|(field//8)<<10|base<<5|19),'original setter writes untruncated X1 via X19')
  else:require(access==(0xf9400000|(field//8)<<10|base<<5),'original getter returns uint64 in X0')
  direct=[]
  for i,w in enumerate(words):
   dest=helper['target'](w,start+4*i)
   if w&0xfc000000==0x94000000:direct.append(dest)
  require(set(direct)<={0x4125b4,0x3a59a4,0x40fe48},'no unported actual method side effect')
  methods.append(dict(startRVA=start,endRVA=end,contextCallRVA=call,selector=selector,modernPhysicalField=field,
   write=write,originalFunctionHex=image.raw(start,end-start).hex(),kind='write' if write else 'read',
   originalIdentitySource='actual incoming this+0xd8',originalSignature='void(this*,uint64_t)' if write else 'uint64_t(this*)'))
 require(len(methods)==110 and len({m['startRVA'] for m in methods})==110,'106 plus four genuine methods')
 # Both ACTLR calls are one real read-modify-write job, not two virtual getters.
 start,end=image.bounds(0x306584);require((start,end)==(0x306564,0x306604),'actual complete ACTLR job')
 require(image.raw(start,end-start)==old.raw(start,end-start),'unchanged complete ACTLR job')
 exact={0x306578:0x39402014,0x30657c:0xf9400c36,0x306580:0xf9406ec0,
  0x3065ac:0xf9420a75,0x3065b0:0xf9406ec0,0x3065dc:0xb37f0295,0x3065ec:0xf9020a75}
 require(all(struct.unpack('<I',image.raw(pc,4))[0]==w for pc,w in exact.items()),'actual nested CPU, flag and bit1 semantics')
 methods.append(dict(startRVA=start,endRVA=end,contextCallRVAs=[0x306584,0x3065b4],selector=0x410,
  modernPhysicalField=0x410,kind='actlr',originalFunctionHex=image.raw(start,end-start).hex(),
  originalIdentitySource='actual CPU at incoming argument+0x18, then CPU+0xd8',
  originalSignature='void(actualFlagJob*,actualCPUArgument*)',actualFlagSource='original job byte+8, bit0 to ACTLR bit1'))
 incoming={}
 for section in image.sections:
  if not section['flags']&0x80000400:continue
  raw=image.raw(section['va']-image.base,section['bytes'])
  for k in range(0,len(raw),4):
   pc=section['va']-image.base+k;dest=helper['target'](struct.unpack_from('<I',raw,k)[0],pc)
   if dest is not None:incoming.setdefault(dest,[]).append(pc)
 for row in methods:
  start,end=row['startRVA'],row['endRVA']
  external=[dict(source=pc,target=to) for to in range(start+4,end,4) for pc in incoming.get(to,[]) if not start<=pc<end]
  require(not external,'no genuine external direct interior entry '+hex(start))
  helper['rebase_interior_entries'].__globals__.update(BEGIN=start,END=end)
  rebase=helper['rebase_interior_entries'](image)
  row.update(noExternalDirectOrChainedInteriorEntry=True,chainedWordsWalked=rebase['words'])
 readParent=next(m for m in methods if m['kind']=='write' and m['endRVA']-m['startRVA']>=96)
 updateParent=next(m for m in methods if m['kind']=='write' and m['startRVA']!=readParent['startRVA'] and m['endRVA']-m['startRVA']>=96)
 writeParent=methods[-1]
 parents={'read':readParent,'write':writeParent,'actlr':updateParent}
 resolver={kind:parent['startRVA']+16 for kind,parent in parents.items()}
 names={'read':'VM27VMMReadCPUScalarV1','write':'VM27VMMWriteCPUScalarV1','actlr':'VM27VMMUpdateACTLRBit1V1'}
 used={m['startRVA'] for m in parents.values()};literals=[]
 for kind,name in names.items():
  parent=next(m for m in methods if m['kind']=='write' and m['startRVA'] not in used and m['endRVA']-m['startRVA']>=64)
  used.add(parent['startRVA']);at=parent['startRVA']+20;data=name.encode()+b'\0'
  require(at+len(data)<=parent['endRVA'],'literal bounded dead function tail')
  literals.append(dict(kind=kind,symbol=name,rva=at,parentStartRVA=parent['startRVA'],bytes=len(data)))
 out.mkdir(mode=0o700);commands=[]
 def run(label,args):
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,args=list(map(str,args)),returncode=r.returncode))
  require(not r.returncode,label+': '+r.stderr.decode(errors='replace'));return r.stdout
 # The compiler confirms the two distinct authentication operations: dlsym
 # already returns its function pointer; the exact original code address for
 # the failure callback is constructed as a new properly signed C pointer.
 oracle=out/'typed-tail-pac.c';oracleObj=out/'typed-tail-pac.o'
 oracle.write_text('#include "modern_vmm_private_cpu_scalar_v1.h"\n#include <dlfcn.h>\n#include <ptrauth.h>\n'
  'typedef uint64_t(*Getter)(hv_vcpu_t,uint32_t,VM27VMMScalarFailureV1);\n'
  'uint64_t typed(hv_vcpu_t cpu,uint32_t s,void *code){\n'
  ' Getter fn=(Getter)dlsym(RTLD_DEFAULT,"VM27VMMReadCPUScalarV1");\n'
  ' VM27VMMScalarFailureV1 f=(VM27VMMScalarFailureV1)ptrauth_sign_unauthenticated(code,ptrauth_key_function_pointer,0);\n'
  ' if(!fn)__builtin_trap();return fn(cpu,s,f);}\n')
 run('typed-tail-pac',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-O2','-I',R/'VirtualMac/vz/host','-c',oracle,'-o',oracleObj])
 oracleAsm=run('typed-tail-disassembly',['xcrun','llvm-objdump','--disassemble',oracleObj]).decode()
 require(re.search(r'\bbraaz\s+x\d+',oracleAsm) and
  (re.search(r'\bpaciza\s+x\d+',oracleAsm) or
   (re.search(r'\bpacia1716\b',oracleAsm) and re.search(r'\bmov\s+x16, #0x0',oracleAsm))),
  'actual tail authentication ABI oracle')
 require('autibsp' in oracleAsm and re.search(r'\bbrk\s+#0xc471',oracleAsm),'actual compiler failed-LR authentication gate')
 fragments=[]
 for row in methods:
  start=row['startRVA'];kind=row['kind']
  if kind=='actlr':code=['ldr x8, [x1, #0x18]','ldrb w1, [x0, #8]','ldr x0, [x8, #0xd8]']
  elif kind=='write':code=['mov x2, x1','ldr x0, [x0, #0xd8]',f'mov w1, #{row["selector"]}']
  else:code=['ldr x0, [x0, #0xd8]',f'mov w1, #{row["selector"]}']
  code.append(f'b . + {resolver[kind]-start-4*len(code)}')
  fragments.append(dict(kind='entry',rva=start,instructions=code,parentStartRVA=start))
 for kind,parent in parents.items():
  at=resolver[kind];literal=next(x for x in literals if x['kind']==kind)
  code=['pacibsp','stp x29, x30, [sp, #-0x40]!','mov x29, sp','stp x0, x1, [sp, #0x10]']
  if kind=='write':code.append('str x2, [sp, #0x20]')
  code.append('mov x0, #-2');code.append(f'adr x1, . + {literal["rva"]-at-4*len(code)}')
  code.append(f'bl . + {0x4129f4-at-4*len(code)}');code+=['mov x16, x0','ldp x0, x1, [sp, #0x10]']
  if kind=='write':code.append('ldr x2, [sp, #0x20]')
  code+=['ldp x29, x30, [sp], #0x40','autibsp',
   'eor x17, x30, x30, lsl #1','tbz x17, #62, . + 8','brk #0xc471']
  code.append('cbnz x16, . + 8')
  code.append(f'b . + {0x40fe48-at-4*len(code)}')
  callback='x3' if kind=='write' else 'x2'
  # The exact original helper is more than1MiB from these method bodies.
  # Encode actual page-relative ADRP, then its real low12, never an absolute
  # runtime address or a truncating out-of-range ADR/conditional branch.
  pc=at+4*len(code);pages=(0x40f000-(pc&~0xfff))//0x1000
  require(-(1<<20)<=pages<(1<<20),'bounded true helper ADRP')
  imm=pages&0x1fffff;reg=3 if kind=='write' else 2
  adrp=0x90000000|((imm&3)<<29)|((imm>>2)<<5)|reg
  code.append(f'.inst 0x{adrp:08x}')
  code.append(f'add {callback}, {callback}, #0xe48');code+=[f'paciza {callback}','braaz x16']
  require(at+len(code)*4<=parent['endRVA'],'bounded common resolver '+kind)
  fragments.append(dict(kind='resolver',operation=kind,rva=at,instructions=code,parentStartRVA=parent['startRVA'],symbolRVA=literal['rva']))
 assembly=out/'private-methods.s';text='.text\n'
 for i,f in enumerate(fragments):text+=f'.globl _vm27_scalar_{i}\n_vm27_scalar_{i}:\n'+'\n'.join(f['instructions'])+'\n'
 assembly.write_text(text);obj=out/'private-methods.o'
 run('assemble',['xcrun','clang','-target','arm64e-apple-macos27','-c',assembly,'-o',obj])
 compiled=helper['object_text'](obj.read_bytes());require(len(compiled)==sum(4*len(f['instructions']) for f in fragments),'exact compiled fragments')
 functionBytes={m['startRVA']:bytearray(struct.pack('<I',0xd503201f)*((m['endRVA']-m['startRVA'])//4)) for m in methods}
 cursor=0;cases=0
 for f in fragments:
  n=4*len(f['instructions']);code=compiled[cursor:cursor+n];cursor+=n;words=struct.unpack('<'+'I'*(n//4),code)
  parent=functionBytes[f['parentStartRVA']];offset=f['rva']-f['parentStartRVA'];parent[offset:offset+n]=code;f['compiledHex']=code.hex()
  if f['kind']=='entry':
   row=next(m for m in methods if m['startRVA']==f['rva'])
   require(words[-1]&0xfc000000==0x14000000 and helper['target'](words[-1],f['rva']+n-4)==resolver[row['kind']],'true frameless tail target')
   if row['kind']=='read':require(words[0]==0xf9406c00 and words[1]==0x52800001|(row['selector']<<5),'true reader this+d8 and selector')
   elif row['kind']=='write':require(words[:2]==(0xaa0103e2,0xf9406c00) and words[2]==0x52800001|(row['selector']<<5),'true writer X1, this+d8 and selector')
   else:require(words[:3]==(0xf9400c28,0x39402001,0xf9406d00),'actual nested job identity and byte flag')
   for cpu in (0,0x123456789abcdef0,0xffffffffffffffff):
    for value in (0,0x83,0xffffffffffffffff):
     this,job,flagJob=0x100000,0x200000,0x300000
     memory={this+0xd8:cpu,job+0x18:this,flagJob+8:value&0xff}
     regs={0:flagJob if row['kind']=='actlr' else this,1:job if row['kind']=='actlr' else value}
     for insn in words[:-1]:
      if insn==0xaa0103e2:regs[2]=regs[1]
      elif insn&0xffc00000==0xf9400000:
       rt,rn=insn&31,(insn>>5)&31;offset=((insn>>10)&0xfff)*8
       regs[rt]=memory[regs[rn]+offset]
      elif insn&0xffc00000==0x39400000:
       rt,rn=insn&31,(insn>>5)&31;offset=(insn>>10)&0xfff
       regs[rt]=memory[regs[rn]+offset]&0xff
      elif insn&0xff800000==0x52800000:regs[insn&31]=(insn>>5)&0xffff
      else:raise ValueError('Unmodeled actual entry instruction')
     expected=(cpu,value&0xff) if row['kind']=='actlr' else (cpu,row['selector'])
     require((regs[0],regs[1])==expected,'actual original CPU identity/selector/flag from decoded arguments')
     if row['kind']=='write':require(regs[2]==value,'original untruncated setter value')
     cases+=1
  else:
   require(words[0]==0xd503237f and 0xd50323ff in words and words[-1]==0xd61f0a1f,'real PACIBSP/AUTIBSP and authenticated zero-modifier tail')
   # The ABI's spill/restore preserves original X0/X1, and X2 for a setter,
   # while the callback occupies X2/X3 only after dlsym has returned.
   require(words[1]==0xa9bc7bfd and words[3]==0xa90107e0,'bounded actual resolver frame/arguments')
   callback=3 if f['operation']=='write' else 2
   require(words[-2]==(0xdac123e0|callback),'actual original failure pointer signed with IA0')
   branches=[(f['rva']+4*i,helper['target'](w,f['rva']+4*i)) for i,w in enumerate(words) if helper['target'](w,f['rva']+4*i) is not None]
   require([target for _,target in branches]==[0x4129f4,branches[1][0]+8,branches[2][0]+8,0x40fe48],'actual dlsym/LR-failure/missing-provider error targets')
   adr=words[-4];imm=(((adr>>5)&0x7ffff)<<2)|((adr>>29)&3)
   if imm&(1<<20):imm-=1<<21
   address=((f['rva']+n-16)&~0xfff)+(imm<<12)+0xe48
   require(adr&0x9f00001f==0x90000000|callback and address==0x40fe48,'actual page-relative original helper callback')
 for literal in literals:
  parent=functionBytes[literal['parentStartRVA']];offset=literal['rva']-literal['parentStartRVA'];parent[offset:offset+literal['bytes']]=literal['symbol'].encode()+b'\0'
 after=bytearray(before);allowed=set()
 for row in methods:
  start=row['startRVA'];data=functionBytes[start];segment=next(s for s in image.segments if s['va']<=image.base+start and image.base+start+len(data)<=s['va']+s['bytes'])
  fileAt=segment['offset']+image.base+start-segment['va'];require(not allowed.intersection(range(fileAt,fileAt+len(data))),'disjoint actual functions')
  allowed.update(range(fileAt,fileAt+len(data)));after[fileAt:fileAt+len(data)]=data;row['compiledFunctionHex']=data.hex()
 require(all(x==y or k in allowed for k,(x,y) in enumerate(zip(before,after))),'only reviewed actual method bodies change')
 revised=a['MachO'](after)
 require(revised.imports==image.imports and revised.binds==image.binds and revised.libs==image.libs and revised.starts==image.starts and revised.sections==image.sections and revised.segments==image.segments,'original strong bindings/PAC/function metadata preserved')
 require(revised.raw(0x2875a8,0x28cc24-0x2875a8)==image.raw(0x2875a8,0x28cc24-0x2875a8),'all frozen SAVE55/RESTORE55/gates intact')
 currentCalls=[]
 for section in revised.sections:
  if section['name']!='__text':continue
  for k in range(0,section['bytes'],4):
   pc=section['va']-revised.base+k;w=struct.unpack_from('<I',after,section['offset']+k)[0]
   if w&0xfc000000==0x94000000 and helper['target'](w,pc)==0x4125b4:currentCalls.append(pc)
 require(len(currentCalls)==35,'147 minus 112 actual context calls')
 target=out/'VMM27.routed-save55-restore55-scalar112.inert.macho-data';target.write_bytes(after);target.chmod(0o600)
 run('compiled-disassembly',['xcrun','llvm-objdump','--disassemble',obj]);run('validate',['xcrun','dyld_info','-validate_only',target])
 report=dict(schema='genuine original VMM112 scalar owner calls in111 methods inert source ports v1',
  source=pin(Path(__file__)),previousCandidate=pin(previousPath),sourceImage=pin(source),candidate=pin(target),
  trueScalarSourceAdapter=pin(adapterPath),trueScalarSourceProvider=adapter['provider'],actualRoot11Provider=adapter['actualOwnerProvider'],
  actualDlsymBind=bind,methods=methods,resolvers=[f for f in fragments if f['kind']=='resolver'],literals=literals,
  actualMethodArgumentCases=cases,portedActualContextCalls=112,portedActualFunctions=111,
  remainingActualContextCalls=35,remainingActualContextCallRVAs=list(map(hex,currentCalls)),
  remainingModel4FrameCalls8SkippedByFrozenOriginalGates=True,other27ActualGuestBootPathsStillUnclosed=True,
  originalActualIdentityFromThisD8=True,noGetContextProjection=True,
  originalAuthenticatedVirtualBindingsAndPACWordsUnchanged=True,originalStrongImportsUnchanged=True,
  originalUnwindMetadataBytesPreserved=True,newFramelessMethodTailRouting=True,
  resolverRestoresSPAndAuthenticatesOriginalLRBeforeSourceTail=True,
  newFailurePointerIsSignedExactOriginal40fe48=True,actualDlsymFunctionPointerNeverResigned=True,
  sourceErrorInvokesOriginalNoReturnCrashHelper=True,asyncOriginalMetadataUnwindExecutionProven=False,
  genericIndirectInteriorEntrypointAbsenceExhaustivelyProven=False,
  newSourceProviderPreloadedRTLDGlobalOnDevice=False,sourceProviderSigned=False,
  signed=False,loaded=False,nativeCallsExecuted=0,deviceOperations=0,originalVMMExecuted=False,fullIndependent27GuestBoot=False,commands=commands)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 paths=[Path(__file__),parserPath,helperPath,previousPath,source,oldPath,closurePath,adapterPath,Path(adapter['provider']['path'])]+[p for p in out.iterdir() if p.is_file()]
 (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in paths],nativeCallsExecuted=0,deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),remainingGetContextCalls=35,actualMethodFunctions=111)))
if __name__=='__main__':main()
