#!/usr/bin/env python3
"""Four genuine DTR methods, finite code-only merge recipe, no device/sign."""
from pathlib import Path
import argparse,hashlib,json,re,runpy,struct,subprocess,sys,importlib.util
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,m):
 if not v:raise ValueError(m)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve();need(out.parent==N and not out.exists(),'fresh host output')
 stagePath=N/'independent27-flat-graph-stage-v1-attempt3/candidate.json';need(pin(stagePath)['sha256']=='97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206','exact stage71 candidate');stage=json.loads(stagePath.read_text())
 row=next(x for x in stage['stagedImages']if x['key']=='com.apple.Virtualization.VirtualMachine');source=Path(row['staged']['path']);need(pin(source)==row['staged'],'actual staged VMM source pin')
 cp=N/'cpu-dtr-factory-local-v21-attempt2/candidate.json';j=json.loads(cp.read_text());fp=cp.parent/'freeze.json'
 for q in json.loads(fp.read_text())['files']:need(pin(q['path'])==q,'frozen DTR source '+q['path'])
 need(j['models']['normal']['checks']==689 and j['models']['san']['checks']==689,'actual bounded normal/SAN')
 parserPath=N/'vmm-public-adapter-gap-design-v1/audit.py';a=runpy.run_path(str(parserPath));helperPath=R/'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py';h=runpy.run_path(str(helperPath));m=a['MachO'](source.read_bytes());oldPath=a['VM'];old=a['MachO'](oldPath.read_bytes());need(m.uuid=='4a6a588d1afd30f5a64d6304eb79be0b','genuine main UUID')
 methods=[dict(start=0x2964a0,end=0x296528,kind='read',selector=0x9820,semantics='RX low32 OR TX full64 shifted32',contextCalls=[0x2964b8,0x2964e8]),dict(start=0x296528,end=0x2965d8,kind='write',selector=0x9820,semantics='TX=uint32(value), second real owned/version boundary, TX=value>>32',contextCalls=[0x296548,0x296588]),dict(start=0x2965d8,end=0x296628,kind='read',selector=0x9828,semantics='RX full64',contextCalls=[0x2965ec]),dict(start=0x296628,end=0x296688,kind='write',selector=0x9828,semantics='TX full64=value',contextCalls=[0x296640])]
 for q in methods:
  need(m.bounds(q['start'])==(q['start'],q['end']) and m.raw(q['start'],q['end']-q['start'])==old.raw(q['start'],q['end']-q['start']),'genuine bounded original method');q['originalHex']=m.raw(q['start'],q['end']-q['start']).hex()
  for pc in q['contextCalls']:need(h['target'](struct.unpack('<I',m.raw(pc,4))[0],pc)==0x4125b4,'actual native modern view call')
 exact={0x2964e0:0xb9469214,0x296510:0xf9434e68,0x296514:0xaa088280,0x296570:0x2a1303e8,0x296580:0xf9034e88,0x2965b0:0xd360fe68,0x2965c0:0xf9034e88,0x296614:0xf9434800,0x296674:0xf9034e93}
 # Actual encodings are independently decoded below; retain exact captured
 # words as evidence rather than relying on mnemonic guesses/field aliases.
 captures={hex(pc):hex(struct.unpack('<I',m.raw(pc,4))[0])for pc in exact}
 for pc in [0x296580,0x2965c0,0x296674]:
  word=struct.unpack('<I',m.raw(pc,4))[0];need(word&0xffc00000==0xf9000000 and ((word>>10)&0xfff)*8==0x698,'true three TX stores')
 word=struct.unpack('<I',m.raw(0x2964e0,4))[0];need(word&0xffc00000==0xb9400000 and ((word>>10)&0xfff)*4==0x690,'true first low32 RX read')
 word=struct.unpack('<I',m.raw(0x296614,4))[0];need(word&0xffc00000==0xf9400000 and ((word>>10)&0xfff)*8==0x690,'true full RX read')
 need(struct.unpack('<I',m.raw(0x296570,4))[0]==0x2a1303e8 and struct.unpack('<I',m.raw(0x2965b0,4))[0]==0xd360fe68,'actual low32/high32 source')
 slot,bind=a['authenticated_stub'](m,m.raw(0x4129f4,16),0x4129f4);need(slot==0x4c6998 and bind['importRecord']==m.imports[326] and bind['importRecord']['name']=='_dlsym' and bind['importRecord']['ordinal']==15 and not bind['importRecord']['weak'],'actual current authenticated dlsym import')
 need(m.libs[20]=='@loader_path/VM27HVVMProduction.dylib','actual strong same-registry provider load21');need(m.raw(0x40fe48,0x60)==old.raw(0x40fe48,0x60),'same real error helper')
 incoming={}
 for s in m.sections:
  if not s['flags']&0x80000400:continue
  data=m.raw(s['va']-m.base,s['bytes'])
  for k in range(0,len(data),4):
   pc=s['va']-m.base+k;to=h['target'](struct.unpack_from('<I',data,k)[0],pc)
   if to is not None:incoming.setdefault(to,[]).append(pc)
 for q in methods:
  q['externalDirectInteriorEntries']=[dict(source=pc,target=to)for to in range(q['start']+4,q['end'],4)for pc in incoming.get(to,[])if not q['start']<=pc<q['end']];need(not q['externalDirectInteriorEntries'],'no real external interior jump')
  h['rebase_interior_entries'].__globals__.update(BEGIN=q['start'],END=q['end']);q['actualChainedInteriorAudit']=h['rebase_interior_entries'](m);need(not q['actualChainedInteriorAudit']['interior'],'no chained interior pointer')
 resolver={'read':0x2964ac,'write':0x296538};literal={'read':0x29650c,'write':0x2965a0};names={'read':'VM27VMMReadDTRV1','write':'VM27VMMWriteDTRV1'};fragments=[]
 for q in methods:
  code=['mov x2, x1','ldr x0, [x0, #0xd8]',f'mov w1, #{q["selector"]}']if q['kind']=='write'else['ldr x0, [x0, #0xd8]',f'mov w1, #{q["selector"]}'];code.append(f'b . + {resolver[q["kind"]]-q["start"]-4*len(code)}');fragments.append(dict(kind='entry',rva=q['start'],parent=q['start'],instructions=code))
 for kind in ['read','write']:
  at=resolver[kind];parent=methods[0]if kind=='read'else methods[1];code=['pacibsp','stp x29, x30, [sp, #-0x40]!','mov x29, sp','stp x0, x1, [sp, #0x10]']
  if kind=='write':code+=['str x2, [sp, #0x20]']
  code+=['mov x0, #-2'];code.append(f'adr x1, . + {literal[kind]-at-4*len(code)}');code.append(f'bl . + {0x4129f4-at-4*len(code)}');code+=['mov x16, x0','ldp x0, x1, [sp, #0x10]']
  if kind=='write':code+=['ldr x2, [sp, #0x20]']
  code+=['ldp x29, x30, [sp], #0x40','autibsp','eor x17, x30, x30, lsl #1','tbz x17, #62, . + 8','brk #0xc471','cbnz x16, . + 8'];code.append(f'b . + {0x40fe48-at-4*len(code)}');reg=3 if kind=='write' else 2;pc=at+4*len(code);pages=(0x40f000-(pc&~0xfff))//0x1000;imm=pages&0x1fffff
  code+=[f'.inst {0x90000000|((imm&3)<<29)|((imm>>2)<<5)|reg:#x}',f'add x{reg}, x{reg}, #0xe48',f'paciza x{reg}','braaz x16'];need(at+4*len(code)<=literal[kind] and literal[kind]+len(names[kind])+1<=parent['end'],'bounded actual common resolver and literal')
  fragments.append(dict(kind='resolver',operation=kind,rva=at,parent=parent['start'],instructions=code))
 out.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  p=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=list(map(str,argv)),returncode=p.returncode));need(not p.returncode,label+': '+p.stderr.decode());return p.stdout
 typed=out/'typed-pac.c';typed.write_text('#include "modern_vmm_dtr_v1.h"\n#include <dlfcn.h>\n#include <ptrauth.h>\nuint64_t typed(hv_vcpu_t id,void *code){typedef uint64_t(*Fn)(hv_vcpu_t,uint32_t,VM27VMMScalarFailureV1);Fn f=(Fn)dlsym(RTLD_DEFAULT,"VM27VMMReadDTRV1");VM27VMMScalarFailureV1 fail=(VM27VMMScalarFailureV1)ptrauth_sign_unauthenticated(code,ptrauth_key_function_pointer,0);if(!f)__builtin_trap();return f(id,0x9820,fail);}\n')
 run('typed-pac',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-O2','-I',S,'-c',typed,'-o',out/'typed-pac.o']);dis=run('typed-pac-disassembly',['xcrun','llvm-objdump','--disassemble',out/'typed-pac.o']).decode();need('braaz' in dis and 'autibsp' in dis and '#0xc471' in dis and ('paciza' in dis or 'pacia1716' in dis),'actual compiler C function pointer/LR authentication oracle')
 asm=out/'dtr.s';asm.write_text('.text\n'+''.join(f'.globl _vm27_dtr_{i}\n_vm27_dtr_{i}:\n'+'\n'.join(f['instructions'])+'\n'for i,f in enumerate(fragments)));obj=out/'dtr.o';run('assemble',['xcrun','clang','-target','arm64e-apple-ios16.1','-c',asm,'-o',obj]);compiled=h['object_text'](obj.read_bytes());need(len(compiled)==sum(4*len(f['instructions'])for f in fragments),'exact real assembled fragments')
 body={q['start']:bytearray(struct.pack('<I',0xd503201f)*((q['end']-q['start'])//4))for q in methods};cursor=0;cases=[]
 for f in fragments:
  n=4*len(f['instructions']);data=compiled[cursor:cursor+n];cursor+=n;body[f['parent']][f['rva']-f['parent']:f['rva']-f['parent']+n]=data;f['compiledHex']=data.hex();words=struct.unpack('<'+'I'*(n//4),data)
  if f['kind']=='entry':
   q=next(q for q in methods if q['start']==f['rva']);need(h['target'](words[-1],f['rva']+n-4)==resolver[q['kind']],'true shared resolver target')
   for identity in [0,0x123456789abcdef0,0xffffffffffffffff]:
    for value in [0,0x87654321deadbeef,0xffffffffffffffff]:
     regs={0:0x100000,1:value};memory={0x1000d8:identity}
     for word in words[:-1]:
      if word==0xaa0103e2:regs[2]=regs[1]
      elif word==0xf9406c00:regs[0]=memory[regs[0]+0xd8]
      elif word&0xff80001f==0x52800001:regs[1]=(word>>5)&0xffff
      else:raise ValueError('unknown actual entry opcode')
     need((regs[0],regs[1])==(identity,q['selector']) and (q['kind']=='read' or regs[2]==value),'true this+d8 and full64 setter args');cases.append(dict(method=q['start'],identity=identity,value=value,selector=regs[1]))
  else:
   reg=3 if f['operation']=='write' else 2;need(words[0]==0xd503237f and words[1]==0xa9bc7bfd and words[3]==0xa90107e0 and 0xd50323ff in words and words[-2]==0xdac123e0|reg and words[-1]==0xd61f0a1f,'actual PAC and spill/restore/source tail')
   branches=[(f['rva']+4*i,h['target'](word,f['rva']+4*i))for i,word in enumerate(words)if h['target'](word,f['rva']+4*i)is not None];need([to for _,to in branches]==[0x4129f4,branches[1][0]+8,branches[2][0]+8,0x40fe48],'real resolver/missing provider/LR failure branch targets')
   word=words[-4];imm=(((word>>5)&0x7ffff)<<2)|((word>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm;need(((f['rva']+n-16)&~0xfff)+(imm<<12)+0xe48==0x40fe48,'exact helper signed callback')
 for kind in ['read','write']:
  parent=methods[0]if kind=='read'else methods[1];data=names[kind].encode()+b'\0';offset=literal[kind]-parent['start'];body[parent['start']][offset:offset+len(data)]=data
 changed=bytearray(m.b);allowed=set();patches=[]
 for q in methods:
  start=q['start'];data=bytes(body[start]);seg=next(s for s in m.segments if s['va']<=m.base+start and m.base+q['end']<=s['va']+s['bytes']);fo=seg['offset']+m.base+start-seg['va'];need(not allowed.intersection(range(fo,fo+len(data))),'disjoint four method ranges');allowed.update(range(fo,fo+len(data)));changed[fo:fo+len(data)]=data;q['afterHex']=data.hex();patches.append(dict(startRVA=start,endRVA=q['end'],originalFileOffset=fo,beforeHex=q['originalHex'],afterHex=q['afterHex'],functionSignature='void(this*,uint64_t)'if q['kind']=='write'else'uint64_t(this*)',semanticSelector=q['selector']))
 need(all(x==y or i in allowed for i,(x,y)in enumerate(zip(m.b,changed))),'only four code bodies');after=a['MachO'](changed);need(after.imports==m.imports and after.binds==m.binds and after.libs==m.libs and after.starts==m.starts and after.uuid==m.uuid and after.sections==m.sections and after.segments==m.segments,'all stage header/fixup/PAC metadata retained')
 windows=[]
 for begin,end,label in [(0x3a7278,0x3a7b08,'genuine four SYS9820/9828 EL/HCR/MDCR/flags gates'),(0xb24e8,0xb2530,'actual CPU construction of emulator flags'),(0x3b6478,0x3b6534,'actual emulator constructor stores'),(0x2e9d30,0x2e9d60,'original child setup call and LR admission')]:
  need(after.raw(begin,end-begin)==m.raw(begin,end-begin)==old.raw(begin,end-begin),'actual original gates/constructor/childentry unchanged');path=out/(label.split()[0]+'-'+hex(begin)+'.bin');path.write_bytes(m.raw(begin,end-begin));windows.append(dict(label=label,beginRVA=begin,endRVA=end,bytesPin=pin(path)))
 text=next(s for s in after.sections if s['name']=='__text');calls=[]
 for k in range(0,text['bytes'],4):
  pc=text['va']-after.base+k;word=struct.unpack_from('<I',changed,text['offset']+k)[0]
  if word&0xfc000000==0x94000000 and h['target'](word,pc)==0x4125b4:calls.append(pc)
 need(len(calls)==28,'34 minus true six DTR modern context calls')
 target=out/'VMM27.dtr4.inert.macho-data';target.write_bytes(changed);run('assembled-disassembly',['xcrun','llvm-objdump','--disassemble',obj]);run('validate',['xcrun','dyld_info','-validate_only',target])
 nativeParser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';spec=importlib.util.spec_from_file_location('dtrexports',nativeParser);lib=importlib.util.module_from_spec(spec);spec.loader.exec_module(lib);provider=lib.MachO(Path(j['provider']['path']).read_bytes());symbols={name:provider.exports['_'+name]for name in names.values()}
 recipe=dict(schema='Finite genuine DTR method merge recipe v1',sourceVMM=pin(source),sourceStageCandidate=pin(stagePath),mainUUID=m.uuid,codePatches=patches,selectedExistingImport=dict(index=326,name='_dlsym',ordinal=15,library=m.libs[14],authenticatedStubRVA=0x4129f4,slotRVA=slot,bind=bind),importChanges=[],newDynamicallyResolvedSymbols=symbols,replacementProvider=j['provider'],replacementExistingStrongLoad=dict(ordinal=21,path=m.libs[20],required=True),newRequiredLoads=[],providerMustBeVisibleToRTLDDefault=True,applyAfterAnyHeaderEditsByRealSectionRVATranslation=True,preserveUUIDFunctionStartsUnwindPACChainedFixups=True,platformVersionPortOwnedByRoot=True)
 (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2)+'\n');record=dict(schema='Genuine four DTR VMM methods inert own bank source port v1',builder=pin(__file__),sourceImage=pin(source),candidate=pin(target),inheritedStage=pin(stagePath),DTRSourceCandidate=pin(cp),DTRSourceFreeze=pin(fp),actualProvider=j['provider'],actualNewExports=symbols,methods=methods,originalPhysicalInstructionWords=captures,resolvers=fragments,literalRVAs=literal,actualArgumentCases=cases,originalGatesAndConstructors=windows,patchRecipe=pin(out/'patch-recipe.json'),removedActualContextCalls=6,remainingActualContextCalls=28,remainingActualContextCallRVAs=list(map(hex,calls)),importsChainedBindingsHeaderUUIDUnchanged=True,combinedSetterActualTwoTXStoresPreserved=True,ownSoftwareDTRResetZeroPolicy=True,hardwareDebuggerRXProducerImplemented=False,sourceProviderPreloadedOnDevice=False,asynchronousOriginalUnwindExecutionProven=False,genericIndirectInteriorEntrypointAbsenceExhaustivelyProven=False,deviceOperations=0,nativeOperations=0,codeSigned=False,originalVMMExecuted=False,fullIndependent27GuestBoot=False)
 (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');(out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n');paths={Path(__file__).resolve(),source,stagePath,cp,fp,parserPath,helperPath,oldPath,nativeParser,Path(j['provider']['path'])}|set(out.iterdir());(out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in sorted(paths)if p.is_file()],deviceOperations=0,nativeOperations=0),indent=2)+'\n');print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),patchRecipe=pin(out/'patch-recipe.json'),remainingGetContextCalls=28)))
if __name__=='__main__':main()
