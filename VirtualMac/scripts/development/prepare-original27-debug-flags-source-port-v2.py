#!/usr/bin/env python3
"""Port only the genuine conditional physical debug word write, inert data."""
import argparse,hashlib,json,pathlib,re,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);args=ap.parse_args()
 o=args.output.resolve();assert o.parent==N.resolve() and not o.exists()
 previous=N/'original27-private-cpu-scalar-methods-data-v1-attempt3/candidate.json';j=json.loads(previous.read_bytes())
 freeze=previous.parent/'freeze.json';f=json.loads(freeze.read_bytes())
 for row in f['files']:assert pin(row['path'])==row,row['path']
 parser=N/'vmm-public-adapter-gap-design-v1/audit.py';a=runpy.run_path(str(parser))
 helperPath=R/'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py';h=runpy.run_path(str(helperPath))
 imagePath=pathlib.Path(j['candidate']['path']);assert pin(imagePath)==j['candidate'];image=a['MachO'](imagePath.read_bytes());before=image.b
 old=a['MachO'](a['VM'].read_bytes());start,end=image.bounds(0x28ceec);assert(start,end)==(0x28ce38,0x28cf08)
 assert image.raw(start,end-start)==old.raw(start,end-start)
 words={0x28ce4c:0x39412008,0x28ce50:0xf9406c00,0x28ce54:0x36000188,
  0x28cee4:0xaa080134,0x28cee8:0xf9406e60,0x28ceec:0x940615b2,0x28cef0:0xf901a814,
  0x28cef4:0xa9417bfd,0x28cef8:0xa8c24ff4,0x28cefc:0xd65f0fff,0x28cf00:0x94060bd2,0x28cf04:0xd4200020}
 assert all(struct.unpack('<I',image.raw(at,4))[0]==word for at,word in words.items())
 slot,bind=a['authenticated_stub'](image,image.raw(0x412e64,16),0x412e64)
 assert bind['importRecord']['name']=='_hv_vcpu_set_sys_reg' and bind['importRecord']['ordinal']==21 and not bind['importRecord']['weak']
 assert image.raw(0x40fe48,0x60)==old.raw(0x40fe48,0x60)
 # Reuse a real already-ported reader's unreachable NOP tail. Its actual
 # method entry unconditionally jumps away before the tail, not a guessed
 # image padding allocation. The previous full chain audit covers this range.
 nop=struct.pack('<I',0xd503201f);parent=None
 for row in j['methods']:
  if row['kind']!='read':continue
  at=row['startRVA']+12
  if at+20<=row['endRVA'] and image.raw(at,20)==nop*5:parent=row;cave=at;break
 assert parent is not None
 assert h['target'](struct.unpack('<I',image.raw(parent['startRVA']+8,4))[0],parent['startRVA']+8)==next(x['rva']for x in j['resolvers']if x['operation']=='read')
 incoming=[]
 for s in image.sections:
  if not s['flags']&0x80000400:continue
  data=image.raw(s['va']-image.base,s['bytes'])
  for k in range(0,len(data),4):
   pc=s['va']-image.base+k;target=h['target'](struct.unpack_from('<I',data,k)[0],pc)
   if target is not None and cave<=target<cave+20:incoming.append(dict(sourceRVA=pc,targetRVA=target))
 assert not incoming
 h['rebase_interior_entries'].__globals__.update(BEGIN=cave-1,END=cave+20)
 chain=h['rebase_interior_entries'](image);assert chain['words']==17234 and not chain['interior']
 o.mkdir();cmds=[]
 def run(label,argv):
  argv=list(map(str,argv));cp=subprocess.run(argv,capture_output=True,timeout=45)
  (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
  cmds.append(dict(label=label,argv=argv,exit=cp.returncode));assert not cp.returncode,(label,cp.stderr.decode());return cp
 instructions=['mov x2, x20','mov w1, #0x8012',f'bl . + {0x412e64-(cave+8)}',
  f'cbnz w0, . + {0x28cf00-(cave+12)}',f'b . + {0x28cef4-(cave+16)}']
 asm=o/'debug-word.s';asm.write_text('.text\n.globl _vm27_debug_word\n_vm27_debug_word:\n'+'\n'.join(instructions)+'\n')
 obj=o/'debug-word.o';run('assemble',['xcrun','clang','-target','arm64e-apple-ios16.1','-c',asm,'-o',obj])
 code=h['object_text'](obj.read_bytes());assert len(code)==20
 compiled=struct.unpack('<5I',code);assert compiled[:2]==(0xaa1403e2,0x52900241)
 assert h['target'](compiled[2],cave+8)==0x412e64 and h['target'](compiled[3],cave+12)==0x28cf00 and h['target'](compiled[4],cave+16)==0x28cef4
 branch=0x14000000|(((cave-0x28ceec)//4)&0x3ffffff);assert h['target'](branch,0x28ceec)==cave
 changed=bytearray(before)
 for at,data in [(0x28ceec,struct.pack('<I',branch)+nop),(cave,code)]:
  # The parser's exact section translation retains the original on-disk
  # address. These are instruction words only, never chained/PAC pointers.
  fo=next(s['offset']+at-(s['va']-image.base)for s in image.sections if s['va']-image.base<=at and at+len(data)<=s['va']-image.base+s['bytes'])
  changed[fo:fo+len(data)]=data
 candidatePath=o/'VMM27.routed-save55-restore55-scalar112-debug1.inert.macho-data';candidatePath.write_bytes(changed)
 after=a['MachO'](candidatePath.read_bytes());assert after.imports==image.imports and after.binds==image.binds and after.libs==image.libs and after.starts==image.starts
 allowed=set()
 for at,n in[(0x28ceec,8),(cave,20)]:
  fo=next(s['offset']+at-(s['va']-image.base)for s in image.sections if s['va']-image.base<=at< s['va']-image.base+s['bytes']);allowed.update(range(fo,fo+n))
 assert all(i in allowed for i,(a0,b0)in enumerate(zip(before,changed))if a0!=b0)
 actual=[]
 text=next(s for s in after.sections if s['name']=='__text');textBegin=text['va']-after.base;buf=after.raw(textBegin,text['bytes'])
 for i in range(0,len(buf),4):
  pc=textBegin+i
  if a['branch'](struct.unpack_from('<I',buf,i)[0],pc)==0x4125b4:actual.append(hex(pc))
 assert len(actual)==34 and '0x28ceec' not in actual
 oldRoute=S/'modern_cpu_kernel_system_fields.inc';assert '{0x8012, VZ_KERNEL_SYS_PHYSICAL, 0x350, 8, UINT64_C(0x0000000000000000), 0}' in oldRoute.read_text()
 sdk=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/System/Library/Frameworks/Hypervisor.framework/Headers/hv_vcpu_types.h')
 assert 'HV_SYS_REG_MDSCR_EL1 = 0x8012' in sdk.read_text()
 cases=[]
 for cpu in[0,0x123456789abcdef0,0xffffffffffffffff]:
  for value in[0,1,0x8001,0xffffffffffffffff]:
   for status in[0,1,0xfae94003,0xffffffff]:
    regs={0:cpu,20:value};regs[compiled[0]&31]=regs[(compiled[0]>>16)&31]
    regs[compiled[1]&31]=(compiled[1]>>5)&0xffff
    assert(regs[0],regs[1],regs[2])==(cpu,0x8012,value)
    actualDestination=h['target'](compiled[3],cave+12) if status&0xffffffff else h['target'](compiled[4],cave+16)
    assert actualDestination==(0x28cf00 if status else 0x28cef4)
    cases.append(dict(actualPublicID=cpu,physicalDebugWord=value,publicSYSSelector=regs[1],
     publicReturn32=status,resumeRVA=actualDestination))
 for label,m,begin,stop in [('original-debug',image,start,end),('ported-debug',after,start,end),('actual-veneer',after,cave,cave+20)]:
  path=imagePath if m is image else candidatePath
  cp=run(label,['xcrun','llvm-objdump','--disassemble','--start-address='+hex(m.base+begin),'--stop-address='+hex(m.base+stop),path])
  lines=[]
  for line in cp.stdout.decode().splitlines():
   match=re.match(r'^([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$',line)
   if match:
    va=int(match[1],16);assert begin<=va-m.base<stop and struct.unpack('<I',m.raw(va-m.base,4))[0]==int(match[2],16);lines.append(line)
  assert len(lines)==(stop-begin)//4
 record=dict(schema='Genuine conditional VMM physical debug-word caller port v2',builder=pin(pathlib.Path(__file__)),
  previousCandidate=pin(previous),inheritedFreeze=pin(freeze),sourceImage=pin(imagePath),candidate=pin(candidatePath),
  actualOriginalDebugFunction=[start,end],unchangedCPUIdentitySource='actual CPU+d8, loaded at28cee8',
  unchangedFlagsAndPublicTrapCallSequence=True,conditionStillActualCPUByte48Bit0=True,actualPhysicalDebugSYSSelector=0x8012,
  actualOldNativePhysicalField=0x350,actualOldNativeDirtyMask=0,realOriginalPublicStub=dict(rva=0x412e64,slot=slot,bind=bind),
  originalReturnAndNoReturnFailureTargetsPreserved=True,unreachableOriginalReaderTailParent=parent,veneerRVA=cave,
  originalNoIncomingToReusedTail=incoming,originalChainedInteriorInspection=chain,compiledVeneerHex=code.hex(),
  genuinePublicArgumentCases=cases,remainingActualGetContextCalls=34,remainingActualGetContextCallRVAs=actual,
  frameModel4GateStillUnchanged=True,newSourceProviderExportRequired=False,importsAndPACAndFunctionStartsUnchanged=True,
  asynchronousOriginalUnwindExecutionProven=False,originalVMMExecuted=False,deviceOperations=0,codeSigned=False,fullIndependent27GuestBoot=False)
 (o/'commands.json').write_text(json.dumps(cmds,indent=2)+'\n');(o/'candidate.json').write_text(json.dumps(record,indent=2)+'\n')
 pins=[pathlib.Path(__file__),parser,helperPath,previous,freeze,imagePath,oldRoute,sdk]+list(o.iterdir())
 (o/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in pins if p.is_file()],deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),vmm=pin(candidatePath),remainingGetContextCalls=34)))
if __name__=='__main__':main()
