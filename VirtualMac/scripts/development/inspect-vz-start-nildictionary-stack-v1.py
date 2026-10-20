#!/usr/bin/env python3
"""HOST readonly actual VZ exception stack/function/ObjC metadata windows."""
import hashlib,importlib.util,json,pathlib,struct,sys,bisect
import capstone
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 cp=N/'independent27-signed-runtime-uikit-filter-product-v10-attempt1/candidate.json';c=json.loads(cp.read_bytes());path=pathlib.Path(c['runtimeRoot'])/'parent-flat/VZ27.dylib';reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';sp=importlib.util.spec_from_file_location('vz_stack_actual_macho',reader);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);raw=path.read_bytes();q=m.MachO(raw);assert q.uuid=='418efc4809d93606918eb6f95baeffdc'
 def ptr(va):
  word=struct.unpack_from('<Q',raw,q.file(va))[0]
  if not word:return 0
  if word>>62&1:return dict(importIndex=word&0xffffff,importName=q.imports[word&0xffffff]['name'])
  return q.base+((word&0xffffffff)if word>>63 else word&((1<<43)-1))
 def string(va):
  a=q.file(va);z=raw.index(0,a,a+8192);return raw[a:z].decode()
 methods=[];errors=[];seen=set()
 def methodlist(ml,name,meta):
  if not ml or isinstance(ml,dict)or ml in seen:return
  seen.add(ml);a=q.file(ml);flags,count=struct.unpack_from('<II',raw,a);stride=flags&0xfffc;assert count<4096
  for i in range(count):
   entry=ml+8+i*stride;e=q.file(entry)
   try:
    if flags>>31:
     assert stride==12
     n,t,imp=struct.unpack_from('<iii',raw,e);np=entry+n if flags&0x40000000 else ptr(entry+n);tp=entry+4+t;target=entry+8+imp
     sel=string(np);typ=string(tp)
    else:
     assert stride==24;sel=string(ptr(entry));typ=string(ptr(entry+8));target=ptr(entry+16)
    methods.append(dict(className=name,classMethod=meta,selector=sel,typeEncoding=typ,IMP=target-q.base,methodEntryRVA=entry-q.base))
   except (ValueError,AssertionError,UnicodeDecodeError,TypeError)as error:errors.append(dict(className=name,entry=hex(entry),flags=hex(flags),error=str(error)))
 def lists(p,name,meta):
  if not p:return
  if p&1:
   p&=~7;stride,count=struct.unpack_from('<II',raw,q.file(p));assert count<512
   for i in range(count):
    e=p+8+i*8;delta=struct.unpack_from('<q',raw,q.file(e))[0];methodlist(e+(delta>>16),name,meta)
  else:methodlist(p&~7,name,meta)
 sec=next(x for x in q.sections if x['name']=='__objc_classlist')
 for va in range(sec['va'],sec['va']+sec['size'],8):
  cls=ptr(va);ro=ptr(cls+32)&~7;name=string(ptr(ro+24));lists(ptr(ro+32),name,False);met=ptr(cls);mro=ptr(met+32)&~7;lists(ptr(mro+32),name,True)
 starts=[];at=32
 for i in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,size=struct.unpack_from('<II',raw,at)
  if cmd==0x26:
   off,n=struct.unpack_from('<II',raw,at+8);encoded=raw[off:off+n];cursor=0;addr=0
   while cursor<len(encoded):
    delta=0;shift=0
    while True:
     byte=encoded[cursor];cursor+=1;delta|=(byte&127)<<shift
     if not byte&128:break
     shift+=7
    if not delta:break
    addr+=delta;starts.append(addr)
  at+=size
 assert starts==sorted(set(starts))
 classrva=q.exports['_OBJC_CLASS_$_VZVirtualMachine']['address'];actualBase=0x106d25708-classrva
 pcs=[0x106c3c560,0x106b47b24,0x106aefc80];out=N/'actual-normal11-vz-start-dictionary-stack-host-v1-attempt1';out.mkdir(mode=0o700);md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);md.skipdata=True;rows=[]
 for pc in pcs:
  rva=pc-actualBase;ix=bisect.bisect_right(starts,rva)-1;lo=starts[ix];hi=starts[ix+1];assert 0<hi-lo<=32768;code=raw[q.file(q.base+lo):q.file(q.base+lo)+hi-lo];lines=[f'{x.address-q.base:08x} {x.bytes.hex()} {x.mnemonic} {x.op_str}'for x in md.disasm(code,q.base+lo)];p=out/(hex(rva)+'.asm');p.write_text('\n'.join(lines)+'\n');print(hex(rva),hex(lo),hex(hi),[x for x in methods if x['IMP']==lo]);rows.append(dict(actualPC=hex(pc),RVA=hex(rva),functionStart=hex(lo),functionEnd=hex(hi),actualMethods=[x for x in methods if x['IMP']==lo],disassembly=pin(p),actualFunctionBytes=code.hex()))
 report=dict(schema='Actual Normal11 VZ nil NSDictionary stack readonly HOST symbolication',actualStartStdout=pin(N/'independent27-app15-normal-guest-lifecycle-v11-attempt1/device-receipts/start/stdout'),runtimeCandidate=pin(cp),actualParentVZ=pin(path),actualUUID=q.uuid,actualVZClassAddress=hex(0x106d25708),actualClassExportRVA=hex(classrva),derivedActualImageBase=hex(actualBase),stack=rows,parsedObjCMethods=len(methods),methodParseErrors=errors,methodIndex=methods,deviceOperations=0,nativeCalls=0,actualCPUExecutionNotEstablished=True,actualGuestFramesNotEstablished=True)
 p=out/'report.json';p.write_text(json.dumps(report,indent=2)+'\n');f=out/'freeze.json';f.write_text(json.dumps(dict(files=[pin(x)for x in out.iterdir()if x.is_file()]+[pin(__file__),pin(reader),pin(path),pin(cp),report['actualStartStdout']]),indent=2)+'\n');print(json.dumps(dict(report=pin(p),freeze=pin(f))))
if __name__=='__main__':main()
