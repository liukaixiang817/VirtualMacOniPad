#!/usr/bin/env python3
"""Only read exact current/original VMM strong-import callers. No load/spawn."""
import argparse,hashlib,json,pathlib,runpy,struct,sys,capstone
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve();assert o.is_relative_to(N)and not o.exists();o.mkdir()
 parser=N/'vmm-public-adapter-gap-design-v1/audit.py';a=runpy.run_path(str(parser))
 c=N/'original27-private-cpu-scalar-methods-data-v1-attempt3/candidate.json';j=json.loads(c.read_bytes());p=pathlib.Path(j['candidate']['path']);assert pin(p)==j['candidate']
 image=a['MachO'](p.read_bytes());original=a['MachO'](a['VM'].read_bytes())
 names={'_MTLCopyAllDevices','_CGDisplayCopyColorSpace','_SLSDisplayGetPotentialHeadroom','_xpc_add_bundle_with_lwcr','_xpc_connection_create','_xpc_connection_set_oneshot_instance','_xpc_main'}
 stubs={}
 for sec in image.sections:
  if sec['name']!='__auth_stubs':continue
  for n in range(0,sec['bytes'],16):
   at=sec['va']-image.base+n;slot,b=a['authenticated_stub'](image,image.raw(at,16),at)
   if b['importRecord']['name']in names:stubs[at]=dict(stubRVA=at,slotRVA=slot,bind=b)
 assert {v['bind']['importRecord']['name']for v in stubs.values()}==names
 calls=[]
 for sec in image.sections:
  if not sec['flags']&0x80000400:continue
  for n in range(0,sec['bytes'],4):
   at=sec['va']-image.base+n;w=struct.unpack('<I',image.raw(at,4))[0];to=a['branch'](w,at)
   if to in stubs:
    start,end=image.bounds(at);calls.append(dict(callRVA=at,word=w,kind='BL' if w&0xfc000000==0x94000000 else 'B',functionStart=start,functionEnd=end,**stubs[to]))
 md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM);md.skipdata=True;bodies=[]
 for start,end in sorted({(r['functionStart'],r['functionEnd'])for r in calls}):
  assert 0<end-start<=65536
  raw=image.raw(start,end-start);assert raw==original.raw(start,end-start),'Unexpected modified graphics/startup caller'
  q=o/(f'caller-{start:x}.bin');q.write_bytes(raw)
  instructions=[dict(rva=i.address,word=struct.unpack('<I',i.bytes)[0],mnemonic=i.mnemonic,operands=i.op_str)for i in md.disasm(raw,start)]
  assert len(instructions)==len(raw)//4
  bodies.append(dict(startRVA=start,endRVA=end,originalWholeFunctionIdentical=True,body=pin(q),instructions=instructions))
 save(o/'audit.json',dict(schema='Actual VMM seven gfx/startup strong-import caller windows readonly v1',candidate=pin(c),image=pin(p),original=pin(a['VM']),parser=pin(parser),reviewer=pin(pathlib.Path(__file__)),calls=calls,bodies=bodies,
  callingSemanticsImplemented=False,originalVMMExecuted=False,deviceOperations=0,nativeCPUCalls=0,guestBoot=False))
 save(o/'freeze.json',dict(schema='VMM gfx startup readonly caller evidence freeze v1',files=[pin(q)for q in o.iterdir()if q.is_file()]+[pin(pathlib.Path(__file__))]))
 print(json.dumps(dict(audit=pin(o/'audit.json'),calls=[dict(symbol=r['bind']['importRecord']['name'],call=hex(r['callRVA']),function=hex(r['functionStart']))for r in calls])))
if __name__=='__main__':main()
