#!/usr/bin/env python3
"""HOST-only selected original Error constructor call route; no signing/execution."""
import argparse,hashlib,json,pathlib,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO']
def pin(p):
 p=p.resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();base=a.baseline.resolve();c=json.loads(base.read_bytes());o=a.output.resolve();assert not(o/'candidate.json').exists()
 old=pathlib.Path(c['runtimeRoot'])/'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine';b=old.read_bytes();m=M(b);assert m.uuid=='4a6a588d1afd30f5a64d6304eb79be0b' and m.loads[2]['path']=='@loader_path/MD' and m.loads[2]['cmd']==0xc
 sig=next(v for v in m.commands if v['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8);assert cs+sz==len(b)
 calls=[0x2ea2ec,0x2eb42c,0x2eb4e8,0x2eb954,0x2ec30c,0x2ec43c,0x2ec5ec,0x2ec7a0,0x2ec7ec,0x2ecc64,0x2eccb8]
 thunk=0x4a2000;slot=0x4c85c0;previous=0x4c85b8
 assert b[thunk:thunk+16]==b'\0'*16 and b[slot:slot+8]==b'\0'*8
 for sec in m.sections:
  if sec['fileoff'] and sec['size']:assert not(sec['fileoff']<=thunk<sec['fileoff']+sec['size']) and not(sec['fileoff']<=slot<sec['fileoff']+sec['size'])
 prevword=struct.unpack_from('<Q',b,previous)[0];assert (prevword>>51)&2047==0
 fix=next(v for v in m.commands if v['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8);raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw);assert v==0 and fmt==2 and sfmt==0 and count==len(m.imports)==1203
 name=b'_VM27OwnedChildBuildErrorReasonDiagnosticV1\0';entry=((len(raw)-so)<<9)|3;fx=bytearray(raw[:io+8*count]+struct.pack('<Ii',entry,0)+raw[io+8*count:]+name);struct.pack_into('<I',fx,12,so+8);struct.pack_into('<I',fx,16,count+1)
 out=bytearray(b[:cs]);patched=[]
 for at in calls:
  word=struct.unpack_from('<I',b,at)[0];delta=(word&0x3ffffff);delta=delta-(1<<26)if delta&(1<<25)else delta;assert word>>26==0x25 and at+delta*4==0x3e4fb0
  new=0x94000000|(((thunk-at)//4)&0x3ffffff);struct.pack_into('<I',out,at,new);patched.append(dict(at=at,returnRVA=at+4,oldWord=word,newWord=new,originalTargetRVA=0x3e4fb0))
 page=(slot>>12)-(thunk>>12);adrp=0x90000010|((page&3)<<29)|(((page>>2)&0x7ffff)<<5)
 code=struct.pack('<4I',adrp,0x91000210|((slot&4095)<<10),0xf9400211,0xd71f0a30);out[thunk:thunk+16]=code
 newprev=prevword|(1<<51);struct.pack_into('<Q',out,previous,newprev);newslot=(3<<62)|(1<<48)|count;struct.pack_into('<Q',out,slot,newslot)
 align=lambda x:(x+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newfix=len(out);out.extend(fx)
 sym=next(v for v in m.commands if v['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8);tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz];ds=next(v for v in m.commands if v['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']));assert fields[6]+fields[7]==ns
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab);out.extend(struct.pack('<IBBHQ',len(strings),1,0,3<<8,0));newstrings=len(out);out.extend(strings+name)
 commands=[]
 for z in m.commands:
  if z['cmd']==0x1d:continue
  x=bytearray(z['raw'])
  if z['cmd']==0x80000034:struct.pack_into('<II',x,8,newfix,len(fx))
  if z['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+1,newstrings,len(strings)+len(name))
  if z['cmd']==11:struct.pack_into('<I',x,28,fields[7]+1)
  if z['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   end=len(out)-struct.unpack_from('<Q',x,40)[0];struct.pack_into('<Q',x,32,(end+16383)&~16383);struct.pack_into('<Q',x,48,end)
  commands.append(bytes(x))
 header=b''.join(commands);start=m.sections[0]['fileoff'];assert 32+len(header)<=start;out[32:start]=header+b'\0'*(start-32-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 p=o/'com.apple.Virtualization.VirtualMachine';p.write_bytes(out);q=M(out);assert q.uuid==m.uuid and q.exports==m.exports and len(q.imports)==count+1 and q.imports[-1]['name']==name[:-1].decode() and q.imports[-1]['ordinal']==3 and q.imports[-1]['weak']==0
 assert [(z['cmd'],z['path'])for z in q.loads]==[(z['cmd'],z['path'])for z in m.loads]
 for x,y in zip(m.imports,q.imports[:count]):assert all(x[k]==y[k]for k in ['index','ordinal','weak','name','addend'])
 for sec in m.sections:
  lo=sec['fileoff'];hi=lo+sec['size']
  if not lo or not sec['size']:continue
  expected=bytearray(b[lo:hi])
  for z in patched:
   if lo<=z['at']<hi:struct.pack_into('<I',expected,z['at']-lo,z['newWord'])
  if lo<=previous<hi:struct.pack_into('<Q',expected,previous-lo,newprev)
  assert out[lo:hi]==expected,sec['name']
 assert next(z for z in q.binds if z['fileoff']==slot)['index']==count
 assert [(z['fileoff'],z['word'])for z in m.binds if z['fileoff']!=previous]==[(z['fileoff'],z['word'])for z in q.binds if z['fileoff']not in [slot,previous]]
 tool='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_info'
 for f,label in [(p,'child'),(o/'MD','md')]:
  r=subprocess.run([tool,'-validate_only',str(f)],capture_output=True);(o/(label+'-validate.stdout')).write_bytes(r.stdout);(o/(label+'-validate.stderr')).write_bytes(r.stderr);dump(o/(label+'-validate.json'),dict(command=[tool,'-validate_only',str(f)],exit=r.returncode));assert r.returncode==0,r.stderr
 dump(o/'recipe.json',dict(original=pin(old),patched=pin(p),selectedOriginalCalls=patched,newSymbol=name[:-1].decode(),newImportIndex=count,existingRequiredOrdinal=3,newRequiredLoads=0,thunkRVA=thunk,thunkBytes=code.hex(),newAuthSlotRVA=slot,newAuthWord=newslot,previousChainTailRVA=previous,previousOldWord=prevword,previousNewWord=newprev,previousOnlyNextStrideChanged=True,originalErrorFunctionRVA=0x3e4fb0,originalErrorFunctionWholeUnchanged=True,allOtherCodeAndBackedSectionsUnchanged=True,allOldImportSemanticsUnchanged=True,allOtherAuthWordsWholeUnchanged=True,originalUUIDAndExportsUnchanged=True,terminalNlistAndStringsRelocatedAfterNewFixups=True,codeSigned=False,actualDeviceOperations=0))
 print(json.dumps(dict(patchedChild=pin(p),recipe=pin(o/'recipe.json'))))
if __name__=='__main__':main()
