#!/usr/bin/env python3
"""HOST-only exact one-auth-slot PVG capability route; no signing/execution."""
import argparse,hashlib,json,pathlib,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO']
def pin(p):
 p=p.resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--baseline',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 base=a.baseline.resolve();p=json.loads(base.read_bytes());root=base.parent/'runtime';rel='child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS';old=root/rel/'ParavirtualizedGraphics27.dylib';o=a.output.resolve();assert not (o/'candidate.json').exists()
 b=old.read_bytes();m=M(b);assert m.uuid=='9e6a667aa77532de8dd56872ef6a53d9' and len(m.imports)==261 and len(m.loads)==9
 sig=next(c for c in m.commands if c['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8);assert cs+sz==len(b)
 fix=next(c for c in m.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8);raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw);assert v==0 and count==261 and fmt==1 and sfmt==0 and io+4*count<=so
 name=b'_VM27OwnedPVGSupportsBufferAddressRangesV1\0';newentry=((len(raw)-so)<<9)|10
 fx=bytearray(raw[:io+4*count]+struct.pack('<I',newentry)+raw[io+4*count:]+name);struct.pack_into('<I',fx,12,so+4);struct.pack_into('<I',fx,16,count+1)
 out=bytearray(b[:cs]);slot=0x6d1a0;oldword=struct.unpack_from('<Q',out,slot)[0];row=next(q for q in m.binds if q['fileoff']==slot);assert row['index']==144 and row['name']=='_objc_msgSend' and row['auth']==1 and row['key']==0 and row['addrdiv']==1 and row['diversity']==0
 struct.pack_into('<Q',out,slot,(oldword&~65535)|261)
 align=lambda x:(x+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newoff=len(out);out.extend(fx)
 sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8);tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz]
 ds=next(c for c in m.commands if c['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']));assert fields[6]+fields[7]==ns
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab);out.extend(struct.pack('<IBBHQ',len(strings),1,0,10<<8,0));newstrings=len(out);out.extend(strings+name)
 commands=[]
 for c in m.commands:
  if c['cmd']==0x1d:continue
  x=bytearray(c['raw'])
  if c['cmd']==0x80000034:struct.pack_into('<II',x,8,newoff,len(fx))
  if c['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+1,newstrings,len(strings)+len(name))
  if c['cmd']==11:struct.pack_into('<I',x,28,fields[7]+1)
  if c['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   fileoff=struct.unpack_from('<Q',x,40)[0];extent=len(out)-fileoff;struct.pack_into('<Q',x,32,(extent+16383)&~16383);struct.pack_into('<Q',x,48,extent)
  commands.append(bytes(x))
 load=b'@loader_path/MD\0';size=align(24+len(load));commands.append(struct.pack('<6I',0xc,size,24,0,0,0)+load+b'\0'*(size-24-len(load)))
 header=b''.join(commands);assert 32+len(header)<=4088;out[32:4088]=header+b'\0'*(4088-32-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 patched=o/'ParavirtualizedGraphics27.dylib';patched.write_bytes(out);q=M(out)
 assert q.uuid==m.uuid and q.exports==m.exports and len(q.imports)==262 and q.imports[-1]['name']==name[:-1].decode() and q.imports[-1]['ordinal']==10 and q.imports[-1]['weak']==0
 assert [(x['path'],x['cmd']) for x in q.loads[:9]]==[(x['path'],x['cmd']) for x in m.loads]
 for x,y in zip(m.imports,q.imports[:261]):assert all(x[k]==y[k] for k in ['index','ordinal','weak','name','addend'])
 for s in m.sections:
  lo=s['fileoff'];hi=lo+s['size']
  if not lo or not s['size']:continue
  expected=bytearray(b[lo:hi])
  if lo<=slot<hi:struct.pack_into('<Q',expected,slot-lo,(oldword&~65535)|261)
  assert out[lo:hi]==expected,s['name']
 assert [(x['fileoff'],x['word']) for x in m.binds if x['fileoff']!=slot]==[(x['fileoff'],x['word']) for x in q.binds if x['fileoff']!=slot]
 tool=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_info')
 for f,label in [(patched,'pvg'),(o/'MD','md')]:
  z=subprocess.run([str(tool),'-validate_only',str(f)],capture_output=True);(o/(label+'-validate.stdout')).write_bytes(z.stdout);(o/(label+'-validate.stderr')).write_bytes(z.stderr);dump(o/(label+'-validate.json'),dict(command=[str(tool),'-validate_only',str(f)],exit=z.returncode));assert z.returncode==0
 recipe=dict(original=pin(old),patched=pin(patched),onlyAuthSlotRVA=slot,oldWord=oldword,newWord=(oldword&~65535)|261,selectorStubRVA=0x65ee0,selectorSlotRVA=0x6ba90,originalCallerReturnRVAs=[0x2108c,0x31fb0],newRequiredLoad='@loader_path/MD',newOrdinal=10,newImportIndex=261,newSymbol=name[:-1].decode(),allOriginalTextAndCodeWholeUnchanged=True,allOldImportSemanticsWholeUnchanged=True,allOldSectionsWholeExceptSelectedAuthSlot=True,oldNlistRowsWhole=True,appendedUndefinedSymbol=True,newFixupsBeforeRelocatedTerminalNlistAndStrings=True,originalUUIDAndExportsUnchanged=True,allOtherAuthWordsWholeUnchanged=True,codeSigned=False,deviceOperations=0)
 dump(o/'recipe.json',recipe)
 print(json.dumps(dict(patchedPG=pin(patched),recipe=pin(o/'recipe.json'))))
if __name__=='__main__':main()
