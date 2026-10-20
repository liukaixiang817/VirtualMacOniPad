#!/usr/bin/env python3
"""Root-executed HOST compile/link and two owned Child VT import bindings only."""
import argparse,collections,hashlib,json,pathlib,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PLAN_SHA='1b74d664940bc8cba749a7715e83c14eda463c389e969662eba68a890bd930ba'
module=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))
M=module['MachO']
def need(v,why):
 if not v:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
 p=pathlib.Path(r['path']);need(pin(p)==r,'frozen input changed: '+str(p));return p
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def semantics(m):return collections.Counter((r['ordinal'],r['weak'],r['name'],r['addend'])for r in m.imports)

def patch_child(old,destination,selected):
 b=old.read_bytes();m=M(b)
 need(m.uuid=='4a6a588d1afd30f5a64d6304eb79be0b' and len(m.imports)==1205,'actual current Child')
 need(m.loads[2]['path']=='@loader_path/MD' and m.loads[2]['cmd']==12,'existing required Child MD ordinal3')
 sig=next(c for c in m.commands if c['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8)
 need(cs+sz==len(b),'terminal Child signature')
 fix=next(c for c in m.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8)
 raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw)
 need(v==0 and count==1205 and fmt==2 and sfmt==0 and io+8*count==so,'actual Child addend32 import format')
 sc=struct.unpack_from('<I',raw,st)[0]
 for i in range(sc):
  rel=struct.unpack_from('<I',raw,st+4+4*i)[0]
  if rel:need(st+rel+struct.unpack_from('<I',raw,st+rel)[0]<=io,'all starts records precede imports')
 names=[r['newName'].encode()+b'\0'for r in selected]
 entries=b''.join(struct.pack('<Ii',((len(raw)-so+sum(map(len,names[:i])))<<9)|3,0)for i in range(2))
 fx=bytearray(raw[:so]+entries+raw[so:]+b''.join(names))
 struct.pack_into('<I',fx,12,so+16);struct.pack_into('<I',fx,16,count+2)
 out=bytearray(b[:cs]);changes=[]
 for r in selected:
  slot=r['authSlotRVA'];row=next(q for q in m.binds if q['fileoff']==slot)
  need(row['va']-m.base==slot and row['index']==r['originalIndex'] and row['name']==r['originalName'] and
       row['auth']==1 and row['key']==0 and row['addrdiv']==1 and row['diversity']==0 and row['pointerFormat']==12,'exact VT authenticated import slot')
  word=struct.unpack_from('<Q',out,slot)[0];newword=(word&~0xffffff)|r['newIndex']
  struct.pack_into('<Q',out,slot,newword);changes.append(dict(**r,oldWord=word,newWord=newword))
 align=lambda v:(v+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newoff=len(out);out.extend(fx)
 sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8)
 tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz]
 ds=next(c for c in m.commands if c['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']))
 need(fields[6]+fields[7]==ns,'terminal existing undefined nlist rows')
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab)
 for i in range(2):out.extend(struct.pack('<IBBHQ',len(strings)+sum(map(len,names[:i])),1,0,3<<8,0))
 newstrings=len(out);out.extend(strings+b''.join(names));commands=[]
 for c in m.commands:
  if c['cmd']==0x1d:continue
  x=bytearray(c['raw'])
  if c['cmd']==0x80000034:struct.pack_into('<II',x,8,newoff,len(fx))
  if c['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+2,newstrings,len(strings)+sum(map(len,names)))
  if c['cmd']==11:struct.pack_into('<I',x,28,fields[7]+2)
  if c['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   off=struct.unpack_from('<Q',x,40)[0];extent=len(out)-off
   struct.pack_into('<Q',x,32,(extent+16383)&~16383);struct.pack_into('<Q',x,48,extent)
  commands.append(bytes(x))
 header=b''.join(commands);need(len(header)<=m.sizeofcmds,'no added load commands')
 out[32:32+m.sizeofcmds]=header+b'\0'*(m.sizeofcmds-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 q=M(out);need(q.uuid==m.uuid and q.exports==m.exports,'Child UUID and original exports preserved')
 need([(x['path'],x['cmd'])for x in q.loads]==[(x['path'],x['cmd'])for x in m.loads],'all existing required Child loads preserved')
 need(len(q.imports)==1207,'only two new Child imports')
 for x,y in zip(m.imports,q.imports[:1205],strict=True):
  need(all(x[k]==y[k]for k in ['index','ordinal','weak','name','addend']),'all original Child import semantics')
 for r in selected:
  z=q.imports[r['newIndex']];need(z['name']==r['newName'] and z['ordinal']==3 and not z['weak'] and not z['addend'],'exact new strong MD binding')
 slots={r['authSlotRVA']for r in selected}
 for s in m.sections:
  lo=s['fileoff'];hi=lo+s['size']
  if not lo or not s['size']:continue
  expected=bytearray(b[lo:hi])
  for r in changes:
   if lo<=r['authSlotRVA']<hi:struct.pack_into('<Q',expected,r['authSlotRVA']-lo,r['newWord'])
  need(out[lo:hi]==expected,'Child section changed beyond two VT slots: '+s['name'])
 need([(r['fileoff'],r['word'])for r in m.binds if r['fileoff']not in slots]==
      [(r['fileoff'],r['word'])for r in q.binds if r['fileoff']not in slots],'all other Child bindings whole')
 destination.write_bytes(out)
 return dict(original=pin(old),patched=pin(destination),selectedAuthSlots=changes,
  all1205OldImportSemanticsWhole=True,allOriginalTextAndCodeWholeUnchanged=True,
  allOldSectionsWholeExceptTwoSelectedAuthSlots=True,allOtherAuthWordsWholeUnchanged=True,
  originalUUIDAndExportsUnchanged=True,allOriginalRequiredLoadsWholeUnchanged=True,
  oldNlistRowsWhole=True,appendedUndefinedSymbols=2,newRequiredLoadsAdded=0,
  codeSignedByProductSigner=False,deviceOperations=0)

def native_row(plan,provider,row):
 proof=plan['nativeDefinitionProof'];idx=json.loads(exact(plan['nativeDefinitionIndex']).read_bytes())
 need(idx['currentCacheUUID']==proof['actualNativeCacheUUID'],'same actual captured iPad cache')
 files=[plan['nativeDefinitionIndex'],*proof['actualCompleteCommands'],*proof['actualCompleteExports']]
 for r in files:exact(r)
 def commands(r):
  b=exact(r).read_bytes();need(struct.unpack_from('<I',b)[0]==0xfeedfacf,'actual native Mach-O header')
  count,size=struct.unpack_from('<II',b,16);need(32+size<=len(b),'complete actual native commands')
  at=32;loads=[];uuid=None
  for _ in range(count):
   cmd,z=struct.unpack_from('<II',b,at);need(z>=8 and at+z<=32+size,'bounded actual native command')
   if cmd==0x1b:uuid=b[at+8:at+24].hex()
   if cmd in [12,0x80000018,0x8000001f,0x80000023]:
    no=struct.unpack_from('<I',b,at+8)[0];end=b.find(b'\0',at+no,at+z);need(end>=0,'native load path')
    loads.append(dict(ordinal=len(loads)+1,command=cmd,path=b[at+no:end].decode()))
   at+=z
  need(at==32+size,'complete native command extent');return uuid,loads
 uid,loads=commands(proof['actualCompleteCommands'][0]);lid,_=commands(proof['actualCompleteCommands'][1])
 need(uid==proof['umbrellaUUID'] and lid==proof['leafUUID'] and proof['reexport']in loads,'actual libSystem-to-libdyld reexport')
 definitions,_=module['trie'](exact(proof['actualCompleteExports'][1]).read_bytes())
 need(definitions[proof['symbol']]==proof['definition'] and idx['images'][proof['leafPath']]['definitions'][proof['symbol']]==dict(flags=0,offset=8124),'actual direct strong dlsym export')
 load=next(x for x in provider.loads if x['ordinal']==row['ordinal'])
 need(load['path']==proof['umbrellaPath'] and load['cmd']==12,'new actual native import through existing strong libSystem load')
 return dict(actualImport=row,requiredLoad=load,actualDefinition=dict(resolved=True,
  image=proof['leafPath'],UUID=lid,flags=proof['definition']['flags'],address=proof['definition']['address'],
  actualNativeCacheUUID=proof['actualNativeCacheUUID'],route=[dict(image=proof['umbrellaPath'],uuid=uid,actualReexport=proof['reexport']),
  dict(image=proof['leafPath'],uuid=lid,actualExport=proof['definition'])],actualCapturedCommandAndExportPins=files))

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-plan',type=pathlib.Path,required=True)
 ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();pp=a.source_plan.resolve();out=a.output.resolve()
 need(pp.is_relative_to(N) and pin(pp)['sha256']==PLAN_SHA,'frozen VT source plan')
 need(out.parent==N and not out.exists(),'fresh HOST-only output');p=json.loads(pp.read_bytes())
 base=exact(p['baselineRuntimeCandidate']);depthpath=exact(p['inheritedDepth24Candidate']);depth=json.loads(depthpath.read_bytes())
 source=exact(p['source']);oldchild=exact(p['baselineCurrentChild']);oldmd=exact(p['inheritedProvider']);pg=exact(p['inheritedPG'])
 for r in [*p['inheritedWholeIOSObjects'],p['inheritedCompile'],p['inheritedLink']]:exact(r)
 compile_record=json.loads(exact(p['inheritedCompile']).read_bytes());link_record=json.loads(exact(p['inheritedLink']).read_bytes())
 need(compile_record['exit']==link_record['exit']==0,'actual inherited successful MD linkage')
 out.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  z=subprocess.run(argv,capture_output=True,timeout=90);(out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr)
  row=dict(command=argv,exit=z.returncode);dump(out/(label+'.json'),row);commands.append(dict(label=label,**row))
  need(z.returncode==0,label+': '+z.stderr.decode(errors='replace'))
 obj=out/'vm27_owned_vt_host_unavailable_v1.o';md=out/'MD';child=out/'com.apple.Virtualization.VirtualMachine'
 argv=[x for x in compile_record['command']if x!='-fno-objc-arc']
 need(argv.count(depth['source']['path'])==argv.count(depth['actualIOSObjects'][0]['path'])==1,'actual inherited MD compiler inputs')
 argv[argv.index(depth['source']['path'])]=str(source);argv[argv.index(depth['actualIOSObjects'][0]['path'])]=str(obj);run('compile',argv)
 argv=list(link_record['command']);exportarg=next(x for x in argv if x.startswith('-Wl,-exported_symbols_list,'))
 oldexports=pathlib.Path(exportarg.split(',',2)[2]);need(oldexports.is_relative_to(N),'owned inherited MD exports')
 names=oldexports.read_text().splitlines();added=[r['newName']for r in p['selectedChildImports']]
 need(not set(names)&set(added),'only two new VT exports');exports=out/'exports.txt';exports.write_text('\n'.join(names+added)+'\n')
 need([x for x in argv if x.endswith('.o')]==[r['path']for r in p['inheritedWholeIOSObjects']],'both actual current MD objects and order whole')
 argv.insert(argv.index('-install_name'),str(obj));argv[argv.index(depth['newProvider']['path'])]=str(md)
 argv[argv.index(exportarg)]='-Wl,-exported_symbols_list,'+str(exports);run('link',argv)
 before=M(oldmd.read_bytes());after=M(md.read_bytes());extra=semantics(after)-semantics(before)
 need(set(after.exports)==set(before.exports)|set(added),'two new exports, all nine inherited exports preserved')
 need(not semantics(before)-semantics(after) and extra==collections.Counter({(4,0,'_dlsym',0):1}),'all 49 current native imports plus sole real dlsym import')
 need([(x['path'],x['cmd'])for x in after.loads]==[(x['path'],x['cmd'])for x in before.loads],'all native MD loads and Metal reexport preserved')
 addedrow=next({k:r[k]for k in ['ordinal','weak','name','addend']}for r in after.imports if r['name']=='_dlsym')
 native=native_row(p,after,addedrow);recipe=patch_child(oldchild,child,p['selectedChildImports']);dump(out/'recipe.json',recipe)
 for f,label in [(md,'md-validate'),(child,'child-validate')]:run(label,['xcrun','dyld_info','-validate_only',str(f)])
 record=dict(schema='Actual HOST VT Create Deliver unavailable MD and two Child import source port v1',
  sourcePlan=pin(pp),baselineRuntimeCandidate=pin(base),inheritedDepth24Candidate=pin(depthpath),builder=pin(__file__),
  providerKey='MD',roles=['child'],source=pin(source),originalProvider=pin(oldmd),actualR71OriginalProvider=depth['originalProvider'],
  newProvider=pin(md),actualProviderPin=pin(md),originalChildPG=depth['originalChildPG'],patchedChildPG=pin(pg),
  originalChild=pin(oldchild),patchedChild=pin(child),recipe=pin(out/'recipe.json'),
  actualIOSCompile=pin(out/'compile.json'),actualIOSLink=pin(out/'link.json'),actualIOSObject=pin(obj),
  actualIOSObjects=[*p['inheritedWholeIOSObjects'],pin(obj)],actualMDValidate=pin(out/'md-validate.json'),
  actualChildValidate=pin(out/'child-validate.json'),actualPGValidate=depth['actualPGValidate'],
  addedExports=added,actualVTAddedStrongNativeRows=[native],actualProviderNativeImportCount=len(after.imports),
  providerUUID=after.uuid,actualAddedChildImportCount=2,all1205OldChildImportSemanticsWhole=True,
  allOtherChildAuthSlotsAndCodeWhole=True,all49CurrentMDNativeImportsAndLoadsPreserved=True,
  originalChildErrorReasonAndVMInitializationAndExceptionBridgeSemanticsWhole=True,
  actualDepth24PGAndTwoMDObjectsWhole=True,all29CPUObjectsWholeRuntime71=True,
  newRequiredLoadsAdded=0,newDevicePathsAdded=0,actualDeviceOperations=0,actualGuestStarted=False,
  archiveRestoreSupported=False,codeSignedByProductSigner=False,commands=commands,
  compileLinkAndBothValidateExit=[0,0,0,0],contractKey=p['contractKey'])
 record[p['contractKey']]=p[p['contractKey']];dump(out/'candidate.json',record)
 files=[pin(f)for f in sorted(out.rglob('*'))if f.is_file()]+[pin(__file__),pin(pp),pin(base),pin(depthpath),pin(source),pin(oldchild),pin(oldmd),pin(pg),pin(oldexports),*p['inheritedWholeIOSObjects'],p['inheritedCompile'],p['inheritedLink'],*native['actualDefinition']['actualCapturedCommandAndExportPins']]
 dump(out/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0,codeSigningOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),MD=pin(md),Child=pin(child),PG=pin(pg))))
if __name__=='__main__':main()
