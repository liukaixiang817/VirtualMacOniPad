#!/usr/bin/env python3
"""Root-executed HOST one-root MD compile and fifteen exact remaining PG BOOL query slots."""
import argparse,collections,hashlib,json,pathlib,runpy,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PLAN_SHA='c9615fd07e4cfbbec8d59dfc7248d1c144ccbf43e981c6d1afbf353a4032bc3d'
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO']
def need(v,why):
 if not v:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(pin(p)==row,'frozen input changed: '+str(p));return p
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def semantics(m):return collections.Counter((r['ordinal'],r['weak'],r['name'],r['addend'])for r in m.imports)

def patch_pg(old,destination,selected):
 b=old.read_bytes();m=M(b)
 need(m.uuid=='9e6a667aa77532de8dd56872ef6a53d9' and len(m.imports)==270 and len(m.loads)==10,'actual R73 PG with existing depth24 and three BOOL routes')
 need(m.loads[9]['path']=='@loader_path/MD' and m.loads[9]['cmd']==12,'existing required MD ordinal10')
 sig=next(c for c in m.commands if c['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8)
 need(cs+sz==len(b),'terminal current PG signature')
 fix=next(c for c in m.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8)
 raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw)
 need(v==0 and count==270 and fmt==1 and sfmt==0 and io+4*count<=so,'actual PG import format')
 names=[r['symbol'].encode()+b'\0'for r in selected]
 entries=b''.join(struct.pack('<I',((len(raw)-so+sum(map(len,names[:i])))<<9)|10)for i in range(len(selected)))
 fx=bytearray(raw[:io+4*count]+entries+raw[io+4*count:]+b''.join(names))
 struct.pack_into('<I',fx,12,so+4*len(selected));struct.pack_into('<I',fx,16,count+len(selected))
 out=bytearray(b[:cs]);changes=[]
 for r in selected:
  slot=r['authSlotRVA'];row=next(q for q in m.binds if q['fileoff']==slot)
  need(row['va']-m.base==slot and row['index']==144 and row['name']=='_objc_msgSend' and
       row['auth']==1 and row['key']==0 and row['addrdiv']==1 and row['diversity']==0 and row['pointerFormat']==9,'exact optional BOOL auth slot')
  oldword=struct.unpack_from('<Q',out,slot)[0];newword=(oldword&~65535)|r['newImportIndex']
  struct.pack_into('<Q',out,slot,newword);changes.append(dict(**r,slot=slot,oldWord=oldword,newWord=newword,newIndex=r['newImportIndex']))
 align=lambda x:(x+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newoff=len(out);out.extend(fx)
 sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8)
 tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz]
 ds=next(c for c in m.commands if c['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']))
 need(fields[6]+fields[7]==ns,'terminal existing undefined nlist rows')
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab)
 for i in range(len(selected)):out.extend(struct.pack('<IBBHQ',len(strings)+sum(map(len,names[:i])),1,0,10<<8,0))
 newstrings=len(out);out.extend(strings+b''.join(names));commands=[]
 for c in m.commands:
  if c['cmd']==0x1d:continue
  x=bytearray(c['raw'])
  if c['cmd']==0x80000034:struct.pack_into('<II',x,8,newoff,len(fx))
  if c['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+len(selected),newstrings,len(strings)+sum(map(len,names)))
  if c['cmd']==11:struct.pack_into('<I',x,28,fields[7]+len(selected))
  if c['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   off=struct.unpack_from('<Q',x,40)[0];extent=len(out)-off
   struct.pack_into('<Q',x,32,(extent+16383)&~16383);struct.pack_into('<Q',x,48,extent)
  commands.append(bytes(x))
 header=b''.join(commands);need(len(header)<=m.sizeofcmds,'no added PG load commands')
 out[32:32+m.sizeofcmds]=header+b'\0'*(m.sizeofcmds-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 q=M(out);need(q.uuid==m.uuid and q.exports==m.exports,'original PG UUID and exports')
 need([(x['path'],x['cmd'])for x in q.loads]==[(x['path'],x['cmd'])for x in m.loads],'all PG required loads whole')
 need(len(q.imports)==285,'fifteen new strong MD imports')
 for x,y in zip(m.imports,q.imports[:270],strict=True):
  need(all(x[k]==y[k]for k in ['index','ordinal','weak','name','addend']),'all270 original PG import semantics')
 for r in selected:
  z=q.imports[r['newImportIndex']];need(z['name']==r['symbol'] and z['ordinal']==10 and not z['weak'] and not z['addend'],'exact new owned MD import')
 slots={r['authSlotRVA']for r in selected}
 for s in m.sections:
  lo=s['fileoff'];hi=lo+s['size']
  if not lo or not s['size']:continue
  expected=bytearray(b[lo:hi])
  for r in changes:
   if lo<=r['slot']<hi:struct.pack_into('<Q',expected,r['slot']-lo,r['newWord'])
  need(out[lo:hi]==expected,'PG section changed beyond the finite selected auth slots: '+s['name'])
 need([(r['fileoff'],r['word'])for r in m.binds if r['fileoff']not in slots]==
      [(r['fileoff'],r['word'])for r in q.binds if r['fileoff']not in slots],'all other PG bindings including depth24 and prior three BOOL slots whole')
 destination.write_bytes(out)
 return dict(original=pin(old),patched=pin(destination),selectedAuthSlots=changes,newSymbols=[r['symbol']for r in selected],newOrdinals=[10]*len(selected),
  all270OldImportSemanticsWhole=True,allOriginalTextAndCodeWholeUnchanged=True,allOldSectionsWholeExceptSelectedAuthSlots=True,
  allOtherAuthWordsWholeUnchanged=True,originalUUIDAndExportsUnchanged=True,allOriginalRequiredLoadsWholeUnchanged=True,
  oldNlistRowsWhole=True,appendedUndefinedSymbols=len(selected),newRequiredLoadsAdded=0,codeSignedByProductSigner=False,deviceOperations=0)

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-plan',type=pathlib.Path,required=True)
 ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();pp=a.source_plan.resolve()
 need(pp.is_relative_to(N) and pin(pp)['sha256']==PLAN_SHA,'frozen reviewed cmd58 capability source plan')
 need(out.parent==N and not out.exists(),'fresh owned HOST output');p=json.loads(pp.read_bytes())
 base=exact(p['baselineRuntimeCandidate']);priorpath=exact(p['currentMDLinkCandidate']);prior=json.loads(priorpath.read_bytes())
 oldmd=exact(p['baselineCurrentChildMD']);oldpg=exact(p['baselineCurrentChildPG']);child=exact(p['baselineCurrentChild']);source=exact(p['newRootCompileSource'])
 for r in [*p['currentMDObjects'],*p['sourceFiles'],p['sourceDiff'],p['inheritedCompile'],p['inheritedLink'],p['currentMDWholeUnsignedProvider'],p['exactCurrentPGCallerAndABIProof'],p['actualNormal88ChildSyslog']]:exact(r)
 for r in p['sourcePairs']:exact(r['original']);exact(r['derived'])
 compiler=json.loads(exact(p['inheritedCompile']).read_bytes());linker=json.loads(exact(p['inheritedLink']).read_bytes())
 need(compiler['exit']==linker['exit']==0 and len(p['currentMDObjects'])==3,'actual successful full current three-object MD')
 selected=p['capabilityContracts'];need(len(selected)==15 and [x['newImportIndex']for x in selected]==list(range(270,285)),'fifteen finite actual selectors')
 out.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  z=subprocess.run(argv,capture_output=True,timeout=90);(out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr)
  row=dict(command=argv,exit=z.returncode);dump(out/(label+'.json'),row);commands.append(dict(label=label,**row))
  need(z.returncode==0,label+': '+z.stderr.decode(errors='replace'))
 obj=out/'modern_metal_device_array_v20.o';md=out/'MD';pg=out/'ParavirtualizedGraphics27.dylib'
 argv=list(compiler['command']);oldsource=p['sourcePairs'][1]['original']['path'];oldobj=p['currentMDObjects'][0]['path']
 need(argv.count(oldsource)==argv.count(oldobj)==1,'inherited actual MD16 compiler root source and object')
 argv[argv.index(oldsource)]=str(source);argv[argv.index(oldobj)]=str(obj);run('compile',argv)
 argv=list(linker['command']);need([x for x in argv if x.endswith('.o')]==[r['path']for r in p['currentMDObjects']],'actual complete current MD three-object link order')
 need(argv.count(oldobj)==argv.count(prior['newProvider']['path'])==1,'one current MD root object and output')
 argv[argv.index(oldobj)]=str(obj);argv[argv.index(prior['newProvider']['path'])]=str(md)
 exportarg=next(x for x in argv if x.startswith('-Wl,-exported_symbols_list,'));oldexports=pathlib.Path(exportarg.split(',',2)[2]);need(oldexports.is_relative_to(N),'owned current export list')
 names=oldexports.read_text().splitlines();symbols=[r['symbol']for r in selected];need(not set(names)&set(symbols),'fifteen unique new exports')
 exports=out/'exports.txt';exports.write_text('\n'.join(names+symbols)+'\n');argv[argv.index(exportarg)]='-Wl,-exported_symbols_list,'+str(exports);run('link',argv)
 before=M(oldmd.read_bytes());after=M(md.read_bytes())
 need(len(before.imports)==50 and len(before.exports)==14 and set(after.exports)==set(before.exports)|set(symbols),'all14 existing MD exports and only fifteen new real functions')
 need(semantics(after)==semantics(before),'all50 native MD import semantics preserved')
 need([(x['path'],x['cmd'])for x in after.loads]==[(x['path'],x['cmd'])for x in before.loads],'all current MD loads and both real Metal reexports whole')
 recipe=patch_pg(oldpg,pg,selected);dump(out/'recipe.json',recipe)
 for f,label in [(pg,'pvg-validate'),(md,'md-validate')]:run(label,['xcrun','dyld_info','-validate_only',str(f)])
 record=dict(schema='Actual HOST R73 full-current-link MD and fifteen remaining cmd58 optional BOOL PG capability source port v1',
  sourcePlan=pin(pp),baselineRuntimeCandidate=pin(base),providerKey='MD',roles=['child'],source=pin(source),sourceFiles=p['sourceFiles'],builder=pin(__file__),
  originalProvider=pin(oldmd),newProvider=pin(md),actualProviderPin=pin(md),originalChildPG=pin(oldpg),patchedChildPG=pin(pg),originalChild=pin(child),
  actualIOSObject=pin(obj),actualIOSObjects=[pin(obj),*p['inheritedWholeLinkObjects']],actualIOSCompile=pin(out/'compile.json'),actualIOSLink=pin(out/'link.json'),
  actualPGValidate=pin(out/'pvg-validate.json'),actualMDValidate=pin(out/'md-validate.json'),recipe=pin(out/'recipe.json'),
  currentMDLinkCandidate=pin(priorpath),currentMDObjects=p['currentMDObjects'],inheritedWholeLinkObjects=p['inheritedWholeLinkObjects'],
  capabilityContracts=selected,addedExports=symbols,actualAddedPGImportCount=len(selected),selectedPGImportsDefinitionCount=len(selected),
  actualProviderNativeImportCount=len(after.imports),providerUUID=after.uuid,all270OldPGImportSemanticsWhole=True,allOtherPGAuthSlotsWhole=True,
  all50CurrentMDNativeImportsAndLoadsPreserved=True,all14CurrentMDExportsPreserved=True,originalVTCreateDeliverObjectAndBindingsWhole=True,
  originalExceptionBridgeObjectWhole=True,originalChildErrorReasonAndVMInitializationAndExceptionBridgeSemanticsWhole=True,
  parentMDWholeUnchangedRequired=True,CPUAndVMMProvidersAndChildEntitlementsAndShaderUnchangedRequired=True,
  exactCurrentPGCallerAndABIProof=p['exactCurrentPGCallerAndABIProof'],actualNormal88ChildSyslog=p['actualNormal88ChildSyslog'],
  newRequiredLoadsAdded=0,globalAppleClassMutation=False,actualDeviceOperations=0,actualGuestStarted=False,codeSignedByProductSigner=False,
  compileLinkAndBothValidateExit=[0,0,0,0],contractKey=p['contractKey'],commands=commands)
 record[p['contractKey']]=p[p['contractKey']];dump(out/'candidate.json',record)
 files=[pin(f)for f in sorted(out.rglob('*'))if f.is_file()]+[pin(__file__),pin(pp),pin(base),pin(priorpath),pin(oldmd),pin(oldpg),pin(child),pin(oldexports),
  *p['currentMDObjects'],*p['sourceFiles'],p['sourceDiff'],p['inheritedCompile'],p['inheritedLink'],p['currentMDWholeUnsignedProvider'],p['exactCurrentPGCallerAndABIProof'],p['actualNormal88ChildSyslog']]
 for pair in p['sourcePairs']:files.extend([pair['original'],pair['derived']])
 dump(out/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0,codeSigningOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),MD=pin(md),PG=pin(pg))))
if __name__=='__main__':main()
