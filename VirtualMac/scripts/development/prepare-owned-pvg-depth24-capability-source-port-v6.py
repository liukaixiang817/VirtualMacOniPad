#!/usr/bin/env python3
"""HOST-only one current-MD12-root compile/link preserving MD V10 diagnostics and one owned PG depth24 auth-slot route.

Root alone executes this builder, signs the resulting product and operates iPad.
No original PG instruction, other binding or required load is changed.
"""
import argparse, collections, hashlib, json, pathlib, runpy, struct, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
PLAN_SHA='2df64beb7d2485f28989bb052f282bdc99d76241e1a948fa0c309366016e16b0'
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO']
SYMBOL='_VM27OwnedPVGIsDepth24Stencil8PixelFormatSupportedV1'
SLOT=0x6c8d0

def need(v,why):
 if not v:raise ValueError(why)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(pin(p)==row,'frozen input changed: '+str(p));return p
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def import_semantics(image):
 return collections.Counter((q['ordinal'],q['weak'],q['name'],q['addend']) for q in image.imports)

def patch_pg(old,destination):
 b=old.read_bytes();m=M(b)
 need(m.uuid=='9e6a667aa77532de8dd56872ef6a53d9' and len(m.imports)==266 and len(m.loads)==10,'actual current owned PG')
 need(m.loads[9]['path']=='@loader_path/MD' and m.loads[9]['cmd']==0xc,'existing required child MD ordinal10')
 sig=next(c for c in m.commands if c['cmd']==0x1d);cs,sz=struct.unpack_from('<II',sig['raw'],8)
 need(cs+sz==len(b),'current PG terminal signature')
 row=next(q for q in m.binds if q['fileoff']==SLOT)
 need(row['va']-m.base==SLOT and row['index']==144 and row['name']=='_objc_msgSend' and
      row['auth']==1 and row['key']==0 and row['addrdiv']==1 and row['diversity']==0 and row['pointerFormat']==9,
      'one original authenticated depth24 selector slot')
 fix=next(c for c in m.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',fix['raw'],8)
 raw=b[fo:fo+fs];v,st,io,so,count,fmt,sfmt=struct.unpack_from('<7I',raw)
 need(v==0 and count==266 and fmt==1 and sfmt==0 and io+4*count<=so,'current PG import format')
 name=SYMBOL.encode()+b'\0';entry=struct.pack('<I',((len(raw)-so)<<9)|10)
 fx=bytearray(raw[:io+4*count]+entry+raw[io+4*count:]+name)
 struct.pack_into('<I',fx,12,so+4);struct.pack_into('<I',fx,16,count+1)
 out=bytearray(b[:cs]);oldword=struct.unpack_from('<Q',out,SLOT)[0]
 newword=(oldword&~65535)|count;struct.pack_into('<Q',out,SLOT,newword)
 align=lambda x:(x+7)&~7
 out.extend(b'\0'*(align(len(out))-len(out)));newoff=len(out);out.extend(fx)
 sym=next(c for c in m.commands if c['cmd']==2);sy,ns,strs,strsz=struct.unpack_from('<4I',sym['raw'],8)
 tab=b[sy:sy+16*ns];strings=b[strs:strs+strsz]
 ds=next(c for c in m.commands if c['cmd']==11);fields=list(struct.unpack('<20I',ds['raw']))
 need(fields[6]+fields[7]==ns,'terminal old undefined nlist rows')
 out.extend(b'\0'*(align(len(out))-len(out)));newsym=len(out);out.extend(tab)
 out.extend(struct.pack('<IBBHQ',len(strings),1,0,10<<8,0));newstrings=len(out);out.extend(strings+name)
 commands=[]
 for c in m.commands:
  if c['cmd']==0x1d:continue
  x=bytearray(c['raw'])
  if c['cmd']==0x80000034:struct.pack_into('<II',x,8,newoff,len(fx))
  if c['cmd']==2:struct.pack_into('<4I',x,8,newsym,ns+1,newstrings,len(strings)+len(name))
  if c['cmd']==11:struct.pack_into('<I',x,28,fields[7]+1)
  if c['cmd']==0x19 and x[8:24].rstrip(b'\0')==b'__LINKEDIT':
   fileoff=struct.unpack_from('<Q',x,40)[0];extent=len(out)-fileoff
   struct.pack_into('<Q',x,32,(extent+16383)&~16383);struct.pack_into('<Q',x,48,extent)
  commands.append(bytes(x))
 header=b''.join(commands);need(32+len(header)<=4088,'existing PG load-command capacity')
 out[32:4088]=header+b'\0'*(4088-32-len(header));struct.pack_into('<II',out,16,len(commands),len(header))
 q=M(out);need(q.uuid==m.uuid and q.exports==m.exports,'PG original UUID and exports')
 need([(x['path'],x['cmd'])for x in q.loads]==[(x['path'],x['cmd'])for x in m.loads],'all existing PG required loads')
 need(len(q.imports)==267 and q.imports[-1]['name']==SYMBOL and q.imports[-1]['ordinal']==10 and
      not q.imports[-1]['weak'] and q.imports[-1]['addend']==0,'one new exact MD import')
 for x,y in zip(m.imports,q.imports[:266],strict=True):
  need(all(x[k]==y[k]for k in ['index','ordinal','weak','name','addend']),'old PG import semantics')
 for s in m.sections:
  lo=s['fileoff'];hi=lo+s['size']
  if not lo or not s['size']:continue
  expected=bytearray(b[lo:hi])
  if lo<=SLOT<hi:struct.pack_into('<Q',expected,SLOT-lo,newword)
  need(out[lo:hi]==expected,'PG section changed beyond exact auth slot: '+s['name'])
 need([(x['fileoff'],x['word'])for x in m.binds if x['fileoff']!=SLOT]==
      [(x['fileoff'],x['word'])for x in q.binds if x['fileoff']!=SLOT],'all other authenticated bindings whole')
 destination.write_bytes(out)
 return dict(original=pin(old),patched=pin(destination),selectedAuthSlots=[dict(slot=SLOT,oldWord=oldword,newWord=newword,newIndex=266)],
  newSymbols=[SYMBOL],newOrdinals=[10],all266OldImportSemanticsWhole=True,allOriginalTextAndCodeWholeUnchanged=True,
  allOldSectionsWholeExceptOneSelectedAuthSlot=True,allOtherAuthWordsWholeUnchanged=True,originalUUIDAndExportsUnchanged=True,
  allOriginalRequiredLoadsWholeUnchanged=True,oldNlistRowsWhole=True,appendedUndefinedSymbols=1,
  codeSignedByProductSigner=False,deviceOperations=0)

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--source-plan',type=pathlib.Path,required=True)
 ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();pp=a.source_plan.resolve()
 need(pp.is_relative_to(N) and pin(pp)['sha256']==PLAN_SHA,'frozen reviewed depth24 source plan')
 need(out.parent==N and not out.exists(),'fresh owned HOST output')
 p=json.loads(pp.read_bytes());base=exact(p['baselineRuntimeCandidate']);oldmd=exact(p['baselineCurrentChildMD']);oldpg=exact(p['baselineCurrentChildPG'])
 prior=json.loads(exact(p['currentMDLinkCandidate']).read_bytes())
 leaf=json.loads(exact(p['baselineMD6SourceCandidate']).read_bytes());source=exact(p['newRootCompileSource'])
 frozen_inputs=[p['baselineMD6Source'],p['sourceDiff'],p['inheritedCompile'],p['inheritedLink'],
  leaf['header'],leaf['oldMetalArraySource'],leaf['inheritedCapabilityHeader'],p['currentMDLinkCandidate'],
  p['currentMDWholeUnsignedProvider'],p['correctedBuildProvenanceFromFrozenDepth24SourcePlan'],
  *p['currentMDObjects'],*p['additionalFrozenCurrentLinkInputs'],*p['sourceFiles'],p['derivedIncludeChainDiff']]
 for row in p['derivedIncludeChain']:frozen_inputs.extend([row['original'],row['derived']])
 for row in frozen_inputs:exact(row)
 compile_record=json.loads(exact(p['inheritedCompile']).read_bytes());link_record=json.loads(exact(p['inheritedLink']).read_bytes())
 need(compile_record['exit']==link_record['exit']==0,'actual successful current MD V10 compiler and clang++ link')
 out.mkdir(mode=0o700);commands=[]
 def run(label,argv):
  z=subprocess.run(argv,capture_output=True,timeout=90)
  (out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr)
  row=dict(command=argv,exit=z.returncode);dump(out/(label+'.json'),row);commands.append(dict(label=label,**row))
  need(z.returncode==0,label+': '+z.stderr.decode(errors='replace'))
 obj=out/'modern_metal_device_array_v12.o';md=out/'MD'
 argv=list(compile_record['command']);oldsource=prior['source']['path'];oldobj=prior['actualIOSObjects'][0]['path']
 need(argv.count(oldsource)==argv.count(oldobj)==1,'exact inherited one-source current MD V10 root compiler')
 argv[argv.index(oldsource)]=str(source);argv[argv.index(oldobj)]=str(obj);run('compile',argv)
 oldlink=list(link_record['command']);exportarg=next(x for x in oldlink if x.startswith('-Wl,-exported_symbols_list,'))
 oldexports=pathlib.Path(exportarg.split(',',2)[2]);need(oldexports.is_relative_to(N),'inherited owned MD exports')
 exports=out/'exports.txt';names=oldexports.read_text().splitlines()
 need(SYMBOL not in names and names,'new unique typed depth24 export');exports.write_text('\n'.join(names+[SYMBOL])+'\n')
 argv=oldlink;need(argv.count(oldobj)==1 and argv.count(prior['newProvider']['path'])==1,'actual inherited current MD V10 link root object and output')
 argv[argv.index(oldobj)]=str(obj);argv[argv.index(prior['newProvider']['path'])]=str(md)
 argv[argv.index(exportarg)]='-Wl,-exported_symbols_list,'+str(exports)
 need([x for x in argv if x.endswith('.o')]==[str(obj)]+[r['path']for r in p['inheritedWholeLinkObjects']],
      'only current MD V10 root object replaced; actual exception bridge object and order whole')
 run('link',argv)
 before=M(oldmd.read_bytes());after=M(md.read_bytes())
 need(set(after.exports)==set(before.exports)|{SYMBOL},'one added MD export')
 for name in before.exports:need(after.exports[name]['flags']==before.exports[name]['flags'],'all original MD export kinds')
 need(after.exports[SYMBOL]['flags']==0 and import_semantics(after)==import_semantics(before),'one real typed export and native imports unchanged')
 need([(x['path'],x['cmd'])for x in after.loads]==[(x['path'],x['cmd'])for x in before.loads],'MD native Metal reexport and required loads unchanged')
 pg=out/'ParavirtualizedGraphics27.dylib';recipe=patch_pg(oldpg,pg);dump(out/'recipe.json',recipe)
 for f,label in [(pg,'pvg-validate'),(md,'md-validate')]:run(label,['xcrun','dyld_info','-validate_only',str(f)])
 contract=p[p['contractKey']]
 record=dict(schema='Actual HOST compiled owned PG depth24 capability with complete current MD linkage source port v6',
  sourcePlan=pin(pp),baselineRuntimeCandidate=pin(base),providerKey='MD',roles=['child'],source=pin(source),builder=pin(__file__),
  originalProvider=pin(oldmd),newProvider=pin(md),actualProviderPin=pin(md),originalChildPG=pin(oldpg),patchedChildPG=pin(pg),
  actualIOSObject=pin(obj),actualIOSObjects=[pin(obj),*p['inheritedWholeLinkObjects']],actualIOSCompile=pin(out/'compile.json'),actualIOSLink=pin(out/'link.json'),
  actualPGValidate=pin(out/'pvg-validate.json'),actualMDValidate=pin(out/'md-validate.json'),recipe=pin(out/'recipe.json'),
  compileLinkAndBothValidateExit=[0,0,0,0],addedExports=[SYMBOL],actualAddedPGImportCount=1,
  selectedPGImportsDefinitionCount=1,actualProviderNativeImportCount=len(after.imports),providerUUID=after.uuid,
  all266OldPGImportSemanticsWhole=True,allOtherPGAuthSlotsWhole=True,parentMDWholeUnchangedRequired=True,
  CPUAndVMMProvidersAndChildEntitlementsAndShaderUnchangedRequired=True,newRequiredLoadsAdded=0,
  globalAppleClassMutation=False,actualDeviceOperations=0,actualGuestStarted=False,codeSignedByProductSigner=False,
  contractKey=p['contractKey'],commands=commands)
 record[p['contractKey']]=contract
 record.update(currentMDLinkCandidate=p['currentMDLinkCandidate'],
  currentMDLinkagePreservedV1Contract=p['currentMDLinkagePreservedV1Contract'],
  currentMDObjects=p['currentMDObjects'],inheritedWholeLinkObjects=p['inheritedWholeLinkObjects'],
  currentMDCompilerRootSource=pin(source),depth24LeafSource=p['sourceFiles'][0],
  allEightCurrentMDExportsPreserved=True,all49CurrentMDNativeImportsAndLoadsPreserved=True,
  originalChildErrorReasonAndVMInitializationAndExceptionBridgeSemanticsWhole=True,
  originalFrozenDepth24SourcePlan=p['correctedBuildProvenanceFromFrozenDepth24SourcePlan'])
 dump(out/'candidate.json',record)
 files=[pin(f)for f in sorted(out.rglob('*'))if f.is_file()]
 files += [pin(__file__),pin(pp),pin(base),p['baselineCurrentChildMD'],p['baselineCurrentChildPG'],p['baselineMD6SourceCandidate'],
           *p['sourceFiles'],p['sourceDiff'],p['inheritedCompile'],p['inheritedLink'],pin(oldexports),
           *frozen_inputs]
 dump(out/'freeze.json',dict(files=list({r['path']:r for r in files}.values()),deviceOperations=0,codeSigningOperations=0))
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),MD=pin(md),PG=pin(pg))))
if __name__=='__main__':main()
