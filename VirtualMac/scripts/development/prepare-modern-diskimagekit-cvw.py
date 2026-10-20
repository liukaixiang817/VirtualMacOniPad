#!/usr/bin/env python3
"""Add a private positive seven-symbol DIKit27 CVW route; never execute/deploy."""
import argparse,pathlib,sys,struct,json,re,hashlib,subprocess,shutil
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);p.add_argument('--provider-build',required=True);args=p.parse_args()
r=pathlib.Path(__file__).resolve().parents[3];out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False);build=pathlib.Path(args.provider_build).resolve();source=r/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-load-only-v1/DiskImageKit27.load-only.ios.dylib';original=source.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(original)=='66a965f8fba3f3b37b1f3e51bdcfdd110b54464aea29d5189f942277ec58f1a3'
c=r/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler';sys.path.insert(0,str(c));from compiler_image import commands,segments,imports,chain_entries
names={'_swift_cvw_'+n for n in ['destroy','initWithCopy','initWithTake','assignWithCopy','assignWithTake','initializeBufferWithCopyOfBuffer','initStructMetadataWithLayoutString']};cmds=list(commands(original));loads=[q for q in cmds if q[0]in(12,0x80000018,0x8000001f,0x80000023)];assert len(loads)==12
path=b'@loader_path/VM27DIKCVW.dylib\0';length=(24+len(path)+7)&~7;command=struct.pack('<6I',12,length,24,0,0,0)+path;command+=bytes(length-len(command));end=32+struct.unpack_from('<I',original,20)[0];first=min(s['fileoff']for g in segments(original)for s in g['sections']if s['size'] and s['fileoff']);rows=imports(original)['imports'];routes=[];logs=[];files=[]
rawPath=r/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-contract-v1/DiskImageKit.raw';raw=rawPath.read_bytes();assert sha(raw)=='c223d70ea155ea329036311a55a9b430d9bc10a165728473d163b7547ec6cf91';oldSegments=segments(raw);newSegments=segments(original);oldText=oldSegments[0]['address'];newText=newSegments[0]['address']
def oldFileoff(address):
 for seg in oldSegments:
  if seg['address']<=address<seg['address']+seg['filesize']:return seg['fileoff']+address-seg['address']
 raise AssertionError(('unmapped original relative pointer',hex(address)))
def relocate(address):
 for old in oldSegments:
  if old['address']<=address<old['address']+old['filesize']:
   new=next(g for g in newSegments if g['name']==old['name']);return new['address']+address-old['address']
 raise AssertionError(('unknown original target',hex(address)))
from swift_relative_metadata import RelativeMetadata
symbols=json.loads((r/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-reflection-schema-v1/symbols.a2s.batch.json').read_text())['symbols']
metadataAudit=RelativeMetadata(raw,original);metadataAudit.singletons();metadataAudit.conformances();metadataAudit.reflection();externalTargets=sorted({q['target']for q in metadataAudit.unresolved});assert len(externalTargets)==32
externalRoutes=[]
for target in externalTargets:
 name,owner=symbols[hex(target)];assert name.startswith('__got.');name=name[6:];labels={q['label']for q in metadataAudit.unresolved if q['target']==target};assert labels<={'protocol','resilientRequirement','mangledSymbolicContextIndirect'}
 ordinal={'/usr/lib/swift/libswiftCore.dylib':5,'/usr/lib/swift/libswiftos.dylib':12,'/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation':1}[owner];externalRoutes.append({'originalSlotVA':target,'symbol':name,'owner':owner,'ordinal':ordinal,'newSlotVA':0x100017000+len(externalRoutes)*8,'authenticatedContextDescriptor':bool(labels&{'protocol','mangledSymbolicContextIndirect'}),'labels':sorted(labels)})
for role,platform,version in [('ios',2,0x100100),('mac',1,0x1b0000)]:
 b=bytearray(original);newcmds=[]
 for cmd,at,n in cmds:
  raw=bytes(original[at:at+n])
  if cmd==0xd:
   identity=b'@rpath/DiskImageKit27.dylib\0';ns=(24+len(identity)+7)&~7;raw=bytearray(raw[:24])+identity;raw+=bytes(ns-len(raw));struct.pack_into('<I',raw,4,ns)
  newcmds.append(bytes(raw))
 newcmds.append(command);joined=b''.join(newcmds);assert 32+len(joined)<=first and not any(original[end:first]);b[32:first]=joined+bytes(first-32-len(joined));struct.pack_into('<II',b,16,len(newcmds),len(joined))
 activecmds=list(commands(b))
 for cmd,at,n in activecmds:
  if cmd==0x32:struct.pack_into('<III',b,at+8,platform,version,version)
 current=[]
 for row in rows:
  if row['name']in names:
   assert row['ordinal']==5 and not row['weak'];old=struct.unpack_from('<I',b,row['command'])[0];new=(old&~0x1ff)|13;struct.pack_into('<I',b,row['command'],new);current.append({'symbol':row['name'],'importIndex':row['index'],'beforeOrdinal':5,'afterOrdinal':13,'strong':True})
 assert len(current)==7
 # dyld resolves every chained import row, including unused rows. The exact
 # original empty ivar cstrings were already localized in load-only v1; remove
 # their now-unreferenced '?' row instead of binding it to an invented symbol.
 info=imports(b);question=[x for x in info['imports']if x['name']=='?'];assert len(question)==1;hole=question[0]['index'];assert not any(x.get('symbol')=='?'for x in chain_entries(b));entries=list(chain_entries(b));start=question[0]['command'];last=info['data']+info['header'][2]+len(info['imports'])*4;b[start:last-4]=b[start+4:last];b[last-4:last]=bytes(4);struct.pack_into('<I',b,info['data']+16,len(info['imports'])-1)
 for entry in entries:
  if entry['bind'] and entry['import_index']>hole:struct.pack_into('<Q',b,entry['fileoff'],entry['word']-1)
 assert not any(x['name']=='?'for x in imports(b)['imports'])
 for cmd,at,n in activecmds:
  if cmd==2:
   symoff,nsyms,stroff,strsize=struct.unpack_from('<4I',b,at+8)
   for i in range(nsyms):
    off=symoff+i*16;strx,typ,sect,desc,val=struct.unpack_from('<IBBHQ',b,off);name=b[stroff+strx:b.find(b'\0',stroff+strx,stroff+strsize)].decode()
    if name in names and not(typ&0xe):assert desc>>8==5;struct.pack_into('<H',b,off+6,(desc&0xff)|13<<8)
 # Localize the original shared-cache indirect slots into reserved, mapped,
 # initially zero bytes. Bind each real data symbol to its proven native owner.
 assert not any(b[0x17000:0x17000+len(externalRoutes)*8]);info=imports(b);oldBlob=bytes(b[info['data']:info['data']+info['size']]);oldCount=len(info['imports']);prefix=bytearray(oldBlob[:info['header'][2]]);symbolPool=bytearray(oldBlob[info['header'][3]:]);importWords=bytearray(b[info['data']+info['header'][2]:info['data']+info['header'][2]+oldCount*4]);newMap={}
 for i,route in enumerate(externalRoutes):
  name=route['symbol'].encode()+b'\0';nameOffset=len(symbolPool);symbolPool+=name;importWords+=struct.pack('<I',(nameOffset<<9)|route['ordinal']);index=oldCount+i;word=(1<<62)|((1 if i+1<len(externalRoutes) else 0)<<51)|index
  if route['authenticatedContextDescriptor']:word|=(1<<63)|(0xae86<<32)|(1<<48)|(2<<49)
  struct.pack_into('<Q',b,0x17000+i*8,word);newMap[route['originalSlotVA']]=route['newSlotVA']
 starts=info['header'][1];segrel=struct.unpack_from('<I',prefix,starts+8)[0];startInfo=starts+segrel;assert struct.unpack_from('<H',prefix,startInfo+20)[0]==2;assert struct.unpack_from('<H',prefix,startInfo+24)[0]==0xffff;struct.pack_into('<H',prefix,startInfo+24,0x3000)
 for cmd,at,n in activecmds:
  if cmd==0x19:
   # The synthetic __got section already begins before these reserved bytes.
   name=bytes(b[at+8:at+24]).split(b'\0')[0].decode()
   if name=='__DATA_CONST':
    count=struct.unpack_from('<I',b,at+64)[0]
    for j in range(count):
     section=at+72+j*80
     if bytes(b[section:section+16]).split(b'\0')[0]==b'__got':address=struct.unpack_from('<Q',b,section+32)[0];struct.pack_into('<Q',b,section+40,0x100017000+len(externalRoutes)*8-address)
 audit=RelativeMetadata(rawPath.read_bytes(),b);audit.singletons();audit.conformances(newMap);audit.reflection(newMap);assert not audit.unresolved;b=bytearray(audit.apply())
 struct.pack_into('<I',prefix,12,len(prefix)+len(importWords));struct.pack_into('<I',prefix,16,oldCount+len(externalRoutes));newBlob=prefix+importWords+symbolPool
 signature=next(at for cmd,at,n in activecmds if cmd==0x1d);signatureOffset=struct.unpack_from('<I',b,signature+8)[0];b=b[:signatureOffset];newOffset=len(b);b+=newBlob;struct.pack_into('<II',b,signature+8,0,0)
 for cmd,at,n in activecmds:
  if cmd==0x80000034:struct.pack_into('<II',b,at+8,newOffset,len(newBlob))
  if cmd==0x19 and bytes(b[at+8:at+24]).split(b'\0')[0]==b'__LINKEDIT':fileoff=struct.unpack_from('<Q',b,at+40)[0];filesize=len(b)-fileoff;struct.pack_into('<Q',b,at+32,(filesize+0x3fff)&~0x3fff);struct.pack_into('<Q',b,at+48,filesize)
 # Remove the obsolete signature command before codesign creates a fresh
 # signature after the appended fixup blob. Preserve all other command bytes.
 oldEnd=32+struct.unpack_from('<I',b,20)[0];kept=[bytes(b[at:at+n])for cmd,at,n in commands(b)if cmd!=0x1d];joined=b''.join(kept);b[32:oldEnd]=joined+bytes(oldEnd-32-len(joined));struct.pack_into('<II',b,16,len(kept),len(joined))
 target=out/role;target.mkdir();binary=target/'DiskImageKit27.dylib';binary.write_bytes(b);provider=target/'VM27DIKCVW.dylib';shutil.copy2(build/('VM27DIKCVW-'+role+'.dylib'),provider)
 for label,argv in [('sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)]),('strict',['codesign','--verify','--strict',str(binary)]),('dyld',['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(binary)]),('signature',['codesign','-d','--verbose=4',str(binary)])]:
  z=subprocess.run(argv,capture_output=True,text=True,timeout=60);logs.append({'role':role,'label':label,'argv':argv,'exit':z.returncode,'stdout':z.stdout,'stderr':z.stderr});assert z.returncode==0,z.stderr
 final=binary.read_bytes();code=[]
 for g in segments(original):
  for s in g['sections']:
   if s['flags']&0x80000000:assert original[s['fileoff']:s['fileoff']+s['size']]==final[s['fileoff']:s['fileoff']+s['size']];code.append({'section':s['name'],'sha256':sha(final[s['fileoff']:s['fileoff']+s['size']])})
 # Bind-site offsets, payloads and PAC discriminators are untouched.
 beforeSites=list(chain_entries(original));afterSites=list(chain_entries(final));assert len(afterSites)==len(beforeSites)+len(externalRoutes)
 afterLookup={q['fileoff']:q for q in afterSites}
 for a in beforeSites:
  z=afterLookup[a['fileoff']]
  assert a['fileoff']==z['fileoff'] and a['symbol']==z['symbol']
  assert (a['word']^z['word'])&~0xffff==0
  assert z['word']==a['word']-(1 if a['bind'] and a['import_index']>hole else 0)
 files.append({'role':role,'image':str(binary),'bytes':len(final),'sha256':sha(final),'cdhash':re.search(r'CDHash=(\w+)',logs[-1]['stderr'])[1],'providerSHA256':sha(provider.read_bytes()),'routes':current,'instructionSections':code})
manifest={'originalDIKitUUID':'652b07a998be31d298d7ffcaf14aca5e','source':str(source),'sourceSHA256':sha(original),'newStrongProvider':path[:-1].decode(),'newDylibIdentity':'@rpath/DiskImageKit27.dylib','loadCommandCompaction':'LC_ID_DYLIB path shortened, command blocks repacked without section movement','providerOrdinal':13,'sevenPositiveRoutes':True,'allOtherImportSemanticsUnchanged':True,'allExistingBindPACAndNextBitsUnchanged':True,'unusedQuestionImportRowRemoved':12,'bindIndexesAboveRemovedRowReindexed':True,'instructionSectionsUnchangedFromReconstructedSource':True,'swiftMetadataRelativeSchemaRepairs':audit.rows,'externalSwiftMetadataPositiveDataRoutes':externalRoutes,'rawOriginalSHA256':sha(rawPath.read_bytes()),'nativeMetadataExecution':False,'deviceExecuted':False,'fullFrameworkClosure':False,'files':files};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n');print(json.dumps(manifest,indent=2))
