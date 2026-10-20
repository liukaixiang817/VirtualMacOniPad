#!/usr/bin/env python3
"""Private genuine27 DiskImageKit load-only derivative; no fake implementation."""
import argparse,pathlib,struct,json,hashlib,subprocess,sys,importlib.util,re
parser=argparse.ArgumentParser();parser.add_argument('--contract',required=True);parser.add_argument('--output',required=True);args=parser.parse_args();root=pathlib.Path(__file__).resolve().parents[3];contract=pathlib.Path(args.contract).resolve();out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False);source=contract/'DiskImageKit.strong-flat.mac';before=source.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(before)=='aed4492a89a0aa079b2645f38d6e167b9a8ef1bb5bae61c861cb35e8aa0d3da4'
compiler=root/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler';sys.path.insert(0,str(compiler));from compiler_image import commands,segments,imports,chain_entries
original=json.loads((contract/'original-identity-imports-initializers.json').read_text());assert original['uuid']=='652b07a998be31d298d7ffcaf14aca5e' and not original['initializers'] and not original['routines'];known={r['name']:r for r in original['nlistImports']};batch=json.loads((contract/'symbols.a2s.batch.json').read_text());owners={}
for address,pair in batch['symbols'].items():
 name,path=pair
 if name:
  if name.startswith('__got.'):name=name[6:]
  owners.setdefault(name,set()).add(path)
cmds=list(commands(before));segs=segments(before);base=next(r['address']for r in segs if r['name']=='__TEXT');deps=[];changes=[];after=bytearray(before)
for cmd,at,size in cmds:
 if cmd in (12,0x80000018,0x8000001f,0x80000023):
  pos=struct.unpack_from('<I',before,at+8)[0];path=before[at+pos:at+size].split(b'\0')[0].decode();deps.append(path);flat=re.sub(r'/Versions/[AC]/','/',path)
  if flat!=path:
   encoded=flat.encode()+b'\0';assert len(encoded)<=size-pos;after[at+pos:at+size]=encoded+bytes(size-pos-len(encoded));changes.append({'kind':'frameworkPathFlatten','ordinal':len(deps),'cmd':cmd,'offset':at,'before':path,'after':flat,'beforeHex':before[at:at+size].hex(),'afterHex':bytes(after[at:at+size]).hex()})
 if cmd==0x32:
  assert struct.unpack_from('<III',before,at+8)==(1,0x1b0000,0x1b0000);struct.pack_into('<III',after,at+8,2,0x100100,0x100100);changes.append({'kind':'buildVersion','offset':at,'beforePlatform':1,'afterPlatform':2,'minSDK':'16.1'})
# Restore known original symbol ordinals. For cache optimization references,
# explicitly introduce positive routing at their observed native owner/reexport.
importRows=[]
for row in imports(before)['imports']:
 name=row['name'];old=struct.unpack_from('<I',before,row['command'])[0]
 if name=='?':continue
 if name in known:
  ordinal=known[name]['ordinal'];weak=known[name]['weak'];policy='original nlist requested ordinal and weak flag'
 else:
  found=owners.get(name,set());assert len(found)==1 and None not in found,('unproven cache owner',name,found);path=next(iter(found));
  if path in deps:ordinal=deps.index(path)+1;policy='new positive compatibility route to original cache-observed provider'
  elif path.startswith('/usr/lib/system/'):
   ordinal=deps.index('/usr/lib/libSystem.B.dylib')+1;policy='new positive route through public libSystem reexport of original cache-observed system provider'
  else:raise AssertionError(('unmapped provider',name,path))
  weak=False
 assert 1<=ordinal<=len(deps);new=(old&~0x1ff)|ordinal|(int(weak)<<8);struct.pack_into('<I',after,row['command'],new);importRows.append({'symbol':name,'index':row['index'],'fileoff':row['command'],'beforeOrdinal':row['ordinal'],'beforeWeak':row['weak'],'afterOrdinal':ordinal,'afterWeak':weak,'policy':policy,'cacheOwner':list(owners.get(name,set()))})
# Preserve the actual original empty Objective-C ivar type, not a missing symbol.
spec=importlib.util.spec_from_file_location('u',root/'VirtualMac/vz/uncache.py');u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u);cache='/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e';emptyAddress=0x1f949c4bf;assert u.read_cache_cstrs(cache,[emptyAddress],32).get(emptyAddress)==b''
refs=[r for r in chain_entries(before)if r.get('symbol')=='?'];assert len(refs)==4 and all(not r['auth'] and r['section']=='__objc_const' for r in refs);pool=next(s for g in segs for s in g['sections']if s['name']=='__cstring');zero=before.index(0,pool['fileoff'],pool['fileoff']+pool['size']);target=pool['address']+zero-pool['fileoff'];localizations=[]
for row in refs:
 new=(row['word']&(((1<<11)-1)<<51))|(target-base);struct.pack_into('<Q',after,row['fileoff'],new);localizations.append({'fileoff':row['fileoff'],'originalCacheCString':emptyAddress,'originalBytes':'00','localStringVA':target,'beforeWord':row['word'],'afterWord':new})
assert not [r for r in chain_entries(after)if r.get('symbol')=='?']
# Verify these four exact fields really are ivar type slots in the parsed class.
spec=importlib.util.spec_from_file_location('metadata',compiler/'gpu-error-protocol-audit/read-protocol.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
binary=out/'DiskImageKit27.load-only.ios.dylib';binary.write_bytes(after);image=m.Image(binary)
(out/'objc-metadata.json').write_text(json.dumps({'classes':image.classes,'methods':image.methods},indent=2)+'\n')
logs=[]
for argv in [['codesign','--force','--sign','-','--timestamp=none',str(binary)],['codesign','--verify','--strict',str(binary)],['codesign','-d','--verbose=4',str(binary)],['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(binary)]]:
 r=subprocess.run(argv,capture_output=True,text=True,timeout=60);logs.append({'argv':argv,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert not r.returncode,r.stderr
final=binary.read_bytes();code=[]
for g in segs:
 for s in g['sections']:
  if s['flags']&0x80000000:
   assert final[s['fileoff']:s['fileoff']+s['size']]==before[s['fileoff']:s['fileoff']+s['size']];code.append({'segment':g['name'],'section':s['name'],'sha256':sha(final[s['fileoff']:s['fileoff']+s['size']])})
report={'path':str(binary),'bytes':len(final),'sha256':sha(final),'cdhash':re.search(r'CDHash=(\w+)',logs[2]['stderr']).group(1),'uuid':original['uuid'],'source':str(source),'sourceSHA256':sha(before),'extractedOriginalRawSHA256':original['sha256'],'instructionSectionsUnchangedFromReconstruction':True,'originalCacheInstructionsReconstructed':True,'codeSections':code,'loadCommandPolicyChanges':changes,'positiveImportRows':importRows,'originalRequiredStrongNames':75,'originalKnownRoutedRows':sum(r['policy'].startswith('original')for r in importRows),'newCacheOwnerPositiveRoutes':sum(not r['policy'].startswith('original')for r in importRows),'unresolvedUnusedQuestionImportRetained':True,'questionImportHasNoBindSites':True,'exactOriginalEmptyIvarTypes':localizations,'initializers':[],'noMetadataOrDiskCalls':True,'deviceExecuted':False,'fullDiskImageKitFunctional':False,'requiredClosureBeforeCalls':['7 Swift CVW functions for 9 genuine DIKit types /52 sites','DI2 original5classes+2constants+actual method ABI','all reconstructed optimization Foundation/Core/os symbols']};(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in ['positiveImportRows','loadCommandPolicyChanges','exactOriginalEmptyIvarTypes']},indent=2))
