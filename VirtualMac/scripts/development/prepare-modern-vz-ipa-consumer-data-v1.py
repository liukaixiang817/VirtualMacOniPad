#!/usr/bin/env python3
"""Prepare inert original27 VZ bytes: only import559 routes to genuine own IPA.

No image is loaded, signed, deployed or executed. Existing header space is
reclaimed by an explicit byte-exact title provider alias and vmnet NUL tail.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER=N/'vz-typed-routes-independent-review-v1/review.py'
READER_SHA='a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
SOURCE=N/'vz-process-title-original-route-v1/build-v2/VZ27.private-process-title.inert.macho-data'
SOURCE_SHA='7c566270f72901fc1f40d639d04c51c598d0c3df2c24ed760825cd8f41b4ae36'
IPA=N/'hv-ipa-native-provider-contract-v1/ios/VM27IPALimit.dylib'
IPA_SHA='f1d29e35c023b6c8606a641b66f1fb2b3540fff91e23d3e7fe8af7025705ad54'
TITLE=N/'process-title-state-contract-v1/ios/VM27PrivateProcessTitle.dylib'
TITLE_SHA='0e4654ed43bfeb38d4df18a60186079105a8c8fc69c6191978158263f5baf300'
PATH='@loader_path/VM27IPALimit.dylib';TITLE_PATH='@loader_path/VT'
SYMBOL='_hv_vm_config_get_max_ipa_size'
assert hashlib.sha256(READER.read_bytes()).hexdigest()==READER_SHA
s=importlib.util.spec_from_file_location('bounded_original_vz_reader',READER);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def commands(b):
 assert len(b)>=32 and struct.unpack_from('<I',b)[0]==0xfeedfacf
 count,size=struct.unpack_from('<II',b,16);assert 0<count<256 and 32+size<=len(b)
 at=32;rows=[]
 for _ in range(count):
  cmd,z=struct.unpack_from('<II',b,at);assert z>=8 and z%8==0 and z<=32+size-at
  rows.append((cmd,at,z));at+=z
 assert at==32+size;return rows
def uleb(b,at,end):
 value=0
 for shift in range(0,64,7):
  assert at<end;x=b[at];at+=1
  if shift==63:assert x<2
  value|=(x&127)<<shift
  if not x&128:return value,at
 raise AssertionError('ULEB overflow')
def provider(b,sha,name,uuid,exports):
 assert m.sha(b)==sha;ids=[];deps=[];uuids=[];build=[];trie=None;init=[];chain=None
 for cmd,at,z in commands(b):
  if cmd in m.DEP_COMMANDS or cmd==13:
   off,t,cur,comp=struct.unpack_from('<4I',b,at+8);assert 24<=off<z
   path,_=m.checked_string(b,at+off,at+z);(ids if cmd==13 else deps).append(dict(cmd=cmd,path=path,versions=[t,cur,comp]))
  elif cmd==0x1b:assert z==24;uuids.append(b[at+8:at+24].hex())
  elif cmd==0x32:build.append(list(struct.unpack_from('<4I',b,at+8)))
  elif cmd==0x80000033:assert z==16 and trie is None;trie=struct.unpack_from('<II',b,at+8)
  elif cmd==0x80000022:
   info=struct.unpack_from('<10I',b,at+8);assert trie is None;trie=info[8:10]
  elif cmd==0x80000034:assert chain is None;chain=struct.unpack_from('<II',b,at+8)
  elif cmd==0x19:
   ns=struct.unpack_from('<I',b,at+64)[0];assert z==72+ns*80
   for k in range(ns):
    a=at+72+k*80;flags=struct.unpack_from('<I',b,a+64)[0];size=struct.unpack_from('<Q',b,a+40)[0]
    if flags&255 in (9,10):init.append(size)
 assert ids==[dict(cmd=13,path='@rpath/'+name,versions=[1,65536,65536])] and uuids==[uuid]
 assert build[0][:2]==[2,1048832] and len(build)==1 and not init
 assert trie and len(deps)==1 and deps[0]['cmd']==12 and deps[0]['path']=='/usr/lib/libSystem.B.dylib'
 start,size=trie;assert start+size<=len(b) and size>0;found={};seen=set()
 def node(offset,prefix):
  assert 0<=offset<size and offset not in seen and len(prefix)<512;seen.add(offset)
  terminal,at=uleb(b,start+offset,start+size);end=at+terminal;assert end<=start+size
  if terminal:
   flags,at=uleb(b,at,end);address,at=uleb(b,at,end);assert flags==0 and address>0 and at==end and prefix not in found;found[prefix]=address
  assert end<start+size;n=b[end];at=end+1;links=[]
  for _ in range(n):
   edge,at=m.checked_string(b,at,start+size);child,at=uleb(b,at,start+size);assert edge;links.append((child,prefix+edge))
  for child,prefix in links:node(child,prefix)
 node(0,'');assert set(found)==set(exports)
 return dict(ID=ids[0],UUID=uuid,exports=found,strongDependencies=deps,build=build[0],initializers=0)
def derive(source):
 assert len(source)==4212080 and m.sha(source)==SOURCE_SHA;a=m.parse(source)
 assert a['header'][3:5]==[79,9552] and len(a['deps'])==60
 raws=[]
 for row in a['commands']:
  raw=row['raw']
  if row.get('ordinal')==24:
   assert row['name']=='@loader_path/VM27PrivateProcessTitle.dylib' and row['size']==88 and row['versions']==[2,80347136,65536]
   path=TITLE_PATH.encode()+b'\0';raw=bytearray(raw[:24]+path+bytes(40-24-len(path)));assert len(raw)==40;struct.pack_into('<I',raw,4,40);raw=bytes(raw)
  elif row.get('ordinal')==30:
   assert row['name']=='@loader_path/VM27VMNetUnavailable.dylib' and row['size']==80 and row['raw'][64:]==bytes(16)
   raw=bytearray(raw[:64]);struct.pack_into('<I',raw,4,64);raw=bytes(raw)
  raws.append(raw)
 path=PATH.encode()+b'\0';assert (24+len(path)+7)&~7==56
 raws.append(struct.pack('<6I',12,56,24,2,65536,65536)+path+bytes(56-24-len(path)))
 block=b''.join(raws);assert len(block)==9544
 out=bytearray(source);out[32:9584]=block+bytes(8);struct.pack_into('<II',out,16,80,9544)
 selected=a['imports'][559];assert selected['name']==SYMBOL and selected['ordinal']==26 and not selected['weak'] and selected['addend']==0
 out[selected['at']]=61
 nl=[r for r in a['nlists']if r['name']==SYMBOL];assert len(nl)==1 and nl[0]['type']==1 and nl[0]['section']==nl[0]['value']==0 and nl[0]['desc']==26<<8
 out[nl[0]['at']+7]=61;return bytes(out)
def verify(source,output,ipa,title):
 ip=provider(ipa,IPA_SHA,'VM27IPALimit.dylib','7896f54f5b3a3969a2b31dbe3b240b90',[SYMBOL,'_VZFrameworkCopyMaxIPANativeReceiptV1'])
 # Title imports CoreFoundation; the already independently frozen whole-file
 # pin is checked here. Parse its exact own ID/UUID directly without borrowing
 # the IPA provider's narrower dependency assumptions.
 assert m.sha(title)==TITLE_SHA
 titleids=[];titleuuids=[]
 for c,at,z in commands(title):
  if c==13:
   off,t,cur,compat=struct.unpack_from('<4I',title,at+8);name,_=m.checked_string(title,at+off,at+z);titleids.append([name,t,cur,compat])
  if c==0x1b:titleuuids.append(title[at+8:at+24].hex())
 assert titleids==[['@rpath/VM27PrivateProcessTitle.dylib',1,65536,65536]] and titleuuids==['af3943239b763dfd950771718607b9c9']
 assert output==derive(source);a=m.parse(source);b=m.parse(output)
 assert len(output)==len(source) and b['header'][3:5]==[80,9544] and b['segments']==a['segments'] and b['words']==a['words'] and len(b['words'])==26993
 assert output[9576:9584]==bytes(8) and len(b['deps'])==61 and len(b['imports'])==len(a['imports'])==1056
 for x,y in zip(a['deps'],b['deps']):
  assert x['ordinal']==y['ordinal'] and x['cmd']==y['cmd'] and x['versions']==y['versions'] and x['nameOffset']==y['nameOffset']
  assert y['name']==(TITLE_PATH if x['ordinal']==24 else x['name'])
 assert b['deps'][-1]['name']==PATH and b['deps'][-1]['cmd']==12 and b['deps'][-1]['versions']==[2,65536,65536]
 for x,y in zip(a['imports'],b['imports']):
  expect=dict(x)
  if x['index']==559:expect['ordinal']=61
  assert y==expect
 for x,y in zip(a['nlists'],b['nlists']):
  expect=dict(x)
  if x['name']==SYMBOL:expect['desc']=61<<8
  assert y==expect
 for sg in a['segments']:
  for sec in sg['sections']:
   at,size=sec['at'],sec['bytes']
   if at and size and sec['flags']&255 not in (1,12,18):assert source[at:at+size]==output[at:at+size]
 nl=next(r for r in a['nlists']if r['name']==SYMBOL)
 outside=[i for i,(x,y)in enumerate(zip(source,output))if x!=y and i>=9584];assert outside==sorted([a['imports'][559]['at'],nl['at']+7])
 assert a['imports'][560]==b['imports'][560] and b['imports'][560]['ordinal']==60 and a['deps'][25]['name']==b['deps'][25]['name']
 return dict(selectedImport=b['imports'][559],onlyChangesAfterOriginalHeader=outside,chainAndPACWordsExact=26993,allCodeAndDataSectionsExact=True,
  maxCPUImport560Unchanged=True,originalHVDependencyRetained=True,headerOldBytes=9552,headerNewBytes=9544,newHeaderPaddingBytes=8,
  titlePathExplicitlyChanged=dict(ordinal=24,old=a['deps'][23]['name'],new=TITLE_PATH,oldCommandBytes=88,newCommandBytes=40,versionAndStrongImportSemanticsUnchanged=True),
  vmnetOnlyOriginalTrailingNULCompacted=dict(ordinal=30,bytes=16,oldCommandBytes=80,newCommandBytes=64,pathUnchanged=True),
  addedStrongDependency=dict(ordinal=61,path=PATH,bytes=56,compatibility=65536),ipaProvider=ip,
  titleAliasOriginalID=titleids[0],titleAliasOriginalUUID=titleuuids[0],signatureStale=True,originalImageLoaded=False,full27Backend=False)
def negatives(source,output,ipa,title):
 a=m.parse(output);cases=[]
 def bad(label,b,p=ipa,t=title):
  try:verify(source,b,p,t)
  except (AssertionError,ValueError,IndexError,struct.error):cases.append(dict(name=label,rejected=True));return
  raise AssertionError('Accepted '+label)
 nl=next(r for r in a['nlists']if r['name']==SYMBOL);chain=next(r for r in a['words']if r['bind']and r['index']==559)
 for label,at,mask in [('IPA ordinal',a['imports'][559]['at'],1),('IPA weak',a['imports'][559]['at']+1,1),('IPA addend',a['imports'][559]['at']+4,1),('IPA nlist',nl['at']+7,1),
  ('maxCPU preserved',a['imports'][560]['at'],1),('PAC',chain['at']+7,128),('text',9584,1),('header padding',9576,1),('title alias',a['deps'][23]['at']+24,1),
  ('vmnet path',a['deps'][29]['at']+24,1),('EFI path',a['deps'][31]['at']+24,1),('old HV path',a['deps'][25]['at']+24,1),('new dependency',a['deps'][-1]['at']+24,1),
  ('new minversion',a['deps'][-1]['at']+20,1),('old typed route',a['imports'][42]['at'],1),('header count',16,1),('header bytes',20,1)]:
  b=bytearray(output);b[at]^=mask;bad(label,bytes(b))
 b=bytearray(output);struct.pack_into('<I',b,a['deps'][-1]['at'],0x80000018);bad('weak load',bytes(b))
 p=bytearray(ipa);p[-1]^=1;bad('IPA provider changed',output,bytes(p))
 t=bytearray(title);t[-1]^=1;bad('title alias changed',output,ipa,bytes(t));bad('trailing bytes',output+b'\0')
 return cases
def ordinary(p,expected):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not p.is_symlink() and p.read_bytes()==expected
def run(out,check):
 source=SOURCE.read_bytes();ipa=IPA.read_bytes();title=TITLE.read_bytes();target=out/'VZ27.ipa-native-route.inert.macho-data'
 if check:
  c=m.json_read(out/'candidate.json');assert c['builder']==m.pin(pathlib.Path(__file__)) and c['reader']==m.pin(READER)
  assert c['source']==m.pin(SOURCE) and c['IPA']==m.pin(IPA) and c['title']==m.pin(TITLE)
  output=target.read_bytes();assert c['target']==m.pin(target);ordinary(out/'VT',title);ordinary(out/'VM27IPALimit.dylib',ipa)
  assert c['verification']==verify(source,output,ipa,title);print(json.dumps(dict(checkPassed=True,target=m.pin(target))));return
 assert not out.exists();out.mkdir(parents=True,mode=0o700);output=derive(source);target.write_bytes(output);target.chmod(0o600)
 for name,b in [('VT',title),('VM27IPALimit.dylib',ipa)]:
  p=out/name
  with p.open('xb')as f:f.write(b)
  p.chmod(0o600);ordinary(p,b)
 proof=verify(source,output,ipa,title);bad=negatives(source,output,ipa,title)
 metadata=subprocess.run(['xcrun','dyld_info','-platform','-dependents','-imports','-validate_only',str(target)],capture_output=True)
 (out/'metadata.stdout').write_bytes(metadata.stdout);(out/'metadata.stderr').write_bytes(metadata.stderr);assert metadata.returncode==0
 c=dict(schema='Original VZ single genuine IPA import inert route v1',builder=m.pin(pathlib.Path(__file__)),reader=m.pin(READER),source=m.pin(SOURCE),IPA=m.pin(IPA),title=m.pin(TITLE),target=m.pin(target),
  aliases=[dict(name='VT',copy=m.pin(out/'VT'),original=m.pin(TITLE),nlink=1,ordinary=True,providerIDAndUUIDUnchanged=True),dict(name='VM27IPALimit.dylib',copy=m.pin(out/'VM27IPALimit.dylib'),original=m.pin(IPA),nlink=1,ordinary=True,providerLeafNamePreservedForOwnFrame=True)],
  verification=proof,badControls=bad,metadataExit=metadata.returncode,deviceOperations=0,originalVZLoaded=False,guestInstructions=0,signatureStale=True,
  actualIOSProviderReceiptNotYetAttached=True,CPUAndVMCreated=False,full27Backend=False)
 (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
 files=[m.pin(p)for p in sorted(out.rglob('*'))if p.is_file()];files.extend(m.pin(p)for p in [pathlib.Path(__file__),READER,SOURCE,IPA,TITLE])
 (out/'freeze.json').write_text(json.dumps(dict(schema='Original VZ IPA inert route local freeze v1',files=files),indent=2)+'\n')
 print(json.dumps(dict(candidate=m.pin(out/'candidate.json'),target=m.pin(target),freeze=m.pin(out/'freeze.json'),badControls=len(bad),files=len(files))))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--out',required=True,type=pathlib.Path);ap.add_argument('--check',action='store_true');args=ap.parse_args();run(args.out.resolve(),args.check)
