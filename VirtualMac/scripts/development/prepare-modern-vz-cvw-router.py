#!/usr/bin/env python3
"""New strong positive VZ-only provider route for its six CVW import records."""
import argparse,pathlib,hashlib,json,struct,subprocess,re
parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--provider',required=True);parser.add_argument('--output',required=True);args=parser.parse_args();source=pathlib.Path(args.input).resolve();provider=pathlib.Path(args.provider).resolve();out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False);before=source.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(before)=='6ed244db9adf72ce5362b6daf7e412273ec2d5021bdd4d174c03e4c074a6dfb6','requires frozen USB-off VZ input'
assert sha(provider.read_bytes())=='49bb11d6417a93bc6d8c63f5505a98c6b718747cd64d8c7c6945322c1f2aa826','requires native-tested three-type CVW router v1'
expected={'_swift_cvw_initializeBufferWithCopyOfBuffer','_swift_cvw_destroy','_swift_cvw_initWithCopy','_swift_cvw_assignWithCopy','_swift_cvw_assignWithTake','_swift_cvw_enumFn_getEnumTag'}
ncmd,size=struct.unpack_from('<II',before,16);at=32;commands=[];sections=[];first=None;fix=None;uuid=None;ordinal=0;symtab=None
for i in range(ncmd):
 cmd,length=struct.unpack_from('<II',before,at);assert length>=8 and length%8==0
 commands.append({'index':i,'offset':at,'cmd':cmd,'bytes':length,'hex':before[at:at+length].hex()})
 if cmd in (12,0x80000018,0x8000001f,0x80000023):ordinal+=1
 if cmd==0x1b:uuid=before[at+8:at+24].hex()
 if cmd==0x80000034:fix=struct.unpack_from('<II',before,at+8)
 if cmd==2:symtab=struct.unpack_from('<4I',before,at+8)
 if cmd==25:
  for j in range(struct.unpack_from('<I',before,at+64)[0]):
   so=at+72+j*80;name=before[so:so+16].rstrip(b'\0').decode();seg=before[so+16:so+32].rstrip(b'\0').decode();lengthSec=struct.unpack_from('<Q',before,so+40)[0];pos=struct.unpack_from('<I',before,so+48)[0];flags=struct.unpack_from('<I',before,so+64)[0]
   if pos and flags&255 not in (1,12,18):sections.append({'segment':seg,'section':name,'offset':pos,'bytes':lengthSec,'sha256':sha(before[pos:pos+lengthSec])});first=min(pos,first if first else pos)
 at+=length
assert at==32+size and uuid=='418efc4809d93606918eb6f95baeffdc' and fix and symtab
name=b'@loader_path/VM27VZCVW.dylib\0';length=(24+len(name)+7)&~7;newOrdinal=ordinal+1;assert newOrdinal<128 and at+length<=first and not any(before[at:at+length])
command=struct.pack('<6I',12,length,24,2,0x10000,0x10000)+name+bytes(length-24-len(name));after=bytearray(before);after[at:at+length]=command;struct.pack_into('<II',after,16,ncmd+1,size+length)
fixpos,fixlength=fix;version,starts,imports,symbols,count,fmt,sfmt=struct.unpack_from('<7I',before,fixpos);assert version==0 and fmt==1 and sfmt==0
changes=[]
for i in range(count):
 pos=fixpos+imports+4*i;word=struct.unpack_from('<I',before,pos)[0];no=word>>9;string=fixpos+symbols+no;symbol=before[string:before.index(b'\0',string)].decode()
 if symbol not in expected:continue
 assert word&255==254 and (word>>8)&1==1
 new=(word&~0x1ff)|newOrdinal;struct.pack_into('<I',after,pos,new);changes.append({'index':i,'fileoff':pos,'symbol':symbol,'beforeOrdinal':254,'beforeOrdinalMeaning':'DYLD_CHAINED_SYMBOL_LOOKUP flat','beforeWeak':True,'afterOrdinal':newOrdinal,'afterWeak':False,'beforeWord':word,'afterWord':new,'oldPositiveOriginalSourceOrdinal':37,'newPolicy':'explicit app-private true typed implementation for VZ only'})
assert {r['symbol']for r in changes}==expected and len(changes)==6
symoff,nsyms,stroff,strsize=symtab;nlistChanges=[]
for i in range(nsyms):
 pos=symoff+i*16;strx,kind,sect,desc,value=struct.unpack_from('<IBBHQ',before,pos)
 if kind&0xe!=0:continue
 string=stroff+strx;symbol=before[string:before.index(b'\0',string)].decode()
 if symbol not in expected:continue
 new=(desc&0xbf)|newOrdinal<<8;struct.pack_into('<H',after,pos+6,new);nlistChanges.append({'index':i,'fileoff':pos+6,'symbol':symbol,'beforeDesc':desc,'afterDesc':new,'afterOrdinal':newOrdinal,'afterWeakRef':False})
assert len(nlistChanges)==6
binary=out/'VZ27.usb-off-scoped-cvw.ios.dylib';binary.write_bytes(after);(out/'VM27VZCVW.dylib').write_bytes(provider.read_bytes());usb=source.parent/'VM27USBUnavailable.dylib';assert sha(usb.read_bytes())=='aa1c4213943516fa4237591b6131403fd0e92d36155ec0f0498ae0337e8976d6';(out/usb.name).write_bytes(usb.read_bytes());logs=[]
for argv in [['codesign','--force','--sign','-','--timestamp=none',str(binary)],['codesign','--verify','--strict',str(binary)],['codesign','-d','--verbose=4',str(binary)],['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(binary)]]:
 r=subprocess.run(argv,capture_output=True,text=True,timeout=60);logs.append({'argv':argv,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert not r.returncode,r.stderr
final=binary.read_bytes()
for row in sections:assert sha(final[row['offset']:row['offset']+row['bytes']])==row['sha256']
# All unselected chained-import bytes must remain identical.
for i in range(count):
 pos=fixpos+imports+4*i
 if i not in {r['index']for r in changes}:assert final[pos:pos+4]==before[pos:pos+4]
manifest={'source':str(source),'sourceSHA256':sha(before),'path':str(binary),'bytes':len(final),'sha256':sha(final),'cdhash':re.search(r'CDHash=(\w+)',logs[2]['stderr']).group(1),'uuid':uuid,'newStrongProviderOrdinal':newOrdinal,'addedLoadCommand':{'index':ncmd,'offset':at,'cmd':12,'cmdsize':length,'path':name[:-1].decode(),'hex':command.hex()},'changedChainedImportRows':changes,'changedNlistRows':nlistChanges,'allFileBackedSectionsUnchanged':True,'allUnselectedChainedImportsUnchanged':True,'newPrivatePositiveProviderSemantics':True,'globalSwiftOverride':False,'allOtherReconstructedWeakFlatSemanticsUnchanged':True,'requiredImportGateMandatory':844,'metadataCallsAllowed':False,'originalObservedWitnessSites':17,'fullyRestoredOriginalClosure':False,'deviceExecuted':False,'providerSHA256':sha(provider.read_bytes()),'USBProviderSHA256':sha(usb.read_bytes())};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n');print(json.dumps({k:v for k,v in manifest.items() if k not in ['changedChainedImportRows','changedNlistRows','addedLoadCommand']},indent=2));print('changed rows',len(changes),'nlist',len(nlistChanges),'added ordinal',newOrdinal)
