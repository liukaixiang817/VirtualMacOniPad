#!/usr/bin/env python3
"""Isolated strong IOUSBHost dependency route; no code/fixup/UUID change."""
import argparse,pathlib,hashlib,json,struct,subprocess,re
parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--provider',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
source=pathlib.Path(args.input).resolve();provider=pathlib.Path(args.provider).resolve();out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
sha=lambda b:hashlib.sha256(b).hexdigest();before=source.read_bytes()
assert sha(before)=='9344be569c9b476e7382c2f8e7259c2149c99528901066d7e81b5e3832b5a0b0','requires audited flat-iOS VZ27 v2 input'
assert sha(provider.read_bytes())=='aa1c4213943516fa4237591b6131403fd0e92d36155ec0f0498ae0337e8976d6','requires strict USB provider v3'
def parse(data):
 magic,_,_,_,ncmd,size,_,_=struct.unpack_from('<8I',data);assert magic==0xfeedfacf and ncmd<1024 and size<65536
 off=32;rows=[];sections=[];uuid=None
 for index in range(ncmd):
  cmd,length=struct.unpack_from('<II',data,off);assert length>=8 and length%8==0 and off+length<=32+size
  row={'index':index,'offset':off,'cmd':cmd,'cmdsize':length,'hex':data[off:off+length].hex()}
  if cmd in (12,0x80000018,0x8000001f,0x80000023):
   pos=struct.unpack_from('<I',data,off+8)[0];assert 24<=pos<length;row.update(name=data[off+pos:off+length].split(b'\0',1)[0].decode(),nameOffset=pos)
  if cmd==0x1b:uuid=data[off+8:off+24].hex()
  if cmd==0x19:
   for j in range(struct.unpack_from('<I',data,off+64)[0]):
    so=off+72+j*80;name=data[so:so+16].rstrip(b'\0').decode();seg=data[so+16:so+32].rstrip(b'\0').decode();lengthSec=struct.unpack_from('<Q',data,so+40)[0];pos=struct.unpack_from('<I',data,so+48)[0];flags=struct.unpack_from('<I',data,so+64)[0]
    if pos and flags&255 not in (1,12,18):sections.append({'segment':seg,'section':name,'bytes':lengthSec,'sha256':sha(data[pos:pos+lengthSec])})
  rows.append(row);off+=length
 assert off==32+size;return rows,sections,uuid
rows,sections,uuid=parse(before);assert uuid=='418efc4809d93606918eb6f95baeffdc'
targets=[r for r in rows if r.get('name')=='/System/Library/Frameworks/IOUSBHost.framework/IOUSBHost'];assert len(targets)==1
row=targets[0];assert row['cmd']==12,'original strong required LC_LOAD_DYLIB preserved'
replacement=b'@loader_path/VM27USBUnavailable.dylib\0';space=row['cmdsize']-row['nameOffset'];assert len(replacement)<=space
after=bytearray(before);start=row['offset']+row['nameOffset'];after[start:start+space]=replacement+bytes(space-len(replacement));binary=out/'VZ27.usb-off-load-only.ios.dylib';binary.write_bytes(after)
privateProvider=out/'VM27USBUnavailable.dylib';privateProvider.write_bytes(provider.read_bytes());logs=[]
for argv in [['codesign','--force','--sign','-','--timestamp=none',str(binary)],['codesign','--verify','--strict',str(binary)],['codesign','-d','--verbose=4',str(binary)],['otool','-L',str(binary)]]:
 p=subprocess.run(argv,capture_output=True,text=True,timeout=60);logs.append({'argv':argv,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert not p.returncode,p.stderr
newRows,newSections,newUUID=parse(binary.read_bytes());assert newSections==sections and newUUID==uuid
changes=[{'index':a['index'],'offset':a['offset'],'cmdBefore':a['cmd'],'cmdAfter':b['cmd'],'beforeHex':a['hex'],'afterHex':b['hex'],'beforePath':a.get('name'),'afterPath':b.get('name')}for a,b in zip(rows,newRows)if a['hex']!=b['hex']]
assert len(rows)==len(newRows) and [r['cmd'] for r in rows]==[r['cmd']for r in newRows]
manifest={'input':str(source),'inputSHA256':sha(before),'path':str(binary),'bytes':binary.stat().st_size,'sha256':sha(binary.read_bytes()),'cdhash':re.search(r'CDHash=(\w+)',logs[2]['stderr']).group(1),'uuid':uuid,'provider':str(privateProvider),'providerSHA256':sha(privateProvider.read_bytes()),'dependencyPolicy':'New positive app-private compatibility dependency, same original strong LC_LOAD_DYLIB slot/ordinal; USB hardware explicitly unavailable.','loadCommandDiffs':changes,'allFileBackedSectionsUnchanged':True,'fileBackedSections':sections,'unchangedReconstructedFlatWeakImportSemantics':True,'originalStrongFixupClosureRestored':False,'requiredImportGateMandatory':844,'metadataCallsAllowed':False,'deviceExecuted':False}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'commands.json').write_text(json.dumps(logs,indent=2)+'\n');print(json.dumps({k:v for k,v in manifest.items() if k not in ('fileBackedSections','loadCommandDiffs')},indent=2));print('LC diffs',len(changes))
