#!/usr/bin/env python3
"""Independent byte/route review of frozen staging. Never stage/load/sign."""
import argparse,hashlib,importlib.util,json,pathlib,struct,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def commands(b):
 assert struct.unpack_from('<I',b)[0]==0xfeedfacf
 count,size=struct.unpack_from('<II',b,16);at=32;rows=[]
 for i in range(count):
  kind,z=struct.unpack_from('<II',b,at);assert z>=8 and z%8==0 and at+z<=32+size
  rows.append((kind,at,b[at:at+z]));at+=z
 assert at==32+size;return rows
def verifyfreeze(path):
 j=json.loads(path.read_bytes());rows=j.get('files',j.get('pins',[]));assert rows
 for row in rows:assert pin(row['path'])==row,row['path']
 return len(rows)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);o=ap.parse_args().output.resolve()
 assert o.is_relative_to(N) and not o.exists();o.mkdir()
 stagePath=N/'independent27-flat-graph-stage-v1-attempt3/candidate.json'
 verificationPath=N/'independent27-staged-definition-graph-v1-attempt1/verification.json'
 indexPath=N/'current-native-header-export-index-v3/index.json'
 stage=json.loads(stagePath.read_bytes());verification=json.loads(verificationPath.read_bytes())
 assert pin(stagePath)['sha256']=='97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206'
 assert pin(verificationPath)['sha256']=='12843df01385fba433caa6d286249e888d2c085c3f96b66fd8fc3bb7e41a0335'
 verifiedPins={str(p):verifyfreeze(p)for p in [stagePath.parent/'freeze.json',verificationPath.parent/'freeze.json']}
 planPath=pathlib.Path(stage['plan']['path']);plan=json.loads(planPath.read_bytes());assert pin(planPath)==stage['plan']
 reader=pathlib.Path(stage['reader']['path']);assert pin(reader)==stage['reader']
 spec=importlib.util.spec_from_file_location('peer_readonly_macho',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 nativeIndex=json.loads(indexPath.read_bytes());native=nativeIndex['images'];assert len(native)==67
 # Validate every captured commands/export range before consulting its index.
 for row in nativeIndex['inputs']:assert pin(row['path'])==row,row['path']
 for image in native.values():
  for k in ['actualCompleteCommands','actualCompleteExportSource']:
   row=image[k];row=row.get('rangePin',row);assert pin(row['path'])==row
 own={};summaries=[];totalCodeBytes=0
 for row in stage['stagedImages']:
  assert pin(row['source']['path'])==row['source'] and pin(row['staged']['path'])==row['staged']
  a=pathlib.Path(row['source']['path']).read_bytes();b=pathlib.Path(row['staged']['path']).read_bytes()
  ca,cb=commands(a),commands(b);assert len(a)==len(b)
  old,new=m.MachO(a),m.MachO(b);own[row['key']]=new
  assert old.uuid==new.uuid==row['UUID'] and old.segments==new.segments and old.sections==new.sections
  assert old.binds==new.binds and old.exports==new.exports
  assert len(cb)==len(ca)+len(row['addedRequiredLoads'])
  for (ka,aa,ra),(kb,ab,rb) in zip(ca,cb):
   assert ka==kb
   if ka in (12,0x80000018,0x8000001f,0x80000023):
    na=struct.unpack_from('<I',ra,8)[0];nb=struct.unpack_from('<I',rb,8)[0];assert na==nb>=24
    oldname=ra[na:].split(b'\0',1)[0];newname=rb[nb:].split(b'\0',1)[0]
    assert not any(ra[na+len(oldname)+1:]) and not any(rb[nb+len(newname)+1:])
    expected=bytearray(ra[:na]+newname+b'\0');expected+=bytes((-len(expected))%8)
    struct.pack_into('<I',expected,4,len(expected));assert bytes(expected)==rb
    ordinal=next(q['ordinal']for q in old.loads if q['at']==aa)
    changed=[q for q in row['loadPathChanges']if q['ordinal']==ordinal]
    if changed:assert len(changed)==1 and changed[0]['oldPath']==oldname.decode() and changed[0]['newPath']==newname.decode()
    else:assert oldname==newname and ra==rb
   else:assert ra==rb
  oldEnd=32+struct.unpack_from('<I',a,20)[0];newEnd=32+struct.unpack_from('<I',b,20)[0]
  assert oldEnd==row['existingHeaderEnd'] and newEnd==row['actualHeaderEnd'] and newEnd<=row['firstFileBackedSection']
  if newEnd>oldEnd:assert not any(a[oldEnd:newEnd])
  if newEnd<oldEnd:assert not any(b[newEnd:oldEnd])
  code=0
  for s in old.sections:
   if s['fileoff'] and s['size'] and s['flags']&255 not in (1,12):
    at=s['fileoff'];assert a[at:at+s['size']]==b[at:at+s['size']]
    if s['flags']&0x80000400:code+=s['size']
  totalCodeBytes+=code
  assert len(old.imports)==len(new.imports)
  for original,actual in zip(old.imports,new.imports):
   expected=dict(original)
   for change in row['actualImportChanges']:
    if change['index']==original['index']:
     assert original['name']==change['symbol'] and original['ordinal']==change['oldOrdinal']
     expected['ordinal']=change['newOrdinal']
   assert actual==expected
  allowed=set(range(16,24))|set(range(32,max(oldEnd,newEnd)))
  for change in row['actualImportChanges']:allowed.update(range(change['at'],change['at']+2))
  for change in row['actualNlistChanges']:allowed.update(range(change['at'],change['at']+2))
  assert all(at in allowed for at,(x,y)in enumerate(zip(a,b))if x!=y)
  summaries.append(dict(key=row['key'],UUID=new.uuid,actualCodeBytesCompared=code,
   allOriginalFileBackedSectionsExact=True,allActualPointerWordsAndExportsExact=True,
   onlyRealZeroLoadStringPaddingRemoved=True,headerPaddingCapacityChecked=True))
 assert len(own)==71
 di=[q for q in stage['stagedImages']if q['key']=='DiskImages227.dylib'];assert len(di)==1
 assert [(q['index'],q['oldOrdinal'],q['newOrdinal'])for q in di[0]['actualImportChanges']]==[(78,14,33)]
 assert len(di[0]['addedRequiredLoads'])==1 and di[0]['addedRequiredLoads'][0]=='@loader_path/VM27FoundationCompat.dylib'
 assert len([q for q in stage['stagedImages']if q['actualImportChanges']])==1
 # Independently walk every recorded exact export route from actual bytes.
 def dependencies(kind,key):
  return native[key]['dependencies']if kind=='native'else [dict(ordinal=x['ordinal'],path=x['path'],command=x['cmd'])for x in own[key].loads]
 def definitions(kind,key):return native[key]['definitions']if kind=='native'else own[key].exports
 def target(path):
  if path in native:return ('native',path)
  if path.startswith('@loader_path/') and path.split('/',1)[1]in own:return ('own',path.split('/',1)[1])
  return ('missing',path)
 routes=0
 def proof(res,initial):
  assert res['resolved'];route=res['route'];assert route and (route[0]['kind'],route[0]['path'])==initial
  for i,step in enumerate(route):
   kind,key,symbol=step['kind'],step['path'],step['symbol'];definition=definitions(kind,key).get(symbol)
   if 'actualExport'in step:assert definition==step['actualExport']
   else:assert definition is None
   if i+1==len(route):
    assert definition and not definition['flags']&8
    assert step['UUID']==(native[key]['UUID']if kind=='native'else own[key].uuid)
   else:
    nxt=route[i+1];deps=dependencies(kind,key)
    if definition and definition['flags']&8:
     dep=next(x for x in deps if x['ordinal']==definition['ordinal'])
     assert nxt['symbol']==(definition.get('alias',definition.get('importedName',''))or symbol)
     assert target(dep['path'])==(nxt['kind'],nxt['path'])
    else:
     assert nxt['symbol']==symbol and any(x['command']==0x8000001f and target(x['path'])==(nxt['kind'],nxt['path'])for x in deps)
  return len(route)
 missing=[]
 for row in verification['actualStrongImportRows']:
  image=own[row['importer']];imp=row['actualImport'];assert image.imports[imp['index']]==imp and not imp['weak']
  if imp['ordinal']>0:initial=target(next(x['path']for x in image.loads if x['ordinal']==imp['ordinal']))
  elif imp['ordinal']==0:initial=('own',row['importer'])
  else:assert False
  if row['resolution']['resolved']:routes+=proof(row['resolution'],initial)
  else:missing.append(row)
 for row in verification['actualNativeWeakDefinitionRows']:
  imp=row['actualImport'];assert own[row['importer']].imports[imp['index']]==imp and imp['ordinal']==-3 and not imp['weak'] and imp['addend']==0
  routes+=proof(row['actualDefinition'],('native','/usr/lib/libc++.1.dylib'))
  assert row['actualDefinition']['route'][-1]['actualExport']['flags']&4
 assert len(verification['actualNativeWeakDefinitionRows'])==13
 assert len(verification['actualStrongImportRows'])+13==verification['actualStrongImports']==5368
 assert len(missing)==6 and missing==verification['unresolvedStrongImportRows']
 # Pre-main has one required incoming edge, from the real child executable.
 premain='VM27OwnedAppChildPreMainV3.dylib';incoming=[]
 for key,image in own.items():
  for d in image.loads:
   if d['path']=='@loader_path/'+premain:incoming.append((key,d['cmd']))
 assert incoming==[('com.apple.Virtualization.VirtualMachine',12)]
 roots=['VZ27.dylib','UniversalHIDKit27.dylib','VM27HVVMProduction.dylib','VM27OwnedAppStartupV3.dylib']
 todo=list(roots);seen=set()
 while todo:
  key=todo.pop()
  if key in seen:continue
  seen.add(key)
  for d in own[key].loads:
   if d['path'].startswith('@loader_path/'):
    k=d['path'].split('/',1)[1];assert k in own;todo.append(k)
 assert premain not in seen and 'com.apple.Virtualization.VirtualMachine'not in seen
 assert not any('StartupV9' in k or 'OriginalV9Transport' in k or 'ModernCPURuntimeCompat'in k or 'OwnedAppStartupV2'in k for k in own)
 result=dict(schema='Independent actual staged graph byte and exact-route review v1',finiteLocalScopePassed=True,findings=[],
  stage=pin(stagePath),verification=pin(verificationPath),sourcePins=[pin(pathlib.Path(__file__)),pin(reader),pin(indexPath),pin(planPath)],
  current67AllActualCapturePinsVerified=True,verifiedFreezePinCounts=verifiedPins,actualImages=71,
  actualStrongImports=5368,actualExactDefinitionRouteSteps=routes,actualCodeBytesCompared=totalCodeBytes,
  all71OriginalCodeSectionsDataSectionsAndPACFixupWordsExact=True,actualSourceUUIDAndVMSetupEntryOffsetsPreserved=True,
  loadCommandPackingOnlyActualZeroStringPaddingRemoved=True,headerGrowthOnlyExistingTrueZeroPadding=True,
  diskImagesSingleIndex78TrueFoundationCompatOrdinal33=True,childPreMain3IncomingOnlyFromActualVMM=True,
  childPreMainNotReachableFromParentRootDSOs=True,parentMainManifestLoadOrderNotYetGenerated=True,
  parentRootClosure=sorted(seen),actualMissingSixStrongRows=missing,perImageByteReview=summaries,
  completeStrongDefinitionGraphClosed=False,actualLoaderOrWeakCoalescingExecuted=False,
  codeSigned=False,deviceOperations=0,nativeOperations=0,guestBoot=False)
 (o/'review.json').write_text(json.dumps(result,indent=2)+'\n')
 (o/'freeze.json').write_text(json.dumps(dict(files=[pin(o/'review.json')]+result['sourcePins']+[pin(stagePath),pin(verificationPath),pin(stagePath.parent/'freeze.json'),pin(verificationPath.parent/'freeze.json')]),indent=2)+'\n')
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),images=71,imports=5368,findings=[])))
if __name__=='__main__':main()
