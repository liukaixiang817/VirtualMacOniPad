#!/usr/bin/env python3
from pathlib import Path
import copy,hashlib,importlib.util,json,re,struct,sys,tempfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('V',ROOT/'scripts/tests/validate-modern-original-xpc-transport.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)
X,M,L,S,R=V.X,V.M,V.L,V.S,V.R;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
LIBS={'VM27LargeBundleRegistryRegister':'VM27LargeRegistry.dylib','VM27LargePrivateServiceConsumerCreate':'VM27LargeConsumer.dylib','VM27LargeOriginalParentCheckFile':'VM27LargeParent.dylib','VM27BundleRegistryRegister':'VM27BundleRegistry.dylib','VM27ApprovedCodeInspectBytes':'VM27ApprovedCode.dylib','VM27LWCRPolicyCreate':'VM27LWCRPolicy.dylib','VM27PrivateEndpointCopyABI':'VM27PrivateEndpoint.dylib'}
ORIGINAL_SHA='42df45e72778512a2ea5054d01e2c940650e7a836f580b99723f8bce5f02266d'
def preserved_original_payload(original,data):
 assert struct.unpack_from('<IIII',original)==struct.unpack_from('<IIII',data) and struct.unpack_from('<I',data,12)[0]==2
 ledger=[]
 for command,at,size in M.commands(original):
  if command==0x19:
   count=struct.unpack_from('<I',original,at+64)[0]
   for index in range(count):
    row=struct.unpack_from('<16s16sQQIIIIIIII',original,at+72+80*index)
    section,segment,_,length,offset,_,_,_,flags,*_=row
    if flags&255 in (1,12,18) or not length:continue
    assert offset>0 and offset+length<=len(original) and original[offset:offset+length]==data[offset:offset+length]
    ledger.append({'segment':segment.rstrip(b'\0').decode(),'section':section.rstrip(b'\0').decode(),'offset':offset,'bytes':length,'SHA256':hashlib.sha256(original[offset:offset+length]).hexdigest(),'sameBytes':True})
  elif command==0x80000034:
   offset,length=struct.unpack_from('<II',original,at+8);assert original[offset:offset+length]==data[offset:offset+length]
   ledger.append({'kind':'chainedFixupsIncludingAuthenticatedPointers','offset':offset,'bytes':length,'SHA256':hashlib.sha256(original[offset:offset+length]).hexdigest(),'sameBytes':True})
 assert ledger and any(r.get('kind')=='chainedFixupsIncludingAuthenticatedPointers' for r in ledger)
 assert M.libraries(original)==M.libraries(data) and V.V.imports(original)==V.V.imports(data)
 return ledger
def native_transcript(build,path,role,pid,wait):
 assert role in ('ios','macos') and pid>1 and wait==0
 c=json.loads((build/'candidate.json').read_text());files={r['name']:r for r in c['candidates'] if r['role']==role};data=next(r for r in c['candidates'] if r['role']=='data');rows=[json.loads(l) for l in Path(path).read_text().splitlines()];assert not any(r['record']=='failure' for r in rows)
 def one(kind):
  a=[r for r in rows if r['record']==kind];assert len(a)==1;return a[0]
 start,end=one('start'),one('summary');assert start['PID']==end['PID']==pid and start['UID']>=0 and (role!='ios' or start['UID']==0)
 expectedData={str(build/'OriginalVMM27.data')} if role=='macos' else {'/var/root/VirtualMac2/testing/original-capacity8-v1/OriginalVMM27.data','/private/var/root/VirtualMac2/testing/original-capacity8-v1/OriginalVMM27.data'}
 assert start['originalDataPath'] in expectedData
 assert start['originalSHA256']==data['sha256'] and start['originalCDHash']==data['CDHash'] and start['originalUUID']==data['UUID']=='4a6a588d1afd30f5a64d6304eb79be0b' and start['originalBytes']==data['bytes']>2097152 and start['codePages']==S.check(Path(data['path']).read_bytes())[0]['pages']>0
 assert start['OriginalVMMExecutions']==start['VMCalls']==start['GPUCalls']==0
 assert end['checks']>=76 and end['failures']==0 and end['passed'] is end['ownTemporaryRemoved'] is end['largeOriginalDataVerified'] is end['old2MiBRefused'] is True
 assert re.fullmatch(r'/private/(?:var/)?tmp/VM27-LargeCapacity-[A-Za-z0-9]+',end['ownTemporaryPath'])
 assert end['capacityBytes']==8388608 and end['plistCapacityBytes']==65536 and end['plansCreated']==end['plansDestroyed']==3 and end['consumersCreated']==end['consumersDestroyed']==1
 for n in ['messages','spawns','nativeTaskCalls','originalVMMExecutions','bootstrapChanges']:assert end[n]==0
 assert end['systemModified'] is False
 providers=[r for r in rows if r['record']=='provider'];assert len(providers)==14
 for symbol,lib in LIBS.items():
  a=[dict(r) for r in providers if r['symbol']==symbol];assert len(a)==2 and {r.pop('phase') for r in a}=={'before','after'} and a[0]==a[1];row=files[lib];p=row['path'] if role=='macos' else '/private/var/root/VirtualMac2/testing/original-capacity8-v1/'+lib
  assert a[0]['path']==p and a[0]['SHA256']==row['sha256'] and a[0]['UUID']==row['UUID'] and int(a[0]['RVA'],16)==X.symbol_rva(Path(row['path']).read_bytes(),symbol)>0
 return {'passed':True,'directPID':pid,'actualWait':wait,'start':start,'summary':end,'providers':providers,'originalVMMExecuted':False,'originalRuntimeClosureComplete':False,'dataOnly':True}
def receipt_negatives(build,pid):
 original=[json.loads(l) for l in (build/'macos-native.stdout').read_text().splitlines()];mutations=[]
 for kind,names in [('start',('PID','originalDataPath','originalSHA256','originalCDHash','originalUUID','originalBytes','codePages','OriginalVMMExecutions','VMCalls','GPUCalls')),('summary',('PID','checks','failures','passed','ownTemporaryPath','ownTemporaryRemoved','largeOriginalDataVerified','old2MiBRefused','capacityBytes','plistCapacityBytes','plansCreated','plansDestroyed','consumersCreated','consumersDestroyed','messages','spawns','nativeTaskCalls','originalVMMExecutions','bootstrapChanges','systemModified')),('provider',('path','SHA256','UUID','RVA','phase','symbol'))]:
  for name in names:
   rows=copy.deepcopy(original);row=next(r for r in rows if r['record']==kind);value=row[name]
   row[name]=not value if isinstance(value,bool) else (0 if name in ('checks','codePages') else value+1) if isinstance(value,int) else '/wrong/path' if name.endswith('Path') or name=='path' else 'corrupt'
   mutations.append((kind+'.'+name,rows))
 for label in ('providerMissing','duplicateStart','failureRecord'):
  rows=copy.deepcopy(original)
  if label=='providerMissing':rows.remove(next(r for r in rows if r['record']=='provider'))
  elif label=='duplicateStart':rows.append(copy.deepcopy(next(r for r in rows if r['record']=='start')))
  else:rows.append({'record':'failure','label':'corrupt'})
  mutations.append((label,rows))
 results=[]
 with tempfile.NamedTemporaryFile(prefix='VM27-Capacity-Receipt-',suffix='.jsonl',mode='w+',encoding='utf8') as f:
  for label,rows in mutations:
   f.seek(0);f.truncate();f.write(''.join(json.dumps(r)+'\n' for r in rows));f.flush()
   try:native_transcript(build,f.name,'macos',pid,0)
   except (AssertionError,KeyError,ValueError):results.append({'mutation':label,'rejected':True})
   else:raise AssertionError('bad receipt accepted '+label)
  f.seek(0);f.truncate();f.write(''.join(json.dumps(r)+'\n' for r in original));f.flush()
  for wait in (-5,133,78):
   try:native_transcript(build,f.name,'macos',pid,wait)
   except AssertionError:results.append({'mutation':'actualWait='+str(wait),'rejected':True})
   else:raise AssertionError('failed process accepted')
 return results
def main(build):
 c=json.loads((build/'candidate.json').read_text());assert len(c['candidates'])==17 and c['capacityBytes']==8388608 and c['plistCapacityBytes']==65536
 for n in ['originalVMMExecuted','dataFileExecuted','iOSExecuted','deviceOperations','systemModified']:assert c[n] is False
 assert c['originalInputUnchanged'] is True and sha(Path(c['originalUnsignedSource']['path']))==c['originalUnsignedSource']['SHA256']==ORIGINAL_SHA
 payload=preserved_original_payload(Path(c['originalUnsignedSource']['path']).read_bytes(),(build/'OriginalVMM27.data').read_bytes())
 for name,digest in c['sourceSHA256'].items():assert sha(build/'source'/name)==digest
 bindings=[];controls=[]
 for r in c['candidates']:
  d=Path(r['path']).read_bytes();assert len(d)==r['bytes'] and sha(Path(r['path']))==r['sha256'];cd=S.check(d);assert len(cd)==1 and cd[0]['cdhash']==r['CDHash'];assert next(d[a+8:a+24].hex() for k,a,z in M.commands(d) if k==0x1b)==r['UUID']
  ent= L.canonical(L.signed_entitlements(d));expected={} if r['name']!='large-capacity-data-probe' or r['role']!='ios' else {'platform-application':True,'com.apple.private.security.no-container':True,'com.apple.private.security.no-sandbox':True,'com.apple.private.amfi.can-execute-cdhash':True};assert ent==L.canonical(r['entitlements'])==L.canonical(expected)
  if r['role']=='data':assert r['executableDeployment'] is False and r['UUID']=='4a6a588d1afd30f5a64d6304eb79be0b';continue
  imports,deps=V.V.imports(d),M.libraries(d);assert all(x['ordinal']>0 and not x['weak'] for x in imports)
  assert not any(any(s in name for s in ('Virtualization.framework','Hypervisor.framework','ParavirtualizedGraphics.framework','VirtualMachine.xpc')) for name in deps)
  if r.get('unchanged'):assert sha(Path(r['source']))==r['sha256'];continue
  if r['name']=='VM27LargeParent.dylib':required=[('VM27ApprovedCodeInspectBytes','@rpath/VM27ApprovedCode.dylib')]
  elif r['name']=='VM27LargeRegistry.dylib':required=[(n,'@rpath/VM27LWCRPolicy.dylib') for n in ('VM27LWCRPolicyCreate','VM27LWCRPolicyRelease','VM27LWCRPolicyCheckReceivedMessage')]
  elif r['name']=='VM27LargeConsumer.dylib':
   required=[(n,'@rpath/VM27LargeRegistry.dylib') for n in ('VM27LargeBundleRegistryCopyServicePlan','VM27LargeServicePlanCopyInfo','VM27LargeServicePlanVerify','VM27LargeServicePlanRelease')]+[(n,'@rpath/VM27ApprovedCode.dylib') for n in ('VM27ApprovedCodeInspectBytes','VM27ApprovedCodePolicyCreate','VM27ApprovedCodePolicyRelease','VM27ApprovedCodeCheckReceivedMessage')]+[(n,'@rpath/VM27LWCRPolicy.dylib') for n in ('VM27LWCRPolicyCreate','VM27LWCRPolicyRelease')]+[('VM27PrivateEndpointCopySendRight','@rpath/VM27PrivateEndpoint.dylib')]
  else:
   assert r['name']=='large-capacity-data-probe';assert not any('posix_spawn' in x['symbol'] or 'VM27LargePrivateServiceConsumerSpawn' in x['symbol'] or 'xpc_connection_create' in x['symbol'] for x in imports)
   required=[(n,'@rpath/'+LIBS[n]) for n in LIBS]+[(n,'@rpath/VM27LargeRegistry.dylib') for n in ('VM27LargeBundleRegistryCreate','VM27LargeBundleRegistryRelease','VM27LargeBundleRegistryCopyServicePlan','VM27LargeServicePlanCopyInfo','VM27LargeServicePlanVerify','VM27LargeServicePlanRelease','VM27LargeBundleRegistryCopyStats')]+[(n,'@rpath/VM27LargeConsumer.dylib') for n in ('VM27LargePrivateServiceConsumerRelease','VM27LargePrivateServiceConsumerCopyStats')]
  for symbol,provider in required:
   bindings.append(V.V.require_binding(imports,deps,'_'+symbol,provider))
   for mutation in ['weak','flat','missing','wrongProvider']:
    bad=[dict(x) for x in imports];lib=list(deps);x=next(x for x in bad if x['symbol']=='_'+symbol)
    if mutation=='weak':x['weak']=True
    elif mutation=='flat':x['ordinal']=-2
    elif mutation=='missing':bad.remove(x)
    else:lib[x['ordinal']-1]='/VM27/Wrong.dylib'
    try:V.V.require_binding(bad,lib,'_'+symbol,provider)
    except AssertionError:controls.append({'symbol':symbol,'mutation':mutation,'rejected':True})
    else:raise AssertionError('bad binding accepted')
 p=next(x for x in c['processes'] if x['label']=='macos-native');assert p['reaped'] is True;native=native_transcript(build,build/'macos-native.stdout','macos',p['PID'],p['wait']);return {'passed':True,'exactFiles':17,'strongBindings':bindings,'badBindings':controls,'badActualReceipts':receipt_negatives(build,p['PID']),'originalPayloadPreserved':payload,'actualMacDataContract':native,'originalVMMExecuted':False,'iOSExecuted':False}
if __name__=='__main__':assert len(sys.argv)==2;print(json.dumps(main(Path(sys.argv[1]).resolve()),indent=2))
