"""Stage real dependency/ordinal mutations into fresh, unsigned flat images.

This does not load, sign or install the graph. Source code/sections, UUIDs,
all pointer fixups and all nonselected import fields stay byte exact. Original
VM setup offsets remain fixed; load commands use only existing header space.
"""
import argparse,collections,hashlib,importlib.util,json,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 d=a.output.resolve();need(d.is_relative_to(N) and not d.exists(),'fresh output');d.mkdir()
 planPath=N/'independent27-runtime-strong-inventory-plan-v4/plan.json'
 need(pin(planPath)['sha256']=='0796f0143ae2bc6d857f6567b15377454afe0fb17739f2473ef451eda98575f1','exact startup/Swift plan')
 plan=json.loads(planPath.read_bytes());catalog={k:v['pin']for k,v in plan['catalogueProvenance'].items()}
 netPath=N/'vmnet-unavailable-contract-v2-attempt1/candidate.json';net=json.loads(netPath.read_bytes())
 need(pin(netPath)['sha256']=='0f354f017ba6ee96497c725e5315d8b04edfd525e3a30b8ae4b964fbaa270c00','explicit NIC0 provider')
 catalog['VM27VMNetUnavailable.dylib']=net['provider']
 forbidden={'ModernCPURuntimeCompat.dylib','VM27OwnedAppStartupV2.dylib',
  'VM27OwnedAppChildPreMainV2.dylib','VM27StartupV9.dylib'}
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec=importlib.util.spec_from_file_location('stage_macho',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 for row in catalog.values():need(pin(row['path'])==row,'exact selected source')
 aliases={}
 for key in sorted(catalog,key=lambda s:(len(s),s)):
  aliases.setdefault(catalog[key]['sha256'],key)
 canonical={k:aliases[v['sha256']]for k,v in catalog.items()}
 def pathTarget(path):
  path=plan['proposedLoadPathMap'].get(path,{}).get('target',path)
  if path.startswith(('@loader_path/','@rpath/')):
   key=path.split('/',1)[1]
   need(key not in forbidden,'forbidden old CPU/startup path')
   if key in catalog:return '@loader_path/'+canonical[key],canonical[key]
  return path,None
 images={k:m.MachO(pathlib.Path(v['path']).read_bytes())for k,v in catalog.items()}
 roots=['VZ27.dylib','com.apple.Virtualization.VirtualMachine','UniversalHIDKit27.dylib',
  'VM27HVVMProduction.dylib','VM27OwnedAppStartupV3.dylib','VM27OwnedAppChildPreMainV3.dylib']
 queue=collections.deque(canonical[k]for k in roots);reached=set()
 while queue:
  k=queue.popleft()
  if k in reached:continue
  need(k not in forbidden,'forbidden graph image');reached.add(k)
  for dep in images[k].loads:
   _,target=pathTarget(dep['path'])
   if target:queue.append(target)
  if k==canonical['DiskImages227.dylib']:queue.append(canonical['VM27FoundationCompat.dylib'])
  if k==canonical['com.apple.Virtualization.VirtualMachine']:queue.append(canonical['VM27OwnedAppChildPreMainV3.dylib'])
 output=d/'flat';output.mkdir();reports=[];commands=[]
 def loadCommand(path):
  name=path.encode()+b'\0';size=(24+len(name)+7)&~7
  return struct.pack('<6I',12,size,24,1,65536,65536)+name+bytes(size-24-len(name))
 for key in sorted(reached):
  source=pathlib.Path(catalog[key]['path']);raw=source.read_bytes();old=images[key]
  commandRows=[];changes=[];loadOrdinal=0
  for c in old.commands:
   cmd=c['raw']
   if c['cmd']in[12,0x80000018,0x8000001f,0x80000023]:
    loadOrdinal+=1;no=struct.unpack_from('<I',cmd,8)[0]
    oldName=cmd[no:].split(b'\0',1)[0].decode();newName,target=pathTarget(oldName)
    payload=newName.encode()+b'\0';size=(no+len(payload)+7)&~7
    # Load commands are variable-length records. Reclaim only their genuine
    # zero string padding; no section, instruction, fixup or VM setup address
    # moves when this command list is packed inside the existing header.
    suffix=cmd[no+len(oldName.encode())+1:]
    need(not any(suffix),'actual zero load-command string padding')
    if newName!=oldName or size!=len(cmd):
     amended=bytearray(cmd[:no]+payload+bytes(size-no-len(payload)))
     struct.pack_into('<I',amended,4,size);cmd=bytes(amended)
     changes.append(dict(ordinal=loadOrdinal,oldPath=oldName,newPath=newName,
      command=c['cmd'],oldCommandSize=c['size'],newCommandSize=len(cmd)))
   commandRows.append(cmd)
  extra=[];selected=[]
  if key==canonical['DiskImages227.dylib']:
   selected=[r for r in plan['proposedImportRetargets']if r['importer']=='DiskImages227.dylib']
   need(len(selected)==1,'single actual Foundation conversion import')
   extra.append('@loader_path/'+canonical['VM27FoundationCompat.dylib'])
  if key==canonical['com.apple.Virtualization.VirtualMachine']:
   extra.append('@loader_path/'+canonical['VM27OwnedAppChildPreMainV3.dylib'])
  newOrdinalByPath={}
  for path in extra:
   loadOrdinal+=1;newOrdinalByPath[path]=loadOrdinal;commandRows.append(loadCommand(path))
  body=b''.join(commandRows);oldEnd=32+old.sizeofcmds;newEnd=32+len(body)
  # Header-only reexport dylibs can have no file-backed sections at all.
  # Their actual next file-backed segment is still a strict byte boundary.
  first=min([s['fileoff']for s in old.sections if s['size'] and s['fileoff']>0
   and (s['flags']&255)not in[1,12]]+
   [s['fileoff']for s in old.segments if s['filesize'] and s['fileoff']>0])
  need(newEnd<=first,'existing load-command capacity '+key+' '+str(newEnd)+' > '+str(first))
  if newEnd>oldEnd:need(not any(raw[oldEnd:newEnd]),'only actual zero header padding may be used')
  data=bytearray(raw);data[32:max(oldEnd,newEnd)]=body+bytes(max(oldEnd,newEnd)-newEnd)
  struct.pack_into('<II',data,16,len(commandRows),len(body));importChanges=[];nlistChanges=[]
  for row in selected:
   imp=row['actualImport'];need(old.imports[imp['index']]==imp,'exact selected original import')
   target='@loader_path/'+canonical['VM27FoundationCompat.dylib'];ordinal=newOrdinalByPath[target]
   fix=next(c for c in old.commands if c['cmd']==0x80000034);offset=struct.unpack_from('<I',fix['raw'],8)[0]
   form=struct.unpack_from('<I',raw,offset+20)[0];bits=16 if form==3 else 8;fmt='<Q'if form==3 else'<I'
   word=struct.unpack_from(fmt,raw,imp['at'])[0];need(ordinal<(1<<(bits-1)),'positive non-special ordinal')
   struct.pack_into(fmt,data,imp['at'],(word&~((1<<bits)-1))|ordinal)
   importChanges.append(dict(index=imp['index'],symbol=imp['name'],oldOrdinal=imp['ordinal'],newOrdinal=ordinal,at=imp['at']))
   sym=next(c for c in old.commands if c['cmd']==2);so,count,ss,sz=struct.unpack_from('<4I',sym['raw'],8)
   for i in range(count):
    at=so+16*i;strx,typ,sect,desc,value=struct.unpack_from('<IBBHQ',raw,at)
    end=raw.find(b'\0',ss+strx,ss+sz);need(end>=ss+strx,'nlist string bound')
    if raw[ss+strx:end].decode()==imp['name']and typ&0x0e==0:
     need(desc>>8==imp['ordinal'],'matching undefined symbol ordinal');need(ordinal<254,'nlist ordinal extent')
     struct.pack_into('<H',data,at+6,(desc&255)|(ordinal<<8))
     nlistChanges.append(dict(index=i,symbol=imp['name'],at=at+6,oldOrdinal=desc>>8,newOrdinal=ordinal))
  actual=bytes(data);new=m.MachO(actual)
  need(new.uuid==old.uuid and new.segments==old.segments and new.sections==old.sections,'identity and all section geometry retained')
  need(new.binds==old.binds and new.exports==old.exports,'all authenticated pointer words and exports unchanged')
  for section in old.sections:
   if section['size']and section['fileoff']and (section['flags']&255)not in[1,12]:
    at=section['fileoff'];need(raw[at:at+section['size']]==actual[at:at+section['size']],'all file-backed section contents unchanged')
  need(len(new.imports)==len(old.imports),'import table count unchanged')
  for before,after in zip(old.imports,new.imports):
   expected=dict(before)
   for change in importChanges:
    if change['index']==before['index']:expected['ordinal']=change['newOrdinal']
   need(expected==after,'only selected exact import ordinal changes')
  allowed=set(range(16,24))|set(range(32,max(oldEnd,newEnd)))
  for change in importChanges:allowed.update(range(change['at'],change['at']+(2 if form==3 else 1)))
  for change in nlistChanges:allowed.update(range(change['at'],change['at']+2))
  need(len(actual)==len(raw) and all(x in allowed for x,(a,b)in enumerate(zip(raw,actual))if a!=b),'finite byte mutation extent')
  p=output/key;p.write_bytes(actual);p.chmod(0o600)
  cp=subprocess.run(['xcrun','dyld_info','-validate_only',str(p)],capture_output=True,timeout=30)
  (d/(key+'.validate.stdout')).write_bytes(cp.stdout);(d/(key+'.validate.stderr')).write_bytes(cp.stderr)
  need(cp.returncode==0,'actual dyld metadata validation '+key)
  reports.append(dict(key=key,source=catalog[key],staged=pin(p),UUID=new.uuid,
   loadPathChanges=changes,addedRequiredLoads=extra,actualImportChanges=importChanges,
   actualNlistChanges=nlistChanges,allCodeSectionsAndFixupWordsUnchanged=True,
   existingHeaderEnd=oldEnd,actualHeaderEnd=newEnd,firstFileBackedSection=first,
   actualDyldValidationPassed=True,codeSignatureStaleUntilFinalSigning=True))
  commands.append(dict(image=key,status=cp.returncode))
 for row in catalog.values():need(pin(row['path'])==row,'all source files still unchanged')
 result=dict(schema='Actual independent27 flat strong-graph staging v1',plan=pin(planPath),network=pin(netPath),
  builder=pin(__file__),reader=pin(reader),selectedSourceCatalog=catalog,canonicalAliases=canonical,
  selectedRoots=roots,stagedImages=reports,actualRetargetingPerformed=True,
  childOnlyPreMainAddedToActualOriginalVMM=True,childOnlyPreMainAddedToParent=False,
  codeAndDataAndUUIDAndNativeVMSetupOffsetsPreserved=True,
  remainingUnclosedOriginalImports=['MTLCopyAllDevices','xpc_add_bundle_with_lwcr','CGDisplayCopyColorSpace',
   'SLSDisplayGetPotentialHeadroom','IOSurfaceAcceleratorParavirtProcessGuestData','OBJC_CLASS_$_DisplayServicesClient'],
  remainingCPUContextPortsRequired=True,finalStrongDefinitionGraphClosed=False,
  finalSignedProductManifestGenerated=False,codeSigned=False,readyForDeviceExecution=False,
  deviceOperations=0,nativeCPUOperations=0,guestBoot=False)
 (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
 files=[pin(p)for p in sorted(d.rglob('*'))if p.is_file()]+[pin(planPath),pin(netPath),pin(reader),pin(__file__)]+list(catalog.values())
 (d/'freeze.json').write_text(json.dumps(dict(candidate=pin(d/'candidate.json'),pins=files),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(d/'candidate.json'),freeze=pin(d/'freeze.json'),images=len(reports),remainingStrongSymbols=6)))
if __name__=='__main__':main()
