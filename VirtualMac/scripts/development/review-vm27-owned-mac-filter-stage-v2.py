#!/usr/bin/env python3
"""HOST-only independent named filter ABI, single classref and Stage composition."""
import argparse,hashlib,importlib.util,json,pathlib,struct,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(r):
 need(pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},'actual pin '+r['path']);return pathlib.Path(r['path'])
def parse_module(p):
 s=importlib.util.spec_from_file_location('macfilter_independent_macho',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def methods(p,data,cls):
 def ptr(w):
  need(not(w>>62&1),'internal class/RO/method pointer is actual rebase');return p.base+((w&0xffffffff)if w>>63 else w&((1<<43)-1))
 def cstring(va):
  f=p.file(va);return data[f:data.index(0,f)].decode()
 ro=ptr(struct.unpack_from('<Q',data,p.file(cls)+32)[0])&~7;ml=ptr(struct.unpack_from('<Q',data,p.file(ro)+32)[0]);f=p.file(ml);flags,count=struct.unpack_from('<II',data,f);need(flags>>31 and flags&0xffff==12 and count<=64,'actual relative ObjC methods')
 rows=[]
 for i in range(count):
  loc=ml+8+12*i;n,t,imp=struct.unpack_from('<iii',data,f+8+12*i);name=loc+n
  if not(flags&0x40000000):name=ptr(struct.unpack_from('<Q',data,p.file(name))[0])
  rows.append(dict(selector=cstring(name),encoding=cstring(loc+4+t),IMP_RVA=loc+8+imp-p.base))
 return rows,ptr
def main():
 a=argparse.ArgumentParser();a.add_argument('--provider-candidate',type=pathlib.Path,required=True);a.add_argument('--stage-candidate',type=pathlib.Path,required=True);a.add_argument('--output',type=pathlib.Path,required=True);a=a.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh peer')
 c=json.loads(a.provider_candidate.read_bytes());sc=json.loads(a.stage_candidate.read_bytes());pf=a.provider_candidate.parent/'freeze.json';sf=a.stage_candidate.parent/'freeze.json'
 for f in [pf,sf]:
  for r in json.loads(f.read_bytes())['files']:actual(r)
 reader=parse_module(actual(c['reader']));oldraw=actual(c['originalVZ']).read_bytes();newraw=actual(c['patchedVZ']).read_bytes();old=reader.MachO(oldraw);new=reader.MachO(newraw);providerraw=actual(c['provider']).read_bytes();provider=reader.MachO(providerraw);contract=c['ownMacEventFilterContract'];recipe=json.loads(actual(c['recipe']).read_bytes())
 need(contract['rawOriginalMonitorInstanceSize']==18 and contract['actualAlignedMonitorInstanceSize']==24 and contract['actualMonitorIvarOffsets']==[8,16,17],'raw18 vs genuine runtime24 layout distinguished')
 source=actual(c['source']).read_text();need('class_getInstanceSize(monitor)!=24'in source and 'class_getInstanceSize(monitor)!=18'not in source and 'ivar_getOffset(enabled)!=16'in source and 'ivar_getOffset(translators)!=17'in source and 'ivar_getOffset(filter)!=8'in source,'actual aligned/typed monitor profile guard')
 need('@implementation VM27OwnedUIKitMacEventFilterV1'in source and '+ (BOOL)isEnabled {RequireClassProfileV1(self);return NO;}'in source and '+ (BOOL)hasEventTranslators {RequireClassProfileV1(self);return NO;}'in source,'real named class explicit false Mac capabilities')
 for token in ['getuid()!=501 || geteuid()!=501','com.mac.virtual.independent27','VirtualMacPVGBackendVersion','_actualPID=getpid()','_actualPID!=getpid()','_actualVZBase!=base','0x14cd04','VM27OwnedUIKitMacEventFilterUnavailable','#error "Mac event filter fixture cannot enter iOS products"']:
  need(token in source,'actual production owner/image/fixture/error guard '+token)
 need('return @[]'not in source and 'return nil;'not in source and source.count('[self requireActualOwner];')==3 and source.count('RejectV1(@"')>=5,'typed unsupported no empty report/zero-success fallback')
 owncls=provider.base+provider.exports['_OBJC_CLASS_$_VM27OwnedUIKitMacEventFilterV1']['address'];ownmeta=provider.base+provider.exports['_OBJC_METACLASS_$_VM27OwnedUIKitMacEventFilterV1']['address'];inst,_=methods(provider,providerraw,owncls);caps,_=methods(provider,providerraw,ownmeta)
 originalcls=old.base+0x34e258;oi,ptr=methods(old,oldraw,originalcls);om,_=methods(old,oldraw,ptr(struct.unpack_from('<Q',oldraw,old.file(originalcls))[0]))
 named=['getHIDReportsFromHIDEvent:','getHIDReportsFromNSEvent:','updateCoordinateTransform:isFlipped:'];actualabi={r['selector']:r['encoding']for r in inst+caps};originalabi={r['selector']:r['encoding']for r in oi+om}
 need(all(actualabi[n]==originalabi[n]for n in named+['isEnabled','hasEventTranslators','init']),'actual iOS provider ObjC method table ABI equals original real VZ table')
 need(set(provider.exports)==set(c['actualExports'])=={'_OBJC_CLASS_$_VM27OwnedUIKitMacEventFilterV1','_OBJC_METACLASS_$_VM27OwnedUIKitMacEventFilterV1'}and provider.imports==c['actualNativeImports']and len(provider.imports)==36 and not any('Fixture'in r['name']for r in provider.imports),'true2 class exports/36 production native imports/no fixture')
 for label in ['run-normal.stdout','run-sanitized.stdout']:need((a.provider_candidate.parent/label).read_text()=='owned UIKit Mac-event filter: 19 finite checks passed; no guest execution\n','real existing19 fixture result retained, not rerun')
 slot=recipe['classrefFileOffset'];ow=struct.unpack_from('<Q',oldraw,slot)[0];nw=struct.unpack_from('<Q',newraw,slot)[0]
 need(ow==0x000800000034e258 and nw==0x4008000000000420 and ow>>63==nw>>63==0 and ow>>62&1==0 and nw>>62&1==1 and (ow>>51)&0x7ff==(nw>>51)&0x7ff,'actual unauthenticated classref rebase-to-bind preserves next; no invented PAC auth')
 row=new.imports[-1];need(row['index']==1056 and row['ordinal']==63 and row['weak']==row['addend']==0 and row['name']=='_OBJC_CLASS_$_VM27OwnedUIKitMacEventFilterV1','only true appended strong ownclass binding')
 need(new.loads[:-1]==old.loads and new.loads[-1]['cmd']==12 and new.loads[-1]['path']=='@loader_path/VM27OwnedUIKitMacEventFilter.dylib'and new.loads[-1]['ordinal']==63,'all original loads plus exactly one required new provider')
 fix=next(x for x in old.commands if x['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',oldraw,fix['at']+8);rawfix=oldraw[fo:fo+fs];ver,starts,imports,symbols,count,form,sform=struct.unpack_from('<7I',rawfix);need(form==2 and count==1056,'actual eight-byte imports')
 e=struct.pack('<Ii',63|((len(rawfix)-symbols)<<9),0);payload=bytearray(rawfix[:symbols]+e+rawfix[symbols:]+row['name'].encode()+b'\0');struct.pack_into('<I',payload,12,symbols+8);struct.pack_into('<I',payload,16,count+1)
 expected=bytearray(oldraw);h=32+old.sizeofcmds;dep=b'@loader_path/VM27OwnedUIKitMacEventFilter.dylib\0';sz=(24+len(dep)+7)&~7;need(sz==72 and oldraw[h:h+sz]==bytes(sz),'true zero header capacity only')
 lc=struct.pack('<6I',12,sz,24,2,0x10000,0x10000)+dep;expected[h:h+sz]=lc+bytes(sz-len(lc));struct.pack_into('<II',expected,16,old.ncmds+1,old.sizeofcmds+sz);struct.pack_into('<Q',expected,slot,nw)
 while len(expected)%8:expected.append(0)
 off=len(expected);expected.extend(payload);struct.pack_into('<II',expected,fix['at']+8,off,len(payload));link=next(x for x in old.commands if x['cmd']==25 and oldraw[x['at']+8:x['at']+24].rstrip(b'\0')==b'__LINKEDIT');linkfo=struct.unpack_from('<Q',expected,link['at']+40)[0];size=len(expected)-linkfo;struct.pack_into('<Q',expected,link['at']+48,size);struct.pack_into('<Q',expected,link['at']+32,max(struct.unpack_from('<Q',oldraw,link['at']+32)[0],(size+16383)&~16383))
 need(bytes(expected)==newraw,'independent complete patched VZ reconstruction exact bytes')
 need(old.uuid==new.uuid and old.exports==new.exports and [{k:v for k,v in r.items()if k!='at'}for r in old.imports]==[{k:v for k,v in r.items()if k!='at'}for r in new.imports[:-1]]and old.binds==[r for r in new.binds if r['fileoff']!=slot],'all old UUID/exports/import semantics/authenticated GOT rawwords preserved')
 for section in old.sections:
  if not section['fileoff']or not section['size']:continue
  f=section['fileoff'];b=bytearray(newraw[f:f+section['size']]);original=oldraw[f:f+section['size']]
  if f<=slot<f+section['size']:b[slot-f:slot-f+8]=oldraw[slot:slot+8]
  need(bytes(b)==original,'all old backed sections including code exactly preserved except single classref')
 base=json.loads(actual(sc['baseStage']).read_bytes());oldimages={r['key']:r for r in base['stagedImages']};images={r['key']:r for r in sc['stagedImages']};need(len(images)==sc['actualImages']==74 and set(images)-set(oldimages)=={c['providerKey']},'actual74 images/one provider addition')
 need(sc['ownMacEventFilterProviderCandidate']==pin(a.provider_candidate)and images[c['providerKey']]['staged']['sha256']==c['provider']['sha256']and images['VZ27.dylib']['staged']['sha256']==c['patchedVZ']['sha256'],'actual exact provider/source-port adoption')
 for key,row0 in oldimages.items():
  if key!='VZ27.dylib':need(images[key]['staged']['sha256']==row0['staged']['sha256']and images[key]['staged']['bytes']==row0['staged']['bytes'],'other72 actual image wholebytes '+key)
 proofpath=a.stage_candidate.parent/'verification.json';proof=json.loads(proofpath.read_bytes());oldproof=json.loads(actual(proof['inheritedExactPreviousVerification']).read_bytes());need(proof['actualImages']==74 and proof['remainingActualStrongSymbols']==0 and proof['incrementallyResolvedActualStrongRows']==37,'fresh current74/37 strong metadata, no stale73')
 ownrows=[r for r in proof['actualStrongImportRows']if r['importer']==c['providerKey']];classrows=[r for r in proof['actualStrongImportRows']if r['importer']=='VZ27.dylib'and r['actualImport']['index']==1056];need(len(ownrows)==36 and len(classrows)==1,'true36 newnative +1class records')
 need([r['actualImport']for r in ownrows]==provider.imports and classrows[0]['actualImport']==row and all(r['resolution']['resolved']is True for r in ownrows+classrows),'new actual import index/at routes joined, not names only')
 def normalized(rows):
  return [dict(importer=r['importer'],actualImport={k:v for k,v in r['actualImport'].items()if k!='at'},resolution=r['resolution'])for r in rows]
 remaining=[r for r in proof['actualStrongImportRows']if r not in ownrows+classrows];need(normalized(remaining)==normalized(oldproof['actualStrongImportRows'])and proof['actualNativeWeakDefinitionRows']==oldproof['actualNativeWeakDefinitionRows'],'all old5472 semantic routes and13 weak unchanged')
 need(proof['actualStrongImports']==5509 and proof['actualNormalStrongImports']==len(proof['actualStrongImportRows'])==5496 and proof['actualWeakLookupStrongImports']==proof['nativeWeakDefinitionsResolved']==len(proof['actualNativeWeakDefinitionRows'])==13 and proof['unresolvedStrongImportRows']==[],'actual normal5496 plus weaklookup13 equals total5509/zero gaps')
 out.mkdir(mode=0o700);report=dict(schema='Independent named UIKit Mac-event filter V2 and Stage composition finite peer',providerCandidate=pin(a.provider_candidate),stageCandidate=pin(a.stage_candidate),providerFreeze=pin(pf),stageFreeze=pin(sf),actualSource=c['source'],actualProvider=c['provider'],actualMethodTable=inst+caps,actualOriginalMethodTable=oi+om,actualTypedABIMatchesOriginal=True,rawMonitorSize=18,alignedRuntimeMonitorSize=24,actualMonitorIvarOffsets=[8,16,17],V1Raw18GuardHeldAndNotApproved=True,actualNamedNSObjectClass=True,capabilities=dict(isEnabled=False,hasEventTranslators=False),MacMethodsTypedUnsupported=True,fakeNSEventClass=False,fakeSwiftMetadata=False,classref=dict(RVA='0x318d68',oldRaw=hex(ow),newRaw=hex(nw),oldAuthenticated=False,newAuthenticated=False,rebaseToStrongBind=True,nextPreserved=True),actualOnlyClassrefSlotChanged=True,actualNewRequiredOrdinal=63,actualNewImportIndex=1056,allOriginalCodeSectionsAndOldAuthenticatedGOTPreserved=True,patchedVZWholebytesIndependentlyReconstructed=True,actualImages=74,other72ImageWholebytesSame=True,actualNewStrongRows=37,actualJoinedStrongRows=5509,weakDefinitions=13,definitionGaps=0,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,fullUIKitInputSupport=False,ordinaryKeyPointerExecuted=False,unsupportedAlsoIncludes=contract['unsupportedAlsoIncludes'],runtimeMonitorGetterNotExecutedOnIPadYet=True,staticSourceAndCompositionOnly=True,actualRuntime9SigningFailed=True,knownBlockingFollowup='Root actual child VZ codesign internal error; new fixup payload appended beyond old LC_CODE_SIGNATURE requires a new signing-layout source candidate. V2 not ready for device execution.',readyForDeviceExecution=False,readyForSuccessfulSigningClaim=False,historicalStageAttempt1Stale73MetadataResolvedByAttempt2=True,actualGuestBoot=False,actualGuestSSHAuthenticated=False,deviceOperations=0,trustCacheOperations=0,findings=[],finiteLocalScopePassed=True)
 (out/'review.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(a.provider_candidate),pin(pf),pin(a.stage_candidate),pin(sf),c['builder'],c['reader'],c['source'],c['header'],c['tests'],c['provider'],c['originalVZ'],c['patchedVZ'],c['recipe'],sc['builder'],sc['baseStage'],pin(proofpath),proof['inheritedExactPreviousVerification']]+[pin(out/'review.json')]
 (out/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))
if __name__=='__main__':main()
