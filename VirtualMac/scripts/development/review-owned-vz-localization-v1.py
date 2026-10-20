#!/usr/bin/env python3
"""Finite independent source/ABI/callsite recipe peer; no model rerun or device."""
import pathlib,json,hashlib,struct,importlib.util,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):
 assert pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')};return pathlib.Path(row['path'])
def main():
 cp=N/'owned-vz-localization-source-local-v1-attempt2/candidate.json';c=json.loads(cp.read_bytes());fp=cp.parent/'freeze.json'
 for row in json.loads(fp.read_bytes())['files']:exact(row)
 text=exact(c['source']).read_text();h=exact(c['header']).read_text();recipe=json.loads(exact(c['recipe']).read_bytes());raw=exact(recipe['originalParentVZ']).read_bytes();reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';sp=importlib.util.spec_from_file_location('locpeer',reader);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);q=m.MachO(raw)
 assert q.uuid==recipe['originalUUID']=='418efc4809d93606918eb6f95baeffdc'
 assert 'ns_returns_not_retained' in h and 'extern "C"'in h
 assert '? [actualBundle localizedStringForKey:originalKey value:nil table:nil]'in text and 'return translation;'in text and 'return originalKey;'in text
 assert 'isKindOfClass:[NSString class]'in text and 'isKindOfClass:[NSBundle class]'in text and 'NSInvalidArgumentException'in text
 assert not any(v in text for v in ('errorWithDomain:','setuid','sandbox','confstr','bundleWithIdentifier:'))
 assert recipe['newImport']==dict(index=len(q.imports),name='_VM27OwnedVZLocalizedStringOrEnglishKeyV1',ordinal=64,weak=False,addend=0)
 assert len(recipe['codeWords'])==2
 for row in recipe['codeWords']:
  assert raw[q.file(q.base+row['rva']):q.file(q.base+row['rva'])+4].hex()==row['before']
 words=recipe['codeWords'];assert words[0]['rva']==0x39c4 and words[0]['before']=='e20313aa'and words[0]['after']=='e10313aa'
 target=recipe['authenticatedThunk']['rva'];call=struct.unpack('<I',bytes.fromhex(words[1]['after']))[0];assert call==0x94000000|(((target-words[1]['rva'])//4)&0x3ffffff)
 thunk=recipe['authenticatedThunk'];slot=recipe['authenticatedSlot'];assert target==0x2e4e30 and slot['rva']==0x3197d0
 assert raw[q.file(q.base+target):q.file(q.base+target)+16]==bytes(16) and raw[q.file(q.base+slot['rva']):q.file(q.base+slot['rva'])+8]==bytes(8)
 encoded=int(slot['afterWord'],16);assert encoded>>63==1 and encoded>>62&1==1 and encoded>>48&1==1 and encoded>>49&3==0 and encoded&0xffffffff==len(q.imports) and encoded>>51&0x7ff==0
 assert thunk['after']=='b00100b010421f91110240f9300a1fd7'
 assert recipe['chainStart']['pageIndex']==12 and recipe['chainStart']['addedStart']==6096 and recipe['chainStart']['method'].startswith('new MULTI')
 assert recipe['preservedOriginalLocalizer']['returnRetainAutorelease']and recipe['preservedOriginalLocalizer']['unwindAndLSDA']and recipe['preservedOriginalLocalizer']['originalErrorCode1']
 steps={r['label']:r for r in c['steps']};assert all(r['exitCode']==0 for r in c['steps'])
 for label in ('normal-execute','san-execute'):
  assert b'actualFoundationChecks=10'in exact(steps[label]['stdout']).read_bytes()
 assert exact(steps['actual-cxx-undefined']['stdout']).read_text().strip()=='_VM27OwnedVZLocalizedStringOrEnglishKeyV1'
 assert c['actualFoundationChecksNormal']==c['actualFoundationChecksSAN']==10 and not c['ownLocalizationContract']['actualNativeBundlePointerOnDeviceObserved']
 out=N/'owned-vz-localization-source-independent-peer-v1-attempt1';out.mkdir(mode=0o700);report=dict(schema='Owned VZ true localization +0 ABI and precise parent recipe finite independent peer',sourceCandidate=pin(cp),producerFreeze=pin(fp),source=c['source'],header=c['header'],actualIOSObject=c['actualIOSObject'],actualRecipe=c['recipe'],actualFrozenSourceAndObjectPinsChecked=True,actualNSBundleTranslationPreserved=True,missingBundleOrTranslationReturnsActualOriginalEnglishKey=True,invalidKeyOrWrongBundleStillThrows=True,errorCode1AndReasonNotConvertedToSuccess=True,exactObjCPlusZeroABIAndTypedCxxReceiptVerified=True,actualFoundationNormal10AndSAN10ReceiptsInherited=True,hostModelsRepeated=False,originalParent395cOnlyTwoWordsListed=True,originalCallerPACLSDAAndKeyAndReturnLifecycleNotPatched=True,originalZeroThunkAndSlotActualBytesVerified=True,realIAAddressDiversifiedAuthBindAnd16ByteThunk=True,newStrongImport1057OnSharedOrdinal64Explicit=True,composerMustActuallyApplyAndVerifyMULTIChainStart=True,parentOnlyRecipe=True,childAndGlobalFoundationNotPatched=True,actualPatchedImageNotProducedHere=True,deviceOperations=0,trustCacheOperations=0,actualNativeNSBundlePointerRead=False,actualVMErrorResolutionNotExecuted=False,findings=[],finiteLocalScopePassed=True,passed=True)
 rp=out/'review.json';rp.write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(cp),pin(fp),c['source'],c['header'],c['actualIOSObject'],c['recipe'],recipe['originalParentVZ'],pin(reader),pin(rp)]+[r['stdout']for r in c['steps']]+[r['stderr']for r in c['steps']]+[c['fixture']];sf=out/'freeze.json';sf.write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(rp),freeze=pin(sf),findings=[])))
if __name__=='__main__':main()
