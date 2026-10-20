#!/usr/bin/env python3
"""Build an explicit failure provider and one-import inert VMM port.

No accelerator, driver IO, signing, loader, subprocess guest or device call.
"""
import argparse,hashlib,importlib.util,json,pathlib,shlex,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from vz_import_addend_image import commands,segments,imports
READER=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
spec=importlib.util.spec_from_file_location('iosurface_port_ptr12',READER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
OWN='_VM27IOSurfaceGuestTransformUnavailableV1';OLD='_IOSurfaceAcceleratorParavirtProcessGuestData'
LOAD='@loader_path/VM27IOSurfaceGuestUnavailableV1.dylib'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def port(before):
 rows=commands(before);info=imports(before);selected=[r for r in info['imports']if r['name']==OLD]
 assert len(selected)==1 and selected[0]['index']==830 and selected[0]['ordinal']==32 and not selected[0]['weak'] and selected[0]['addend']==0
 count=sum(cmd in (12,0x80000018,0x8000001f,0x80000023)for cmd,at,z in rows);ordinal=count+1;assert ordinal<128
 end=32+struct.unpack_from('<I',before,20)[0];name=LOAD.encode()+b'\0';z=(24+len(name)+7)&~7
 command=struct.pack('<6I',12,z,24,1,65536,65536)+name+bytes(z-24-len(name))
 first=min(s['fileoff']for g in segments(before)for s in g['sections']if s['fileoff'] and s['size'] and s['flags']&255 not in (1,12,18))
 assert end+z<=first and not any(before[end:end+z]),'Actual packed header capacity is required'
 data=bytearray(before);data[end:end+z]=command
 struct.pack_into('<II',data,16,struct.unpack_from('<I',before,16)[0]+1,struct.unpack_from('<I',before,20)[0]+z)
 version,starts,imp,names,count,form,compressed=info['header'];assert version==compressed==0 and form==2
 blob=bytearray(before[info['data']:info['data']+info['size']]);pool=len(blob)-names;assert pool<(1<<23)
 oldword=struct.unpack_from('<I',blob,imp+830*8)[0]
 struct.pack_into('<I',blob,imp+830*8,(oldword&256)|ordinal|(pool<<9));blob+=OWN.encode()+b'\0'
 newfix=(len(data)+7)&~7;data+=bytes(newfix-len(data));data+=blob
 for cmd,at,z in commands(data):
  if cmd==0x80000034:struct.pack_into('<II',data,at+8,newfix,len(blob))
  if cmd==0x19 and data[at+8:at+24].split(b'\0')[0]==b'__LINKEDIT':
   off=struct.unpack_from('<Q',data,at+40)[0];struct.pack_into('<Q',data,at+32,(len(data)-off+16383)&~16383);struct.pack_into('<Q',data,at+48,len(data)-off)
 return bytes(data),dict(index=830,oldName=OLD,ownName=OWN,oldOrdinal=32,newOrdinal=ordinal,
  originalHeaderEnd=end,newRequiredLoad=LOAD,newHeaderEnd=end+len(command),firstOriginalSection=first,
  chainedImportFormat=form,oldFixupData=info['data'],newFixupData=newfix)
def validate(before,after):
 expected,recipe=port(before);assert expected==after
 original,new=imports(before)['imports'],imports(after)['imports'];assert len(original)==len(new)
 for a,b in zip(original,new):
  e=dict(a);e['command']=b['command']
  if a['index']==830:e['ordinal']=recipe['newOrdinal'];e['name']=OWN
  assert e==b
 oldchain,newchain=m.MachO(before).binds,m.MachO(after).binds;assert len(oldchain)==len(newchain)
 for a,b in zip(oldchain,newchain):
  expected=dict(a);expected['name']=OWN if a['index']==830 else a['name'];assert expected==b
 assert m.MachO(before).exports==m.MachO(after).exports
 for g in segments(before):
  for s in g['sections']:
   if s['fileoff'] and s['size'] and s['flags']&255 not in (1,12,18):
    at=s['fileoff'];assert after[at:at+s['size']]==before[at:at+s['size']]
 uuid=lambda b:[b[a+8:a+24].hex()for c,a,z in commands(b)if c==27]
 assert uuid(before)==uuid(after)==['4a6a588d1afd30f5a64d6304eb79be0b']
 return recipe
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();o=a.output.resolve();assert o.is_relative_to(N)and not o.exists();o.mkdir()
 source=S/'vm27_iosurface_guest_transform_unavailable_v1.c';header=S/'vm27_iosurface_guest_transform_unavailable_v1.h';fixture=S/'test-vm27-iosurface-guest-transform-unavailable-v1.c'
 stagePath=N/'independent27-flat-graph-stage-v1-attempt3/candidate.json';stage=json.loads(stagePath.read_bytes());r=next(r for r in stage['stagedImages']if r['key']=='com.apple.Virtualization.VirtualMachine')
 assert pin(r['staged']['path'])==r['staged'];before=pathlib.Path(r['staged']['path']).read_bytes()
 for row in json.loads((stagePath.parent/'freeze.json').read_bytes())['pins']:assert pin(row['path'])==row
 macLog=N/'macos27-iosurfaceaccel-source-disassembly-readonly-v1/all-code.stdout';macContract=macLog.with_name('image-contract.stdout')
 macBody=macLog.read_text().split('_IOSurfaceAcceleratorParavirtProcessGuestData:\n',1)[1].split('_ioSurfaceAcceleratorFinalize:',1)[0]
 assert len([x for x in macBody.splitlines()if x.startswith('0x')])==45
 assert '0x1A2E9EFAC   str      w0, [x19, #0x4]'in macBody and 'mov      w3, #0x1b0'in macBody
 assert '0x00002F0C  _IOSurfaceAcceleratorParavirtProcessGuestData'in macContract.read_text()
 nativeDir=N/'ipad-current-iosurfaceaccel-native-code-readonly-v1';nativeJSON=nativeDir/'true-native-transform-dispatch.json';native=json.loads(nativeJSON.read_bytes())
 nativeBytes=(nativeDir/'iosurfaceaccelerator-text.bin').read_bytes();assert len(nativeBytes)==16384
 for ins in native:assert nativeBytes[ins['rva']:ins['rva']+4].hex()==ins['bytes']
 assert any(ins['operands']=='w3, #0x170'for ins in native)
 caller=N/'vmm-essential-display-profile-readonly-v2/accel-caller-0.stdout';text=caller.read_text()
 assert 'cmp\tx25, #0x20'in text and 'cmp\tx25, #0x610'in text and '1001b5268:'in text and '1001b52ec:'in text
 # Independently validate the exact current staged machine words consumed by
 # that diagnostic, not just its disassembler's labels.
 profile=N/'vmm-public-adapter-gap-design-v1/audit.py';import runpy;p=runpy.run_path(str(profile));image=p['MachO'](before)
 expected={0x1b5220:0xf100833f,0x1b50c0:0xf118433f,0x1b5260:0xaa1303e1,0x1b5264:0x52800402,0x1b5268:0x94097157,
  0x1b52e4:0xaa1303e1,0x1b52e8:0x5280c202,0x1b52ec:0x94097136}
 for at,w in expected.items():assert struct.unpack('<I',image.raw(at,4))[0]==w,(hex(at),hex(w),image.raw(at,4).hex())
 commandsLog=[]
 def run(label,args):
  c=subprocess.run(list(map(str,args)),capture_output=True,timeout=60);(o/(label+'.stdout')).write_bytes(c.stdout);(o/(label+'.stderr')).write_bytes(c.stderr)
  commandsLog.append(dict(label=label,argv=list(map(str,args)),exit=c.returncode));save(o/'commands.json',commandsLog);assert c.returncode==0,(label,c.stderr.decode(errors='replace'));return c.stdout
 sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip();models=[]
 for san in [False,True]:
  name='san'if san else'normal';exe=o/('host-'+name)
  flags=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-O2',source,fixture,'-o',exe]
  if san:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
  run('compile-'+name,flags);model=json.loads(run('execute-'+name,[exe]));assert model['passed']and model['nativeAcceleratorCalls']==0;models.append(model)
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-O2','-fvisibility=hidden']
 provider=o/'VM27IOSurfaceGuestUnavailableV1.unsigned.dylib';run('ios-provider',flags+['-dynamiclib',source,'-Wl,-install_name,'+LOAD,'-Wl,-no_adhoc_codesign','-o',provider])
 for q in ['validate_only','exports','imports','dependents']:run('provider-'+q,['xcrun','dyld_info','-'+q,provider])
 assert OWN[1:]in (o/'provider-exports.stdout').read_text();assert 'IOSurfaceAccelerator' not in (o/'provider-imports.stdout').read_text()
 llvm=o/'ios-source.ll';run('ios-ir',flags+['-S','-emit-llvm',source,'-o',llvm]);signature=next(x for x in llvm.read_text().splitlines()if x.startswith('define ')and 'VM27IOSurfaceGuestTransformUnavailableV1'in x)
 assert 'i32 @VM27IOSurfaceGuestTransformUnavailableV1('in signature and 'i64'in signature
 closure={}
 dep=run('ios-actual-include',flags+['-MM',source]).decode().replace('\\\n',' ')
 for path in shlex.split(dep.split(':',1)[1]):
  q=pathlib.Path(path).resolve();closure[str(q)]=pin(q)
 after,_=port(before);recipe=validate(before,after);candidate=o/'VMM27.iosurface-explicit-unsupported.inert.macho-data';candidate.write_bytes(after)
 run('validate-vmm',['xcrun','dyld_info','-validate_only',candidate])
 negatives=[]
 for name,at in [('packet-call-code',0x1b5268),('own-load-path',recipe['originalHeaderEnd']+24),('own-fixup-import',recipe['newFixupData']+imports(after)['header'][2]+830*8),('native-PAC-word',0x4c6398)]:
  bad=bytearray(after);bad[at]^=1
  try:validate(before,bytes(bad))
  except(AssertionError,ValueError):negatives.append(dict(name=name,rejected=True))
  else:raise AssertionError(name)
 typed=o/'typed-entry.cpp';typed.write_text('#include "vm27_iosurface_guest_transform_unavailable_v1.h"\nextern "C" IOReturn VM27ActualTypedGuestTransformCaller(const void*a,void*p,size_t n){return VM27IOSurfaceGuestTransformUnavailableV1(a,p,n);}\n')
 typedDSO=o/'typed-entry.unsigned.dylib';run('typed-cpp-link',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-dynamiclib',typed,provider,'-Wl,-no_adhoc_codesign','-o',typedDSO]);run('typed-cpp-validate',['xcrun','dyld_info','-validate_only','-imports',typedDSO])
 sourcePins=[pin(q)for q in [pathlib.Path(__file__),source,header,fixture,stagePath,macLog,macContract,nativeJSON,nativeDir/'manifest.json',nativeDir/'receipt.json',nativeDir/'iosurfaceaccelerator-text.bin',caller,profile,READER,pathlib.Path(__file__).with_name('vz_import_addend_image.py')]]
 record=dict(schema='Own IOSurface guest transform precise unsupported source and one-import port v1',finiteLocalSourceScopePassed=True,findings=[],
  provider=pin(provider),sourcePins=sourcePins,actualIncludeClosure=list(closure.values()),stageSource=r['staged'],vmmCandidate=pin(candidate),patchRecipe=recipe,
  realCallerWordChecks=len(expected),trueMacEntryRVA=0x2f0c,trueMacEntryBytes=180,trueMacStatusOffset=4,actualNativePayloadBytes368VersusMac432=True,
  validCommandByteExtents={'1':32,'2':1552},models=models,negativeControls=negatives,typedCPPStrongLinkPassed=True,actualIOReturn32IRSignature=signature,
  exactSDKBadArgumentStatus=0xe00002c2,exactSDKUnsupportedStatus=0xe00002c7,
  validPacketOnlyStatus4Changed=True,invalidCommandsOrSizesLeavePacketUnchanged=True,acceleratorOrEmbeddedPointersRead=False,
  nativeDriverIOCalls=0,originalAppleAPIDefined=False,allOriginalVMMCodeSectionsAndPACWordsExact=True,
  actualOriginalVMMCallerExecuted=False,guestTransformOrDisplayImplemented=False,impactOnActualVisibleBootNotYetValidated=True,
  completeLoadGraphValidated=False,deviceOperations=0,codeSigned=False,guestBoot=False)
 save(o/'candidate.json',record);files={str(q.resolve()):pin(q)for q in o.rglob('*')if q.is_file()}
 for row in sourcePins+list(closure.values()):files[row['path']]=row
 save(o/'freeze.json',dict(files=list(files.values())))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),provider=pin(provider),vmmCandidate=pin(candidate),freeze=pin(o/'freeze.json'),models=models)))
if __name__=='__main__':main()
