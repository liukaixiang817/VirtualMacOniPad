#!/usr/bin/env python3
"""Offline import90-only route. Output is inert, stale-signature data, never loaded."""
import argparse,hashlib,importlib.util,json,pathlib,shutil,stat,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE=N/'softlinking-original-consumer-routes-v1/inert-data-v2/VMM27.scoped-softlinking.inert.macho-data'
SOURCE_SHA='cde54210342545872acd1bb4c1b406e899179877f1ba65f500e10cfb3a6bb251'
PROVIDER=N/'vmm-headless-checkin-contract-v1/ios/VM27HeadlessCheckIn.dylib'
PROVIDER_SHA='539d419dc0d9ab3cd769ed383ff5f6541c8d34a971f6329614323defc1713d38'
PROVIDER_FREEZE=N/'vmm-headless-checkin-contract-v1/freeze.json'
PROVIDER_FREEZE_SHA='ec6cd97a3ff704e8955722ba91a7064e5cd5181da9779d38764be1a73ee0d425'
READER=N/'original-service-factory-caller-contract-v1/inspect.py'
DEPENDENCY='@loader_path/VM27HeadlessCheckIn.dylib'
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=sha(b))
def module(p,name):s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=module(READER,'checkin_original_image')
sys.path.insert(0,str(R/'VirtualMac/scripts/development'));from vz_import_addend_image import imports
def parse(b,name):
 # Image's mapper is read-only. Use a temporary view without a backing-file write.
 class MemoryPath:
  def read_bytes(self):return b
 im=M.Image(name,MemoryPath());return im
def command_set(im):
 deps=[];rows=[]
 for cmd,at,z in im.commands:
  r=dict(cmd=cmd,at=at,size=z,raw=im.data[at:at+z])
  if cmd in(12,0x80000018,0x8000001f,0x80000023):
   deps.append(r);r['ordinal']=len(deps)+0
  rows.append(r)
 return rows,deps
def transform(source):
 assert sha(source)==SOURCE_SHA
 im=parse(source,'source');rows,deps=command_set(im)
 assert len(rows)==69 and len(deps)==53 and struct.unpack_from('<I',source,20)[0]==8464
 text=im.section('__text');assert text['file']==8528 and source[8496:8528]==bytes(32)
 soft=deps[35];assert soft['at']==7240 and soft['size']==104
 no,t,cur,compat=struct.unpack_from('<4I',soft['raw'],8)
 assert no==24 and soft['raw'][no:].split(b'\0')[0]==b'@loader_path/VM27ScopedSoftLinking.dylib'
 assert soft['raw'][-32:]==bytes(32)
 compact=bytearray(soft['raw'][:-32]);struct.pack_into('<I',compact,4,len(compact));assert len(compact)==72
 path=DEPENDENCY.encode()+b'\0';z=(24+len(path)+7)//8*8;assert z==64
 new=struct.pack('<6I',12,z,24,2,65536,65536)+path+bytes(z-24-len(path))
 commands=b''.join(bytes(compact)if r is soft else r['raw']for r in rows)+new
 assert len(commands)==8496 and 32+len(commands)==text['file']
 target=bytearray(source);target[32:text['file']]=commands
 struct.pack_into('<II',target,16,70,8496)
 original=imports(source)['imports'][90];assert original['name']=='__LSApplicationCheckIn'and original['ordinal']==5 and not original['weak']and original['addend']==0
 ia=original['command'];word=struct.unpack_from('<I',source,ia)[0];struct.pack_into('<I',target,ia,(word&~255)|54)
 symbols=[(a,z)for c,a,z in im.commands if c==2];assert len(symbols)==1
 symoff,count,stroff,strsize=struct.unpack_from('<4I',source,symbols[0][0]+8)
 assert count>327 and im.nlist[327]['name']=='__LSApplicationCheckIn'and im.nlist[327]['descriptor']==1280
 descriptor=symoff+327*16+6;struct.pack_into('<H',target,descriptor,54<<8)
 return bytes(target),dict(importOffset=ia,nlistDescriptorOffset=descriptor,originalSoftLinkingCommand=soft['raw'].hex(),newDependencyBytes=z)
def verify(source,target,record):
 assert sha(source)==SOURCE_SHA and len(source)==len(target)
 expected,again=transform(source);assert target==expected and record==again
 a=parse(source,'source');b=parse(target,'target');ar,ad=command_set(a);br,bd=command_set(b)
 assert len(br)==70 and len(bd)==54
 assert b.libraries[-1]==DEPENDENCY
 assert b.imports[90]==dict(symbol='__LSApplicationCheckIn',ordinal=54,weak=False,addend=0)
 assert all(b.imports[i]==v for i,v in enumerate(a.imports)if i!=90)
 assert all(b.nlist[i]==v for i,v in enumerate(a.nlist)if i!=327)
 assert b.nlist[327]=={**a.nlist[327],'descriptor':54<<8}
 assert [b.imports[i]for i in (91,92,93,94,981,982)]==[a.imports[i]for i in (91,92,93,94,981,982)]
 assert a.sections==b.sections and a.segments==b.segments
 changed=[i for i in range(8528,len(source))if source[i]!=target[i]]
 assert changed==sorted([record['nlistDescriptorOffset']+1,record['importOffset']])
 # The authenticated bind slot keeps import INDEX90, key/diversity/all bits.
 assert a.read(0x4c6230,8)==b.read(0x4c6230,8)==bytes.fromhex('5a000000000009c0')
 for x,y in zip(ar,br):
  if x.get('ordinal')==36:assert y['raw']==x['raw'][:4]+struct.pack('<I',72)+x['raw'][8:-32]
  else:assert x['raw']==y['raw']
 return dict(onlyChangesAfterTextStart=changed,allSectionsAndCodeExact=True,allAuthPACWordsExactByWholeByteComparison=True,
  originalImportIndex90Retained=True,sixOtherCoreServicesImportsPreserved=True,headerOriginalBytes=8464,headerNewBytes=8496,
  originalHeaderNULBytesUsed=32,originalSoftLinkingTailNULRemoved=32,softLinkingPathAndVersionsPreserved=True,
  newStrongOrdinal=54,oldCoreServicesOrdinal5Retained=True,signatureStale=True,originalVMMExecuted=False,full27Backend=False)
def inverse(source,target,record):
 verify(source,target,record)
 im=parse(target,'target');rows,deps=command_set(im)
 assert deps[-1]['raw'].split(DEPENDENCY.encode())[0][:4]==struct.pack('<I',12)
 restored=bytearray(target)
 original_soft=bytes.fromhex(record['originalSoftLinkingCommand'])
 commands=b''.join(original_soft if r.get('ordinal')==36 else r['raw']for r in rows[:-1])
 assert len(commands)==8464
 restored[32:8528]=commands+bytes(32);struct.pack_into('<II',restored,16,69,8464)
 restored[record['importOffset']]=5;struct.pack_into('<H',restored,record['nlistDescriptorOffset'],1280)
 assert bytes(restored)==source and sha(restored)==SOURCE_SHA
 return bytes(restored)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path);ap.add_argument('--check',type=pathlib.Path);args=ap.parse_args()
 source=SOURCE.read_bytes();provider=PROVIDER.read_bytes()
 assert sha(provider)==PROVIDER_SHA and sha(PROVIDER_FREEZE.read_bytes())==PROVIDER_FREEZE_SHA
 if args.check:
  c=json.loads((args.check/'candidate.json').read_bytes());target=(args.check/'VMM27.headless-checkin-route.inert.macho-data').read_bytes();verify(source,target,c['transform']);inverse(source,target,c['transform']);print('inert original VMM import90 route verified; no image executed');return
 assert args.output and not args.output.exists();args.output.mkdir(parents=True)
 out=args.output;target,record=transform(source);proof=verify(source,target,record);restored=inverse(source,target,record)
 path=out/'VMM27.headless-checkin-route.inert.macho-data';path.write_bytes(target);path.chmod(0o600)
 restored_path=out/'VMM27.roundtrip-source.inert.macho-data';restored_path.write_bytes(restored);restored_path.chmod(0o600)
 alias=out/'VM27HeadlessCheckIn.dylib';shutil.copyfile(PROVIDER,alias);alias.chmod(0o600);assert stat.S_ISREG(alias.lstat().st_mode)and alias.lstat().st_nlink==1 and alias.read_bytes()==provider
 bad=[]
 for label,at in [('text',8528),('PAC',parse(source,'guard').offset(parse(source,'guard').base+0x4c6230)),('import90',record['importOffset']),('other nlist',record['nlistDescriptorOffset']-16),('new dependency',8528-64+24),('old CoreServices path',4320+24),('header count',16),('header size',20),('SoftLinking path',7240+24)]:
  damaged=bytearray(target);damaged[at]^=1
  try:inverse(source,bytes(damaged),record)
  except (AssertionError,ValueError,IndexError,UnicodeError):bad.append(dict(name=label,rejected=True))
  else:raise AssertionError(label+' accepted')
 validation=subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True)
 (out/'metadata.stdout').write_bytes(validation.stdout);(out/'metadata.stderr').write_bytes(validation.stderr)
 c=dict(schema='Original VMM import90-only private CheckIn inert route v1',builder=pin(pathlib.Path(__file__)),source=pin(SOURCE),provider=pin(PROVIDER),providerFreeze=pin(PROVIDER_FREEZE),
  target=pin(path),providerCopy=pin(alias),transform=record,verification=proof,roundtripSource=pin(restored_path),wholeByteRoundtripExact=True,
  roundtripScope='exact immediate pre-existing inert input cde542; prior routes not silently undone; genuine original code stays unchanged',badControls=bad,metadataExit=validation.returncode,
  requiresActualPrivateProviderReceiptBeforeRuntimeLoad=True,privateProviderNativeExecuted=False,wholeStrongDependencyClosureAudited=False,
  originalVMMExecuted=False,originalVZLoaded=False,nativeOperations=0,deviceOperations=0,guestInstructions=0,signatureStale=True,full27Backend=False)
 (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
 files=[pin(p)for p in sorted(out.iterdir())if p.is_file()];(out/'freeze.json').write_text(json.dumps(dict(schema='Inert single VMM import route freeze v1',files=files),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),target=pin(path),freeze=pin(out/'freeze.json'),guards=len(bad),metadataExit=validation.returncode,executed=False)))
if __name__=='__main__':main()
