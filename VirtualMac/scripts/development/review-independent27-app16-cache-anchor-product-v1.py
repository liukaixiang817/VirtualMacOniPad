#!/usr/bin/env python3
"""HOST-only finite App16 anchor delta/signature peer; no execution or signing."""
import argparse,hashlib,importlib.util,json,pathlib,plistlib,re,stat,struct,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development'
BASE=N/'independent27-signed-app-cpu-bitmap-display-v15-attempt1/candidate.json'
PEER=N/'independent27-app15-cpu-bitmap-signed-independent-peer-v1-attempt1/review.json'
READER=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
SIGNATURE=B/'review-independent27-signed-runtime-product-v1.py'
def need(ok,msg):
 if not ok:raise ValueError(msg)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(row):
 p=pathlib.Path(row['path']);need(pin(p)==row,'actual frozen '+str(p));return p

def mod(p,name):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def freeze(p):
 f=p.parent/'freeze.json';d=json.loads(f.read_bytes())
 for row in d['files']:exact(row)
 return pin(f),len(d['files'])

def sigslots(m):
 command=next(c for c in m.commands if c['cmd']==0x1d);at,size=struct.unpack_from('<II',command['raw'],8);blob=m.data[at:at+size];magic,length,count=struct.unpack_from('>III',blob);need(magic==0xfade0cc0,'signature superblob');r={}
 for i in range(count):
  slot,off=struct.unpack_from('>II',blob,12+8*i);length=struct.unpack_from('>I',blob,off+4)[0];r[slot]=blob[off:off+length]
 return r

def nlists(m):
 cmd=next(c for c in m.commands if c['cmd']==2);at,count,strings,length=struct.unpack_from('<4I',cmd['raw'],8);out={}
 for i in range(count):
  ix,typ,sect,desc,value=struct.unpack_from('<IBBHQ',m.data,at+16*i);end=m.data.find(b'\0',strings+ix,strings+length);name=m.data[strings+ix:end].decode();out[name]=(typ,sect,desc,value)
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--signed-candidate',type=pathlib.Path,required=True);ap.add_argument('--runtime-candidate',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh finite peer');sp=a.signed_candidate.resolve();rp=a.runtime_candidate.resolve();signed=json.loads(sp.read_bytes());old=json.loads(BASE.read_bytes());prior=json.loads(PEER.read_bytes());need(prior['finiteLocalScopePassed'] and prior['findings']==[],'actual previous peer');sf,checked=freeze(sp);up=exact(signed['sourceCandidate']);unsigned=json.loads(up.read_bytes());uf,ucheck=freeze(up);runtime=json.loads(rp.read_bytes());need(signed['runtimeCandidate']==pin(rp),'actual Runtime11 product pin');need(runtime['schema'].find('Runtime11')>=0,'actual Runtime11 schema');oldunsigned=json.loads(exact(old['sourceCandidate']).read_bytes());need(len(unsigned['objects'])==len(oldunsigned['objects'])==35 and len(unsigned['commands'])==80 and all(x['exit']==0 for x in unsigned['commands']),'actual35 objects/80 successful commands');changed=[i for i,(x,y) in enumerate(zip(unsigned['objects'],oldunsigned['objects'])) if x['sha256']!=y['sha256'] or x['bytes']!=y['bytes']];need(changed==[34],'only real anchor object34 changes');need(unsigned['sourceFiles'][:-1]==oldunsigned['sourceFiles'][:-1],'all34 actual source pins unchanged');need(signed['realCompiledManifestAnchor']==runtime['anchorSource']==unsigned['sourceFiles'][-1],'actual anchor source compiled');exact(runtime['anchorSource']);exact(runtime['manifest']);raw=pathlib.Path(runtime['manifest']['path']).read_bytes();digest=hashlib.sha256(raw).digest();source=pathlib.Path(runtime['anchorSource']['path']).read_text();match=re.search(r'SHA256V1\[32\]=\{([^}]+)\}',source);need(match and bytes(int(x) for x in match[1].split(','))==digest and 'ManifestBytesV1='+str(len(raw))+';' in source,'genuine manifest digest/extent source');reader=mod(READER,'app16_independent_macho');signature=mod(SIGNATURE,'app16_independent_signature');image=reader.MachO(exact(signed['binary']).read_bytes());before=reader.MachO(exact(unsigned['binary']).read_bytes());oldimage=reader.MachO(exact(old['binary']).read_bytes());need(image.uuid==before.uuid and image.sections==before.sections and image.imports==before.imports and image.exports==before.exports and image.binds==before.binds,'signing leaves true image/code/PAC identity');
 for section in before.sections:
  at,size=section['fileoff'],section['size']
  if at and size and section['flags']&255 not in (1,12,18):need(before.data[at:at+size]==image.data[at:at+size],'actual unsigned/signed section identical')
 need(image.loads==oldimage.loads and image.imports==oldimage.imports and image.exports==oldimage.exports and image.binds==oldimage.binds,'all487 native imports/namespace/PAC unchanged');routes_path=exact(prior['actualNativeRoutes']);routes=json.loads(routes_path.read_bytes());need(routes['actualImports']==len(image.imports)==487 and routes['unresolved']==[] and len(routes['actualRows'])==487,'prior complete actual487 routes');
 for imp,row in zip(image.imports,routes['actualRows']):need(imp==row['actualNewImport'] and image.loads[imp['ordinal']-1]['path']==row['requiredLoad'],'each actual import/load row inherits genuine route')
 root=pathlib.Path(signed['app']);oldroot=pathlib.Path(old['app']);files={str(pathlib.Path(x['path']).relative_to(root)):x for x in signed['appFiles']};oldfiles={str(pathlib.Path(x['path']).relative_to(oldroot)):x for x in old['appFiles']};need(set(files)==set(oldfiles) and len(files)==103,'same103 whole package files');need(set(files)=={str(x.relative_to(root)) for x in root.rglob('*') if x.is_file()},'no extra package files');changes=[]
 for rel,row in files.items():
  path=exact(row);need(stat.S_ISREG(path.lstat().st_mode),'regular packaged file')
  if (row['bytes'],row['sha256'])!=(oldfiles[rel]['bytes'],oldfiles[rel]['sha256']):changes.append(rel)
 need(changes==['VirtualMacIndependent27'],'only main file delta; all102 resources unchanged');actual=signature.signed_image(exact(signed['binary']),signed['actualSignature'],{1:(root/'Info.plist').read_bytes(),3:(root/'_CodeSignature/CodeResources').read_bytes()});need(actual==signed['actualSignature'],'actual fresh codepage/special slot verification');slots=sigslots(image);oldslots=sigslots(oldimage);need(slots[5]==oldslots[5] and slots[7]==oldslots[7],'XML/DER entitlement blobs unchanged');symbols=nlists(image);sha_symbol=symbols['_VM27IndependentRuntimeManifestSHA256V1'];size_symbol=symbols['_VM27IndependentRuntimeManifestBytesV1'];need(image.data[image.file(sha_symbol[3]):image.file(sha_symbol[3])+32]==digest and struct.unpack_from('<Q',image.data,image.file(size_symbol[3]))[0]==len(raw),'real digest/extent in linked signed main');newbuilder=exact(unsigned['builder']);oldbuilder=exact(oldunsigned['builder']);need(newbuilder.read_text().replace('App16 Runtime11 real private cache context with genuine IOSurface','App15 genuine IOSurface')==oldbuilder.read_text(),'builder differs only truthful schema labels');out.mkdir(mode=0o700);report=dict(schema='Independent finite actual App16 Runtime11 cache manifest anchor signed product peer',signedCandidate=pin(sp),unsignedCandidate=pin(up),runtimeCandidate=pin(rp),actualSignature=actual,signedInputFreeze=sf,unsignedInputFreeze=uf,verifiedFrozenPins=checked+ucheck,priorActualSignedProductPeer=pin(PEER),actualChangedObjectIndices=changed,other34ObjectsWholeBytesSame=True,allOther102AppFilesWholeBytesSame=True,onlyUpdatedAppFile='VirtualMacIndependent27',actualCompiledRuntime11Anchor=runtime['anchorSource'],manifestDigestAndExtentVerifiedInSourceAndLinkedMain=True,actualNativeImports=len(image.imports),actualNativeRoutes=pin(routes_path),all487ActualRowsAndLoadsJoined=True,XMLDER14EntitlementsWholeBytesSame=True,actualSignatureCodePages=actual['actualCodePages'],allPrimaryPagesAnd7SpecialSlotsVerified=True,actualSigningPreservesOriginalCompiledSectionsAndPAC=True,Runtime11SignedImagesRepeated=False,deviceOperations=0,codeSigningOperations=0,actualGuestBoot=False,actualVisibleGuest=False,guestSSHAvailable=False,finalNetworkAndSSHStillRequired=True,findings=[],finiteLocalScopePassed=True);reportpath=out/'review.json';reportpath.write_text(json.dumps(report,indent=2)+'\n');f=out/'freeze.json';pins=[pin(p) for p in (pathlib.Path(__file__),sp,rp,up,BASE,PEER,READER,SIGNATURE,newbuilder,oldbuilder,reportpath)]+[sf,uf,runtime['anchorSource'],runtime['manifest'],signed['binary'],unsigned['binary'],prior['actualNativeRoutes']];f.write_text(json.dumps(dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(reportpath),freeze=pin(f),findings=[])))
if __name__=='__main__':main()
