#!/usr/bin/env python3
"""Stage the exact native-baseline macOS13 payload under a new owned root.

No device write, signing, launch, package publication or backend enablement.
The report exposes external/absolute dependencies before the dual loader is
implemented. A copied tree is not proof of independent guest execution.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,struct
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/original/payload'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=pathlib.Path);args=ap.parse_args();o=args.output.resolve();assert o.parent==N and not o.exists()
 comparison=N/'full13-standalone-device-local-source-comparison-v1.json';a=json.loads(comparison.read_bytes());assert len(a['files'])==a['wholeMatches']==106 and not a['missingLocal']and not a['different']
 receipt=R/a['deviceInventoryReceipt'];assert json.loads(receipt.read_bytes())['exit']==0
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';sp=importlib.util.spec_from_file_location('complete13_macho',reader);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 expected={r['path']:r['actualDeviceSHA256']for r in a['files']};actual={str(p.relative_to(SOURCE)):pin(p)['sha256']for p in SOURCE.rglob('*')if p.is_file()and not p.is_symlink()};assert actual==expected,'exact106 source files, no unreviewed extra regular file'
 links=[]
 for p in SOURCE.rglob('*'):
  if p.is_symlink():
   value=os.readlink(p);target=p.resolve(strict=True);assert not pathlib.Path(value).is_absolute()and target.is_relative_to(SOURCE.resolve()),'only internal relative links';links.append(dict(path=str(p.relative_to(SOURCE)),target=value))
 o.mkdir(mode=0o700);runtime=o/'runtime';runtime.mkdir(mode=0o700);payload=runtime/'payload';shutil.copytree(SOURCE,payload,symlinks=True)
 images=[];files=[];absoluteReferences=[];ownedLoads=[]
 for rel in sorted(expected):
  p=payload/rel;raw=p.read_bytes();assert pin(p)['sha256']==expected[rel]
  macho=raw[:4]==b'\xcf\xfa\xed\xfe';p.chmod(0o700 if macho else 0o600);files.append(dict(path='payload/'+rel,kind='mach-o'if macho else'resource',mode=0o700 if macho else 0o600,bytes=len(raw),sha256=expected[rel]))
  if not macho:continue
  im=m.MachO(raw);assert struct.unpack_from('<I',raw,4)[0]==0x100000c,'arm64 native baseline'
  images.append(dict(path='payload/'+rel,uuid=im.uuid,actualLoads=im.loads,actualStrongImports=sum(not x['weak']for x in im.imports)))
  for load in im.loads:
   path=load['path'];assert not any(x in path for x in ('VM27','VZ27','ModernRuntimeCompat','GPUTask27')),'no macOS27 stack in complete13'
   if path.startswith('@loader_path/'):
    target=(p.parent/path[len('@loader_path/'):]).resolve(strict=False);ownedLoads.append(dict(importer=rel,actualLoad=load,resolvedInsideOwnedPayload=target.is_relative_to(payload),target=str(target.relative_to(runtime))if target.is_relative_to(runtime)else str(target),exists=target.is_file()))
   elif path.startswith('/var/root/VirtualMac')or path.startswith('/private/var/root/VirtualMac'):
    absoluteReferences.append(dict(importer=rel,kind='load',value=path))
  for item in raw.split(b'\0'):
   if item.startswith((b'/var/root/VirtualMac/',b'/private/var/root/VirtualMac/'))and len(item)<4096:
    absoluteReferences.append(dict(importer=rel,kind='cstring',value=item.decode(errors='replace')))
 for p in [runtime,*runtime.rglob('*')]:
  if p.is_dir()and not p.is_symlink():p.chmod(0o700)
 uuids={r['path']:r['uuid']for r in images}
 for rel,uuid in {'Frameworks/Hypervisor.framework/Versions/A/Hypervisor':'1b1e116f81fd3fd6b42452d4fa96e9ab','Frameworks/Virtualization.framework/Versions/A/Virtualization':'dcfc0a797728308994d71508e71f38e5','Frameworks/ParavirtualizedGraphics.framework/Versions/A/ParavirtualizedGraphics':'732073ab34e538c9a91953b628977bdb'}.items():assert uuids['payload/'+rel]==uuid
 manifest=o/'complete13-files.json';save(manifest,dict(schema='Exact complete13 baseline source staged under own root',canonicalDeviceRoot='/private/var/mobile/Library/VirtualMacFull13Runtime-v1',files=files,relativeSymlinks=links,all106ActualDeviceSourceHashesPreserved=True,noModern27ProviderLoads=True))
 graph=o/'complete13-dependencies.json';save(graph,dict(images=images,actualOwnedRelativeLoads=ownedLoads,absoluteOldRootReferences=absoluteReferences,unresolvedOwnedLoads=[r for r in ownedLoads if not r['resolvedInsideOwnedPayload']or not r['exists']],systemNativeLoadAndStrongImportClosureNotReverified=True,actualGuestExecutionNotClaimed=True))
 result=dict(schema='Complete13 owned source stage v1, not an enabled backend',runtimeRoot=str(runtime),canonicalDeviceRoot='/private/var/mobile/Library/VirtualMacFull13Runtime-v1',sourceRoot=str(SOURCE),sourceComparison=pin(comparison),actualDeviceInventoryReceipt=pin(receipt),manifest=pin(manifest),dependencyReport=pin(graph),builder=pin(__file__),files=106,machOImages=len(images),allSourceBytesWhole=True,backendEnabled=False,appLoaderStillNeedsOwnedComplete13Admission=True,installationAndNetworkHelperIndependenceStillNeedsImplementation=True,actualGuestExecution=False,deviceOperations=0,trustCacheOperations=0);save(o/'candidate.json',result);save(o/'freeze.json',dict(files=[pin(p)for p in o.rglob('*')if p.is_file()and not p.is_symlink()]+[pin(__file__),pin(reader),pin(comparison),pin(receipt)],deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),files=106,images=len(images),absoluteOldRootReferences=len(absoluteReferences),unresolvedOwnedLoads=len(json.loads(graph.read_bytes())['unresolvedOwnedLoads']),guestExecutionNotClaimed=True)))
if __name__=='__main__':main()
