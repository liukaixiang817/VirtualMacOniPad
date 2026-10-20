#!/usr/bin/env python3
"""HOST preparation only: actual small guest files, no disk hashing."""
import hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 out=N/'independent27-guest-bundle-readonly-prepared-v1-attempt1';assert not out.exists()
 controller=N/'independent27-external-signature-recovery-v2-attempt1/control.py'
 sp=importlib.util.spec_from_file_location('readonly_guest_transport',controller);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 body=m.prefix(0)+m.off_check()+m.HEALTH.read_text()+'''
OWN_GUEST=/private/var/mobile/Media/VirtualMac/Tahoe3.bundle
for own_ancestor in /private /private/var /private/var/mobile /private/var/mobile/Media /private/var/mobile/Media/VirtualMac "$OWN_GUEST"; do
 [ -d "$own_ancestor" ] && [ ! -L "$own_ancestor" ]
 [ "$(realpath "$own_ancestor")" = "$own_ancestor" ]
done
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_GUEST")" = 16777220:45558514:501:501:755:9 ]
printf 'GUEST_CANONICAL_PATH %s\\n' "$OWN_GUEST"
'''
 sizes={'MachineIdentifier':68,'HardwareModel':150,'AuxiliaryStorage':33570816,'Disk.img':274877906944,'VirtualMac.plist':1415}
 inodes=dict(MachineIdentifier=45558517,HardwareModel=45558516,AuxiliaryStorage=45558515,**{'Disk.img':45558518,'VirtualMac.plist':46773243})
 for name,size in sizes.items():
  mode=644 if name in('MachineIdentifier','HardwareModel')else 600
  body+=f'''own_file="$OWN_GUEST/{name}"
[ -f "$own_file" ] && [ ! -L "$own_file" ]
[ "$(realpath "$own_file")" = "$own_file" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s "$own_file")" = 16777220:{inodes[name]}:501:501:{mode}:1:{size} ]
printf 'GUEST_FILE_META {name} '
stat -c %d:%i:%u:%g:%a:%h:%s "$own_file"
'''
  if name in('MachineIdentifier','HardwareModel','VirtualMac.plist'):
   body+=f'''own_before=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$own_file")
own_sha_before=$(sha256sum "$own_file" | cut -d ' ' -f1)
printf 'GUEST_SMALL_SHA256 {name} %s\\n' "$own_sha_before"
printf 'GUEST_SMALL_BASE64 {name} '
base64 < "$own_file" | tr -d '\\n'
printf '\\n'
[ "$(sha256sum "$own_file" | cut -d ' ' -f1)" = "$own_sha_before" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$own_file")" = "$own_before" ]
'''
 body+=m.off_check()+"printf 'INDEPENDENT27_GUEST_CONFIG_READONLY_COMPLETE_NO_GUEST_EXECUTION\\n'\n"
 script=m.prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 subprocess.run(['/bin/sh','-n'],input=script.encode(),check=True)
 for name in('Disk.img','AuxiliaryStorage'):
  start=body.index('own_file="$OWN_GUEST/'+name+'"');end=body.find('own_file=',start+10)
  assert 'sha256sum' not in body[start:end]
 out.mkdir(mode=0o700);(out/'read-root.sh').write_text(script)
 runner=r'''#!/usr/bin/env python3
"""Explicit Root read-only dispatch, only after exact initializer post0."""
import argparse,base64,getpass,hashlib,importlib.util,json,pathlib,plistlib,re,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--post-receipt',required=True,type=pathlib.Path);ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 prepared=pathlib.Path(__file__).resolve().parent;c=json.loads((prepared/'candidate.json').read_bytes())
 for row in json.loads((prepared/'freeze.json').read_bytes())['files']:assert pin(row['path'])==row
 post=json.loads(a.post_receipt.read_bytes());assert post['transportExit']==0
 assert pin(post['request']['path'])==post['request']
 request=json.loads(pathlib.Path(post['request']['path']).read_bytes())
 assert request['action']=='post' and request['packetCandidate']==c['currentInitializerCandidate']
 for name in('stdout','stderr'):assert pin(post[name]['path'])==post[name]
 assert b'INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in pathlib.Path(post['stdout']['path']).read_bytes()
 out=a.output.resolve();assert out.parent==N and not out.exists();out.mkdir(mode=0o700)
 sp=importlib.util.spec_from_file_location('actual_guest_readonly_transport',c['controller']['path']);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 password=getpass.getpass('iPad password: ')
 status,stdout,stderr,error=m.run_remote(pathlib.Path(c['script']['path']).read_text(),b'',True,password);password=None
 (out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr)
 receipt=dict(schema='Actual readonly Tahoe3 configuration receipt v1',preparedCandidate=pin(prepared/'candidate.json'),script=c['script'],actualPriorPost=pin(a.post_receipt),transportExit=status,transportError=error,stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),deviceWrites=0,processSignals=0,trustCacheOperations=0,nativeCPUOperations=0)
 (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 assert status==0,error
 text=stdout.decode();assert 'INDEPENDENT27_GUEST_CONFIG_READONLY_COMPLETE_NO_GUEST_EXECUTION' in text
 files={}
 for name,size in [('MachineIdentifier',68),('HardwareModel',150),('VirtualMac.plist',1415)]:
  rawrows=re.findall(r'^GUEST_SMALL_BASE64 '+re.escape(name)+r' ([A-Za-z0-9+/=]+)$',text,re.M)
  sharows=re.findall(r'^GUEST_SMALL_SHA256 '+re.escape(name)+r' ([a-f0-9]{64})$',text,re.M)
  assert len(rawrows)==len(sharows)==1
  raw=base64.b64decode(rawrows[0],validate=True);assert len(raw)==size and hashlib.sha256(raw).hexdigest()==sharows[0]
  (out/name).write_bytes(raw);files[name]=pin(out/name)
 options=plistlib.loads((out/'VirtualMac.plist').read_bytes());assert isinstance(options,dict)
 record=dict(actualParsedSavedOptions=options,sourceFiles=files,CPUCountSaved=options.get('CPUCount'),MemorySizeSaved=options.get('MemorySize'),savedOptionsAreNotMergedRuntimeDefaults=True,guestStarted=False)
 (out/'configuration.json').write_text(json.dumps(record,indent=2,default=str)+'\n')
 print(json.dumps(dict(receipt=pin(out/'receipt.json'),configuration=pin(out/'configuration.json'),actualDeviceWrites=0)))
if __name__=='__main__':main()
'''
 compile(runner,str(out/'read.py'),'exec');(out/'read.py').write_text(runner)
 c=dict(schema='Prepared read-only actual Tahoe3 bundle fact check v1',preparer=pin(__file__),controller=pin(controller),currentInitializerCandidate=pin(controller.parent/'candidate.json'),script=pin(out/'read-root.sh'),runner=pin(out/'read.py'),remoteWallSeconds=20,transportTimeoutSeconds=55,actualBundlePath='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle',hashAndCopyOnly=['MachineIdentifier','HardwareModel','VirtualMac.plist'],largeDiskAndAuxiliaryStorageOnlyMetadata=True,requiresExactInitializerPost0=True,requiresOwnAppAndChildOff=True,deviceOperations=0,deviceWrites=0,trustCacheOperations=0,nativeCPUOperations=0,guestStarted=False,readyForRootExplicitReadonlyDispatch=True)
 (out/'candidate.json').write_text(json.dumps(c,indent=2)+'\n')
 (out/'freeze.json').write_text(json.dumps({'files':[pin(__file__),pin(out/'candidate.json'),pin(out/'read.py'),pin(out/'read-root.sh'),c['controller'],c['currentInitializerCandidate']]},indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),deviceOperations=0)))
if __name__=='__main__':main()

