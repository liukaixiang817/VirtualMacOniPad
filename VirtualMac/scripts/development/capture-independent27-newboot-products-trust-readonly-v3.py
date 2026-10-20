#!/usr/bin/env python3
"""Root-only read of installed R63/App75 products and new-boot native trust."""
import argparse,datetime,getpass,hashlib,importlib.util,json,pathlib,re,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-serialized-wake-device-v59-attempt1'
BOOT=1792161311
BOOT_USEC=643083
UUID='C7D63D1F-86E9-4224-A1C7-108F02E91942'
OLD_BOOT=1792055689
OLD_UUID='A3247B1A-473D-4786-8585-A99DB5B5BDA0'
SESSION=N/'independent27-oct18-current-boot-readonly-v1-attempt2'
PINS={
 OLD/'candidate.json':(7583,'7c8a76a4233f9359d040589dc81632dfbe172bdce9322e95b1b7e946d0550dfa'),
 OLD/'scope.json':(533872,'ce48a4fccc047cbfe72daa8056e4024c528c5f27300d2d529bac3102a8d1b34a'),
 OLD/'control.py':(21412,'de7122cb7b891b3e762591261b06931d746d81006080795bb41b7dbd0e9bfe27'),
 OLD/'health-root.sh':(14487,'ef6339b91a03e4c3e60f07bc37bbd24eec4b78bfa3c99e92be896f6f3365d5ed'),
 B/'independent27_device_product_verify_fast_v1.py':(3533,'52beddad0aea3b2432f1466a59902787b0909a842cbc892dc433abf4bbc37330'),
 SESSION/'receipt.json':(131,'c36983d4774cb2eb49cef647164f56eae734283c165695063a5120b7952afce2'),
 SESSION/'stdout':(98,'b06aba5e35e5ca702a2d9af01c317c7787b98b643ed1cdad94a0ec2e16f92196'),
}
def load(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def pin(p):
 p=pathlib.Path(p).absolute();assert p.is_relative_to(R) and not p.is_symlink() and p.is_file()
 assert all(not q.is_symlink() for q in p.parents if q.is_relative_to(R))
 d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 out=a.output.absolute();assert out.parent==N and not out.exists(),'fresh exclusive readonly output'
 for p,(size,sha) in PINS.items():
  row=pin(p);assert (row['bytes'],row['sha256'])==(size,sha),'frozen input changed: '+str(p)
 prior=json.loads((SESSION/'receipt.json').read_bytes());assert prior['transportExit']==0
 assert (SESSION/'stdout').read_text()==f'{{ sec = {BOOT}, usec = {BOOT_USEC} }} Sat Oct 17 01:35:11 2026\n{UUID}\n'
 base=load(OLD/'control.py','newboot_readonly_transport_v3');fast=load(B/'independent27_device_product_verify_fast_v1.py','newboot_exact_products_v3')
 scope=json.loads((OLD/'scope.json').read_bytes());expected=sorted(scope['trustCacheCDHashes'])
 assert len(expected)==len(set(expected))==144 and len(scope['files'])==259 and len(scope['actualNativeCDSubset'])==3
 for row in scope['files']:base.exact(row['local'])
 prefix=base.prefix(0);assert prefix.count(str(OLD_BOOT))==1 and prefix.count(OLD_UUID)==1
 prefix=prefix.replace(str(OLD_BOOT),str(BOOT)).replace(OLD_UUID,UUID)
 prefix+='[ "$(sysctl -n kern.boottime | sed -n "s/.*usec = \\([0-9]*\\).*/\\1/p")" = '+str(BOOT_USEC)+' ]\n'
 health=base.HEALTH.read_text();assert health.count(str(OLD_BOOT))==1
 body=prefix+base.off_check()+health.replace(str(OLD_BOOT),str(BOOT))+fast.batch_check(scope)+fast.cd_check(scope,scope['actualNativeCDSubset'])
 caches=scope['ownedMutableCacheDirectories'];assert len(caches)==2
 for row in caches:
  path=row['devicePath'];assert path.startswith('/private/var/mobile/Library/VirtualMacIndependent27Cache-v1')
  q=shlex.quote(path);meta=f"{row['uid']}:{row['gid']}:{row['mode']:o}"
  body+=f'[ -d {q} ] && [ ! -L {q} ]\n[ "$(realpath {q})" = {q} ]\n[ "$(stat -c %u:%g:%a {q})" = {shlex.quote(meta)} ]\n'
  body+=f"printf 'OWN_NEWBOOT_CACHE_PRESENT %s %s\\n' {q} \"$(stat -c %d:%i:%u:%g:%a:%h {q})\"\n"
 body+='''
if [ -e "$OWN_LOG" ] || [ -L "$OWN_LOG" ];then
 [ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
 own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
 own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
 [ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
 printf 'OWN_NEWBOOT_LOG_PRESENT %s %s\n' "$own_log_meta" "$own_log_sha"
else
 printf 'OWN_NEWBOOT_LOG_ABSENT\n'
fi
own_trust_exit=0
own_trust_info=$(jbctl trustcache info) || own_trust_exit=$?
printf 'OWN_NEWBOOT_TRUST_NATIVE_EXIT %s\n' "$own_trust_exit"
printf 'OWN_NEWBOOT_TRUST_INFO_BEGIN\n%s\nOWN_NEWBOOT_TRUST_INFO_END\n' "$own_trust_info"
[ "$own_trust_exit" = 0 ]
'''
 body+=base.off_check()+"printf 'INDEPENDENT27_NEWBOOT_INSTALLED_PRODUCTS_AND_TRUST_READONLY_COMPLETE\\n'\n"
 script=prefix+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
 subprocess.run(['/bin/sh','-n'],input=script.encode(),check=True)
 out.mkdir(mode=0o700);(out/'read-root.sh').write_text(script)
 request=dict(source=pin(__file__),script=pin(out/'read-root.sh'),frozenInputs=[pin(p) for p in PINS],historicalInstalledCandidate=pin(OLD/'candidate.json'),historicalInstalledScope=pin(OLD/'scope.json'),actualCurrentSession=pin(SESSION/'receipt.json'),actualCurrentSessionStdout=pin(SESSION/'stdout'),bootSeconds=BOOT,bootMicroseconds=BOOT_USEC,bootSessionUUID=UUID,expectedActiveCDHashes=expected,deviceWrites=0,processSignals=0,trustCacheOperations=0)
 dump(out/'request.json',request)
 password=getpass.getpass('iPad password: ')
 status,stdout,stderr,error=base.run_remote(script,b'',True,password,transport_timeout=55);password=None
 (out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr)
 receipt=dict(finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),request=pin(out/'request.json'),transportExit=status,transportError=error,stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),deviceWrites=0,processSignals=0,trustCacheOperations=0)
 dump(out/'receipt.json',receipt);assert status==0,'actual readonly failed; preserved, no replay or signals'
 text=stdout.decode();assert text.count('INDEPENDENT27_NEWBOOT_INSTALLED_PRODUCTS_AND_TRUST_READONLY_COMPLETE')==1
 assert text.count('OWN_NEWBOOT_TRUST_NATIVE_EXIT 0\n')==1
 assert text.count('OWN_NEWBOOT_TRUST_INFO_BEGIN\n')==text.count('\nOWN_NEWBOOT_TRUST_INFO_END')==1
 info=text.split('OWN_NEWBOOT_TRUST_INFO_BEGIN\n',1)[1].split('\nOWN_NEWBOOT_TRUST_INFO_END',1)[0]
 present={line.split()[-1].lower() for line in info.splitlines() if line.split() and re.fullmatch('[0-9a-fA-F]{40}',line.split()[-1])}
 log=[line for line in text.splitlines() if line.startswith('OWN_NEWBOOT_LOG_')];assert len(log)==1
 if log[0]=='OWN_NEWBOOT_LOG_ABSENT':observation=dict(present=False)
 else:
  match=re.fullmatch(r'OWN_NEWBOOT_LOG_PRESENT ([0-9]+:[0-9]+:501:501:600:1:[0-9]+:[0-9]+:[0-9]+) ([0-9a-f]{64})',log[0]);assert match
  observation=dict(present=True,metadata=match[1],identity=':'.join(match[1].split(':')[:6]),sha256=match[2])
 cache_lines=[line for line in text.splitlines() if line.startswith('OWN_NEWBOOT_CACHE_PRESENT ')];assert len(cache_lines)==len(caches)
 inventory=dict(actualReadonly=pin(out/'receipt.json'),bootSeconds=BOOT,bootMicroseconds=BOOT_USEC,bootSessionUUID=UUID,expectedActiveCDHashes=expected,actualPresentExpectedCDHashes=sorted(set(expected)&present),actualMissingCDHashes=sorted(set(expected)-present),allActualPresentNativeTrustCDHashes=sorted(present),actualNativeTrustQueryExit=0,actualInstalledProductsWholeExact=True,currentInstalledProductsWholeExact=True,actualFullFiles=len(scope['files']),actualActiveCodeDirectoryHashes=len(expected),ownLogObservation=log,actualLogObservation=observation,ownedMutableCacheDirectories=caches,actualOwnedMutableCacheObservation=cache_lines,trustCacheOperations=0,deviceWrites=0,processSignals=0)
 dump(out/'inventory.json',inventory);print(json.dumps(dict(receipt=pin(out/'receipt.json'),inventory=pin(out/'inventory.json'),missing=len(inventory['actualMissingCDHashes']))))
if __name__=='__main__':main()
