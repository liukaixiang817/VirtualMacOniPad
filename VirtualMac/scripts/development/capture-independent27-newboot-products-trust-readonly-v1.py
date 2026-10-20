#!/usr/bin/env python3
"""Root-only read of installed R31/App42 and current-boot native trust membership."""
import argparse,datetime,getpass,hashlib,importlib.util,json,pathlib,re,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B=pathlib.Path(__file__).resolve().parent
OLD=N/'independent27-child-usbh-offline-device-v24-attempt1'
BOOT=1792055689
UUID='A3247B1A-473D-4786-8585-A99DB5B5BDA0'
SESSION=N/'current-ipad-session-readonly-v1-attempt1/receipt.json'
SESSION_SHA='4a2be983c61c9be1e1d4e934f27277314d1804c5e4dd99b3fa8c648a8476936e'
def load(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def pin(p):
 p=pathlib.Path(p).resolve();d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 out=a.output.resolve();assert out.parent==N and not out.exists(),'fresh exclusive read only output'
 base=load(OLD/'control.py','newboot_readonly_transport');fast=load(B/'independent27_device_product_verify_fast_v1.py','newboot_exact_products')
 assert pin(SESSION)['sha256']==SESSION_SHA
 prior=json.loads(SESSION.read_bytes());assert prior['transportExit']==0
 text=base.exact(prior['stdout']).read_text();assert str(BOOT) in text and UUID in text
 scope=json.loads((OLD/'scope.json').read_bytes());expected=sorted(scope['trustCacheCDHashes']);assert len(expected)==144
 for row in scope['files']:base.exact(row['local'])
 prefix=base.prefix(0).replace('= 1791813884 ]','= '+str(BOOT)+' ]')
 prefix+='[ "$(sysctl -n kern.bootsessionuuid)" = '+shlex.quote(UUID)+' ]\n'
 body=prefix+base.off_check()+base.HEALTH.read_text()+fast.batch_check(scope)+fast.cd_check(scope,scope['actualNativeCDSubset'])
 body+='''
if [ -e "$OWN_LOG" ] || [ -L "$OWN_LOG" ];then
 [ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
 own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
 own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
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
 request=dict(source=pin(__file__),script=pin(out/'read-root.sh'),historicalInstalledCandidate=pin(OLD/'candidate.json'),historicalInstalledScope=pin(OLD/'scope.json'),actualCurrentSession=pin(SESSION),bootSeconds=BOOT,bootSessionUUID=UUID,expectedActiveCDHashes=expected,deviceWrites=0,processSignals=0,trustCacheOperations=0)
 dump(out/'request.json',request)
 password=getpass.getpass('iPad password: ')
 status,stdout,stderr,error=base.run_remote(script,b'',True,password);password=None
 (out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr)
 receipt=dict(finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),request=pin(out/'request.json'),transportExit=status,transportError=error,stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),deviceWrites=0,processSignals=0,trustCacheOperations=0)
 dump(out/'receipt.json',receipt);assert status==0,'actual readonly failed; preserved, no replay'
 text=stdout.decode();assert text.count('INDEPENDENT27_NEWBOOT_INSTALLED_PRODUCTS_AND_TRUST_READONLY_COMPLETE')==1
 info=text.split('OWN_NEWBOOT_TRUST_INFO_BEGIN\n',1)[1].split('\nOWN_NEWBOOT_TRUST_INFO_END',1)[0]
 present={line.split()[-1].lower() for line in info.splitlines() if line.split() and re.fullmatch('[0-9a-fA-F]{40}',line.split()[-1])}
 inventory=dict(actualReadonly=pin(out/'receipt.json'),bootSeconds=BOOT,bootSessionUUID=UUID,expectedActiveCDHashes=expected,actualPresentExpectedCDHashes=sorted(set(expected)&present),actualMissingCDHashes=sorted(set(expected)-present),actualNativeTrustQueryExit=0,actualInstalledProductsWholeExact=True,actualFullFiles=len(scope['files']),actualActiveCodeDirectoryHashes=len(expected),ownLogObservation=[line for line in text.splitlines() if line.startswith('OWN_NEWBOOT_LOG_')],trustCacheOperations=0,deviceWrites=0)
 dump(out/'inventory.json',inventory);print(json.dumps(dict(receipt=pin(out/'receipt.json'),inventory=pin(out/'inventory.json'),missing=len(inventory['actualMissingCDHashes']))))
if __name__=='__main__':main()
