#!/usr/bin/env python3
"""Prepare an exact own-App delta from the installed App232 baseline; no device writes."""
from pathlib import Path
import argparse,copy,hashlib,json,re,subprocess
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--app-candidate',required=True,type=Path);p.add_argument('--output',required=True,type=Path);args=p.parse_args();assert not args.output.exists()
 previous=N/'complete-dual-runtime155-app232-plan-v1.json';old=json.loads(previous.read_bytes());app=json.loads(args.app_candidate.read_bytes());root=Path(app['app'])
 previousRows={r['devicePath']:r for r in old['files']};appDevice=next(r['devicePath'].split('/VirtualMacIndependent27.app/')[0]+'/VirtualMacIndependent27.app' for r in old['files'] if r['archivePath'].startswith('VirtualMacIndependent27.app/'))
 files=[copy.deepcopy(r) for r in old['files'] if not r['archivePath'].startswith('VirtualMacIndependent27.app/')]
 for row in app['appFiles']:
  assert pin(row['path'])==row;rel=Path(row['path']).relative_to(root).as_posix();devicePath=appDevice+'/'+rel;prior=previousRows.get(devicePath)
  files.append(dict(archivePath='VirtualMacIndependent27.app/'+rel,devicePath=devicePath,local=row,mode=prior['mode'] if prior else 0o644))
 changes=[]
 for row in files:
  prior=previousRows.get(row['devicePath'])
  if not prior or prior['local']['sha256']!=row['local']['sha256'] or prior['mode']!=row['mode']:
   changes.append(dict(devicePath=row['devicePath'],archivePath=row['archivePath'],mode=row['mode'],old=prior['local'] if prior else None,new=row['local']))
 trusted=set(re.findall(r'\b[0-9a-f]{40}\b',(N/'independent27-lock-pause-device-v210-attempt1/stdout').read_text().lower()))
 trusted.update(re.findall(r'\b[0-9a-f]{40}\b',(N/'complete-dual-device-v211-attempt1/stdout').read_text().lower()))
 trusted.update(re.findall(r'FULL13_ADDED_HASH ([a-f0-9]{40})',(N/'complete13-owned-runtime-device-stage-v1-attempt1/stdout').read_text()))
 hashes=[]
 for rel in ['VirtualMacIndependent27','VZHostCompat.dylib']:
  desc=subprocess.run(['codesign','-d','--verbose=4',str(root/rel)],capture_output=True,check=True).stderr.decode();hashes+=re.findall(r'^CDHash=([a-f0-9]{40})$',desc,re.M)
 assert len(hashes)==2
 result=copy.deepcopy(old);result.update(builder=pin(__file__),previousInstalledPlan=pin(previous),actualApp=pin(args.app_candidate),files=files,changes=changes,newCDHashes=sorted(set(hashes)-trusted),expectedCDHashes=sorted(set(old['expectedCDHashes'])|set(hashes)),whole13RuntimeStagedReceipt=pin(N/'complete13-owned-runtime-device-stage-v1-attempt1/receipt.json'),wholeBackendSwitchChoices=['13.2.1','27'],whole13DeviceGuestExecutionPending=True,restoreImageInstallationDeferred=True,onlyOwnRuntimeAppPaths=True)
 args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(plan=pin(args.output),changedFiles=len(changes),addedFiles=sum(r['old'] is None for r in changes),newCDHashes=result['newCDHashes'])))
if __name__=='__main__':main()
