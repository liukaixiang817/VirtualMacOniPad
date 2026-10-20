#!/usr/bin/env python3
"""Once-only sequential device dispatch after real peer/root review, with receipts."""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'native-sandbox-apply-compat-device-v3-arm64-attempt1'
ACTIONS = ('preflight', 'stage', 'trust', 'execute', 'post')

def need(value, why):
    if not value:
        raise ValueError(why)

def pin(path):
    path = Path(path)
    need(path.is_absolute() and not path.is_symlink() and path.is_file(), 'ordinary absolute pinned file')
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def exact(row):
    need(pin(row['path']) == row, 'actual changed pin ' + row['path'])
    return Path(row['path'])

def save(path, value):
    with path.open('x') as f:
        f.write(json.dumps(value, indent=2) + '\n')

def main():
    p = argparse.ArgumentParser(); p.add_argument('--dispatch-all-once', action='store_true')
    args = p.parse_args(); need(args.dispatch_all_once, 'explicit once-only dispatch')
    ready = json.loads((D/'ready.json').read_text())
    exact(ready['scope']); exact(ready['freeze'])
    for row in json.loads((D/'freeze.json').read_text())['files']:
        exact(row)
    for field in ('unsignedPeerReview', 'signedControllerPeerReview', 'rootReview'):
        report = json.loads(exact(ready[field]).read_text())
        need(report['passed'] is True and report['findings'] == [], 'actual completed review ' + field)
    scope = json.loads((D/'scope.json').read_text())
    exact(scope['continuingAuthorization'])
    need(scope['externalWallSeconds'] == 20 and scope['nativeApplyMaximum'] == 1 and
         scope['entitlements'] == {} and scope['nativeHVCalls'] == scope['nativeVMCalls'] == 0,
         'exact self-only reviewed scope')
    need(pin(__file__) == scope['controller'], 'actual controller source')
    need([(r['action'],r['root']) for r in scope['scripts']] ==
         [(a,a!='execute') for a in ACTIONS], 'actual sequential action identity')
    for row in scope['scripts']:
        exact(row['script'])
    exact(scope['archive'])
    password = getpass.getpass('iPad mobile/root password (runtime only): ')
    save(D/'dispatch-once.json', dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                     scope=ready['scope'], actions=list(ACTIONS), retries=0))
    env = {k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
    env.update(VIRTUALMAC_SSH_PASSWORD=password, SSH_ASKPASS='/private/tmp/virtualmac-ipad-tools/ssh-askpass',
               SSH_ASKPASS_REQUIRE='force', DISPLAY='virtualmac-debug')
    completed = []
    primary_error = None
    for row in scope['scripts']:
        action = row['action']
        if primary_error is not None and action != 'post':
            continue
        # No automatic resubmission after a lost reply. Post observes actual state.
        command = ('sudo -k -S -p "" ' if row['root'] else '') + '/var/jb/bin/sh -c ' + shlex.quote(exact(row['script']).read_text())
        argv = ['ssh','-p','2221','-o','ConnectTimeout=8','-o','ControlMaster=no','-o','ControlPath=none',
                '-o','UserKnownHostsFile=/private/tmp/virtualmac-ipad-known-hosts','-o','StrictHostKeyChecking=yes',
                'mobile@127.0.0.1',command]
        data = (password+'\n').encode() if row['root'] else b''
        if action == 'stage':
            data += exact(scope['archive']).read_bytes()
        directory = D / ('actual-' + action); directory.mkdir(mode=0o700, exist_ok=False)
        save(directory/'request.json',dict(action=action,script=row['script'],scope=ready['scope'],
             root=row['root'],externalSSHSeconds=55,utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
        try:
            result = subprocess.run(argv,input=data,env=env,capture_output=True,timeout=55)
            status, stdout, stderr = result.returncode,result.stdout,result.stderr
        except subprocess.TimeoutExpired as error:
            status, stdout, stderr = 124,error.stdout or b'',error.stderr or b''
        except OSError:
            status, stdout, stderr = 125,b'',b'transport error; no retry\n'
        (directory/'stdout').write_bytes(stdout); (directory/'stderr').write_bytes(stderr)
        receipt = dict(action=action,exit=status,stdout=pin(directory/'stdout'),stderr=pin(directory/'stderr'),
                       utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), retries=0)
        save(directory/'receipt.json',receipt); completed.append(receipt)
        print(json.dumps(receipt),flush=True)
        if status and primary_error is None:
            primary_error = action
    env.pop('VIRTUALMAC_SSH_PASSWORD',None)
    password = None
    save(D/'actual-summary.json',dict(scope=ready['scope'],completed=completed,firstFailedAction=primary_error,
                                     deviceDispatchActuallyAttempted=True,guestBooted=False))
    need(primary_error is None, 'actual failed action ' + str(primary_error))

if __name__ == '__main__':
    main()
