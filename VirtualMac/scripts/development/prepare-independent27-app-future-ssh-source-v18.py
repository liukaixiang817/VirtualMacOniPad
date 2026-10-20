#!/usr/bin/env python3
"""Prepare future Main18 SSH-only source; no App build/sign/device changes."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

R = Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
BASE = N/'independent27-app-start-error-diagnostic-source-v17-attempt1/candidate.json'
BRIDGE = N/'host-genuine-vz-ssh-bridge-source-v2-finalization-v1-attempt1/candidate.json'
QGA = N/'guest-active-vsock-ssh-qga-source-v5-attempt1/candidate.json'

def pin(p):
    p=Path(p).resolve();data=p.read_bytes()
    return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def save(p,value):
    Path(p).write_text(json.dumps(value,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    if out.exists():raise ValueError('fresh output required')
    base=json.loads(BASE.read_bytes());bridge=json.loads(BRIDGE.read_bytes());qga=json.loads(QGA.read_bytes())
    original=Path(base['source']['path']);old=original.read_text();text=old
    changes=[]
    def replace(before,after,label):
        nonlocal text
        if text.count(before)!=1:raise ValueError('one exact source hunk: '+label)
        text=text.replace(before,after,1);changes.append(label)
    replace('#import "vm27_genuine_vz_ssh_bridge_v1.h"',
        '#import "vm27_genuine_vz_ssh_bridge_v2.h"','V2 implementation header with same public V1 ABI')
    replace('static BOOL gIndependent27SSHStarted;','static BOOL gIndependent27SSHStarted;\nstatic BOOL gIndependent27SSHRegisteredV18;',
        'track actual registration separately from VM start')
    replace('// This copied product explicitly limits its first independent27 boot to\n'
        '// CPU, actual guest display and basic input. SSH remains unavailable.\n'
        'static const BOOL kIndependent27FirstDisplaySSHDeferredV13 = YES;',
        '// Future source enables the genuine optional V2 byte bridge. A listener\n'
        '// and HELLO do not establish guest SSH authentication or persistent service.\n'
        'static const BOOL kIndependent27FirstDisplaySSHDeferredV13 = NO;',
        'enable genuine optional listener route in this future source only')
    replace('    gIndependent27SSHStarted=NO;\n    if (gIndependent27SSHBridge) {',
        '    gIndependent27SSHStarted=NO;gIndependent27SSHRegisteredV18=NO;\n    if (gIndependent27SSHBridge) {',
        'real VM finish stops optional admission while retaining original drain')
    replace('        VZIndependent27FailActualDisplay(failure);\n        return;\n    }\n    if (!gIndependent27SSHLastSnapshotValid',
        '        gIndependent27SSHRegisteredV18=NO;\n'
        '        printf("[Independent27SSH] optional bridge stopped: domain=%s code=%ld detail=%s retainedOwner=1 cleanupAtActualVMStop=1 guestSSHAuthenticated=0\\n",\n'
        '            failure.domain.UTF8String ?: "(nil)", (long)failure.code,\n'
        '            failure.localizedDescription.UTF8String ?: "(nil)");\n'
        '        return;\n    }\n    if (!gIndependent27SSHLastSnapshotValid',
        'optional stream failure reports real error without stopping guest/display')
    replace('        gIndependent27SSHStarted=NO;gIndependent27SSHLastSnapshotValid=NO;\n'
        '        if (!registered || !gIndependent27SSHBridge) {\n'
        '            finishVMThreadSafe(delegate,sshError ?: [NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:EIO\n'
        '                userInfo:@{NSLocalizedDescriptionKey:@"The genuine SSH listener could not register before VM start."}]);return;\n'
        '        }\n'
        '        printf("[Independent27SSH] actual listener22223 registered; loopbackTCP22222; guest SSH unverified\\n");',
        '        gIndependent27SSHStarted=NO;gIndependent27SSHLastSnapshotValid=NO;\n'
        '        gIndependent27SSHRegisteredV18=registered && gIndependent27SSHBridge!=nil;\n'
        '        if (!gIndependent27SSHRegisteredV18) {\n'
        '            NSError *actualSSHError=sshError ?: [NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:EIO\n'
        '                userInfo:@{NSLocalizedDescriptionKey:@"The genuine SSH listener could not register before VM start."}];\n'
        '            printf("[Independent27SSH] optional registration unavailable: domain=%s code=%ld detail=%s retainedOwner=%d cleanupAtActualVMStop=1 guestSSHAuthenticated=0\\n",\n'
        '                actualSSHError.domain.UTF8String ?: "(nil)", (long)actualSSHError.code,\n'
        '                actualSSHError.localizedDescription.UTF8String ?: "(nil)", gIndependent27SSHBridge!=nil);\n'
        '        } else {\n'
        '            printf("[Independent27SSH] actual listener22223 registered; loopbackTCP22222; guest SSH unverified\\n");\n'
        '        }',
        'registration failure retains published resources without aborting normal guest path')
    replace('            if (!kIndependent27FirstDisplaySSHDeferredV13) {\n'
        '                gIndependent27SSHStarted=YES;\n',
        '            if (!kIndependent27FirstDisplaySSHDeferredV13 && gIndependent27SSHRegisteredV18) {\n'
        '                gIndependent27SSHStarted=YES;\n',
        'poll only after genuine RuntimeGuestStarted and actual successful registration')
    # The prior-owner conflict is a lease integrity rejection, not a swallowed
    # optional failure. No existing owner/VM is overwritten by this change.
    if 'A retained SSH owner already exists; it must drain before another start.' not in text:
        raise ValueError('original owner conflict rejection retained')
    out.mkdir(mode=0o700)
    source=out/'VirtualMacApp.independent27.future-ssh-source-v18.m';source.write_text(text)
    diff=out/'main17-to-main18.diff';diff.write_text(''.join(difflib.unified_diff(old.splitlines(True),text.splitlines(True),
        fromfile=str(original),tofile=str(source))))
    sdk=subprocess.run(['xcrun','--sdk','iphoneos','--show-sdk-path'],capture_output=True,check=True).stdout.decode().strip()
    command=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-I',str(S),
        '-fsyntax-only',str(source)]
    actual=subprocess.run(command,capture_output=True)
    (out/'ios-syntax.stdout').write_bytes(actual.stdout);(out/'ios-syntax.stderr').write_bytes(actual.stderr)
    save(out/'ios-syntax-command.json',dict(command=command,actualExit=actual.returncode))
    if actual.returncode:raise ValueError('actual iOS Main syntax failed')
    candidate=dict(schema='Future Main18 genuine SSHV2 optional registration source',
        status='HELD_SOURCE_ONLY_NOT_CURRENT_APP',source=pin(source),sourceDiff=pin(diff),
        baselineMain17=pin(BASE),baselineSource=pin(original),bridgeSourceCandidate=pin(BRIDGE),
        requiredBridgeImplementation=bridge['source'],requiredBridgeHeader=bridge['header'],
        publicBridgeV1ABIStillUsed=True,futureBuildMustReplaceOldBridgeTU=True,sourceHunks=changes,
        actualIOSSyntax=pin(out/'ios-syntax-command.json'),actualIOSSyntaxExit=0,
        optionalSSHRegistrationAndStreamFailuresDoNotStopGuestDisplay=True,
        actualErrorDomainCodeDetailLogged=True,publishedOwnerRetainedForActualVMStopDrain=True,
        priorOwnerConflictStillRejectsNewStart=True,originalVMStartAdmissionPreserved=True,
        CPUDisplayInputAndConfigurationUnmodified=True,noFakeHELLOOrAuthentication=True,
        ports=dict(actualListener=22223,loopbackTCP=22222,guestTargetTCP=22),
        futureGuestHelper=dict(sourceCandidate=pin(QGA),callbackAPI='VZGuestToolsInstallOwnedActiveSSHHelperV1',
            signedResource=qga['signedHelper'],requiredConnectionLeaseObject=qga['leaseObject'],
            automaticallyInvoked=False,integratedIntoThisMain=False,guestInstalled=False,
            diagnosticWallSeconds=300,persistentServiceHandoffImplemented=False,
            admission='actual QGA ready/epoch/generation, stable resource FD/SHA and fixed signed guest helper; still requires future explicit integration'),
        applicationLinked=False,codeSigned=False,actualGuestStarted=False,actualSSHAuthenticated=False,
        deviceOperations=0,guestFilesystemWrites=0,currentApp23Modified=False,preparer=pin(__file__))
    cp=out/'candidate.json';save(cp,candidate)
    inputs=[Path(__file__),BASE,BASE.parent/'freeze.json',original,BRIDGE,BRIDGE.parent/'freeze.json',
        Path(bridge['source']['path']),Path(bridge['header']['path']),QGA,QGA.parent/'freeze.json',
        Path(qga['signedHelper']['path']),Path(qga['leaseObject']['path']),S/'VZGuestTools_owned_active_ssh_v5.h']
    files=inputs+[p for p in out.iterdir() if p.is_file()]
    save(out/'freeze.json',dict(files=list({r['path']:r for r in map(pin,files)}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(cp),freeze=pin(out/'freeze.json'))))

if __name__=='__main__':main()
