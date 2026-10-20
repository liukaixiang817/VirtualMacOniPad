#!/usr/bin/env python3
"""Bind completed real HOST socket tests and compiled guest source; never run guest."""
import hashlib
import json
import pathlib
import re
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P=N/'guest-active-vsock-ssh-helper-local-v1-attempt1'
def pin(p):
    p=pathlib.Path(p).resolve();d=p.read_bytes()
    return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def main():
    assert P.is_dir() and not (P/'candidate.json').exists()
    g=R/'VirtualMac/vz/guest';s=R/'VirtualMac/vz/host'
    sources=[g/'vm27_guest_vsock_ssh_helper_v1.h',g/'vm27_guest_vsock_ssh_helper_v1.c',g/'vm27_vsock_ssh_protocol_v1.c',g/'vm27_guest_vsock_ssh_helper_main_v1.c',R/'VirtualMac/vz/development/probes/vm27_guest_vsock_ssh_helper_peer_v1.c']
    core=[s/'vm27_owned_stream_relay_v1.h',s/'vm27_owned_stream_relay_v1.c']
    assert pin(core[1])['sha256']=='0c265aa4d349e7612bdc76a85d089414e16cd9cb14eaceb094c31e15784d2227'
    results=[]
    for kind in ('normal','sanitized'):
        stdout=(P/(kind+'-final.stdout')).read_text();stderr=(P/(kind+'-final.stderr')).read_text()
        names=[x[5:] for x in stdout.splitlines() if x.startswith('PASS ')]
        assert len(names)==11 and stdout.endswith('ALL11_HOST_AFUNIX_MODELS_PASS_NO_VSOCK_OR_GUEST_EXECUTION\n')
        assert 'AddressSanitizer' not in stderr and 'runtime error:' not in stderr and 'PEER_FAIL' not in stderr
        assert 'seq=1 errno=0 stop=1 toSSH=262144 fromSSH=327680' in stderr
        assert 'seq=2 errno=0 stop=1 toSSH=266240 fromSSH=331776' in stderr
        results.append(dict(kind=kind,exit=0,cases=names,stdout=pin(P/(kind+'-final.stdout')),stderr=pin(P/(kind+'-final.stderr'))))
    undefined=(P/'production-undefined.stdout').read_text();loads=(P/'production-loads.stdout').read_text();lc=(P/'production-load-commands.stdout').read_text()
    assert 'VM27GuestSSHPeerConnectV1' not in undefined and 'minos 15.0' in lc
    assert sum('.dylib' in x for x in loads.splitlines())==1 and '/usr/lib/libSystem.B.dylib' in loads
    snapshots=P/'source-snapshots';snapshots.mkdir(exist_ok=False)
    for f in [*sources,*core]: (snapshots/f.name).write_bytes(f.read_bytes())
    command_note='''Actual completed commands used xcrun clang with -std=c11 -Wall -Wextra -Werror -pthread.
Guest production: -target arm64-apple-macos15.0 -O2; helper+protocol+main+same stream core, no PEER macro.
HOST normal: -O2 -DVM27_GUEST_SSH_PEER_TEST=1; helper+protocol+same stream core+real AF_UNIX fixture.
HOST ASan/UBSan: -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer plus same PEER sources.
Protocol iOS compile-only: arm64e-apple-ios16.1, actual iPhoneOS SDK, no guest VSOCK source.
Production executable was not run. No explicit codesign, device operations or trust cache additions.
Mach linker may provide an automatic adhoc CodeDirectory; this is not a deployment authorization.
'''
    (P/'completed-build-commands.txt').write_text(command_note)
    candidate=dict(schema='Guest-initiated VSOCK SSH helper finite source candidate v1',sourceFiles=[pin(p) for p in sources],inheritedStreamCore=[pin(p) for p in core],binary=pin(P/'vm27-guest-vsock-ssh-unsigned'),protocolIOSObject=pin(P/'protocol-ios-arm64e.o'),productionArchitecture='arm64',productionMacOSMinimum='15.0',productionLoadDependencies=['/usr/lib/libSystem.B.dylib'],peerInjectionAbsentFromProduction=True,explicitSigningPerformed=False,automaticToolchainAdhocSignatureMayExist=True,guestExecutableRun=False,actualVSOCKExecuted=False,actualTCP22222Reachable=False,guestSystemDaemonWrites=0,deviceOperations=0,trustCacheAdditions=0,hostModels=results,maximumOwnedSessions=16,controlPort=22223,guestTCPDestination='127.0.0.1:22',headerBytes=32,protocolVersion=1,protocolFields=['magic8 VM27SSH1','BE16 version@8','BE16 type@10','BE32 errno@12 only ERROR','token16@16'],types=dict(HELLO=1,START=2,DATA=3,ERROR=4),token='nonzero host per-control nonce8 + strictly increasing nonzero BE64sequence8; correlation only',tokenSingleDataConnection=True,controlLossCancelsAndJoinsOnlyActualOwnedWorkers=True,borrowCancellationFDNeverClosedByRun=True,borrowCancellationByteKeptUnread=True,HELLORequiresActualLocalTCPPreflightAndControlConnect=True,HELLOProvesSSHAuthentication=False,independentPeerReviewNeeded=True,unknownRequiredRuntimeConditions=['True independent VZ listener/actual VM owner queue installed at22223','Actual guest AF_VSOCK transport and source CID_HOST2 connection','Actual guest helper signature/launch/upload and fresh execution UID','Actual local sshd22 and SSH lkx authentication','Actual host TCP22222 listener/session association and bidirectional VZ lifetime'],modelScope='All success transports are real HOST AF_UNIX socket pairs, external connection-failure injection only in compile-time Mac fixture; no actual VSOCK/guest/TCP22 execution',finalizerSource=pin(__file__))
    (P/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n')
    files=[pin(__file__),*[pin(p) for p in sources+core],*[pin(p) for p in sorted(P.rglob('*')) if p.is_file()]]
    (P/'freeze.json').write_text(json.dumps(dict(files=files,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(P/'candidate.json'),freeze=pin(P/'freeze.json'),binary=candidate['binary'],actualModelsEach=11)))
if __name__=='__main__': main()
