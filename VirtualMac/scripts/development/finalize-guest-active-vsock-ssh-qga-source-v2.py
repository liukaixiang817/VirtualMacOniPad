#!/usr/bin/env python3
"""Finish the source-only QGA candidate using actual original public API names.

The already verified signed-helper candidate and failed source attempt stay
immutable. Only compilation, shell syntax and finite byte comparisons run.
"""
import hashlib
import importlib.util
import json
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
O = N / 'guest-active-vsock-ssh-qga-source-v2-attempt1'
A = N / 'guest-active-vsock-ssh-signed-resource-v1-attempt1'
FIRST = N / 'guest-active-vsock-ssh-qga-source-v1-attempt1'
PREVIOUS = pathlib.Path(__file__).with_name('finalize-guest-active-vsock-ssh-qga-source-v1.py')
spec = importlib.util.spec_from_file_location('guest_qga_frozen_previous_finalizer', PREVIOUS)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
need, pin, save, verify, run = previous.need, previous.pin, previous.save, previous.verify, previous.run


def main():
    need(O.is_dir() and not (O / 'candidate.json').exists() and not
         (O / 'freeze.json').exists(), 'fresh source-only output, never overwrite freeze')
    helper = json.loads((A / 'candidate.json').read_text())
    helper_freeze = json.loads((A / 'freeze.json').read_text())
    for row in helper_freeze['files']:
        verify(row)
    need(helper['binary']['bytes'] == 52448 and helper['binary']['sha256'] == previous.SHA and
         helper['actualSignature']['allPrimaryPagesAndSpecialSlotsVerified'] is True and
         helper['helperExecuted'] is False, 'actual frozen signed helper, never executed')
    source_path = S / 'VZGuestTools_owned_active_ssh_v2.m'
    source = source_path.read_text()
    original_source = (S / 'VZGuestTools.m').read_bytes()
    need(len(original_source) == 43767 and hashlib.sha256(original_source).hexdigest() ==
         '42e37f0dab45aa32ed65e26bd348bc48a31963ac14372098c91fd76ae13faef2',
         'real unchanged frozen GuestTools source')
    old_body = original_source[original_source.index(b'\n#import <objc/message.h>'):]
    prefix_end = source.index('\n#import <objc/message.h>')
    need(source[prefix_end:].encode().startswith(old_body),
         'all original GuestTools function bytes retained')
    prepare = (O / 'prepare-namespace.sh').read_text()
    watcher = (O / 'watcher.sh').read_text()
    finish = (O / 'verify-install-launch.sh').read_text()
    need(source.count('NSString *prepare=@' + json.dumps(prepare) + ';') == 1 and
         source.count('NSString *finish=@' + json.dumps(finish) + ';') == 1 and
         finish.count(shlex.quote(watcher)) == 1,
         'actual source literals equal exact shell scripts')
    need('if ! exact_owned; then wait' not in watcher and
         'CAPTURE_OR_CLEANUP_UNRESOLVED' in watcher and
         'while [ "$own_second" -lt 300 ]' in watcher,
         'bounded monitor never waits an unresolved live process')
    generated = (S / 'vm27_guest_active_ssh_artifact_v1.h').read_text()
    need(previous.SHA in generated and '52448' in generated and previous.SIGNED_NAME in generated,
         'source pins actual signed artifact')
    syntax = [run(O, script + '-syntax', ['/bin/sh', '-n', O / script])
              for script in ('prepare-namespace.sh', 'watcher.sh', 'verify-install-launch.sh')]
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'],
                                  cwd=R, text=True, timeout=30).strip()
    common = ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
              '-O2', '-fblocks', '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror',
              '-Wno-deprecated-declarations', '-I', str(S)]
    compile_row = run(O, 'ios-compile', common + ['-c', source_path,
                                                '-o', O / 'VZGuestTools_owned_active_ssh_v2.o'])
    caller = O / 'typed-header-caller.mm'
    caller.write_text('#import "VZGuestTools_owned_active_ssh_v2.h"\n'
        'using Entry = void (*)(void (^)(BOOL, NSData *));\n'
        'static_assert(__is_same(decltype(&VZGuestToolsInstallOwnedActiveSSHHelperV1), Entry), "typed QGA ABI");\n'
        'Entry VM27GuestQGAHeaderCallerV1 = &VZGuestToolsInstallOwnedActiveSSHHelperV1;\n')
    typed = run(O, 'typed-header-compile', common + ['-x', 'objective-c++', '-std=c++17',
         '-c', caller, '-o', O / 'typed-header-caller.o'])
    symbols = run(O, 'compiled-symbols', ['xcrun', 'nm', '-g', O / 'VZGuestTools_owned_active_ssh_v2.o'])
    symbol_text = pathlib.Path(symbols['stdout']['path']).read_text()
    need(' T _VZGuestToolsInstallOwnedActiveSSHHelperV1' in symbol_text,
         'real compiled new entry defined')
    old_apis = ('VZGuestToolsConfigureDevice', 'VZGuestToolsAttachToVirtualMachine',
                'VZGuestToolsReset', 'VZGuestToolsStartProvisioning',
                'VZGuestToolsConfigureBootArguments', 'VZGuestToolsEnableRemoteLogin')
    inherited_header = (S / 'VZGuestTools.h').read_text()
    for old_api in old_apis:
        need(old_api + '(' in inherited_header and ' T _' + old_api in symbol_text,
             'actual frozen header and retained compiled public API: ' + old_api)
    integration = dict(schema='First diagnostic QGA entry explicit HELD integration plan v2',
         status='HELD_SOURCE_ONLY_FIRST_BOUNDED_DIAGNOSTIC',
         entry='VZGuestToolsInstallOwnedActiveSSHHelperV1', inputContract='completion only, no command/path/credentials',
         transport='existing real AppleQEMUGuestAgent VSOCK505050 guest-exec and guest-file APIs',
         actualAppRole=dict(uid=501, euid=501, bundleIdentifier='com.mac.virtual.independent27', backend='27'),
         resource=helper['binary'], resourceRelativePath=helper['resourceRelativePath'],
         resourceRequiredMode='501:501:0600:regular:nlink1',
         qgaOperationBoundSeconds=45, firstDiagnosticHelperWallSeconds=300,
         guestNamespace='/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f',
         guestNamespaceRequiredMode='0:0:0700', guestExecutableMode='0:0:0700',
         guestAccount='lkx', guestSSHService='system/com.openssh.sshd',
         guestSystemDaemonStateChanges=['enable genuine sshd; bootstrap original ssh.plist only if absent'],
         signalGuard=['actual child PID', 'UID0', 'PPID watcher', 'full executable path', 'start timestamp SHA256'],
         unresolvedCaptureOrCleanup='exit78; retain root normal VM lifecycle obligation; never claim stopped',
         repeatedInstall='fixed fresh namespace and once per actual QGA generation; retry/reuse not implemented',
         launchRequestIsHELLO=False, HELLOIsSSHAuthentication=False,
         persistentSSHImplemented=False, persistentHelperAndLeaseHandoffRequired=True,
         integrationSteps=[
             'Wait for Root actual VM boot, visible guest frames and real QGA505050 readiness.',
             'Only a later reviewed App product may replace its original GuestTools object with this clone and seal the exact resource.',
             'Add a fixed App action calling this typed API; do not expose arbitrary guest shell input.',
             'Observe real helper PID lease and host control HELLO; neither proves SSH.',
             'Verify actual Mac USB forwarding22222 and genuine authenticated guest SSH as lkx.',
             'Implement and verify durable helper/lease lifecycle before claiming complete guest SSH availability.'
         ],
         excluded=['App11 link/sign/install', 'device or guest execution', 'new trust entries',
                   'actual SSH login', 'persistent SSH acceptance'])
    save(O / 'integration-plan.json', integration)
    candidate = dict(schema='Fixed genuine guest active SSH QGA entry source candidate v2',
         status=integration['status'], source=pin(source_path), header=pin(S / 'VZGuestTools_owned_active_ssh_v2.h'),
         artifactHeader=pin(S / 'vm27_guest_active_ssh_artifact_v1.h'), inheritedSource=pin(S / 'VZGuestTools.m'),
         inheritedHeader=pin(S / 'VZGuestTools.h'), allInheritedGuestToolsFunctionBytesUnchanged=True,
         originalFunctionSpanBytes=len(old_body), originalFunctionSpanSHA256=hashlib.sha256(old_body).hexdigest(),
         actualRetainedPublicAPIs=list(old_apis), signedHelperCandidate=pin(A / 'candidate.json'),
         signedHelperFreeze=pin(A / 'freeze.json'), object=pin(O / 'VZGuestTools_owned_active_ssh_v2.o'),
         typedHeaderCaller=pin(caller), compile=compile_row, typedHeaderCompile=typed,
         compiledSymbols=symbols, shellSyntax=syntax, actualEmbeddedScriptsExact=True,
         scripts=[pin(O / script) for script in ('prepare-namespace.sh', 'watcher.sh', 'verify-install-launch.sh')],
         integrationPlan=pin(O / 'integration-plan.json'), firstDiagnosticHelperWallSeconds=300,
         priorSourceFinalizerFailure=pin(FIRST / 'failure.json'),
         actualQGAExecuted=False, helperExecuted=False, guestInstalled=False,
         actualVSOCKExecuted=False, actualTCP22222Reachable=False, guestSSHAuthenticated=False,
         persistentSSHImplemented=False, persistentHelperAndLeaseHandoffRequired=True,
         appOrRuntimeSigningPerformed=False, deviceOperations=0, guestOperations=0, trustCacheAdditions=0)
    save(O / 'candidate.json', candidate)
    files = [pin(p) for p in sorted(O.iterdir()) if p.is_file()]
    files += [pin(source_path), candidate['header'], candidate['artifactHeader'],
              candidate['inheritedSource'], candidate['inheritedHeader'], pin(__file__),
              pin(PREVIOUS), candidate['priorSourceFinalizerFailure'],
              candidate['signedHelperCandidate'], candidate['signedHelperFreeze'], helper['binary']]
    save(O / 'freeze.json', dict(schema='Source-only fixed QGA entry actual freeze v2',
         files=files, status=candidate['status'], deviceOperations=0, guestOperations=0,
         actualQGAExecuted=False, helperExecuted=False, persistentSSHImplemented=False))
    print(json.dumps(dict(candidate=pin(O / 'candidate.json'), freeze=pin(O / 'freeze.json'),
                          signedHelperCandidate=pin(A / 'candidate.json'),
                          signedHelperFreeze=pin(A / 'freeze.json'), deviceOperations=0)))


if __name__ == '__main__':
    main()
