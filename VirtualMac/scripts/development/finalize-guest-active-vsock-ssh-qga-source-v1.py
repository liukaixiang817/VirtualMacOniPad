#!/usr/bin/env python3
"""Freeze the fixed first-diagnostic QGA entry and a HOST-signed helper copy.

No helper, QGA command, guest operation, App link/sign, device or VM is run.
The 300-second helper experiment remains HELD; durable SSH is not implemented.
"""
import hashlib
import importlib.util
import json
import pathlib
import shlex
import struct
import subprocess
import sys
import types

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
O = N / 'guest-active-vsock-ssh-qga-source-v1-attempt1'
A = N / 'guest-active-vsock-ssh-signed-resource-v1-attempt1'
OLD = N / 'guest-active-vsock-ssh-helper-local-v1-attempt1'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
SIG_READER = R / 'VirtualMac/scripts/development/build-independent27-signed-runtime-product-v5.py'
SHA = '33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c'
SIGNED_NAME = 'vm27-guest-vsock-ssh-signed-v1'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def verify(row):
    need(pin(row['path']) == row, 'exact frozen input: ' + row['path'])


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(directory, label, argv):
    result = subprocess.run([str(x) for x in argv], cwd=R,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    (directory / (label + '.stdout')).write_bytes(result.stdout)
    (directory / (label + '.stderr')).write_bytes(result.stderr)
    row = dict(argv=[str(x) for x in argv], exit=result.returncode,
               stdout=pin(directory / (label + '.stdout')),
               stderr=pin(directory / (label + '.stderr')))
    need(result.returncode == 0, 'actual tool failed: ' + label)
    return row


def main():
    need(O.is_dir() and A.is_dir(), 'already prepared owned HOST directories')
    for directory in (O, A):
        need(not (directory / 'candidate.json').exists() and not
             (directory / 'freeze.json').exists(), 'never overwrite a frozen candidate')
    old_candidate = json.loads((OLD / 'candidate.json').read_text())
    verify(old_candidate['binary'])
    for row in old_candidate['sourceFiles'] + old_candidate['inheritedStreamCore']:
        verify(row)
    need(old_candidate['binary']['bytes'] == 52624 and
         old_candidate['binary']['sha256'] ==
         '89e9985c663ace94b100f07a813abe79a7726a2101d5bb19c5f77818b2b90ce9',
         'genuine previously reviewed helper')
    old_freeze = json.loads((OLD / 'freeze.json').read_text())
    frozen_rows = old_freeze.get('files', [])
    need(isinstance(frozen_rows, list), 'actual inherited freeze')
    for row in frozen_rows:
        verify(row)
    original = pathlib.Path(old_candidate['binary']['path']).read_bytes()
    signed_path = A / SIGNED_NAME
    signed = signed_path.read_bytes()
    need(len(signed) == 52448 and hashlib.sha256(signed).hexdigest() == SHA,
         'exact independently signed helper resource')
    reader = module(READER, 'guest_active_metadata_reader')

    class Metadata(reader.MachO):
        # The immutable ARM64e reader rejects this ordinary ARM64 pointer format.
        # This subclass does not claim decoded chain pointers. Exact preservation
        # of all backed sections and the entire fixup payload is checked below.
        def fixups(self, offset, size):
            need(offset + size <= len(self.data), 'actual fixup payload bound')
            self.fixup_range = (offset, size)

    before, after = Metadata(original), Metadata(signed)
    need(before.uuid == after.uuid and before.sections == after.sections and
         before.loads == after.loads and before.exports == after.exports and
         before.ncmds == after.ncmds and before.sizeofcmds == after.sizeofcmds,
         'same genuine helper UUID/sections/dependencies/exports/header layout')
    old_cs = [c for c in before.commands if c['cmd'] == 0x1d]
    new_cs = [c for c in after.commands if c['cmd'] == 0x1d]
    need(len(old_cs) == len(new_cs) == 1, 'one actual signature command')
    old_start, old_size = struct.unpack_from('<II', original, old_cs[0]['at'] + 8)
    new_start, new_size = struct.unpack_from('<II', signed, new_cs[0]['at'] + 8)
    need(old_start == new_start and old_start + old_size == len(original) and
         new_start + new_size == len(signed), 'only real signature tail replaced')
    expected = bytearray(original[:old_start])
    changes = []
    for old_cmd, new_cmd in zip(before.commands, after.commands):
        need((old_cmd['cmd'], old_cmd['at'], old_cmd['size']) ==
             (new_cmd['cmd'], new_cmd['at'], new_cmd['size']), 'same actual command layout')
        if old_cmd['raw'] == new_cmd['raw']:
            continue
        if old_cmd['cmd'] == 0x1d:
            want = bytearray(old_cmd['raw'])
            struct.pack_into('<I', want, 12, new_size)
            need(bytes(want) == new_cmd['raw'], 'signature command only size changed')
        elif old_cmd['cmd'] == 0x19 and old_cmd['raw'][8:24].rstrip(b'\0') == b'__LINKEDIT':
            want = bytearray(old_cmd['raw'])
            old_filesize = struct.unpack_from('<Q', want, 48)[0]
            struct.pack_into('<Q', want, 48, old_filesize + new_size - old_size)
            need(bytes(want) == new_cmd['raw'], 'LINKEDIT only real signature filesize changed')
        else:
            raise ValueError('unexpected signed helper command difference')
        at = old_cmd['at']
        expected[at:at + old_cmd['size']] = new_cmd['raw']
        changes.append(dict(cmd=old_cmd['cmd'], at=at, bytes=old_cmd['size'],
                            beforeSHA256=hashlib.sha256(old_cmd['raw']).hexdigest(),
                            afterSHA256=hashlib.sha256(new_cmd['raw']).hexdigest()))
    need(len(changes) == 2 and bytes(expected) == signed[:new_start],
         'independent entire pre-signature byte reconstruction')
    sections = []
    for row in before.sections:
        start, size = row['fileoff'], row['size']
        need(start > 0 and start + size <= old_start and
             original[start:start + size] == signed[start:start + size],
             'all actual helper backed sections unchanged')
        sections.append(dict(**row, sha256=hashlib.sha256(signed[start:start + size]).hexdigest()))
    need(before.fixup_range == after.fixup_range, 'same complete fixup range')
    fstart, fsize = before.fixup_range
    need(original[fstart:fstart + fsize] == signed[fstart:fstart + fsize],
         'complete actual chain/import payload unchanged')
    signature_reader = module(SIG_READER, 'guest_active_signature_reader')
    # signature() consumes only metadata UUID and LC_CODE_SIGNATURE; its frozen
    # page and special-slot hash verification remains the original function.
    signature_reader.m = types.SimpleNamespace(MachO=Metadata)
    signature = signature_reader.signature(signed, after.uuid)
    need(signature['embeddedEntitlements'] is None and
         signature['allPrimaryPagesAndSpecialSlotsVerified'] is True,
         'actual ad hoc pages/special slots and no new entitlement')
    tools = [run(A, 'final-verify', ['codesign', '--verify', '--strict', '--verbose=2', signed_path]),
             run(A, 'final-display', ['codesign', '--display', '--verbose=4', signed_path])]
    delta = dict(schema='Real HOST signed helper copy finite delta v1',
                 before=old_candidate['binary'], after=pin(signed_path),
                 originalCandidate=pin(OLD / 'candidate.json'), originalFreeze=pin(OLD / 'freeze.json'),
                 uuid=after.uuid, loadDependencies=after.loads, exports=after.exports,
                 signatureMetadataChanges=changes, allOtherPreSignatureBytesUnchanged=True,
                 backedSections=sections, actualFixupPayload=dict(fileoff=fstart, bytes=fsize,
                     sha256=hashlib.sha256(signed[fstart:fstart + fsize]).hexdigest()),
                 actualSignature=signature, tools=tools, helperExecuted=False,
                 actualVSOCKExecuted=False, deviceOperations=0, guestOperations=0,
                 appOrRuntimeSigningPerformed=False)
    save(A / 'delta.json', delta)
    helper = dict(schema='HOST signed genuine guest active SSH helper resource v1',
                  originalCandidate=pin(OLD / 'candidate.json'), binary=pin(signed_path),
                  resourceRelativePath='GuestTools/' + SIGNED_NAME, resourceMode='0600',
                  resourceParentMode='0700', actualSignature=signature,
                  actualSignedDelta=pin(A / 'delta.json'), explicitHOSTAdhocSigningPerformed=True,
                  helperExecuted=False, actualVSOCKExecuted=False, guestInstalled=False,
                  actualTCP22222Reachable=False, guestSSHAuthenticated=False,
                  appOrRuntimeSigningPerformed=False, deviceOperations=0, guestOperations=0,
                  trustCacheAdditions=0, tools=tools)
    save(A / 'candidate.json', helper)
    helper_files = [pin(p) for p in sorted(A.iterdir()) if p.is_file()]
    save(A / 'freeze.json', dict(schema='HOST signed helper resource freeze v1',
         files=helper_files + [pin(OLD / 'candidate.json'), pin(OLD / 'freeze.json'),
                              old_candidate['binary'], pin(READER), pin(SIG_READER), pin(__file__)],
         deviceOperations=0, guestOperations=0, helperExecuted=False))

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
         'compiled literals equal the separately reviewed exact shell scripts')
    need('if ! exact_owned; then wait' not in watcher and
         'CAPTURE_OR_CLEANUP_UNRESOLVED' in watcher and
         'while [ "$own_second" -lt 300 ]' in watcher,
         'bounded monitor never waits an unresolved live process')
    generated = (S / 'vm27_guest_active_ssh_artifact_v1.h').read_text()
    need(SHA in generated and str(len(signed)) in generated and SIGNED_NAME in generated,
         'new source pins actual signed artifact')
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
    symbols = run(O, 'compiled-symbols', ['xcrun', 'nm', '-g',
                                        O / 'VZGuestTools_owned_active_ssh_v2.o'])
    symbol_text = pathlib.Path(symbols['stdout']['path']).read_text()
    need(' T _VZGuestToolsInstallOwnedActiveSSHHelperV1' in symbol_text,
         'real compiled new entry defined')
    for old_api in ('VZGuestToolsCreateSocketDeviceConfiguration', 'VZGuestToolsResetConnection',
                    'VZGuestToolsStartProvisioning', 'VZGuestToolsConfigureBootArguments',
                    'VZGuestToolsEnableRemoteLogin'):
        need(' T _' + old_api in symbol_text, 'real retained old API: ' + old_api)
    integration = dict(schema='First diagnostic QGA entry explicit HELD integration plan v1',
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
    candidate = dict(schema='Fixed genuine guest active SSH QGA entry source candidate v1',
         status=integration['status'], source=pin(source_path), header=pin(S / 'VZGuestTools_owned_active_ssh_v2.h'),
         artifactHeader=pin(S / 'vm27_guest_active_ssh_artifact_v1.h'), inheritedSource=pin(S / 'VZGuestTools.m'),
         inheritedHeader=pin(S / 'VZGuestTools.h'), allInheritedGuestToolsFunctionBytesUnchanged=True,
         originalFunctionSpanBytes=len(old_body), originalFunctionSpanSHA256=hashlib.sha256(old_body).hexdigest(),
         signedHelperCandidate=pin(A / 'candidate.json'), signedHelperFreeze=pin(A / 'freeze.json'),
         object=pin(O / 'VZGuestTools_owned_active_ssh_v2.o'), typedHeaderCaller=pin(caller),
         compile=compile_row, typedHeaderCompile=typed, compiledSymbols=symbols, shellSyntax=syntax,
         actualEmbeddedScriptsExact=True, scripts=[pin(O / script) for script in
           ('prepare-namespace.sh', 'watcher.sh', 'verify-install-launch.sh')],
         integrationPlan=pin(O / 'integration-plan.json'), firstDiagnosticHelperWallSeconds=300,
         actualQGAExecuted=False, helperExecuted=False, guestInstalled=False,
         actualVSOCKExecuted=False, actualTCP22222Reachable=False, guestSSHAuthenticated=False,
         persistentSSHImplemented=False, persistentHelperAndLeaseHandoffRequired=True,
         appOrRuntimeSigningPerformed=False, deviceOperations=0, guestOperations=0, trustCacheAdditions=0)
    save(O / 'candidate.json', candidate)
    files = [pin(p) for p in sorted(O.iterdir()) if p.is_file()]
    files += [pin(source_path), candidate['header'], candidate['artifactHeader'],
              candidate['inheritedSource'], candidate['inheritedHeader'], pin(__file__),
              candidate['signedHelperCandidate'], candidate['signedHelperFreeze'], pin(signed_path)]
    save(O / 'freeze.json', dict(schema='Source-only fixed QGA entry actual freeze v1',
         files=files, status=candidate['status'], deviceOperations=0, guestOperations=0,
         actualQGAExecuted=False, helperExecuted=False, persistentSSHImplemented=False))
    print(json.dumps(dict(candidate=pin(O / 'candidate.json'), freeze=pin(O / 'freeze.json'),
                          signedHelperCandidate=pin(A / 'candidate.json'),
                          signedHelperFreeze=pin(A / 'freeze.json'), deviceOperations=0)))


if __name__ == '__main__':
    main()
