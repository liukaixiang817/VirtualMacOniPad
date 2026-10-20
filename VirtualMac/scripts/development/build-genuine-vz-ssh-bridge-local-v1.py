#!/usr/bin/env python3
"""HOST-only real socket models and genuine VZ adapter compile; no signing/device."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

R = Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
G = R / 'VirtualMac/vz/guest'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit('New output required; frozen candidates are never modified.')
    output.mkdir(parents=True)
    commands = []

    def run(name, argv, timeout=60):
        p = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout)
        (output / (name + '.stdout')).write_bytes(p.stdout)
        (output / (name + '.stderr')).write_bytes(p.stderr)
        row = {'name': name, 'argv': list(map(str, argv)), 'returncode': p.returncode,
               'stdout': pin(output / (name + '.stdout')), 'stderr': pin(output / (name + '.stderr'))}
        commands.append(row)
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if p.returncode:
            raise SystemExit(f'{name} failed: {p.stderr.decode(errors="replace")}')
        return p.stdout.decode()

    mac = Path(run('mac-sdk', ['xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip())
    ios = Path(run('ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).strip())
    new_c = S / 'vm27_host_vsock_ssh_owner_v1.c'
    adapter = S / 'vm27_genuine_vz_ssh_bridge_v1.m'
    fixture = R / 'VirtualMac/vz/development/probes/vm27_host_vsock_ssh_owner_fixture_v1.c'
    shared_c = [new_c, S / 'vm27_owned_stream_relay_v1.c', G / 'vm27_vsock_ssh_protocol_v1.c']
    models = []
    for variant, extra in [('normal', []), ('san', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        binary = output / ('host-socket-model-' + variant)
        run('build-' + variant, ['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-g', *extra, fixture, *shared_c, '-o', binary])
        run('run-' + variant, [binary], timeout=20)
        models.append({'variant': variant, 'binary': pin(binary),
                       'result': pin(output / ('run-' + variant + '.stdout'))})
    objects = []
    for platform, target, sdk in [('mac', 'arm64-apple-macos15', mac), ('ios', 'arm64e-apple-ios16.1', ios)]:
        platform_objects = []
        for source in [*shared_c, adapter]:
            obj = output / (source.stem + '.' + platform + '.o')
            flags = ['-fobjc-arc', '-fblocks'] if source.suffix == '.m' else ['-std=c11', '-fvisibility=hidden']
            run('compile-' + platform + '-' + source.stem,
                ['xcrun', 'clang', '-target', target, '-isysroot', sdk, '-fPIC',
                 '-Wall', '-Wextra', '-Werror', *flags, '-c', source, '-o', obj])
            platform_objects.append(obj)
            objects.append(pin(obj))
        dylib = output / ('VM27GenuineVZSSHBridgeV1.' + platform + '.dylib')
        run('link-' + platform, ['xcrun', 'clang', '-target', target, '-isysroot', sdk,
            '-dynamiclib', *platform_objects, '-framework', 'Foundation',
            '-Wl,-undefined,error', '-Wl,-no_adhoc_codesign', '-o', dylib])
        undefined = run('undefined-' + platform, ['xcrun', 'nm', '-u', dylib])
        if 'OBJC_CLASS_$_VZ' in undefined or 'VZVirtio' in undefined:
            raise SystemExit('Adapter must use actual loaded VZ classes, not platform VZ class imports.')
        objects.append(pin(dylib))
    contract = output / 'actual-mac27-sdk-contract.m'
    contract.write_text('''#import <Virtualization/Virtualization.h>
#include <stddef.h>
_Static_assert(sizeof(((VZVirtioSocketConnection *)0).fileDescriptor)==sizeof(int), "fd ABI");
_Static_assert(sizeof(((VZVirtioSocketConnection *)0).destinationPort)==sizeof(uint32_t), "port ABI");
void ActualVZSocketContract(VZVirtualMachine *vm, VZVirtioSocketDevice *device,
                          VZVirtioSocketListener *listener, VZVirtioSocketConnection *connection,
                          id<VZVirtioSocketListenerDelegate> delegate) {
    dispatch_queue_t queue=vm.queue; NSArray *devices=vm.socketDevices;
    listener.delegate=delegate; [device setSocketListener:listener forPort:22223];
    int fd=connection.fileDescriptor; uint32_t port=connection.destinationPort;
    BOOL accepted=[delegate listener:listener shouldAcceptNewConnection:connection fromSocketDevice:device];
    [device removeSocketListenerForPort:22223]; [connection close];
    (void)queue;(void)devices;(void)fd;(void)port;(void)accepted;
}
''')
    run('compile-actual-sdk-contract', ['xcrun', 'clang', '-target', 'arm64-apple-macos27',
        '-isysroot', mac, '-fobjc-arc', '-fblocks', '-Wall', '-Wextra', '-Werror',
        '-c', contract, '-o', output / 'actual-mac27-sdk-contract.o'])
    cpp = output / 'typed-cpp-consumer.mm'
    cpp.write_text('#import "vm27_genuine_vz_ssh_bridge_v1.h"\n'
                   'BOOL TypedBridge(id vm,NSString *path,VM27GenuineVZSSHBridgeV1 **out,NSError **error) {\n'
                   'return VM27CreateGenuineVZSSHBridgeV1(vm,path,30000,out,error); }\n')
    run('compile-typed-ios-cpp', ['xcrun', 'clang++', '-target', 'arm64e-apple-ios16.1', '-isysroot', ios,
        '-I', S, '-fobjc-arc', '-fblocks', '-Wall', '-Wextra', '-Werror', '-c', cpp,
        '-o', output / 'typed-cpp-consumer.ios.o'])
    undefined = run('undefined-typed-ios-cpp', ['xcrun', 'nm', '-u', output / 'typed-cpp-consumer.ios.o'])
    if '_VM27CreateGenuineVZSSHBridgeV1' not in undefined:
        raise SystemExit('Factory C++ ABI must remain unmangled.')
    headers = mac / 'System/Library/Frameworks/Virtualization.framework/Versions/A/Headers'
    sources = [Path(__file__).resolve(), new_c, S / 'vm27_host_vsock_ssh_owner_v1.h',
               adapter, S / 'vm27_genuine_vz_ssh_bridge_v1.h', fixture,
               *shared_c[1:], G / 'vm27_guest_vsock_ssh_helper_v1.h',
               G / 'vm27_guest_vsock_ssh_helper_v1.c',
               *[headers / h for h in ['VZVirtioSocketDevice.h', 'VZVirtioSocketListener.h',
                                        'VZVirtioSocketConnection.h', 'VZVirtualMachine.h']]]
    inherited = [N / 'owned-stream-relay-independent-peer-v1-attempt1/review.json',
                 N / 'owned-stream-relay-independent-peer-v1-attempt1/freeze.json',
                 N / 'guest-active-vsock-ssh-helper-local-v1-attempt1/candidate.json',
                 N / 'guest-active-vsock-ssh-helper-local-v1-attempt1/freeze.json',
                 N / 'independent27-vsock-ssh-minimum-host-plan-v1-attempt1/report.json',
                 N / 'continuation-20261012-state-v53.json']
    candidate = {
        'schema': 'Genuine VZ socket SSH bridge HOST source candidate v1',
        'sourceCompileAndRealHostSocketTestsPassed': True,
        'actualVZDelegateExecuted': False, 'actualIPadExecuted': False,
        'actualGuestHelperInstalled': False, 'actualSSHAuthenticationVerified': False,
        'actualAppIntegrated': False, 'deviceOperations': 0, 'trustCacheOperations': 0,
        'codeSigningOperations': 0, 'guestBootReady': False,
        'productionPorts': {'TCP': '127.0.0.1:22222', 'VZListener': 22223,
                            'guestTarget': '127.0.0.1:22'},
        'lifecycle': 'actual VM.queue identity, exclusive VM associated owner, retained genuine connections, dup owned fds; cancel, join, release on actual VM.queue before VM lease release',
        'protocol': 'HELLO zero token; fresh random nonzero nonce per control; strictly increasing nonzero BE64 START sequence; DATA exact-once pending match; ERROR exact owned pending token',
        'bounds': {'streams': 16, 'handshakes': 32, 'setupMilliseconds': 5000,
                   'idleMillisecondsRange': [1, 3600000],
                   'controlLoss': 'terminate owner, join and close all streams; no implicit reconnect'},
        'tests': models, 'objects': objects, 'sources': [pin(p) for p in sources],
        'inheritedEvidenceNotRerun': [pin(p) for p in inherited],
        'remaining': ['Wire into a new App source version, exclusively configure one actual socket device and listener port22223.',
                      'Actually register/receive genuine VZ callbacks on iPad.',
                      'Install and start the real guest helper after guest/QGA readiness.',
                      'Verify real guest localhost22 and lkx authentication through actual TCP22222 and USB transport.',
                      'General Ethernet/IP/NAT remains separate.'],
        'commands': pin(output / 'commands.json')}
    candidate_file = output / 'candidate.json'
    candidate_file.write_text(json.dumps(candidate, indent=2) + '\n')
    pins = [pin(p) for p in sources + inherited] + [pin(p) for p in sorted(output.iterdir()) if p.is_file()]
    (output / 'freeze.json').write_text(json.dumps({'schema': 'Exact HOST bridge source artifact freeze v1',
        'candidate': pin(candidate_file), 'pins': pins}, indent=2) + '\n')
    print(json.dumps({'candidate': pin(candidate_file), 'freeze': pin(output / 'freeze.json')}, indent=2))


if __name__ == '__main__':
    main()
