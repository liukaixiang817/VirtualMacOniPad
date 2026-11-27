#!/usr/bin/env python3
"""Build the exact-development-guest raw Bluetooth transport; never deploy it.

Guest modules: exact audited 24G90, 25G83 and 26A5416b arm64e images.
Root broker: jailbroken iPad 20B101 only.
Passing these component checks does not establish physical pairing or audio.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'VirtualMac/vz/shared-radio/exclusive'


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--guest-build', choices=('24G90', '25G83', '26A5416b', '26B131'), default='25G83')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    common = ['-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-O2']
    modern27 = args.guest_build in ('26A5416b', '26B131')
    module_profile = []
    loader_profile = []
    module_name = 'VM27ExclusiveBluetoothGuest27V1' if modern27 else 'VM27ExclusiveBluetoothGuestV15'
    loader_name = 'VM27ExclusiveBluetoothEarlyAutoLoad27V1' if modern27 else 'VM27ExclusiveBluetoothEarlyAutoLoadV2'
    native_sha = ('a4213ba4bc24a63eea18440b6723e1187650b32e9e6a4f9e503b39ca1b472f1a' if modern27 else
                  '8afb2a8c2d6aa90b1e1e9e22a7c0ec3201ce46b02ccb37775bb0c9698b93575a')
    if args.guest_build == '26B131':
        # Audited native arm64e image, Objective-C layouts and native mutex
        # implementations; do not derive an address from the previous build.
        native_sha = '1e371a14b14d8fe6e9b7b179d66c4bec5b246e785389c23a7f6a550480b4b141'
        module_profile = ['-DVM27_EXCLUSIVE_NATIVE_BUILD="26B131"',
                          '-DVM27_EXCLUSIVE_NATIVE_UUID_BYTES=0x84,0xe8,0xa6,0xad,0x7f,0x7e,0x32,0xc9,0xab,0xd0,0xfd,0x71,0xd4,0xa8,0x2f,0xd8',
                          '-DVM27_EXCLUSIVE_CORE_LOCK_RVA=0xfa96c',
                          '-DVM27_EXCLUSIVE_CORE_UNLOCK_RVA=0xfaa7c']
        loader_profile = ['-DVM27_EARLY_NATIVE_BUILD="26B131"',
                          '-DVM27_EARLY_NATIVE_SHA="' + native_sha + '"',
                          '-DVM27_EARLY_NATIVE_MAX_BYTES=64*1024*1024']
    if args.guest_build == '24G90':
        module_name = 'VM27ExclusiveBluetoothGuest15V1'
        loader_name = 'VM27ExclusiveBluetoothEarlyAutoLoad15V1'
        native_sha = '11d5628b36848a947af2b165264f521758928e5c21cf54ffa9548e7651fde7a9'
    module = output / (module_name + '.dylib')
    run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64e-apple-macos15.0',
        '-dynamiclib', *common, *module_profile, SOURCE / (module_name + '.m'),
        '-framework', 'Foundation', '-o', module)
    run('codesign', '-f', '-s', '-', module)
    watcher = output / 'exclusive-early-autoload-v2'
    run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
        *common, *loader_profile, '-DVM27_EARLY_MODULE_SHA="' + sha(module) + '"',
        SOURCE / (loader_name + '.m'), '-framework', 'Foundation',
        '-o', watcher)
    run('codesign', '-f', '-s', '-', watcher)
    relay = output / 'exclusive-guest-relay-v1'
    run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
        '-Wall', '-Wextra', '-Werror', '-O2',
        *(['-DVM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1=1'] if args.guest_build == '24G90' else []),
        SOURCE / 'VM27ExclusiveBluetoothGuestRelayV1.c', '-o', relay)
    run('codesign', '-f', '-s', '-', relay)
    provision = output / 'exclusive-guest-provision-v1'
    run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
        *common, '-DVM27_PROVISION_NATIVE_BUILD="' + args.guest_build + '"',
        SOURCE / 'VM27ExclusiveBluetoothGuestProvisionV1.m', '-framework', 'Foundation', '-o', provision)
    run('codesign', '-f', '-s', '-', provision)
    hogp = output / 'exclusive-hogp-service-v1'
    run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
        *common, '-DVM27_HOGP_NATIVE_BUILD="' + args.guest_build + '"',
        SOURCE / 'VM27ExclusiveBluetoothHOGPServiceV1.m',
        SOURCE / 'VM27ExclusiveBluetoothBondedHIDDiscoveryV1.m',
        SOURCE / 'VM27ExclusiveBluetoothHOGPV1.m',
        SOURCE.parent / 'host/VM27SharedBluetoothGATTPeerV1.m',
        '-framework', 'Foundation', '-framework', 'CoreBluetooth',
        '-framework', 'IOKit', '-o', hogp)
    run('codesign', '-f', '-s', '-', '--entitlements',
        SOURCE / 'HOGPServiceEntitlementsV1.plist', hogp)
    broker = output / 'exclusive-broker-v1'
    run('xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64-apple-ios16.0',
        *common, '-DVM27_EXCLUSIVE_HOST_READY_HANDSHAKE_V1=1', SOURCE / 'VM27ExclusiveBluetoothBrokerV1.m',
        SOURCE / 'VM27ExclusiveBluetoothSkywalkV1.m', '-framework', 'Foundation',
        '-o', broker)
    run('ldid', '-S' + str(SOURCE / 'BrokerEntitlementsV1.plist'), broker)
    for path in SOURCE.glob('com.virtualmac.*.plist'):
        (output / path.name).write_bytes(path.read_bytes())
    tested = False
    if args.test:
        test = output / 'readiness-test-v1'
        readiness_source = ('bluetooth-exclusive-legacy15-v1.m' if args.guest_build == '24G90'
                            else 'bluetooth-exclusive-readiness-v1.m')
        run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
            *common, *(['-DVM27_TEST_NATIVE27=1'] if modern27 else []),
            SOURCE.parent / 'tests' / readiness_source,
            '-framework', 'Foundation', '-o', test)
        run(test)
        controller_test = output / 'controller-init-test-v1'
        run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
            '-Wall', '-Wextra', '-Werror', '-O2',
            SOURCE.parent / 'tests/bluetooth-exclusive-controller-init-v1.c',
            '-o', controller_test)
        run(controller_test)
        host_ready_test = output / 'host-ready-test-v1'
        run('xcrun', '--sdk', 'macosx', 'clang', '-target', 'arm64-apple-macos15.0',
            '-Wall', '-Wextra', '-Werror', '-O2', '-fsanitize=address,undefined',
            SOURCE.parent / 'tests/bluetooth-exclusive-host-ready-v1.c', '-o', host_ready_test)
        run(host_ready_test)
        tested = True
    manifest = {'schema': 1, 'guestBuild': args.guest_build, 'iPadBuild': '20B101',
                'developmentOnly': True, 'componentReadinessTestPassed': tested,
                'beforeNativeMain': True, 'debuggerRequired': False,
                'guestExecutableSHA256': native_sha,
                'guestRebootAcceptanceVerified': False,
                'bondedReconnectOnly': True,
                'nativeHIDOnlyRecommended': True,
                'restrictedGuestEntitlementsRequired': True,
                'physicalPairingVerified': False, 'physicalAudioVerified': False,
                'ownedBrokerHostReadyPrelude': True,
                'guestRelayRequiresHostReadyPrelude': args.guest_build == '24G90',
                'sourceSHA256': {str(path.relative_to(REPO)): sha(path) for path in sorted(set([
                    SOURCE / (module_name + '.m'), SOURCE / 'VM27ExclusiveBluetoothGuestV15.m',
                    SOURCE / (loader_name + '.m'), SOURCE / 'VM27ExclusiveBluetoothEarlyAutoLoadV2.m',
                    SOURCE / 'VM27ExclusiveBluetoothGuestRelayV1.c',
                    SOURCE / 'VM27ExclusiveBluetoothHostReadyV1.h',
                    SOURCE / 'VM27ExclusiveBluetoothGuestProvisionV1.m',
                    SOURCE / 'VM27ExclusiveBluetoothHOGPServiceV1.m',
                    SOURCE / 'VM27ExclusiveBluetoothBondedHIDDiscoveryV1.m',
                    SOURCE / 'VM27ExclusiveBluetoothHOGPV1.m',
                    SOURCE.parent / 'host/VM27SharedBluetoothGATTPeerV1.m',
                    SOURCE / 'VM27ExclusiveBluetoothBrokerV1.m',
                    SOURCE / 'VM27ExclusiveBluetoothSkywalkV1.m']))},
                'sha256': {path.name: sha(path) for path in
                           (module, watcher, relay, hogp, broker, provision)}}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
