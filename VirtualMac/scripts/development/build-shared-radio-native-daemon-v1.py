#!/usr/bin/env python3
"""Build the guest's native Wi-Fi scan and Bluetooth discovery relay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", type=int, default=8)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    radio = root / "VirtualMac/vz/shared-radio"
    sources = [radio / path for path in (
        "guest/VM27SharedRadioNativeDaemonV1.m",
        "guest/VM27SharedBluetoothBonjourGuestV1.m",
        "common/vm27_shared_radio_wire_v1.c",
    )]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not 1 <= args.revision <= 999:
        parser.error('revision must be positive and bounded')
    binary = output / ("shared-radio-native-daemon-v" + str(args.revision))
    commands = [
        ["xcrun", "--sdk", "macosx", "clang", "-arch", "arm64",
         "-mmacosx-version-min=15.0", "-O2", "-fobjc-arc", "-fblocks",
         "-Wall", "-Wextra", "-Werror", "-framework", "Foundation",
         "-framework", "IOKit", "-framework", "SystemConfiguration", *map(str, sources), "-o", str(binary)],
        ["xattr", "-cr", str(binary)],
        ["codesign", "--force", "--sign", "-", "--timestamp=none", str(binary)],
        ["codesign", "--verify", "--strict", str(binary)],
    ]
    # DNSService* is provided by libSystem on macOS; there is no separate
    # libdns_sd SDK stub to link on this target.
    for index, command in enumerate(commands):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / f"build-{index}.log").write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError(result.stdout.decode(errors="replace"))
    manifest = {
        "schema": 1,
        "binary": str(binary),
        "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "sources": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sources + [radio / 'guest/VM27IndependentWiFiDevelopmentV1.inc',
                                           radio / 'common/vm27_shared_radio_native_v1.h',
                                           radio / 'common/vm27_shared_radio_wire_v1.h',
                                           radio / 'guest/VM27SharedRadioGuestLinkV1.m',
                                           radio / 'guest/VM27SharedWiFiNetworkSetupV1.inc']},
        "commands": commands,
        "guestDeploymentPerformed": False,
        "nativeBluetoothDiscoveryValidated": False,
        "nativeBluetoothPairingImplemented": False,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
