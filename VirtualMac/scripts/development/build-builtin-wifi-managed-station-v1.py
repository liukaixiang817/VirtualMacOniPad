#!/usr/bin/env python3
"""Build the bounded iPad14,6 / 20B101 auxiliary STA experiment.

No device changes, trustcache changes, deployment or acceptance are performed.
Wi-Fi credentials are supplied by a guest association, never by this builder.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bss-down-before-remove", action="store_true")
    parser.add_argument("--opposite-band-only", action="store_true")
    parser.add_argument("--native-ap-stop-after-remove", action="store_true")
    parser.add_argument("--retain-auxiliary-controller", action="store_true")
    parser.add_argument("--owned-broker", action="store_true")
    parser.add_argument("--persistent-station-auth", action="store_true",
                        help="Keep the allocated STA and its supplicant across VM leases; device acceptance required")
    parser.add_argument("--native-td-policy-profile", action="store_true",
                        help="Build the frozen revision59 owned actor with native per-BSS TD policy and retained data leases")
    parser.add_argument("--retain-recent-native-bss", action="store_true",
                        help="Retain genuinely observed BSSs for at most 60 seconds through partial scans")
    args = parser.parse_args()
    if args.retain_recent_native_bss and not args.native_td_policy_profile:
        parser.error("Recent native BSS retention requires the native TD policy profile")
    if args.native_td_policy_profile:
        if not args.owned_broker:
            parser.error("The native TD policy profile requires the owned broker")
        args.persistent_station_auth = True
    if args.persistent_station_auth and not args.owned_broker:
        parser.error("Persistent station authentication requires the owned broker")
    if args.persistent_station_auth and (args.bss_down_before_remove or args.native_ap_stop_after_remove):
        parser.error("Persistent station authentication excludes BSS-down and AP-stop")
    if args.owned_broker:
        args.retain_auxiliary_controller = True
        args.opposite_band_only = True
    if args.retain_auxiliary_controller and args.native_ap_stop_after_remove:
        parser.error("Retaining a controller excludes the delete/AP-stop experiment")
    root = Path(__file__).resolve().parents[3]
    probes = root / "VirtualMac/vz/development/probes"
    common = root / "VirtualMac/vz/shared-radio/common"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / ("virtualmac-owned-wifi-v1" if args.owned_broker else "wifi-managed-station-v1")
    definitions = ["VM27_WIFI_NATIVE_STA_LEAVE=1"]
    if args.bss_down_before_remove or args.retain_auxiliary_controller:
        definitions.append("VM27_WIFI_STA_BSS_DOWN_BEFORE_REMOVE=1")
    if args.opposite_band_only:
        definitions.append("VM27_WIFI_OPPOSITE_BAND_ONLY=1")
    if args.native_ap_stop_after_remove:
        definitions.append("VM27_WIFI_NATIVE_AP_STOP_AFTER_STA_REMOVE=1")
    if args.retain_auxiliary_controller:
        definitions.extend(["VM27_WIFI_CLEAR_STA_SECURITY_AFTER_LEAVE=1",
                            "VM27_WIFI_ABORT_STA_JOIN_BEFORE_REMOVE=1",
                            "VM27_WIFI_RETAIN_QUIESCED_STA=1"])
    if args.owned_broker:
        definitions.append("VM27_WIFI_USE_ACTUAL_SCAN_CHANSPEC=1")
    if args.persistent_station_auth:
        definitions = [
            "VM27_WIFI_SINGLE_NATIVE_STA_LEAVE=1", "VM27_WIFI_OPPOSITE_BAND_ONLY=1",
            "VM27_WIFI_RETAIN_QUIESCED_STA=1", "VM27_WIFI_RETAIN_QUIESCED_STA_UP=1",
            "VM27_WIFI_RETAIN_NATIVE_BSD_UP=1", "VM27_WIFI_RESUME_BEFORE_JOIN_CONFIGURATION=1",
            "VM27_WIFI_STA_JOIN_MANAGES_BSS=1", "VM27_WIFI_PERSIST_STA_AUTH=1",
            "VM27_WIFI_USE_ACTUAL_SCAN_CHANSPEC=1",
        ]
    if args.native_td_policy_profile:
        definitions.remove("VM27_WIFI_RESUME_BEFORE_JOIN_CONFIGURATION=1")
        definitions.extend(["VM27_WIFI_PERSIST_PHYSICAL_STA=1",
                            "VM27_WIFI_OWNED_BSS_STAGE_LIFECYCLE=1"])
    if args.retain_recent_native_bss:
        definitions.append("VM27_WIFI_RETAIN_RECENT_NATIVE_BSS=1")
    sources = [probes / "builtin-wifi-auxiliary-station-lease-v1.m",
               common / "vm27_shared_radio_wire_v1.c",
               common / "vm27_wifi_mac_translation_v1.c"]
    inputs = sources + [probes / name for name in (
        "wifi-bpf-dhcp-probe-v1.inc", "wifi-interface-event-filter-v1.inc",
        "wifi-auxiliary-power-lease-v1.inc", "wifi-station-packet-broker-v1.inc")]
    inputs += [probes / name for name in (
        "physical-data-lease.inc", "native-scan-lease.inc", "owned-idle-recovery.inc",
        "persistent-data-descriptor.inc", "native-default-key-preparation.inc",
        "owned-pending-join-recovery.inc", "native-td-policy.inc")]
    inputs += [common / name for name in (
        "vm27_shared_radio_wire_v1.h", "vm27_wifi_mac_translation_v1.h",
        "vm27_wifi_host_isolation_v1.h", "vm27_wifi_native_chanspec_v1.h",
        "vm27_wifi_native_sta_leave_v1.h", "vm27_wifi_native_reader_renewal_v1.h")]
    inputs.append(root / "VirtualMac/vz/shared-radio/independent/VM27OwnedWiFiAdmissionV1.h")
    if args.retain_recent_native_bss:
        inputs.append(probes / "native-scan-cache.inc")
    if args.owned_broker:
        sources[0] = root / "VirtualMac/vz/shared-radio/independent/VM27OwnedWiFiBrokerV1.m"
        inputs.append(sources[0])
    entitlements = {
        "com.apple.developer.driverkit.userclient-access": "com.apple.DriverKit-AppleBCMWLAN",
        "com.apple.private.security.no-container": True,
        "com.apple.security.exception.iokit-user-client-class": ["IO80211APIUserClient", "IOUserUserClient"],
        "com.apple.security.iokit-user-client-class": ["IO80211APIUserClient", "IOUserUserClient"],
        "com.apple.wifi.manager-access": True,
        "com.apple.wlan.authentication": True,
        "com.apple.wifi.hostapd": True,
    }
    entitlement_path = output / "entitlements.plist"
    entitlement_path.write_bytes(plistlib.dumps(entitlements))
    command = ["xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios15.0",
               "-fobjc-arc", "-O2", "-Wall", "-Wextra", "-Werror",
               *("-D" + item for item in definitions), *map(str, sources),
               "-framework", "Foundation", "-framework", "IOKit", "-o", str(binary)]
    subprocess.run(command, check=True)
    subprocess.run(["ldid", "-S" + str(entitlement_path), str(binary)], check=True)
    embedded = subprocess.check_output(["ldid", "-e", str(binary)])
    if plistlib.loads(embedded) != entitlements:
        raise RuntimeError("Embedded entitlements differ from the declared profile")
    signature = subprocess.run(["codesign", "-d", "--verbose=4", str(binary)],
                               capture_output=True, text=True, check=True).stderr
    match = re.search(r"^CDHash=([0-9a-f]{40})$", signature, re.MULTILINE)
    if not match:
        raise RuntimeError("Missing CodeDirectory hash")
    manifest = {
        "schema": 1, "supportedHardware": "iPad14,6", "supportedBuild": "20B101",
        "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "cdhash": match.group(1), "definitions": definitions, "command": command,
        "sources": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in inputs},
        "deviceDeploymentPerformed": False, "persistentProductReady": False,
        "stableLifecycleVerified": False,
        "physicalContextRetainedAfterGuestLease": args.retain_auxiliary_controller,
        "retainsNativeAuthenticationObject": args.persistent_station_auth,
        "cleanupSecurityClearing": args.retain_auxiliary_controller and not args.persistent_station_auth,
        "usesExactNativeScanChanspec": args.owned_broker,
        "transport": "owned-unix-app-session" if args.owned_broker else "bounded-development-loopback",
        "nativeTDPolicyProfile": args.native_td_policy_profile,
        "retainsRecentNativeBSS": args.retain_recent_native_bss,
        "runtimeAcceptanceGranted": False,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary": str(binary), "sha256": manifest["binarySHA256"],
                      "cdhash": manifest["cdhash"]}))


if __name__ == "__main__":
    main()
