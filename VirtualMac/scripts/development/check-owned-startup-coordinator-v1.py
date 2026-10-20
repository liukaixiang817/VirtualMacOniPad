#!/usr/bin/env python3
"""Build and run local state contracts and a separate actual Mac V8 preparation.

No device access, original VMM execution or native CPU implementation. Existing
frozen providers are read/link only; every output belongs to the new directory.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys

if sys.flags.optimize:
    raise RuntimeError("Optimized Python is not permitted for this verifier")
ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "VirtualMac/vz/host"
N = ROOT / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
OUT = N / "owned-vmm-startup-coordinator-contract-v4"
if OUT.exists():
    raise RuntimeError("Refusing to overwrite existing evidence directory")
OUT.mkdir(mode=0o700)
COMMANDS = []


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, arguments, expected=0, env=None):
    result = subprocess.run(arguments, capture_output=True, timeout=100, env=env)
    (OUT / (label + ".stdout")).write_bytes(result.stdout)
    (OUT / (label + ".stderr")).write_bytes(result.stderr)
    (OUT / (label + ".argv.json")).write_text(json.dumps(arguments, indent=2) + "\n")
    (OUT / (label + ".exit")).write_text(str(result.returncode) + "\n")
    COMMANDS.append({"label": label, "argv": arguments, "observedExit": result.returncode})
    if result.returncode != expected:
        raise RuntimeError(f"{label}: observed {result.returncode}, expected {expected}; see saved stderr")
    return result


def bundle(executable, name):
    contents = OUT / (name + ".app/Contents")
    (contents / "MacOS").mkdir(parents=True)
    metadata = {"CFBundleIdentifier": "org.virtualmac.local." + name,
                "CFBundleExecutable": executable.name, "CFBundleName": "VM27 own startup local test",
                "CFBundlePackageType": "APPL", "CFBundleVersion": "1"}
    (contents / "Info.plist").write_bytes(plistlib.dumps(metadata))
    target = contents / "MacOS" / executable.name
    shutil.copyfile(executable, target)
    target.chmod(0o700)
    return target


input_paths = [SOURCE / n for n in (
    "vm27_owned_startup_coordinator_v1.h", "vm27_owned_startup_coordinator_v1.c",
    "vm27_owned_startup_coordinator_v1.md", "test-vm27-owned-startup-coordinator-v1.c",
    "test-vm27-owned-startup-coordinator-real-v8-v1.c", "vm27_headless_checkin_v1.c",
    "vm27_headless_checkin_v1.h", "modern_xpc_original_instance_transport_v8.c",
    "modern_xpc_original_instance_transport_v8.h", "modern_xpc_private_consumer.h",
    "modern_xpc_bundle_registry.h", "modern_xpc_lwcr_policy.h",
    "modern_xpc_approved_code.h", "modern_xpc_private_endpoint.h")]
input_paths += [Path(__file__).resolve()]
before = {str(p): sha(p) for p in input_paths}
clang = run("clang-path", ["/usr/bin/xcrun", "--find", "clang"]).stdout.decode().strip()
mac_sdk = run("mac-sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"]).stdout.decode().strip()
ios_sdk = run("ios-sdk", ["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).stdout.decode().strip()
base = [clang, "-isysroot", mac_sdk, "-std=c11", "-fblocks", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-I", str(SOURCE)]

for flavor in ("ordinary", "asan"):
    extra = [] if flavor == "ordinary" else ["-fsanitize=address", "-fno-omit-frame-pointer"]
    objects = []
    for instance in ("A", "B"):
        obj = OUT / (flavor + "-checkin-" + instance + ".o")
        run(flavor + "-compile-checkin-" + instance, base + extra + [
            "-D_LSApplicationCheckIn=VM27TestCheckIn" + instance,
            "-DVM27CopyPrivateHeadlessCheckInState=VM27TestCopyCheckIn" + instance,
            "-c", str(SOURCE / "vm27_headless_checkin_v1.c"), "-o", str(obj)])
        objects.append(str(obj))
    executable = OUT / (flavor + "-owned-startup-state")
    run(flavor + "-compile-state", base + extra + [str(SOURCE / "vm27_owned_startup_coordinator_v1.c"),
        str(SOURCE / "test-vm27-owned-startup-coordinator-v1.c")] + objects + [
        "-framework", "CoreFoundation", "-o", str(executable)])
    bundled = bundle(executable, flavor + "OwnedStartup")
    environment = dict(os.environ)
    if flavor == "asan":
        # Darwin's runtime explicitly rejects leak detection; preserve that
        # v2 failure and run address checks only, without claiming leak proof.
        environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    actual = run(flavor + "-actual-state", [str(bundled)], env=environment)
    records = [json.loads(line) for line in actual.stdout.decode().splitlines()]
    if len(records) != 9 or [r.get("scenario") for r in records[:-1]] != list(range(8)) or \
            records[-1] != {"record": "localStateSummary", "scenarios": 8, "passed": True,
                            "nativeDeviceReadiness": False, "full27Ready": False}:
        raise RuntimeError("State transcript layout rejected")
    if any(r.get("genuineV8Executed") is not False or r.get("nativeCPUOperations") != 0 or
           r.get("passed") is not True or r.get("checks", 0) <= 0 for r in records[:-1]):
        raise RuntimeError("State scope/results rejected")

ios_obj = OUT / "owned-startup-coordinator-ios-compile-only.o"
run("ios-compile-only", base + ["-target", "arm64e-apple-ios16.1", "-isysroot", ios_sdk,
    "-fptrauth-abi-version=0", "-c", str(SOURCE / "vm27_owned_startup_coordinator_v1.c"), "-o", str(ios_obj)])

# Actual Mac dependency graph is the old frozen graph, linked at its old path.
# No library is copied, re-signed or rewritten. New CheckIn source object is real
# unchanged body, compiled for matching arm64e; its existing arm64 dylib is not
# falsely presented as a compatible arm64e runtime provider.
graph = N / "xpc-original-instance-registration-v8-test-development-v1/build-v4/macos"
libraries = [graph / name for name in ("VM27OriginalV8Transport.dylib", "VM27PrivateConsumer.dylib",
    "VM27BundleRegistry.dylib", "VM27PrivateEndpoint.dylib", "VM27ApprovedCode.dylib",
    "VM27LWCRPolicy.dylib", "VM27ClientRegistration.dylib")]
graph_before = {str(p): sha(p) for p in libraries}
executable = OUT / "actual-v8-owned-startup"
run("real-v8-compile", base + ["-target", "arm64e-apple-macos13", "-isysroot", mac_sdk,
    "-fptrauth-abi-version=0", str(SOURCE / "vm27_owned_startup_coordinator_v1.c"),
    str(SOURCE / "test-vm27-owned-startup-coordinator-real-v8-v1.c"),
    str(SOURCE / "vm27_headless_checkin_v1.c")] + [str(p) for p in libraries] + [
    "-framework", "CoreFoundation", "-framework", "Security", "-Wl,-rpath," + str(graph),
    "-Wl,-no_adhoc_codesign", "-o", str(executable)])
run("real-v8-code-only-sign", ["/usr/bin/codesign", "-s", "-", str(executable)])
run("real-v8-code-only-verify", ["/usr/bin/codesign", "--verify", "--strict", str(executable)])
identity = run("real-v8-code-identity", ["/usr/bin/codesign", "-d", "-vvvv", str(executable)])
match = re.search(rb"\bCDHash=([0-9a-f]{40})\b", identity.stderr)
if not match:
    raise RuntimeError("Missing actual code-only CodeDirectory hash")
bundled = bundle(executable, "actualV8OwnedStartup")
if sha(bundled) != sha(executable):
    raise RuntimeError("Bundled executable differs from code-only verified file")
actual = run("actual-frozen-v8-prepare-stop", [str(bundled), sha(executable), match.group(1).decode(), "prepare-only"])
records = [json.loads(line) for line in actual.stdout.decode().splitlines()]
if [r.get("record") for r in records] != ["actualV8PreparationAttempt", "actualV8PreparationSummary", "actualV8PreparationParent"]:
    raise RuntimeError("Actual preparation transcript layout rejected")
if records[0]["status"] != 0 or records[0]["genuineV8Executed"] is not True or \
        records[1]["listenersCreated"] != 1 or records[1]["listenersDestroyed"] != 1 or \
        records[1]["originalMainCalls"] != 0 or records[1]["originalHandlerCalls"] != 0 or \
        records[1]["nativeCPUOperations"] != 0 or records[1]["full27Ready"] is not False or \
        records[2]["childReaped"] is not True or records[2]["observedWaitExit"] != 0:
    raise RuntimeError("Actual preparation scope/results rejected")
for path, digest in (before | graph_before).items():
    if sha(Path(path)) != digest:
        raise RuntimeError("Input changed during validation: " + path)
report = {"format": "vm27-owned-startup-coordinator-contract-v1", "ordinaryStateScenarios": 8,
          "asanStateScenarios": 8, "actualFrozenMacV8PrepareRequireStop": True,
          "asanAddressChecksOnly": True, "asanLeakDetectionSupported": False,
          "actualMacPeerDelivered": False, "genuineGateSuccessClaimed": False,
          "iosCompileOnly": True, "iosExecuted": False, "originalVMMExecuted": False,
          "nativeCPUOperations": 0, "full27Ready": False, "inputSHA256": before,
          "readOnlyFrozenMacGraphSHA256": graph_before, "commands": COMMANDS,
          "codeOnlyStandaloneSignatureVerified": True, "wholeAppResourceSignatureVerified": False,
          "checkInProviderScope": "unchanged helper body linked once in new local executable; original import integration unverified"}
(OUT / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
pins = []
for path in sorted(OUT.rglob("*")):
    if path.is_file():
        pins.append({"path": str(path), "bytes": path.stat().st_size, "SHA256": sha(path)})
(OUT / "freeze.json").write_text(json.dumps({"files": pins}, indent=2) + "\n")
print(json.dumps({"verification": str(OUT / "verification.json"), "frozenFiles": len(pins),
                  "full27Ready": False}, indent=2))
