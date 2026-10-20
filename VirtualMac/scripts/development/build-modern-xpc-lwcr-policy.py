#!/usr/bin/env python3
"""Build exact original27 LWCR message policy; execute only local Mac fixtures."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE_RIGHTS = {"platform-application": True,
    "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True,
    "com.apple.private.amfi.can-execute-cdhash": True}
PLUGIN = "com.apple.private.virtualization.plugin"
VARIANTS = {"missing": None, "false": False, "integer": 1, "true": True}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def uuid(data):
    at = 32; found = []
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, at)
        if command == 0x1b:
            found.append(data[at + 8:at + 24].hex())
        at += size
    assert len(found) == 1
    return found[0]


def target16(path):
    data = bytearray(path.read_bytes()); at = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, at)
        if command == 0x32:
            struct.pack_into("<III", data, at + 8, 2, 0x100100, 0x100100)
        at += size
    path.write_bytes(data)


def main(output):
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir()
    for path in (Path(__file__), ROOT / "vz/host/modern_xpc_lwcr_policy.c",
                 ROOT / "vz/host/modern_xpc_lwcr_policy.h",
                 ROOT / "scripts/tests/test-modern-xpc-lwcr-policy.c",
                 ROOT / "scripts/tests/validate-modern-xpc-lwcr-policy.py"):
        shutil.copyfile(path, source / path.name)
    processes = []; candidates = []

    def run(label, args, timeout=30, expected=0):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("DYLD_") and not key.startswith("VMM_")}
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(args, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid,
                          "observedWaitExit": child.returncode, "reaped": True})
        assert child.returncode == expected, (label, child.returncode, stdout.decode(errors="replace")[-3000:], stderr.decode(errors="replace")[-3000:])
        return stdout, stderr, child.pid

    def sign(role, path, rights, label):
        if role == "ios": target16(path)
        entitlements = path.parent / (path.name + ".entitlements")
        entitlements.write_bytes(plistlib.dumps(rights))
        run(label + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none",
            "--identifier", "com.virtualmac.diagnostics.lwcr-policy." + path.name,
            "--entitlements", str(entitlements), str(path)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label + "-validate", ["xcrun", "dyld_info", "-validate_only", str(path)])
        _, signature, _ = run(label + "-signature", ["codesign", "-dvvv", str(path)])
        actual = run(label + "-rights", ["codesign", "-d", "--entitlements", ":-", str(path)])[0]
        assert (plistlib.loads(actual) if actual.strip() else {}) == rights
        return {"role": role, "name": path.name, "path": str(path), "bytes": path.stat().st_size,
            "sha256": sha(path), "CDHash": re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode(),
            "UUID": uuid(path.read_bytes()), "entitlements": rights, "iOSExecuted": False}

    for role, sdk, target in (("macos", "macosx", "arm64e-apple-macos13"),
                              ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / role; folder.mkdir()
        sdk_path = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        base = ["xcrun", "clang", "-target", target, "-isysroot", sdk_path,
                "-fptrauth-abi-version=0", "-O2", "-fblocks", "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-Wno-deprecated-declarations", "-I", str(source), "-Wl,-no_adhoc_codesign"]
        library = folder / "VM27LWCRPolicy.dylib"
        run(role + "-library-compile", base + ["-dynamiclib", str(source / "modern_xpc_lwcr_policy.c"),
            "-framework", "CoreFoundation", "-framework", "Security", "-install_name", "@rpath/VM27LWCRPolicy.dylib", "-o", str(library)])
        library_row = sign(role, library, {}, role + "-library")
        candidates.append(library_row)
        (folder / "modern_xpc_lwcr_pins.h").write_text(
            '#define VM27_POLICY_SHA256 "' + library_row["sha256"] + '"\n' +
            '#define VM27_POLICY_BYTES ' + str(library_row["bytes"]) + 'ULL\n' +
            '#define VM27_POLICY_UUID "' + library_row["UUID"] + '"\n')
        unsigned = folder / "lwcr-policy-probe.unsigned"
        run(role + "-probe-compile", base + ["-I", str(folder), str(source / "test-modern-xpc-lwcr-policy.c"),
            "-framework", "CoreFoundation", "-framework", "Security", str(library),
            "-Wl,-rpath,@executable_path", "-o", str(unsigned)])
        unsigned_data = unsigned.read_bytes()
        for variant, value in VARIANTS.items():
            probe = folder / ("lwcr-policy-probe-" + variant); probe.write_bytes(unsigned_data); probe.chmod(0o755)
            rights = dict(BASE_RIGHTS) if role == "ios" else {}
            if value is not None: rights[PLUGIN] = value
            row = sign(role, probe, rights, role + "-" + variant)
            candidates.append(row)
            if role == "macos" and variant == "missing":
                stdout, _, pid = run(role + "-" + variant + "-native", [str(probe), variant, row["sha256"], str(row["bytes"])], timeout=20)
                logs = [json.loads(line) for line in stdout.decode().splitlines()]
                start = next(entry for entry in logs if entry["record"] == "start")
                summary = logs[-1]
                assert start["PID"] == pid and summary["passed"] and summary["failures"] == 0
                assert summary["tasksCreated"] == summary["tasksReleased"] == 64
                assert summary["registrationCalls"] == 0 and summary["policiesCreated"] == summary["policiesDestroyed"] == 1
                row["actualMacNative"] = summary
            elif role == "macos":
                row["nativeSkipped"] = "Private virtualization.plugin entitlements require native AMFI authorization; false signature control in policy-build-v3 was killed9 before main. No signature checks are bypassed."
        unsigned.unlink()
        # All four input machines were exactly the same unsigned bytes; only
        # signatures differ. Final role-specific provider is strongly imported.
        run(role + "-library-imports", ["xcrun", "dyld_info", "-imports", str(library)])
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(folder / "lwcr-policy-probe-missing")])
        assert sha(library) == library_row["sha256"]
    manifest = {"candidates": candidates, "processes": processes,
        "sourceSHA256": {path.name: sha(path) for path in source.iterdir()},
        "deviceOperations": False, "registrationCalls": 0,
        "nativeIOSExecuted": False, "originalVMMExecuted": False,
        "completeBundleRegistration": False, "full27Backend": False,
        "scope": "Exact original27 plugin constraint parser and authentic per-message entitlement gate"}
    (out / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")
    run("independent-validation", [sys.executable,
        str(ROOT / "scripts/tests/validate-modern-xpc-lwcr-policy.py"), str(out)])
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"),
        "iOSFiles": [row for row in candidates if row["role"] == "ios"],
        "actualMacNegative": next(row["actualMacNative"] for row in candidates if "actualMacNative" in row),
        "iOSExecuted": False, "completeBundleRegistration": False}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
