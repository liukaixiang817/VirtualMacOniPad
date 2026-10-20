#!/usr/bin/env python3
"""Build actual owned-bundle registry/plan; local-only native XPC negative fixture."""
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
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
POLICY = N / "xpc-lwcr-compat-v1/policy-build-v5"
RIGHTS = {"platform-application": True,
    "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True,
    "com.apple.private.amfi.can-execute-cdhash": True}
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir()
    for path in (Path(__file__), ROOT / "vz/host/modern_xpc_bundle_registry.c",
                 ROOT / "vz/host/modern_xpc_bundle_registry.h",
                 ROOT / "vz/host/modern_xpc_lwcr_policy.h",
                 ROOT / "scripts/tests/test-modern-xpc-bundle-registry.c",
                 ROOT / "scripts/tests/validate-modern-xpc-bundle-registry.py"):
        shutil.copyfile(path, source / path.name)
    spec = importlib.util.spec_from_file_location("policy_build", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    processes = []; candidates = []

    def run(label, arguments):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        try: stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(arguments, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout); (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode, "reaped": True})
        assert child.returncode == 0, (label, child.returncode, stdout.decode(errors="replace")[-4000:], stderr.decode(errors="replace")[-4000:])
        return stdout, stderr, child.pid

    def sign(role, path, rights, label):
        if role == "ios": B.target16(path)
        entitlements = path.parent / (path.name + ".entitlements")
        entitlements.write_bytes(plistlib.dumps(rights))
        run(label + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none",
            "--identifier", "com.virtualmac.diagnostics.bundle-registry." + path.name,
            "--entitlements", str(entitlements), str(path)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label + "-validate", ["xcrun", "dyld_info", "-validate_only", str(path)])
        _, signature, _ = run(label + "-signature", ["codesign", "-dvvv", str(path)])
        return {"role": role, "name": path.name, "path": str(path), "bytes": path.stat().st_size,
            "sha256": sha(path), "CDHash": re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode(),
            "UUID": B.uuid(path.read_bytes()), "entitlements": rights, "iOSExecuted": False}

    previous = json.loads((POLICY / "candidate.json").read_text())
    for role, sdk, target in (("macos", "macosx", "arm64e-apple-macos13"), ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / role; folder.mkdir()
        old = next(row for row in previous["candidates"] if row["role"] == role and row["name"] == "VM27LWCRPolicy.dylib")
        policy = folder / old["name"]; shutil.copyfile(old["path"], policy)
        assert sha(policy) == old["sha256"]
        row = dict(old); row.update({"path": str(policy), "source": old["path"], "unchanged": True}); candidates.append(row)
        sdk_path = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        base = ["xcrun", "clang", "-target", target, "-isysroot", sdk_path, "-fptrauth-abi-version=0",
            "-std=c11", "-fblocks", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
            "-I", str(source), "-Wl,-no_adhoc_codesign"]
        library = folder / "VM27BundleRegistry.dylib"
        run(role + "-registry-compile", base + ["-dynamiclib", str(source / "modern_xpc_bundle_registry.c"),
            "-framework", "CoreFoundation", str(policy), "-install_name", "@rpath/VM27BundleRegistry.dylib",
            "-Wl,-rpath,@loader_path", "-o", str(library)])
        registry_row = sign(role, library, {}, role + "-registry")
        candidates.append(registry_row)
        (folder / "modern_xpc_registry_pins.h").write_text(
            '#define VM27_POLICY_SHA256 "' + old["sha256"] + '"\n' +
            '#define VM27_POLICY_BYTES ' + str(old["bytes"]) + 'ULL\n' +
            '#define VM27_POLICY_UUID "' + old["UUID"] + '"\n' +
            '#define VM27_REGISTRY_SHA256 "' + registry_row["sha256"] + '"\n' +
            '#define VM27_REGISTRY_BYTES ' + str(registry_row["bytes"]) + 'ULL\n' +
            '#define VM27_REGISTRY_UUID "' + registry_row["UUID"] + '"\n')
        probe = folder / "bundle-registry-probe"
        run(role + "-probe-compile", base + ["-I", str(folder), str(source / "test-modern-xpc-bundle-registry.c"),
            str(library), str(policy), "-Wl,-rpath,@executable_path", "-o", str(probe)])
        probe_row = sign(role, probe, RIGHTS if role == "ios" else {}, role + "-probe")
        candidates.append(probe_row)
        if role == "macos":
            stdout, _, pid = run("macos-owned-native", [str(probe), probe_row["sha256"], str(probe_row["bytes"])])
            logs = [json.loads(line) for line in stdout.decode().splitlines()]
            assert next(row for row in logs if row["record"] == "start")["PID"] == pid
            summary = logs[-1]
            assert summary["passed"] and summary["failures"] == 0 and summary["registrations"] == summary["services"] == 1
            assert summary["tasksCreated"] == summary["tasksReleased"] == 64 and summary["plansCreated"] == summary["plansDestroyed"] == 257
            assert summary["childLaunches"] == summary["launchdRegistrations"] == 0
            probe_row["actualMacOwnedNative"] = summary
        run(role + "-registry-imports", ["xcrun", "dyld_info", "-imports", str(library)])
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)])
        assert sha(policy) == old["sha256"]
    result = {"candidates": candidates, "sourceSHA256": {path.name: sha(path) for path in source.iterdir()},
              "processes": processes, "deviceOperations": False, "iOSExecuted": False,
              "launchdRegistrations": 0, "childLaunches": 0, "completeBundleRegistration": False,
              "originalVMMExecuted": False, "full27Backend": False}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    validator_spec = importlib.util.spec_from_file_location("registry_validation", ROOT / "scripts/tests/validate-modern-xpc-bundle-registry.py")
    validator = importlib.util.module_from_spec(validator_spec); validator_spec.loader.exec_module(validator)
    (out / "verification.json").write_text(json.dumps(validator.main(out), indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"),
        "actualMac": next(row["actualMacOwnedNative"] for row in candidates if "actualMacOwnedNative" in row),
        "iOSFiles": [row for row in candidates if row["role"] == "ios"]}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
