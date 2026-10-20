#!/usr/bin/env python3
"""Local actual approved-code parser/message fixture and four iOS controls."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
POLICY = N / "xpc-lwcr-compat-v1/policy-build-v5"
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True}
PLUGIN = "com.apple.private.virtualization.plugin"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    out = Path(output).resolve(); out.mkdir(parents=True, mode=0o700, exist_ok=False)
    source = out / "source"; source.mkdir()
    for path in (Path(__file__), ROOT / "vz/host/modern_xpc_approved_code.c", ROOT / "vz/host/modern_xpc_approved_code.h",
                 ROOT / "vz/host/modern_xpc_lwcr_policy.h", ROOT / "scripts/tests/test-modern-xpc-approved-code.c",
                 ROOT / "scripts/tests/validate-modern-xpc-approved-code.py"):
        shutil.copyfile(path, source / path.name)
    spec = importlib.util.spec_from_file_location("policy_build", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    candidates, processes = [], []

    def run(label, arguments):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        try: stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(arguments, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout); (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode, "reaped": True})
        assert child.returncode == 0, (label, child.returncode, stdout.decode(errors="replace")[-5000:], stderr.decode(errors="replace")[-5000:])
        return stdout, stderr, child.pid

    def sign(role, path, rights, label):
        if role == "ios": B.target16(path)
        ent = path.parent / (path.name + ".entitlements"); ent.write_bytes(plistlib.dumps(rights))
        identifier = "probe-unapproved" if path.name.endswith("true-unapproved") else "probe" if path.name.startswith("approved-code-probe") else path.name
        run(label + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier",
            "com.virtualmac.diagnostics.approved-code." + identifier, "--entitlements", str(ent), str(path)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label + "-validate", ["xcrun", "dyld_info", "-validate_only", str(path)])
        _, description, _ = run(label + "-signature", ["codesign", "-dvvv", str(path)])
        return {"role": role, "name": path.name, "path": str(path), "bytes": path.stat().st_size,
            "sha256": sha(path), "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", description)[1].decode(),
            "UUID": B.uuid(path.read_bytes()), "entitlements": rights, "iOSExecuted": False}

    previous = json.loads((POLICY / "candidate.json").read_text())
    for role, sdk, target in (("ios", "iphoneos", "arm64e-apple-ios16.1"), ("macos", "macosx", "arm64e-apple-macos13")):
        folder = out / role; folder.mkdir()
        old = next(row for row in previous["candidates"] if row["role"] == role and row["name"] == "VM27LWCRPolicy.dylib")
        policy = folder / old["name"]; shutil.copyfile(old["path"], policy); assert sha(policy) == old["sha256"]
        row = dict(old); row.update({"path": str(policy), "source": old["path"], "unchanged": True}); candidates.append(row)
        sdkPath = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        base = ["xcrun", "clang", "-target", target, "-isysroot", sdkPath, "-fptrauth-abi-version=0", "-std=c11", "-fblocks", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-I", str(source), "-Wl,-no_adhoc_codesign"]
        library = folder / "VM27ApprovedCode.dylib"
        run(role + "-approved-compile", base + ["-dynamiclib", str(source / "modern_xpc_approved_code.c"), "-framework", "CoreFoundation", str(policy), "-install_name", "@rpath/VM27ApprovedCode.dylib", "-Wl,-rpath,@loader_path", "-o", str(library)])
        libraryRow = sign(role, library, {}, role + "-approved"); candidates.append(libraryRow)
        (folder / "modern_xpc_approved_pins.h").write_text(
            '#define VM27_POLICY_SHA256 "' + old["sha256"] + '"\n#define VM27_POLICY_BYTES ' + str(old["bytes"]) + 'ULL\n#define VM27_POLICY_UUID "' + old["UUID"] + '"\n' +
            '#define VM27_APPROVED_SHA256 "' + libraryRow["sha256"] + '"\n#define VM27_APPROVED_BYTES ' + str(libraryRow["bytes"]) + 'ULL\n#define VM27_APPROVED_UUID "' + libraryRow["UUID"] + '"\n')
        unsigned = folder / "approved-code-probe.unsigned"
        run(role + "-probe-compile", base + ["-I", str(folder), str(source / "test-modern-xpc-approved-code.c"), str(library), str(policy), "-Wl,-rpath,@executable_path", "-o", str(unsigned)])
        for variant in ("missing", "false", "integer", "true", "true-unapproved"):
            probe = folder / ("approved-code-probe-" + variant); shutil.copyfile(unsigned, probe); probe.chmod(0o755)
            rights = dict(RIGHTS) if role == "ios" else {}
            if variant != "missing": rights[PLUGIN] = {"false": False, "integer": 1, "true": True, "true-unapproved": True}[variant]
            candidates.append(sign(role, probe, rights, role + "-" + variant))
        run(role + "-approved-imports", ["xcrun", "dyld_info", "-imports", str(library)])
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(folder / "approved-code-probe-missing")])
    approved = next(row for row in candidates if row["role"] == "ios" and row["name"] == "approved-code-probe-true")
    mac = next(row for row in candidates if row["role"] == "macos" and row["name"] == "approved-code-probe-missing")
    stdout, _, pid = run("macos-missing-native", [mac["path"], "missing", mac["sha256"], str(mac["bytes"]), approved["path"], approved["sha256"], approved["CDHash"], str(approved["bytes"])])
    records = [json.loads(line) for line in stdout.decode().splitlines()]
    assert next(row for row in records if row["record"] == "start")["PID"] == pid
    summary = records[-1]
    assert summary["passed"] and summary["failures"] == summary["accepted"] == summary["applicationCalls"] == 0
    assert summary["codeQueries"] == summary["statusQueries"] == summary["tasksCreated"] == summary["tasksReleased"] == 64
    mac["actualMacNative"] = summary
    result = {"candidates": candidates, "sourceSHA256": {path.name: sha(path) for path in source.iterdir()},
        "processes": processes, "nativeSkipped": ["Mac false/integer/true private plugin signatures: previous AMFI launch refusal"],
        "deviceOperations": False, "iOSExecuted": False, "originalVMMExecuted": False,
        "completeBundleRegistration": False, "full27Backend": False, "childLaunches": 0}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    spec = importlib.util.spec_from_file_location("approved_validation", ROOT / "scripts/tests/validate-modern-xpc-approved-code.py")
    validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
    (out / "verification.json").write_text(json.dumps(validator.main(out), indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"), "actualMac": summary,
        "iOSFiles": [row for row in candidates if row["role"] == "ios"]}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
