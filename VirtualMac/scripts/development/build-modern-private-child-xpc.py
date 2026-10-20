#!/usr/bin/env python3
"""Actual scoped child XPC/strict-or-approved gate fixture; local-only execution."""
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
FROZEN = N / "xpc-approved-code-v1/build-v3"
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True,
    "com.apple.private.virtualization.plugin": True}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main(output):
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir()
    for p in (Path(__file__), ROOT / "vz/host/modern_xpc_private_endpoint.c", ROOT / "vz/host/modern_xpc_private_endpoint.h",
              ROOT / "vz/host/modern_xpc_approved_code.h", ROOT / "vz/host/modern_xpc_lwcr_policy.h", ROOT / "scripts/tests/test-modern-private-child-xpc.c", ROOT / "scripts/tests/validate-modern-private-child-xpc.py"):
        shutil.copyfile(p, source / p.name)
    spec = importlib.util.spec_from_file_location("base", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    old = json.loads((FROZEN / "candidate.json").read_text()); candidates, processes = [], []
    def run(label, argv):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try: stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(argv, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout); (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode, "reaped": True})
        assert child.returncode == 0, (label, child.returncode, stdout.decode(errors="replace")[-7000:], stderr.decode(errors="replace")[-7000:])
        return stdout, stderr
    def sign(role, p, rights, label):
        if role == "ios": B.target16(p)
        ent = p.parent / (p.name + ".entitlements"); ent.write_bytes(plistlib.dumps(rights))
        run(label + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", "com.virtualmac.diagnostics.private-child-xpc." + p.name, "--entitlements", str(ent), str(p)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(p)])
        run(label + "-validate", ["xcrun", "dyld_info", "-validate_only", str(p)])
        _, desc = run(label + "-signature", ["codesign", "-dvvv", str(p)])
        return {"role": role, "name": p.name, "path": str(p), "bytes": p.stat().st_size, "sha256": sha(p), "UUID": B.uuid(p.read_bytes()), "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", desc)[1].decode(), "entitlements": rights}
    for role, sdk, target in (("macos", "macosx", "arm64e-apple-macos13"), ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / role; folder.mkdir(); previous = {}
        for name in ("VM27ApprovedCode.dylib", "VM27LWCRPolicy.dylib"):
            original = next(r for r in old["candidates"] if r["role"] == role and r["name"] == name)
            p = folder / name; shutil.copyfile(original["path"], p); assert sha(p) == original["sha256"]
            r = dict(original); r.update({"path": str(p), "source": original["path"], "unchanged": True}); candidates.append(r); previous[name] = r
        sdkPath = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        base = ["xcrun", "clang", "-target", target, "-isysroot", sdkPath, "-fptrauth-abi-version=0", "-std=c11", "-fblocks", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-I", str(source), "-Wl,-no_adhoc_codesign"]
        endpoint = folder / "VM27PrivateEndpoint.dylib"
        run(role + "-endpoint-compile", base + ["-dynamiclib", str(source / "modern_xpc_private_endpoint.c"), "-install_name", "@rpath/VM27PrivateEndpoint.dylib", "-o", str(endpoint)])
        r = sign(role, endpoint, {}, role + "-endpoint"); candidates.append(r); previous[endpoint.name] = r
        macros = []
        for key, name in (("ENDPOINT", endpoint.name), ("APPROVED", "VM27ApprovedCode.dylib"), ("POLICY", "VM27LWCRPolicy.dylib")):
            row = previous[name]; macros += ['#define VM27_' + key + '_SHA256 "' + row["sha256"] + '"', '#define VM27_' + key + '_BYTES ' + str(row["bytes"]) + 'ULL', '#define VM27_' + key + '_UUID "' + row["UUID"] + '"']
        (folder / "modern_xpc_child_pins.h").write_text("\n".join(macros) + "\n")
        probe = folder / "private-child-xpc-probe"
        run(role + "-probe-compile", base + ["-I", str(folder), str(source / "test-modern-private-child-xpc.c"), str(endpoint), str(folder / "VM27ApprovedCode.dylib"), str(folder / "VM27LWCRPolicy.dylib"), "-Wl,-rpath,@executable_path", "-o", str(probe)])
        row = sign(role, probe, RIGHTS if role == "ios" else {}, role + "-probe"); candidates.append(row)
        run(role + "-endpoint-imports", ["xcrun", "dyld_info", "-imports", str(endpoint)])
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)])
        if role == "macos": run("macos-native", [str(probe), row["sha256"], str(row["bytes"]), row["CDHash"]])
    result = {"candidates": candidates, "sourceSHA256": {p.name: sha(p) for p in source.iterdir()}, "processes": processes,
        "deviceOperations": False, "iOSExecuted": False, "originalVMMExecuted": False, "completeBundleRegistration": False,
        "systemModified": False, "bootstrapChanges": 0, "launchdRegistrations": 0}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"), "iOSFiles": [r for r in candidates if r["role"] == "ios"]}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
