#!/usr/bin/env python3
"""Build and locally execute actual owned child port inheritance, no device."""
from pathlib import Path
import importlib.util
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main(output):
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir()
    for path in (Path(__file__), ROOT / "scripts/tests/test-modern-private-child-port.c", ROOT / "scripts/tests/validate-modern-private-child-port.py"):
        shutil.copyfile(path, source / path.name)
    spec = importlib.util.spec_from_file_location("base", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    spec = importlib.util.spec_from_file_location("validator", ROOT / "scripts/tests/validate-modern-private-child-port.py")
    V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
    processes, candidates = [], []
    def run(label, argv):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try: stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(argv, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout); (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode, "reaped": True})
        assert child.returncode == 0, (label, child.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace"))
        return stdout, stderr
    for role, sdk, target in (("macos", "macosx", "arm64e-apple-macos13"), ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / role; folder.mkdir()
        sdkPath = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        probe = folder / "private-child-port-probe"
        run(role + "-compile", ["xcrun", "clang", "-target", target, "-isysroot", sdkPath, "-fptrauth-abi-version=0", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-Wl,-no_adhoc_codesign", str(source / "test-modern-private-child-port.c"), "-o", str(probe)])
        if role == "ios": B.target16(probe)
        rights = V.RIGHTS if role == "ios" else {}
        ent = folder / "probe.entitlements"; ent.write_bytes(plistlib.dumps(rights))
        run(role + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", "com.virtualmac.diagnostics.private-child-port", "--entitlements", str(ent), str(probe)])
        run(role + "-strict", ["codesign", "--verify", "--strict", str(probe)])
        run(role + "-validate", ["xcrun", "dyld_info", "-validate_only", str(probe)])
        _, desc = run(role + "-signature", ["codesign", "-dvvv", str(probe)])
        row = {"role": role, "name": probe.name, "path": str(probe), "bytes": probe.stat().st_size, "sha256": sha(probe), "UUID": B.uuid(probe.read_bytes()), "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", desc)[1].decode(), "entitlements": rights}
        candidates.append(row)
        if role == "macos": run("macos-native", [str(probe), row["sha256"], str(row["bytes"])])
    result = {"candidates": candidates, "sourceSHA256": {p.name: sha(p) for p in source.iterdir()}, "processes": processes,
        "deviceOperations": False, "iOSExecuted": False, "originalVMMExecuted": False, "crossProcessXPCProved": False, "bootstrapChanges": 0, "launchdRegistrations": 0}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    verification = V.main(out); (out / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"), "actualMac": verification["actualMacChildInheritance"], "iOSFiles": [r for r in candidates if r["role"] == "ios"]}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
