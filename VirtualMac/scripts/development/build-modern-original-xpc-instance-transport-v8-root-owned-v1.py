#!/usr/bin/env python3
"""New namespace only: relink the iOS CLI, reuse frozen providers and Mac graph."""
from pathlib import Path
import copy
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
PREVIOUS = N / "xpc-original-instance-registration-v8-test-development-v1/build-v4"
PREVIOUS_FREEZE = "052e2b07bb8c1fb1d816872d75d9a182a9210014f22a61a7ae816ba92bcf7263"
OLD_RUNTIME = "/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8"
NEW_RUNTIME = "/var/root/VirtualMac2/testing-root/original-xpc-instance-registration-v8"
CLI = "original-xpc-instance-transport-v8-probe"
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True,
    "com.apple.private.virtualization.plugin": True, "com.apple.private.virtualization": True}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def previous_pins():
    assert sha(PREVIOUS / "freeze.json") == PREVIOUS_FREEZE
    freeze = json.loads((PREVIOUS / "freeze.json").read_text())
    for row in freeze["files"]:
        path = PREVIOUS / row["path"]
        assert not path.is_symlink() and path.stat().st_nlink == 1
        assert path.stat().st_size == row["bytes"] and sha(path) == row["sha256"]
    return len(freeze["files"])


def main(output):
    assert sys.flags.optimize == 0
    assert previous_pins() == 197
    previous = json.loads((PREVIOUS / "candidate.json").read_text())
    out = Path(output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = out / "source"; source.mkdir(mode=0o700)
    for path in (PREVIOUS / "source").iterdir():
        assert path.is_file() and not path.is_symlink()
        shutil.copyfile(path, source / path.name)
        assert sha(path) == sha(source / path.name)
    shutil.copyfile(Path(__file__), source / Path(__file__).name)
    assert sha(source / "modern_xpc_original_instance_transport_v8.c") == "c46af37631569aa700a762af80f3af3b7b4f5165ab71f17de4d6f37f6775adef"
    ios = out / "ios"; ios.mkdir(mode=0o700)
    candidates = [copy.deepcopy(r) for r in previous["candidates"] if r["role"] == "macos"]
    for row in candidates:
        row["externalFrozenRuntimeGraph"] = True
        row["externalFrozenBuild"] = str(PREVIOUS)
    libraries = [r for r in previous["candidates"] if r["role"] == "ios" and r["name"].endswith(".dylib")]
    assert len(libraries) == 7
    for original in libraries:
        path = ios / original["name"]; shutil.copyfile(original["path"], path); path.chmod(0o600)
        assert sha(path) == original["sha256"] and path.stat().st_nlink == 1
        row = copy.deepcopy(original)
        row.update({"path": str(path), "source": original["path"], "unchanged": True, "copiedFromFrozenV4": True})
        candidates.append(row)
    transport = next(r for r in candidates if r["role"] == "ios" and r["name"] == "VM27OriginalV8Transport.dylib")
    assert transport["sha256"] == "5feada3b0a2746e4449de00584391111074f8083702866e3306714364f464284"
    macros = ios / "modern_xpc_factory_pins.h"
    shutil.copyfile(PREVIOUS / "ios/modern_xpc_factory_pins.h", macros)
    assert sha(macros) == sha(PREVIOUS / "ios/modern_xpc_factory_pins.h")
    processes = []
    def run(label, arguments, expected=0):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = child.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            child.kill(); stdout, stderr = child.communicate()
            raise
        (out / (label + ".argv.json")).write_text(json.dumps(arguments, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "directChildPID": child.pid, "observedWaitExit": child.returncode,
            "reaped": True, "expectedExit": expected})
        assert child.returncode == expected, (label, child.returncode, stdout.decode(errors="replace")[-2500:], stderr.decode(errors="replace")[-2500:])
        return stdout, stderr
    arguments = json.loads((PREVIOUS / "ios-probe-compile.argv.json").read_text())
    arguments = [a.replace(str(PREVIOUS), str(out)).replace("-Wl,-rpath," + OLD_RUNTIME, "-Wl,-rpath," + NEW_RUNTIME) for a in arguments]
    assert "-Wl,-rpath," + NEW_RUNTIME in arguments and "-Wl,-rpath," + OLD_RUNTIME not in arguments
    assert all(not a.endswith("modern_xpc_original_instance_transport_v8.c") for a in arguments)
    run("ios-probe-compile", arguments)
    probe = ios / CLI
    spec = importlib.util.spec_from_file_location("target_helper", ROOT / "scripts/development/build-modern-xpc-lwcr-policy.py")
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    helper.target16(probe)
    entitlements = ios / (CLI + ".entitlements")
    shutil.copyfile(PREVIOUS / "ios" / (CLI + ".entitlements"), entitlements)
    assert plistlib.loads(entitlements.read_bytes()) == RIGHTS
    sign = json.loads((PREVIOUS / "ios-probe-sign.argv.json").read_text())
    sign = [a.replace(str(PREVIOUS), str(out)) for a in sign]
    run("ios-probe-sign", sign)
    run("ios-probe-strict", ["codesign", "--verify", "--strict", str(probe)])
    run("ios-probe-validate", ["xcrun", "dyld_info", "-validate_only", str(probe)])
    _, description = run("ios-probe-signature", ["codesign", "-dvvv", str(probe)])
    probeRow = {"role": "ios", "name": CLI, "path": str(probe), "bytes": probe.stat().st_size,
        "sha256": sha(probe), "UUID": helper.uuid(probe.read_bytes()), "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", description)[1].decode(),
        "entitlements": RIGHTS, "relinkedCLIOnly": True, "newRPATH": NEW_RUNTIME}
    app = ios / "VM27RegistrationV8.app"; app.mkdir(mode=0o700)
    info = app / "Info.plist"; shutil.copyfile(PREVIOUS / "ios/VM27RegistrationV8.app/Info.plist", info); info.chmod(0o600)
    assert sha(info) == "c30aa21cf9d37ea26fc82a4ae3f8053c0f9da46213eabc44aeef072c055877cf"
    bundled = app / CLI; shutil.copyfile(probe, bundled); bundled.chmod(0o700)
    assert sha(bundled) == probeRow["sha256"] and bundled.stat().st_nlink == 1
    probeRow.update({"path": str(bundled), "unbundledSignedPath": str(probe), "actualMainBundleInfoPlist": str(info),
        "InfoPlistSHA256": sha(info), "strictVerificationScope": "flat ordinary CLI before bundle copy",
        "overallBundleResourcesSealed": False, "externalInfoIndependentlyHashed": True})
    candidates.append(probeRow)
    run("ios-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)])
    for variant in ("normal", "deny-handshake", "timeout-handshake", "deny-instance", "timeout-instance", "registration-channel-only", "missing-main-bundle", "wrong-type-main-bundle"):
        command = json.loads((PREVIOUS / ("macos-" + variant + "-native.argv.json")).read_text())
        run("macos-" + variant + "-native", command, 78 if variant in ("missing-main-bundle", "wrong-type-main-bundle") else 0)
    result = {"candidates": candidates, "sourceSHA256": {p.name: sha(p) for p in source.iterdir()}, "processes": processes,
        "deviceOperations": False, "iOSExecuted": False, "originalVMMExecuted": False, "completeBundleRegistration": False,
        "systemModified": False, "bootstrapChanges": 0, "launchdRegistrations": 0, "MacNativePositiveCovered": False,
        "MacActualRegistryComponentPositiveCovered": True, "actualMainBundleMetadataRequired": True, "MacNativeStrictDenialCovered": True,
        "originalVMWireProtocolExecuted": False, "newIOSGraph": str(out), "actualMacGraph": str(PREVIOUS), "actualMacGraphExternalFrozen": True,
        "previousFreezeSHA256": PREVIOUS_FREEZE, "previous197PinsUnchangedBeforeAndAfter": previous_pins() == 197,
        "providersRecompiledOrResigned": False, "onlyIOSCLIWasRelinkedAndSigned": True,
        "flatCLIStrictVerified": True, "overallBundleResourcesSealed": False}
    (out / "candidate.json").write_text(json.dumps(result, indent=2) + "\n")
    manifest = copy.deepcopy(json.loads((PREVIOUS / "diagnostic-readiness.json").read_text()))
    manifest["candidateSHA256"] = sha(out / "candidate.json")
    manifest["fixedPrivateRuntimeRoot"] = NEW_RUNTIME
    manifest["futureRootOwnedParent"] = {"path": "/var/root/VirtualMac2/testing-root", "ownerUID": 0, "ownerGID": 0, "mode": "0700", "createdByRootOnly": True}
    manifest["oldUnsafeParentMustNotBeModifiedOrUsed"] = "/var/root/VirtualMac2/testing"
    manifest["actualMacGraph"] = {"path": str(PREVIOUS), "freezeSHA256": PREVIOUS_FREEZE, "externalFrozenV4": True, "newActualReceiptsSavedIn": str(out)}
    manifest["newIOSGraph"] = str(out)
    manifest["strictSignatureScope"] = {"flatOrdinaryCLIActualStrictExit": 0, "externalInfoIndependentSHA256": sha(info),
        "bundleResourcesSealed": False, "bundlePathStrictSuccessClaimed": False, "directIPCCodeOnlyDiagnostic": True,
        "rootOwnershipAndMetadataHashGuardsRequired": True}
    byName = {r["name"]: r for r in candidates if r["role"] == "ios"}
    for row in manifest["orderedPackageFiles"]:
        name = Path(row["bundleRelativePath"]).name
        if name == "Info.plist":
            row.update({"sourcePath": str(info), "bytes": info.stat().st_size, "sha256": sha(info)})
        else:
            actual = byName[name]
            row.update({key: actual[key] for key in ("bytes", "sha256", "UUID", "CDHash")})
            row["sourcePath"] = actual["path"]
    packageDigest = hashlib.sha256()
    for row in manifest["orderedPackageFiles"]:
        packageDigest.update(Path(row["sourcePath"]).read_bytes())
    manifest["orderedPackageSHA256"] = packageDigest.hexdigest()
    manifest["exactArgvByMode"] = {mode: ["VM27RegistrationV8.app/" + CLI, probeRow["sha256"], str(probeRow["bytes"]), probeRow["CDHash"], mode] for mode in manifest["exactArgvByMode"]}
    for row in manifest["dynamicFixture"]["files"]:
        if row.get("byteExactCopyOfCLI"):
            row["sha256"] = probeRow["sha256"]
    manifest["parser"]["sha256"] = sha(source / "read-modern-original-xpc-instance-registration-v8-mac.py")
    (out / "diagnostic-readiness.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(out), "candidateSHA256": sha(out / "candidate.json"),
        "diagnosticReadinessSHA256": sha(out / "diagnostic-readiness.json"), "orderedPackageSHA256": manifest["orderedPackageSHA256"],
        "actualMacRuns": 8, "unchangedIOSProviders": 7, "onlyIOSCLIWasRelinkedAndSigned": True}))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
