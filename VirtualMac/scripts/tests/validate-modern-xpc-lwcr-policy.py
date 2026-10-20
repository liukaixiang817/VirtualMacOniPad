#!/usr/bin/env python3
"""Independent exact policy binaries, strong providers and native message receipts.

Does not launch binaries, connect to any device, or register XPC bundles.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import plistlib
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
POLICY = "@rpath/VM27LWCRPolicy.dylib"
EXPORTS = ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRetain", "VM27LWCRPolicyRelease",
           "VM27LWCRPolicyEvaluateOwnedEntitlements", "VM27LWCRPolicyCheckReceivedMessage",
           "VM27LWCRCopyStats")
BASE_RIGHTS = {"platform-application": True,
    "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True,
    "com.apple.private.amfi.can-execute-cdhash": True}
PLUGIN = "com.apple.private.virtualization.plugin"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


V = load(ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py", "cxa_validation")
P = load(ROOT / "scripts/development/prepare-modern-vmm-cxx-closure.py", "section_ranges")
S = load(ROOT / "scripts/development/verify-macho-code-directory.py", "code_directory")
M = V.M
sha = lambda data: hashlib.sha256(data).hexdigest()
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))


def signed_entitlements(data):
    signature = [(a, z) for c, a, z in M.commands(data) if c == 0x1d]
    assert len(signature) == 1
    offset, size = struct.unpack_from("<II", data, signature[0][0] + 8)
    magic, length, count = struct.unpack_from(">III", data, offset)
    assert magic == 0xfade0cc0 and length <= size and offset + size <= len(data)
    found = []
    for i in range(count):
        kind, relative = struct.unpack_from(">II", data, offset + 12 + 8 * i)
        if kind == 5:
            magic, length = struct.unpack_from(">II", data, offset + relative)
            assert magic == 0xfade7171 and length >= 8 and relative + length <= size
            found.append(plistlib.loads(data[offset + relative + 8:offset + relative + length]))
    assert len(found) <= 1
    return found[0] if found else {}


def native_transcript(build, path, role, variant, pid, wait):
    assert wait == 0 and pid > 1 and role in ("ios", "macos")
    assert variant in ("missing", "false", "integer", "true")
    candidate = json.loads((build / "candidate.json").read_text())
    library = next(row for row in candidate["candidates"] if row["role"] == role and row["name"] == "VM27LWCRPolicy.dylib")
    records = [json.loads(line) for line in Path(path).read_text().splitlines()]
    starts = [row for row in records if row["record"] == "start"]
    assert len(starts) == 1 and starts[0]["PID"] == pid and starts[0]["signatureVariant"] == variant
    assert starts[0]["registrationCalls"] == starts[0]["VMCalls"] == starts[0]["GPUCalls"] == 0
    assert not any(row["record"] in ("failure", "forbiddenImage") for row in records)
    summary = records[-1]; assert summary["record"] == "summary"
    assert summary["passed"] and summary["failures"] == 0 and summary["checks"] >= 1482
    assert summary["tasksCreated"] == summary["tasksReleased"] == 64
    assert summary["copies"] == summary["releases"] == (0 if variant == "missing" else 64)
    assert summary["policiesCreated"] == summary["policiesDestroyed"] == 1
    assert summary["workersJoined"] == 4 and summary["registrationCalls"] == 0 and summary["messageChecks"] == 65
    signatures = [row for row in records if row["record"] == "selfSignature"]
    assert len(signatures) == 1
    signature = signatures[0]
    assert signature["present"] == (variant != "missing")
    assert signature["isBoolean"] == (variant in ("false", "true"))
    assert signature["value"] == (variant == "true")
    positive = signature["validated"] and variant == "true"
    assert summary["acceptedMessages"] == (64 if positive else 0)
    assert summary["rejectedMessages"] == (1 if positive else 65)
    assert summary["nativeTrustedPositiveCovered"] == positive
    providers = [row for row in records if row["record"] == "provider"]
    policy = [row for row in providers if row["symbol"] == "VM27LWCRPolicyCheckReceivedMessage"]
    assert len(policy) == 2 and policy[0] == policy[1]
    assert policy[0]["UUID"] == library["UUID"] and policy[0]["path"].endswith("/VM27LWCRPolicy.dylib")
    assert int(policy[0]["RVA"], 16) > 0
    native = [row for row in providers if row["symbol"].startswith("SecTask")]
    assert len(native) == 4 and len({row["UUID"] for row in native}) == 1
    assert {row["symbol"] for row in native} == {"SecTaskCreateFromSelf", "SecTaskCreateWithXPCMessage", "SecTaskCopyValueForEntitlement", "SecTaskEntitlementsValidated"}
    assert all("/Security.framework/" in row["path"] and len(row["UUID"]) == 32 and int(row["RVA"], 16) > 0 for row in native)
    return {"variant": variant, "role": role, "directChildPID": pid, "observedWaitExit": wait,
            "summary": summary, "nativeSignature": signature, "provider": policy[0], "passed": True,
            "bundleRegistrationProved": False, "originalVMMExecuted": False}


def main(build):
    candidate = json.loads((build / "candidate.json").read_text())
    assert candidate["deviceOperations"] is candidate["nativeIOSExecuted"] is candidate["originalVMMExecuted"] is False
    assert candidate["completeBundleRegistration"] is candidate["full27Backend"] is False
    for name, digest in candidate["sourceSHA256"].items():
        assert sha((build / "source" / name).read_bytes()) == digest
    controls = []; bindings = []
    for row in candidate["candidates"]:
        data = Path(row["path"]).read_bytes()
        assert len(data) == row["bytes"] and sha(data) == row["sha256"]
        code = S.check(data)
        assert len(code) == 1 and code[0]["cdhash"] == row["CDHash"]
        assert canonical(signed_entitlements(data)) == canonical(row["entitlements"])
        assert struct.unpack_from("<I", data, 24)[0] & 0x80
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            command = next(a for c, a, z in M.commands(data) if c == 0x32)
            assert struct.unpack_from("<III", data, command + 8) == (2, 0x100100, 0x100100)
        imports, deps = V.imports(data), M.libraries(data)
        assert all(not r["weak"] and r["ordinal"] > 0 for r in imports)
        assert not any("Virtualization.framework" in dep or "Hypervisor.framework" in dep for dep in deps)
        assert not any("xpc_add_bundle" in item["symbol"] for item in imports)
        if row["name"] == "VM27LWCRPolicy.dylib":
            assert row["entitlements"] == {}
            for name in ("SecTaskCreateWithXPCMessage", "SecTaskCopyValueForEntitlement", "SecTaskEntitlementsValidated"):
                bindings.append({"role": row["role"], **V.require_binding(imports, deps, "_" + name, "/System/Library/Frameworks/Security.framework/Security" if row["role"] == "ios" else "/System/Library/Frameworks/Security.framework/Versions/A/Security")})
            continue
        variant = row["name"].removeprefix("lwcr-policy-probe-")
        assert variant in ("missing", "false", "integer", "true")
        rights = dict(BASE_RIGHTS) if row["role"] == "ios" else {}
        if variant != "missing": rights[PLUGIN] = {"false": False, "integer": 1, "true": True}[variant]
        assert canonical(rights) == canonical(row["entitlements"])
        for name in EXPORTS:
            binding = V.require_binding(imports, deps, "_" + name, POLICY)
            bindings.append({"role": row["role"], "variant": variant, **binding})
            for mutation in ("weak", "flat", "missing", "wrongProvider"):
                changed = [dict(item) for item in imports]; changed_deps = list(deps)
                selected = next(item for item in changed if item["symbol"] == "_" + name)
                if mutation == "weak": selected["weak"] = True
                elif mutation == "flat": selected["ordinal"] = -2
                elif mutation == "missing": changed.remove(selected)
                else: changed_deps[selected["ordinal"] - 1] = "/usr/lib/libSystem.B.dylib"
                try: V.require_binding(changed, changed_deps, "_" + name, POLICY)
                except AssertionError: controls.append({"role": row["role"], "variant": variant, "symbol": name, "mutation": mutation, "rejected": True})
                else: raise AssertionError("invalid binding accepted")
    for role in ("ios", "macos"):
        probes = [Path(row["path"]).read_bytes() for row in candidate["candidates"] if row["role"] == role and row["name"].startswith("lwcr-policy-probe-")]
        assert len(probes) == 4
        reference = P.ranges(M, probes[0]); deps = M.libraries(probes[0]); imports = V.imports(probes[0])
        assert all(P.ranges(M, data) == reference and M.libraries(data) == deps and V.imports(data) == imports for data in probes)
    process = next(row for row in candidate["processes"] if row["label"] == "macos-missing-native")
    assert process["reaped"]
    native = native_transcript(build, build / "macos-missing-native.stdout", "macos", "missing", process["directChildPID"], process["observedWaitExit"])
    assert len(controls) == 192
    return {"passed": True, "exactBinaries": len(candidate["candidates"]), "strongBindings": bindings,
            "negativeBindingControls": controls, "actualMacNegativeMessageFixture": native,
            "iOSExecuted": False, "completeBundleRegistration": False, "full27Backend": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    result = main(Path(sys.argv[1]).resolve())
    print(json.dumps(result, indent=2))
