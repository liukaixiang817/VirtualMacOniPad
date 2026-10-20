#!/usr/bin/env python3
"""Read-only approved-code signatures, exact bindings and actual XPC receipts."""
from pathlib import Path
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("registry_validator", ROOT / "scripts/tests/validate-modern-xpc-bundle-registry.py")
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
L, V, M, S = R.L, R.V, R.M, R.S
APPROVED = "@rpath/VM27ApprovedCode.dylib"
POLICY = "@rpath/VM27LWCRPolicy.dylib"
API = ("VM27ApprovedCodeInspectBytes", "VM27ApprovedCodePolicyCreate", "VM27ApprovedCodePolicyRelease",
       "VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCodeCopyStats")
VARIANTS = ("missing", "false", "integer", "true", "true-unapproved")
sha = R.sha


def native_transcript(build, path, role, variant, pid, wait):
    assert role in ("ios", "macos") and variant in VARIANTS and pid > 1 and wait == 0
    c = json.loads((build / "candidate.json").read_text())
    files = {r["name"]: r for r in c["candidates"] if r["role"] == role}
    approved = next(r for r in c["candidates"] if r["role"] == "ios" and r["name"] == "approved-code-probe-true")
    logs = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert not any(row["record"] in ("failure", "forbiddenImage") for row in logs)
    starts = [r for r in logs if r["record"] == "start"]
    assert len(starts) == 1
    start = starts[0]; assert start["PID"] == pid and start["signatureVariant"] == variant
    assert start["selfCDHash"] == files["approved-code-probe-" + variant]["CDHash"] and start["approvedCDHash"] == approved["CDHash"]
    for field in ("VMCalls", "GPUCalls", "childLaunches", "registrationCalls"): assert start[field] == 0
    native = [r for r in logs if r["record"] == "nativeIdentity"]
    assert len(native) == 1
    identity = native[0]; positive = role == "ios" and variant == "true"
    assert identity["auditPID"] == pid and identity["auditPIDVersion"] > 0
    assert identity["kernelCDHash"] == start["selfCDHash"]
    assert identity["codeHashMatched"] is positive and identity["explicitApprovedCodeAccepted"] is positive
    assert identity["nativeBooleanTrue"] is (variant in ("true", "true-unapproved"))
    if positive: assert identity["dynamicCodeValid"] is True and identity["codeStatus"] & 1
    summary = logs[-1]
    assert summary["record"] == "summary" and summary["passed"] is True and summary["checks"] >= 832 and summary["failures"] == 0
    assert summary["messageChecks"] == 66 and summary["codeQueries"] == summary["statusQueries"] == 64
    assert summary["tasksCreated"] == summary["tasksReleased"] == 64
    assert summary["approvedPoliciesCreated"] == summary["approvedPoliciesDestroyed"] == 1
    assert summary["workersJoined"] == 4 and summary["accepted"] == summary["applicationCalls"] == (64 if positive else 0)
    assert summary["rejected"] == (2 if positive else 66) and summary["explicitApprovedCodePositiveCovered"] is positive
    assert summary["strictNativePositiveCovered"] is (identity["entitlementsValidated"] and identity["nativeBooleanTrue"])
    assert summary["ownTemporaryRemoved"] is True and summary["childLaunches"] == 0 and summary["completeBundleRegistration"] is False
    providers = [r for r in logs if r["record"] == "provider"]; assert len(providers) == 4
    for name, library in (("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"), ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib")):
        pair = [dict(r) for r in providers if r["symbol"] == name]
        assert len(pair) == 2 and {r.pop("phase") for r in pair} == {"before", "after"} and pair[0] == pair[1]
        assert pair[0]["UUID"] == files[library]["UUID"] and pair[0]["SHA256"] == files[library]["sha256"]
        assert pair[0]["path"].endswith("/" + library) and int(pair[0]["RVA"], 16) > 0
    return {"passed": True, "role": role, "variant": variant, "directChildPID": pid, "observedWaitExit": wait,
        "summary": summary, "nativeIdentity": identity, "providers": providers,
        "explicitApprovedCodePositiveCovered": positive, "completeBundleRegistration": False, "originalVMMExecuted": False}


def main(build):
    c = json.loads((build / "candidate.json").read_text())
    for field in ("deviceOperations", "iOSExecuted", "originalVMMExecuted", "completeBundleRegistration", "full27Backend"): assert c[field] is False
    assert c["childLaunches"] == 0 and len(c["candidates"]) == 14
    for name, digest in c["sourceSHA256"].items(): assert sha((build / "source" / name).read_bytes()) == digest
    bindings, controls = [], []
    for row in c["candidates"]:
        data = Path(row["path"]).read_bytes()
        assert len(data) == row["bytes"] and sha(data) == row["sha256"]
        cds = S.check(data); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
        assert L.canonical(L.signed_entitlements(data)) == L.canonical(row["entitlements"])
        assert [data[at + 8:at + 24].hex() for kind, at, size in M.commands(data) if kind == 0x1b] == [row["UUID"]]
        assert struct.unpack_from("<I", data, 24)[0] & 0x80
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            at = next(at for kind, at, size in M.commands(data) if kind == 0x32)
            assert struct.unpack_from("<III", data, at + 8) == (2, 0x100100, 0x100100)
        imports, deps = V.imports(data), M.libraries(data)
        assert all(not r["weak"] and r["ordinal"] > 0 for r in imports)
        assert not any(any(name in dep for name in ("Virtualization.framework", "Hypervisor.framework", "ParavirtualizedGraphics.framework", "VirtualMachine.xpc")) for dep in deps)
        assert not any("xpc_add_bundle" in r["symbol"] for r in imports + [{"symbol": name} for name in R.defined_names(data)])
        if row["name"] == "VM27LWCRPolicy.dylib":
            assert row["unchanged"] is True and row["entitlements"] == {} and sha(Path(row["source"]).read_bytes()) == row["sha256"]
            continue
        if row["name"] == "VM27ApprovedCode.dylib":
            assert row["entitlements"] == {} and {"_" + n for n in API} <= set(R.defined_names(data))
            required = [(n, POLICY) for n in ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRelease", "VM27LWCRPolicyCheckReceivedMessage")]
            required += [(n, "/usr/lib/libSystem.B.dylib") for n in ("csops_audittoken", "xpc_dictionary_get_audit_token")]
        else:
            variant = row["name"].removeprefix("approved-code-probe-"); assert variant in VARIANTS
            rights = dict(L.BASE_RIGHTS) if row["role"] == "ios" else {}
            if variant != "missing": rights[L.PLUGIN] = {"false": False, "integer": 1, "true": True, "true-unapproved": True}[variant]
            assert L.canonical(rights) == L.canonical(row["entitlements"])
            required = [(n, APPROVED) for n in API] + [(n, POLICY) for n in ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRCopyStats")]
        for name, provider in required:
            bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            for mutation in ("weak", "flat", "missing", "wrongProvider"):
                changed = [dict(r) for r in imports]; changed_deps = list(deps)
                selected = next(r for r in changed if r["symbol"] == "_" + name)
                if mutation == "weak": selected["weak"] = True
                elif mutation == "flat": selected["ordinal"] = -2
                elif mutation == "missing": changed.remove(selected)
                else: changed_deps[selected["ordinal"] - 1] = "/VM27/NonexistentProvider.dylib"
                try: V.require_binding(changed, changed_deps, "_" + name, provider)
                except AssertionError: controls.append({"role": row["role"], "file": row["name"], "symbol": name, "mutation": mutation, "rejected": True})
                else: raise AssertionError("invalid binding accepted")
    for role in ("ios", "macos"):
        data = [Path(r["path"]).read_bytes() for r in c["candidates"] if r["role"] == role and r["name"].startswith("approved-code-probe-")]
        assert len(data) == 5
        assert all(L.P.ranges(M, d) == L.P.ranges(M, data[0]) and V.imports(d) == V.imports(data[0]) and M.libraries(d) == M.libraries(data[0]) for d in data)
    process = next(r for r in c["processes"] if r["label"] == "macos-missing-native")
    assert process["reaped"] is True
    native = native_transcript(build, build / "macos-missing-native.stdout", "macos", "missing", process["directChildPID"], process["observedWaitExit"])
    assert len(bindings) == 80 and len(controls) == 320
    return {"passed": True, "exactBinaries": 14, "strongBindings": bindings, "negativeBindingControls": controls,
        "actualMacNegativeMessageFixture": native, "iOSExecuted": False, "completeBundleRegistration": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
