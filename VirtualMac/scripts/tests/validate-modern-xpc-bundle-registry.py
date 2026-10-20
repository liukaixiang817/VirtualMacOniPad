#!/usr/bin/env python3
"""Read-only independent binary/binding and actual owned-registry receipts.

No child launches, device access, service registration or inferred native exit.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("lwcr_validator", ROOT / "scripts/tests/validate-modern-xpc-lwcr-policy.py")
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)
V, M, S = L.V, L.M, L.S
REGISTRY = "@rpath/VM27BundleRegistry.dylib"
POLICY = "@rpath/VM27LWCRPolicy.dylib"
REGISTRY_API = ("VM27BundleRegistryCreate", "VM27BundleRegistryRelease", "VM27BundleRegistryRegister",
    "VM27BundleRegistryCopyServicePlan", "VM27PrivateServicePlanRelease", "VM27PrivateServicePlanCopyInfo",
    "VM27PrivateServicePlanVerify", "VM27PrivateServicePlanCheckReceivedMessage", "VM27BundleRegistryCopyStats")
POLICY_USED = ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRetain", "VM27LWCRPolicyRelease", "VM27LWCRPolicyCheckReceivedMessage")
sha = lambda data: hashlib.sha256(data).hexdigest()


def defined_names(data):
    command = [at for kind, at, size in M.commands(data) if kind == 2]
    assert len(command) == 1
    offset, count, strings, size = struct.unpack_from("<IIII", data, command[0] + 8)
    assert offset + count * 16 <= len(data) and strings + size <= len(data)
    names = []
    for i in range(count):
        index, kind, section, descriptor, value = struct.unpack_from("<IBBHQ", data, offset + i * 16)
        if kind & 0xe0 or not kind & 1 or kind & 0xe != 0xe: continue
        assert index < size
        end = data.index(0, strings + index, strings + size)
        names.append(data[strings + index:end].decode())
    return names


def native_transcript(build, path, role, pid, wait):
    assert role in ("ios", "macos") and pid > 1 and wait == 0
    candidate = json.loads((build / "candidate.json").read_text())
    files = {row["name"]: row for row in candidate["candidates"] if row["role"] == role}
    logs = [json.loads(line) for line in Path(path).read_text().splitlines()]
    starts = [row for row in logs if row["record"] == "start"]
    assert len(starts) == 1 and starts[0]["PID"] == pid
    for key in ("VMCalls", "GPUCalls", "launchdRegistrations", "childLaunches"): assert starts[0][key] == 0
    assert not any(row["record"] in ("failure", "forbiddenImage") for row in logs)
    summary = logs[-1]
    assert summary["record"] == "summary" and summary["passed"] is True and summary["checks"] >= 1119 and summary["failures"] == 0
    assert summary["registrations"] == summary["services"] == 1
    assert summary["plansCreated"] == summary["plansDestroyed"] == 257
    assert summary["tasksCreated"] == summary["tasksReleased"] == summary["receivedMessages"] == 64
    assert summary["messageChecks"] == 65 and summary["applicationCalls"] == 0 and summary["workersJoined"] == 4
    assert summary["ownTemporaryRemoved"] is True and summary["completeBundleRegistration"] is False
    assert summary["childLaunches"] == summary["launchdRegistrations"] == 0
    providers = [row for row in logs if row["record"] == "provider"]
    assert len(providers) == 6
    for name, library in (("VM27BundleRegistryRegister", "VM27BundleRegistry.dylib"),
                          ("VM27PrivateServicePlanCheckReceivedMessage", "VM27BundleRegistry.dylib"),
                          ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib")):
        actual = [dict(row) for row in providers if row["symbol"] == name]
        assert len(actual) == 2 and {row.pop("phase") for row in actual} == {"before", "after"}
        assert actual[0] == actual[1]
        record, expected = actual[0], files[library]
        assert record["UUID"] == expected["UUID"] and record["SHA256"] == expected["sha256"]
        assert record["path"].endswith("/" + library) and int(record["RVA"], 16) > 0
    registered = [row for row in logs if row["record"] == "registeredService"]
    assert len(registered) == 1
    entry, executable = registered[0], files["bundle-registry-probe"]
    assert entry["service"] == "com.virtualmac.diagnostics.owned.service" and entry["flags"] == 2
    assert entry["codeSHA256"] == executable["sha256"] and entry["codeUUID"] == executable["UUID"] and entry["codeBytes"] == executable["bytes"]
    return {"passed": True, "role": role, "directChildPID": pid, "observedWaitExit": wait,
            "summary": summary, "registeredService": entry, "providers": providers,
            "nativeAuthorizedPositiveCovered": False, "childLaunches": 0,
            "completeBundleRegistration": False, "originalVMMExecuted": False}


def main(build):
    candidate = json.loads((build / "candidate.json").read_text())
    for key in ("deviceOperations", "iOSExecuted", "originalVMMExecuted", "completeBundleRegistration", "full27Backend"): assert candidate[key] is False
    assert candidate["childLaunches"] == candidate["launchdRegistrations"] == 0
    for name, digest in candidate["sourceSHA256"].items(): assert sha((build / "source" / name).read_bytes()) == digest
    controls, bindings = [], []
    assert len(candidate["candidates"]) == 6
    for row in candidate["candidates"]:
        data = Path(row["path"]).read_bytes()
        assert len(data) == row["bytes"] and sha(data) == row["sha256"]
        cds = S.check(data); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
        assert L.canonical(L.signed_entitlements(data)) == L.canonical(row["entitlements"])
        uuid = [data[at + 8:at + 24].hex() for kind, at, size in M.commands(data) if kind == 0x1b]
        assert uuid == [row["UUID"]] and struct.unpack_from("<I", data, 24)[0] & 0x80
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            at = next(at for kind, at, size in M.commands(data) if kind == 0x32)
            assert struct.unpack_from("<III", data, at + 8) == (2, 0x100100, 0x100100)
        imports, deps = V.imports(data), M.libraries(data)
        assert all(not item["weak"] and item["ordinal"] > 0 for item in imports)
        assert not any(any(name in dep for name in ("Virtualization.framework", "Hypervisor.framework", "ParavirtualizedGraphics.framework", "VirtualMachine.xpc")) for dep in deps)
        assert not any("xpc_add_bundle" in item["symbol"] for item in imports + [{"symbol": name} for name in defined_names(data)])
        if row["name"] == "VM27LWCRPolicy.dylib":
            assert row["unchanged"] is True and sha(Path(row["source"]).read_bytes()) == row["sha256"] and row["entitlements"] == {}
            continue
        if row["name"] == "VM27BundleRegistry.dylib":
            assert row["entitlements"] == {} and {"_" + name for name in REGISTRY_API} <= set(defined_names(data))
            required = [(name, POLICY) for name in POLICY_USED]
        else:
            assert row["name"] == "bundle-registry-probe"
            rights = L.BASE_RIGHTS if row["role"] == "ios" else {}
            assert L.canonical(rights) == L.canonical(row["entitlements"])
            required = [(name, REGISTRY) for name in REGISTRY_API] + [(name, POLICY) for name in ("VM27LWCRCopyStats", "VM27LWCRPolicyCheckReceivedMessage")]
        for name, provider in required:
            bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            for mutation in ("weak", "flat", "missing", "wrongProvider"):
                modified = [dict(item) for item in imports]; changed_deps = list(deps)
                selected = next(item for item in modified if item["symbol"] == "_" + name)
                if mutation == "weak": selected["weak"] = True
                elif mutation == "flat": selected["ordinal"] = -2
                elif mutation == "missing": modified.remove(selected)
                else: changed_deps[selected["ordinal"] - 1] = "/usr/lib/libSystem.B.dylib"
                try: V.require_binding(modified, changed_deps, "_" + name, provider)
                except AssertionError: controls.append({"role": row["role"], "file": row["name"], "symbol": name, "mutation": mutation, "rejected": True})
                else: raise AssertionError("invalid binding accepted")
    process = next(row for row in candidate["processes"] if row["label"] == "macos-owned-native")
    assert process["reaped"] is True
    native = native_transcript(build, build / "macos-owned-native.stdout", "macos", process["directChildPID"], process["observedWaitExit"])
    assert len(bindings) == 30 and len(controls) == 120
    return {"passed": True, "exactBinaries": 6, "strongBindings": bindings,
            "negativeBindingControls": controls, "actualMacOwnedRegistryFixture": native,
            "iOSExecuted": False, "completeBundleRegistration": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
