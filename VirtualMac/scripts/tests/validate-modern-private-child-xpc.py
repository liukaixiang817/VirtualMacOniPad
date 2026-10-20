#!/usr/bin/env python3
"""Read-only exact strong providers and actual parent/child XPC receipts.

This validates transport and per-message strict/explicit-approved-code gates;
it does not claim bundle registration, original API or original VMM execution.
"""
from pathlib import Path
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
s = importlib.util.spec_from_file_location("approved_validator", ROOT / "scripts/tests/validate-modern-xpc-approved-code.py")
A = importlib.util.module_from_spec(s); s.loader.exec_module(A)
R, L, V, M, S = A.R, A.L, A.V, A.M, A.S
sha = R.sha
ENDPOINT = "@rpath/VM27PrivateEndpoint.dylib"
ENDPOINT_API = ("VM27PrivateEndpointCopyABI", "VM27PrivateEndpointCopySendRight", "VM27PrivateEndpointConnectSendRight")
RIGHTS = dict(L.BASE_RIGHTS); RIGHTS[L.PLUGIN] = True
SYSTEM = "/usr/lib/libSystem.B.dylib"


def symbol_rva(data, symbol):
    at = next(at for kind, at, size in M.commands(data) if kind == 2)
    offset, count, strings, size = struct.unpack_from("<IIII", data, at + 8)
    assert offset + count * 16 <= len(data) and strings + size <= len(data)
    found = []
    for index in range(count):
        name, kind, section, descriptor, value = struct.unpack_from("<IBBHQ", data, offset + index * 16)
        if kind & 0xe0 or not kind & 1 or kind & 0xe != 0xe: continue
        assert name < size
        end = data.index(0, strings + name, strings + size)
        if data[strings + name:end].decode() == "_" + symbol: found.append(value)
    assert len(found) == 1
    text = [at for kind, at, size in M.commands(data) if kind == 0x19 and data[at + 8:at + 24].rstrip(b"\0") == b"__TEXT"]
    assert len(text) == 1
    return found[0] - struct.unpack_from("<Q", data, text[0] + 24)[0]


def native_transcript(build, path, role, pid, wait):
    assert role in ("ios", "macos") and pid > 1 and wait == 0
    candidate = json.loads((build / "candidate.json").read_text())
    files = {r["name"]: r for r in candidate["candidates"] if r["role"] == role}
    executable = files["private-child-xpc-probe"]
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert not any(r["record"] in ("failure", "forbiddenImage") for r in rows)
    def one(record, process=None):
        values = [r for r in rows if r["record"] == record and (process is None or r["role"] == process)]
        assert len(values) == 1
        return values[0]
    parent, childStart, spawn = one("start", "parent"), one("start", "child"), one("spawn")
    child, positive = childStart["PID"], role == "ios"
    assert parent["PID"] == spawn["parentPID"] == pid and spawn["spawnResult"] == 0
    assert child > 1 and child != pid and spawn["childPID"] == child
    assert childStart["UID"] == parent["UID"]
    for start in (parent, childStart):
        assert start["selfCDHash"] == executable["CDHash"] and start["signedPluginBooleanTrue"] is positive
        for field in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert start[field] == 0
    for process in ("parent", "child"):
        abi = one("endpointABI", process)
        assert abi["exact"] is True and abi["UUID"] == ("7a0ca8d2728537ddae972efaa1de763e" if positive else "0791121fb5fc3f84bf04115e86d2d882")
        assert int(abi["RVA"], 16) > 0
    assert one("endpointABI", "parent")["RVA"] == one("endpointABI", "child")["RVA"]
    negatives = one("endpointNegativeControls")
    assert negatives["checks"] == 12 and negatives["failures"] == 0 and negatives["allRefused"] is True and negatives["ownObjectsReleased"] is True
    providers = [r for r in rows if r["record"] == "provider"]
    assert len(providers) == 12
    for symbol, library in (("VM27PrivateEndpointConnectSendRight", "VM27PrivateEndpoint.dylib"),
                            ("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"),
                            ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib")):
        records = [dict(r) for r in providers if r["symbol"] == symbol]
        assert len(records) == 4 and {(r.pop("role"), r.pop("phase")) for r in records} == {(p, phase) for p in ("parent", "child") for phase in ("before", "after")}
        assert all(r == records[0] for r in records)
        expected = files[library]
        assert records[0]["SHA256"] == expected["sha256"] and records[0]["UUID"] == expected["UUID"]
        expectedPath = ("/private/var/root/VirtualMac2/testing/private-child-xpc-v1/" + library) if positive else expected["path"]
        assert records[0]["path"] == expectedPath
        assert int(records[0]["RVA"], 16) == symbol_rva(Path(expected["path"]).read_bytes(), symbol) > 0
    identity = one("nativeChildIdentity")
    assert identity["childPID"] == child and identity["childPIDVersion"] > 0
    assert identity["nativeBooleanTrue"] is positive and identity["explicitApproved"] is positive
    if positive:
        assert identity["kernelCDHash"] == executable["CDHash"] and identity["codeStatus"] & 1
        # Strict native result is preserved in its own field, never forced true.
        assert type(identity["strictValidated"]) is bool
    else: assert identity["kernelCDHash"] == "" and identity["codeStatus"] == 0 and identity["strictValidated"] is False
    childSummary, summary = one("childSummary"), rows[-1]
    assert childSummary["PID"] == child and childSummary["passed"] is True and childSummary["checks"] >= 222 and childSummary["failures"] == 0
    assert childSummary["realReplies"] == 65 and childSummary["applicationAccepted"] == (64 if positive else 0) and childSummary["deniedReplies"] == (1 if positive else 65)
    assert childSummary["ownedObjectsReleased"] is True
    assert summary["record"] == "summary" and summary["parentPID"] == pid and summary["spawnedChildPID"] == child
    assert summary["observedChildWaitExit"] == 0 and summary["childAbsent"] is True and summary["passed"] is True and summary["checks"] >= 316 and summary["failures"] == 0
    assert summary["realXPCMessages"] == 65 and summary["tasksCreated"] == summary["tasksReleased"] == 65
    assert summary["applicationCalls"] == (64 if positive else 0) and summary["protocolRefused"] == (1 if positive else 0) and summary["approvedCodeQueries"] == (65 if positive else 0)
    assert summary["parentRegisteredPortsUnchanged"] is True and summary["ownObjectsReleased"] is True
    assert summary["bootstrapChanges"] == summary["launchdRegistrations"] == 0 and summary["completeBundleRegistration"] is False
    return {"passed": True, "role": role, "directParentPID": pid, "observedParentWaitExit": wait,
        "spawnedChildPID": child, "observedChildWaitExit": 0, "childAbsent": True,
        "childSummary": childSummary, "summary": summary, "nativeChildIdentity": identity,
        "providers": providers, "endpointNegativeControls": negatives,
        "crossProcessXPCProved": True, "explicitApprovedCodePositiveCovered": positive,
        "strictNativeValidated": identity["strictValidated"], "completeBundleRegistration": False, "originalVMMExecuted": False}


def main(build):
    c = json.loads((build / "candidate.json").read_text())
    for field in ("deviceOperations", "iOSExecuted", "originalVMMExecuted", "completeBundleRegistration", "systemModified"): assert c[field] is False
    assert c["bootstrapChanges"] == c["launchdRegistrations"] == 0 and len(c["candidates"]) == 8
    for name, digest in c["sourceSHA256"].items(): assert sha((build / "source" / name).read_bytes()) == digest
    bindings, controls = [], []
    for row in c["candidates"]:
        data = Path(row["path"]).read_bytes(); assert len(data) == row["bytes"] and sha(data) == row["sha256"]
        cds = S.check(data); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
        expected = RIGHTS if row["role"] == "ios" and row["name"] == "private-child-xpc-probe" else {}
        assert L.canonical(L.signed_entitlements(data)) == L.canonical(row["entitlements"]) == L.canonical(expected)
        assert [data[at + 8:at + 24].hex() for kind, at, size in M.commands(data) if kind == 0x1b] == [row["UUID"]]
        assert struct.unpack_from("<I", data, 24)[0] & 0x80
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            at = next(at for kind, at, size in M.commands(data) if kind == 0x32)
            assert struct.unpack_from("<III", data, at + 8) == (2, 0x100100, 0x100100)
        imports, deps = V.imports(data), M.libraries(data)
        assert all(r["ordinal"] > 0 and not r["weak"] for r in imports)
        assert not any(any(n in r["symbol"] for n in ("task_for_pid", "task_set_special_port", "bootstrap_register", "mach_ports_register", "xpc_add_bundle")) for r in imports + [{"symbol": n} for n in R.defined_names(data)])
        assert not any(any(n in dep for n in ("Virtualization.framework", "Hypervisor.framework", "ParavirtualizedGraphics.framework", "VirtualMachine.xpc")) for dep in deps)
        if row["name"] in ("VM27ApprovedCode.dylib", "VM27LWCRPolicy.dylib"):
            assert row["unchanged"] is True and sha(Path(row["source"]).read_bytes()) == row["sha256"]
            continue
        if row["name"] == "VM27PrivateEndpoint.dylib":
            assert deps == [SYSTEM] and {"_" + n for n in ENDPOINT_API} <= set(R.defined_names(data))
            required = [(n, SYSTEM) for n in ("xpc_endpoint_create", "xpc_get_type", "xpc_connection_create_from_endpoint", "mach_port_type", "mach_port_get_refs", "mach_port_mod_refs", "mach_port_deallocate")]
        else:
            assert row["name"] == "private-child-xpc-probe" and set(deps) == {ENDPOINT, A.APPROVED, A.POLICY, SYSTEM}
            required = [(n, ENDPOINT) for n in ENDPOINT_API] + [(n, A.APPROVED) for n in A.API]
            required += [(n, A.POLICY) for n in ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRelease", "VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRCopyStats")]
            required += [(n, SYSTEM) for n in ("posix_spawnattr_set_registered_ports_np", "posix_spawn", "waitpid", "mach_ports_lookup", "xpc_dictionary_get_audit_token", "xpc_connection_send_message_with_reply")]
        for name, provider in required:
            bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            for mutation in ("weak", "flat", "missing", "wrongProvider"):
                modified = [dict(r) for r in imports]; changed = list(deps); selected = next(r for r in modified if r["symbol"] == "_" + name)
                if mutation == "weak": selected["weak"] = True
                elif mutation == "flat": selected["ordinal"] = -2
                elif mutation == "missing": modified.remove(selected)
                else: changed[selected["ordinal"] - 1] = "/VM27/MissingProvider.dylib"
                try: V.require_binding(modified, changed, "_" + name, provider)
                except AssertionError: controls.append({"role": row["role"], "file": row["name"], "symbol": name, "mutation": mutation, "rejected": True})
                else: raise AssertionError("invalid binding accepted")
    p = next(r for r in c["processes"] if r["label"] == "macos-native"); assert p["reaped"] is True
    assert len(bindings) == 50 and len(controls) == 200
    return {"passed": True, "exactBinaries": 8, "strongBindings": bindings, "negativeBindingControls": controls,
        "actualMacCrossProcessXPC": native_transcript(build, build / "macos-native.stdout", "macos", p["directChildPID"], p["observedWaitExit"]),
        "iOSExecuted": False, "completeBundleRegistration": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
