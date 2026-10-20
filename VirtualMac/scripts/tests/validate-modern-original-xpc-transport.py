#!/usr/bin/env python3
"""Exact original27 create/main transport ABI and real bounded native receipts."""
from pathlib import Path
import importlib.util
import json
import re
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
s = importlib.util.spec_from_file_location("xpc_validator", ROOT / "scripts/tests/validate-modern-private-child-xpc.py")
X = importlib.util.module_from_spec(s); s.loader.exec_module(X)
A, R, L, V, M, S, sha = X.A, X.R, X.L, X.V, X.M, X.S, X.sha
FACTORY = "original-xpc-transport-probe"
TRANSPORT = "@rpath/VM27OriginalTransport.dylib"
CONSUMER, REGISTRY, ENDPOINT = "@rpath/VM27PrivateConsumer.dylib", "@rpath/VM27BundleRegistry.dylib", X.ENDPOINT
VARIANTS = ("normal", "deny-handshake", "timeout-handshake")


def native_transcript(build, path, role, variant, pid, wait):
    assert role in ("ios", "macos") and variant in VARIANTS and pid > 1 and wait == 0
    c = json.loads((build / "candidate.json").read_text()); files = {r["name"]: r for r in c["candidates"] if r["role"] == role}; binary = files[FACTORY]
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert not any(r["record"] in ("failure", "forbiddenImage") for r in rows)
    def one(name, process=None):
        values = [r for r in rows if r["record"] == name and (process is None or r["role"] == process)]; assert len(values) == 1; return values[0]
    parent, childStart, spawn = one("start", "parent"), one("start", "child"), one("spawn")
    child, positive, normal, denied, timeout = childStart["PID"], role == "ios", variant == "normal", variant == "deny-handshake", variant == "timeout-handshake"
    assert parent["PID"] == spawn["parentPID"] == pid and child != pid and child > 1 and spawn["childPID"] == child and spawn["spawnResult"] == 0
    assert parent["UID"] == childStart["UID"]
    for start in (parent, childStart):
        assert start["variant"] == variant and start["selfCDHash"] == binary["CDHash"] and start["signedPluginBooleanTrue"] is positive
        for field in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert start[field] == 0
    expectedParentPaths = {"/var/root/VirtualMac2/testing/original-xpc-transport-v1/" + FACTORY, "/private/var/root/VirtualMac2/testing/original-xpc-transport-v1/" + FACTORY} if positive else {binary["path"]}
    assert parent["executedPath"] in expectedParentPaths
    registered = one("registeredService")
    assert registered["service"] == "com.apple.Virtualization.VirtualMachine" and registered["flags"] == 2
    assert registered["codeSHA256"] == binary["sha256"] and registered["codeUUID"] == binary["UUID"] and registered["codeBytes"] == binary["bytes"]
    assert childStart["executedPath"] == registered["path"] and re.fullmatch(r"/private/(?:var/)?tmp/VM27-OwnedFactory-[A-Za-z0-9]+/Owned\.bundle/Contents/XPCServices/One\.xpc/Contents/MacOS/ServiceExec", registered["path"])
    for process in ("parent", "child"):
        abi = one("endpointABI", process)
        assert abi["exact"] is True and abi["UUID"] == ("7a0ca8d2728537ddae972efaa1de763e" if positive else "0791121fb5fc3f84bf04115e86d2d882") and int(abi["RVA"], 16) > 0
    assert one("endpointABI", "parent")["RVA"] == one("endpointABI", "child")["RVA"]
    negatives = one("endpointNegativeControls"); assert negatives["checks"] == 12 and negatives["failures"] == 0 and negatives["allRefused"] is negatives["ownObjectsReleased"] is True
    providers = [r for r in rows if r["record"] == "provider"]; assert len(providers) == 24
    for symbol, library in (("VM27OriginalTransportCopyABI", "VM27OriginalTransport.dylib"), ("VM27PrivateServiceConsumerCheckMessage", "VM27PrivateConsumer.dylib"), ("VM27BundleRegistryRegister", "VM27BundleRegistry.dylib"), ("VM27PrivateEndpointConnectSendRight", "VM27PrivateEndpoint.dylib"), ("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"), ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib")):
        values = [dict(r) for r in providers if r["symbol"] == symbol]; assert len(values) == 4
        assert {(r.pop("role"), r.pop("phase")) for r in values} == {(p, phase) for p in ("parent", "child") for phase in ("before", "after")}
        assert all(r == values[0] for r in values); expected = files[library]
        assert values[0]["path"] == ("/private/var/root/VirtualMac2/testing/original-xpc-transport-v1/" + library if positive else expected["path"])
        assert values[0]["SHA256"] == expected["sha256"] and values[0]["UUID"] == expected["UUID"] and int(values[0]["RVA"], 16) == X.symbol_rva(Path(expected["path"]).read_bytes(), symbol) > 0
    identities = [r for r in rows if r["record"] == "peerIdentity"]
    assert {(r["role"], r["phase"]) for r in identities} == (set() if timeout else {("parent", "handshake"), ("child", "handshake")} | ({("parent", "reply"), ("child", "request")} if normal and positive else set()))
    assert len(identities) == (0 if timeout else 4 if normal and positive else 2)
    for identity in identities:
        assert identity["PID"] == (child if identity["role"] == "parent" else pid) and identity["PIDVersion"] > 0
        assert identity["kernelCDHash"] == binary["CDHash"] and identity["codeStatus"] & 1 and identity["codeQueryResult"] == identity["statusQueryResult"] == 0 and identity["matched"] is True
    for process in ("parent", "child"):
        versions = {r["PIDVersion"] for r in identities if r["role"] == process}; assert len(versions) == (0 if timeout else 1)
    factoryGates = [r for r in rows if r["record"] == "factoryGate"]; assert len(factoryGates) == (0 if timeout else 1)
    for gate in factoryGates:
        assert gate["nativeBooleanTrue"] is gate["explicitApproved"] is positive and gate["nativeStatus"] == (0 if positive else 13) and gate["transportOnlyOnMac"] is not positive and type(gate["strictValidated"]) is bool
    serviceGates = [r for r in rows if r["record"] == "serviceGate"]; assert len(serviceGates) == (1 if normal and positive else 0)
    for gate in serviceGates: assert gate["nativeBooleanTrue"] is gate["explicitApproved"] is positive and type(gate["strictValidated"]) is bool
    expectedABI = {"XPCUUID": "7a0ca8d2728537ddae972efaa1de763e" if positive else "0791121fb5fc3f84bf04115e86d2d882", "SecurityUUID": "d0585f533f5c349fa16ba9710274e733" if positive else "7b094bb2dd4d3a818c295879451255f5"}
    abiRows = []
    for process in ("parent", "child"):
        abiRow = dict(one("originalABI", process)); assert abiRow.pop("role") == process
        for field, expected in expectedABI.items(): assert abiRow[field] == expected
        for field in ("createRVA", "mainRVA", "auditRVA", "entitlementRVA", "taskRVA", "taskCopyRVA", "validatedRVA"): assert int(abiRow[field], 16) > 0
        assert int(abiRow["auditRVA"], 16) == (0xec5c if positive else 0x17f4c)
        assert int(abiRow["entitlementRVA"], 16) == (0xefe0 if positive else 0x1aa04)
        assert int(abiRow["taskCopyRVA"], 16) == (0x2804 if positive else 0x23b87c)
        assert int(abiRow["validatedRVA"], 16) == (0x113f70 if positive else 0x23c01c)
        abiRows.append(abiRow)
    assert abiRows[0] == abiRows[1]
    originalClient, originalServer = one("originalClient"), one("originalServer")
    enabled = normal and positive
    assert originalClient["installed"] == originalClient["created"] == (1 if enabled else 0) and originalClient["forwarded"] == 1
    assert originalServer["mainCalls"] == 1 and originalServer["handlerCalls"] == (1 if enabled else 0) and originalServer["failures"] == 0
    assert originalServer["tasksCreated"] == originalServer["tasksReleased"] == originalServer["kernelQueries"] == (1 if enabled else 0)
    assert originalServer["mask"] == (3 if enabled else 0) and type(originalServer["strictValidated"]) is bool
    assert originalServer["peerError"] == 0 and originalServer["auditPID"] == (pid if enabled else 0)
    assert (originalServer["auditPIDVersion"] > 0) is enabled
    childSummary, summary = one("childSummary"), rows[-1]
    for result in (childSummary, summary): assert result["passed"] is True and result["failures"] == 0 and result["ownObjectsReleased"] is True and result["handshakeRejected"] is denied and result["handshakeTimeout"] is timeout
    requests, accepted, queries = 65 if normal and positive else 0, 64 if normal and positive else 0, 66 if normal and positive else 0 if timeout else 1
    assert childSummary["PID"] == child and childSummary["checks"] >= (240 if normal and positive else 43)
    assert childSummary["serviceRequests"] == childSummary["tasksCreated"] == childSummary["tasksReleased"] == requests and childSummary["applicationCalls"] == accepted and childSummary["protocolRefused"] == (1 if normal and positive else 0)
    assert childSummary["kernelIdentityQueries"] == queries
    assert summary["record"] == "summary" and summary["parentPID"] == pid and summary["spawnedChildPID"] == child and summary["observedChildWaitExit"] == 0 and summary["childAbsent"] is True
    assert summary["checks"] >= (278 if normal and positive else 78 if timeout else 82) and summary["handshakes"] == (0 if timeout else 1)
    assert summary["reverseReplies"] == requests and summary["applicationAccepted"] == accepted and summary["deniedReplies"] == requests - accepted and summary["kernelIdentityQueries"] == queries
    for field in ("parentRegisteredPortsUnchanged", "ownTemporaryRemoved", "registryPlansReleased"): assert summary[field] is True
    assert summary["bootstrapChanges"] == summary["launchdRegistrations"] == 0 and summary["completeBundleRegistration"] is False
    return {"passed": True, "role": role, "variant": variant, "directParentPID": pid, "observedParentWaitExit": wait, "spawnedChildPID": child, "observedChildWaitExit": 0, "childAbsent": True,
        "summary": summary, "childSummary": childSummary, "providers": providers, "peerIdentities": identities, "registeredService": registered,
        "factoryGates": factoryGates, "serviceGates": serviceGates, "reverseServiceTransportProved": normal and positive, "originalCMainCalled": True, "originalCHandlerAndQueuePositiveCovered": normal and positive, "originalABI": abiRows[0], "originalClient": originalClient, "originalServer": originalServer, "explicitApprovedCodePositiveCovered": normal and positive,
        "ownedHandshakeRefusalCleanupProved": denied, "ownedHandshakeTimeoutCleanupProved": timeout, "completeBundleRegistration": False, "originalVMMExecuted": False}


def main(build):
    c = json.loads((build / "candidate.json").read_text())
    for field in ("deviceOperations", "iOSExecuted", "originalVMMExecuted", "completeBundleRegistration", "systemModified"): assert c[field] is False
    assert len(c["candidates"]) == 14 and c["bootstrapChanges"] == c["launchdRegistrations"] == 0
    for name, digest in c["sourceSHA256"].items(): assert sha((build / "source" / name).read_bytes()) == digest
    bindings, controls = [], []
    for row in c["candidates"]:
        data = Path(row["path"]).read_bytes(); assert len(data) == row["bytes"] and sha(data) == row["sha256"]
        cds = S.check(data); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
        expected = {}
        if row["role"] == "ios":
            if row["name"] == FACTORY: expected = {**X.RIGHTS, "com.apple.private.virtualization": True}

        assert L.canonical(L.signed_entitlements(data)) == L.canonical(row["entitlements"]) == L.canonical(expected)
        assert [data[at + 8:at + 24].hex() for kind, at, size in M.commands(data) if kind == 0x1b] == [row["UUID"]]
        assert struct.unpack_from("<I", data, 24)[0] & 0x80
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            at = next(at for kind, at, size in M.commands(data) if kind == 0x32); assert struct.unpack_from("<III", data, at + 8) == (2, 0x100100, 0x100100)
        imports, deps = V.imports(data), M.libraries(data); assert all(r["ordinal"] > 0 and not r["weak"] for r in imports)
        assert not any(any(n in r["symbol"] for n in ("task_for_pid", "task_set_special_port", "bootstrap_register", "mach_ports_register", "xpc_add_bundle")) for r in imports + [{"symbol": n} for n in R.defined_names(data)])
        assert not any(any(n in d for n in ("Virtualization.framework", "Hypervisor.framework", "ParavirtualizedGraphics.framework", "VirtualMachine.xpc")) for d in deps)
        if row["name"] not in (FACTORY, "VM27OriginalTransport.dylib"):
            assert row["unchanged"] is True and sha(Path(row["source"]).read_bytes()) == row["sha256"]; continue
        security = "/System/Library/Frameworks/Security.framework/" + ("Security" if row["role"] == "ios" else "Versions/A/Security")
        foundation = "/System/Library/Frameworks/CoreFoundation.framework/" + ("CoreFoundation" if row["role"] == "ios" else "Versions/A/CoreFoundation")
        if row["name"] == "VM27OriginalTransport.dylib":
            assert set(deps) == {CONSUMER, A.APPROVED, security, foundation, X.SYSTEM}
            defined = set(R.defined_names(data)); assert {"_xpc_connection_create", "_xpc_main", "_VM27OriginalTransportCopyABI", "_VM27OriginalTransportInstallClientFactoryMessage", "_VM27OriginalTransportCreateServer"} <= defined
            required = [("VM27PrivateServiceConsumerCheckMessage", CONSUMER), ("VM27ApprovedCodeInspectBytes", A.APPROVED)]
            required += [(n, security) for n in ("SecTaskCreateWithAuditToken", "SecTaskCopyValueForEntitlement", "SecTaskEntitlementsValidated")]
            required += [(n, X.SYSTEM) for n in ("csops_audittoken", "dlopen", "dlsym", "dladdr", "xpc_connection_create_from_endpoint", "xpc_endpoint_create", "dispatch_main")]
            for name, provider in required: bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            continue
        assert set(deps) == {TRANSPORT, CONSUMER, REGISTRY, ENDPOINT, A.APPROVED, A.POLICY, security, X.SYSTEM}
        required = [(n, CONSUMER) for n in ("VM27PrivateServiceConsumerCreate", "VM27PrivateServiceConsumerRelease", "VM27PrivateServiceConsumerSpawn", "VM27PrivateServiceConsumerCheckMessage", "VM27PrivateServiceConsumerWait", "VM27PrivateServiceConsumerCopyStats")]
        required += [(n, REGISTRY) for n in ("VM27BundleRegistryCreate", "VM27BundleRegistryRegister", "VM27BundleRegistryRelease", "VM27BundleRegistryCopyStats")]
        required += [(n, ENDPOINT) for n in X.ENDPOINT_API] + [(n, A.APPROVED) for n in A.API]
        required += [(n, A.POLICY) for n in ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRelease", "VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRCopyStats")]
        required += [(n, X.SYSTEM) for n in ("csops_audittoken", "xpc_dictionary_get_audit_token", "xpc_endpoint_create", "xpc_connection_send_barrier")]
        required += [(n, TRANSPORT) for n in ("xpc_connection_create", "xpc_main", "VM27OriginalTransportCopyABI", "VM27OriginalTransportCopyStats", "VM27OriginalTransportInstallClientFactoryMessage", "VM27OriginalTransportClearClient", "VM27OriginalTransportCreateServer", "VM27OriginalTransportStopServer")]
        for name, provider in required:
            bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            for mutation in ("weak", "flat", "missing", "wrongProvider"):
                modified = [dict(r) for r in imports]; changed = list(deps); selected = next(r for r in modified if r["symbol"] == "_" + name)
                if mutation == "weak": selected["weak"] = True
                elif mutation == "flat": selected["ordinal"] = -2
                elif mutation == "missing": modified.remove(selected)
                else: changed[selected["ordinal"] - 1] = "/VM27/MissingProvider.dylib"
                try: V.require_binding(modified, changed, "_" + name, provider)
                except AssertionError: controls.append({"role": row["role"], "symbol": name, "mutation": mutation, "rejected": True})
                else: raise AssertionError("invalid binding accepted")
    natives = []
    for variant in VARIANTS:
        p = next(p for p in c["processes"] if p["label"] == "macos-" + variant + "-native"); assert p["reaped"] is True
        natives.append(native_transcript(build, build / ("macos-" + variant + "-native.stdout"), "macos", variant, p["directChildPID"], p["observedWaitExit"]))
    assert len(bindings) == 92 and len(controls) == 272
    return {"passed": True, "exactBinaries": 14, "strongBindings": bindings, "negativeBindingControls": controls, "actualMacNativeFixtures": natives,
        "iOSExecuted": False, "completeBundleRegistration": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
