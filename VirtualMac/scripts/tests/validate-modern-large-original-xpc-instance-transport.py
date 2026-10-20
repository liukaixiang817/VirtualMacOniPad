#!/usr/bin/env python3
"""Exact original27 create/main transport ABI and real bounded native receipts."""
from pathlib import Path
from collections import Counter
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
FACTORY = "large-original-xpc-instance-transport-probe"
TRANSPORT = "@rpath/VM27LargeOriginalTransport.dylib"
CONSUMER, REGISTRY, ENDPOINT = "@rpath/VM27LargeConsumer.dylib", "@rpath/VM27LargeRegistry.dylib", X.ENDPOINT
VARIANTS = ("normal", "deny-handshake", "timeout-handshake", "deny-instance", "timeout-instance")


def native_transcript(build, path, role, variant, pid, wait):
    assert role in ("ios", "macos") and variant in VARIANTS and pid > 1 and wait == 0
    c = json.loads((build / "candidate.json").read_text()); files = {r["name"]: r for r in c["candidates"] if r["role"] == role}; binary = files[FACTORY]
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert not any(r["record"] in ("failure", "forbiddenImage") for r in rows)
    def one(name, process=None):
        values = [r for r in rows if r["record"] == name and (process is None or r["role"] == process)]; assert len(values) == 1; return values[0]
    parent, childStart, spawn = one("start", "parent"), one("start", "child"), one("spawn")
    instanceDeny, instanceTimeout = variant == "deny-instance", variant == "timeout-instance"
    child, positive, normal, denied, timeout = childStart["PID"], role == "ios", variant == "normal", variant == "deny-handshake", variant == "timeout-handshake"
    assert parent["PID"] == spawn["parentPID"] == pid and child != pid and child > 1 and spawn["childPID"] == child and spawn["spawnResult"] == 0
    assert parent["UID"] == childStart["UID"]
    for start in (parent, childStart):
        assert start["variant"] == variant and start["selfCDHash"] == binary["CDHash"] and start["signedPluginBooleanTrue"] is positive
        for field in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert start[field] == 0
    expectedParentPaths = {"/var/root/VirtualMac2/testing/large-original-xpc-instance-v1/" + FACTORY, "/private/var/root/VirtualMac2/testing/large-original-xpc-instance-v1/" + FACTORY} if positive else {binary["path"]}
    assert parent["executedPath"] in expectedParentPaths
    registered = one("registeredService")
    assert registered["service"] == "com.apple.Virtualization.VirtualMachine" and registered["flags"] == 2
    assert registered["codeSHA256"] == binary["sha256"] and registered["codeUUID"] == binary["UUID"] and registered["codeBytes"] == binary["bytes"]
    assert childStart["executedPath"] == registered["path"] and re.fullmatch(r"/private/(?:var/)?tmp/VM27-LargeOwnedFactory-[A-Za-z0-9]+/Owned\.bundle/Contents/XPCServices/One\.xpc/Contents/MacOS/ServiceExec", registered["path"])
    for process in ("parent", "child"):
        abi = one("endpointABI", process)
        assert abi["exact"] is True and abi["UUID"] == ("7a0ca8d2728537ddae972efaa1de763e" if positive else "0791121fb5fc3f84bf04115e86d2d882") and int(abi["RVA"], 16) > 0
    assert one("endpointABI", "parent")["RVA"] == one("endpointABI", "child")["RVA"]
    rollback = one("listenerRollback"); assert rollback["started"] == rollback["released"] == rollback["finalInvalid"] == 2 and rollback["injectedEndpointFailures"] == rollback["busyRollbacks"] == 1 and rollback["firstServerReleased"] is True
    negatives = one("endpointNegativeControls"); assert negatives["checks"] == 12 and negatives["failures"] == 0 and negatives["allRefused"] is negatives["ownObjectsReleased"] is True
    providers = [r for r in rows if r["record"] == "provider"]; assert len(providers) == 28
    for symbol, library in (("VM27LargeOriginalTransportCopyABI", "VM27LargeOriginalTransport.dylib"), ("VM27LargePrivateServiceConsumerCheckMessage", "VM27LargeConsumer.dylib"), ("VM27LargeBundleRegistryRegister", "VM27LargeRegistry.dylib"), ("VM27PrivateEndpointConnectSendRight", "VM27PrivateEndpoint.dylib"), ("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"), ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib"), ("VM27LargeOriginalParentCheckFile", "VM27LargeParent.dylib")):
        values = [dict(r) for r in providers if r["symbol"] == symbol]; assert len(values) == 4
        assert {(r.pop("role"), r.pop("phase")) for r in values} == {(p, phase) for p in ("parent", "child") for phase in ("before", "after")}
        assert all(r == values[0] for r in values); expected = files[library]
        assert values[0]["path"] == ("/private/var/root/VirtualMac2/testing/large-original-xpc-instance-v1/" + library if positive else expected["path"])
        assert values[0]["SHA256"] == expected["sha256"] and values[0]["UUID"] == expected["UUID"] and int(values[0]["RVA"], 16) == X.symbol_rva(Path(expected["path"]).read_bytes(), symbol) > 0
    identities = [r for r in rows if r["record"] == "peerIdentity"]
    assert {(r["role"], r["phase"]) for r in identities} == (set() if timeout else {("parent", "handshake"), ("child", "handshake")} | ({("child", "instance")} if (normal or instanceDeny or instanceTimeout) and positive else set()) | ({("parent", "reply"), ("child", "request")} if normal and positive else set()))
    assert len(identities) == (0 if timeout else 5 if normal and positive else 3 if (instanceDeny or instanceTimeout) and positive else 2)
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
    assert originalClient["installed"] == originalClient["created"] == (1 if positive and not denied and not timeout else 0) and originalClient["forwarded"] == 1
    assert originalServer["mainCalls"] == 1 and originalServer["handlerCalls"] == (1 if enabled else 0) and originalServer["failures"] == 0
    assert originalServer["tasksCreated"] == originalServer["tasksReleased"] == originalServer["kernelQueries"] == (2 if enabled else 0)
    assert originalServer["mask"] == (3 if enabled else 0) and type(originalServer["strictValidated"]) is bool
    assert originalServer["peerError"] == 0 and originalServer["auditPID"] == (pid if enabled else 0)
    assert (originalServer["auditPIDVersion"] > 0) is enabled
    for process in ("parent", "child"):
        instanceABI = one("instanceABI", process); assert instanceABI["exactCode"] is True
        assert [int(instanceABI[n], 16) for n in ("oneShotRVA", "setInstanceRVA", "getInstanceRVA")] == ([0xed10, 0xecb4, 0xedd4] if positive else [0x1124c, 0x1125c, 0x280e4])
    instanceClient, instanceServer = one("originalInstanceClient"), one("originalInstanceServer")
    attempted = positive and not denied and not timeout
    acknowledged = attempted and not instanceTimeout
    activation = one("originalActivation")
    assert activation["activated"] is activation["finalInvalid"] is attempted and activation["cancellationDrained"] is True
    deadline = one("instanceSetterDeadline")
    assert set(deadline) == {"record", "attempted", "elapsedNanoseconds", "deadlineNanoseconds", "timeoutExpected"}
    assert deadline["attempted"] is attempted and deadline["timeoutExpected"] is (attempted and instanceTimeout)
    assert type(deadline["elapsedNanoseconds"]) is type(deadline["deadlineNanoseconds"]) is int
    assert deadline["deadlineNanoseconds"] == 2000000000
    assert 0 < deadline["elapsedNanoseconds"] < 6000000000 if attempted else deadline["elapsedNanoseconds"] == 0
    if attempted and instanceTimeout: assert deadline["elapsedNanoseconds"] >= deadline["deadlineNanoseconds"]
    ownership = one("timeoutRequestOwnership")
    assert set(ownership) == {"record", "retained", "released", "realParentCloseEvents", "pending", "finalInvalidDrained"}
    for field in ("retained", "released", "realParentCloseEvents", "pending"): assert type(ownership[field]) is int
    assert ownership["retained"] == ownership["released"] == ownership["realParentCloseEvents"] == (1 if attempted and instanceTimeout else 0)
    assert ownership["pending"] == 0 and ownership["finalInvalidDrained"] is True
    for field in ("requests", "callbacks"): assert instanceClient[field] == (1 if attempted else 0)
    for field in ("replies", "tasksCreated", "tasksReleased"): assert instanceClient[field] == (1 if acknowledged else 0)
    for field in ("committed", "copied"): assert instanceClient[field] == (1 if enabled else 0)
    assert instanceClient["pending"] == 0 and instanceClient["nativeSetterCalls"] == instanceServer["nativeSetterCalls"] == 0
    assert instanceClient["lastStatus"] == (37 if enabled else 100 if attempted and instanceDeny else 60 if attempted and instanceTimeout else 0)
    assert instanceServer["bound"] == (1 if enabled else 0) and instanceServer["controlMessages"] == (1 if attempted else 0)
    assert instanceClient["auditPID"] == (child if acknowledged else 0) and (instanceClient["auditPIDVersion"] > 0) is acknowledged
    assert instanceClient["kernelCDHash"] == (binary["CDHash"] if acknowledged else "") and instanceClient["mask"] == (3 if acknowledged else 0) and type(instanceClient["strictValidated"]) is bool
    assert instanceClient["codeQueryResult"] == instanceClient["statusQueryResult"] == 0
    assert bool(instanceClient["codeStatus"] & 1) is acknowledged
    uuids = [r for r in rows if r["record"] == "originalInstanceClientUUID"]; assert len(uuids) == (1 if enabled else 0)
    if enabled:
        assert uuids[0]["UUID"] == instanceServer["UUID"] and re.fullmatch(r"[a-f0-9]{32}", instanceServer["UUID"]) and int(instanceServer["UUID"], 16) != 0 and uuids[0]["callerUUIDMemoryChanged"] is True
    else: assert instanceServer["UUID"] == "0" * 32
    childSummary, summary = one("childSummary"), rows[-1]
    for result in (childSummary, summary): assert result["passed"] is True and result["failures"] == 0 and result["ownObjectsReleased"] is True and result["handshakeRejected"] is denied and result["handshakeTimeout"] is timeout
    requests, accepted, queries = 65 if normal and positive else 0, 64 if normal and positive else 0, 66 if normal and positive else 0 if timeout else 1
    assert childSummary["PID"] == child and childSummary["checks"] >= (240 if normal and positive else 43)
    assert childSummary["serviceRequests"] == childSummary["tasksCreated"] == childSummary["tasksReleased"] == requests and childSummary["applicationCalls"] == accepted and childSummary["protocolRefused"] == (1 if normal and positive else 0)
    assert childSummary["kernelIdentityQueries"] == (67 if enabled else 2 if attempted else queries)
    assert summary["record"] == "summary" and summary["parentPID"] == pid and summary["spawnedChildPID"] == child and summary["observedChildWaitExit"] == 0 and summary["childAbsent"] is True
    assert summary["checks"] >= (278 if normal and positive else 78 if timeout else 82) and summary["handshakes"] == (0 if timeout else 1)
    assert summary["reverseReplies"] == requests and summary["applicationAccepted"] == accepted and summary["deniedReplies"] == requests - accepted and summary["kernelIdentityQueries"] == (66 if enabled else queries)
    for field in ("parentRegisteredPortsUnchanged", "ownTemporaryRemoved", "registryPlansReleased"): assert summary[field] is True
    assert summary["bootstrapChanges"] == summary["launchdRegistrations"] == 0 and summary["completeBundleRegistration"] is False
    exactRecords = Counter({"originalABI": 2, "instanceABI": 2, "start": 2, "endpointABI": 2, "provider": 28,
        "endpointNegativeControls": 1, "listenerRollback": 1, "registeredService": 1, "spawn": 1,
        "originalActivation": 1, "originalInstanceClient": 1, "originalClient": 1, "childSummary": 1,
        "originalInstanceServer": 1, "originalServer": 1, "summary": 1, "instanceSetterDeadline": 1, "timeoutRequestOwnership": 1, "largeInertRoute": 1, "largeTransportRoute": 2})
    if not timeout:
        exactRecords["factoryGate"] = 1
        exactRecords["peerIdentity"] = 5 if enabled else 3 if attempted else 2
    if enabled: exactRecords["serviceGate"] = exactRecords["originalInstanceClientUUID"] = 1
    assert Counter(r["record"] for r in rows) == exactRecords
    inert = one("largeInertRoute")
    original = next(row for row in c["candidates"] if row["role"] == "data")
    assert inert["PID"] == pid and inert["originalDataBytes"] == original["bytes"] == 5206160
    assert inert["originalDataUUID"] == original["UUID"] == "4a6a588d1afd30f5a64d6304eb79be0b"
    assert inert["originalDataSHA256"] == original["sha256"]
    assert re.fullmatch(r"/private/(?:var/)?tmp/VM27-LargeOwnedFactory-[A-Za-z0-9]+", inert["ownTemporaryPath"])
    assert inert["ownTemporaryRemoved"] is True
    for name in ("plansCreatedDestroyed", "unstartedConsumersCreatedDestroyed", "transportLargeParentInspections"): assert inert[name] == 1
    for name in ("originalVMMExecutions", "originalDataSpawns", "messages", "originalPluginLoaderExecutions"): assert inert[name] == 0
    large_routes = [one("largeTransportRoute", process) for process in ("parent", "child")]
    for row, calls, large_calls in zip(large_routes, (4, 1), (1, 0)):
        assert row["parentFileInspections"] == calls and row["largeParentFileInspections"] == large_calls
        assert row["registryCapacityBytes"] == 8388608 and row["plistCapacityBytes"] == 65536
        assert row["originalVMMExecutions"] == row["originalPluginLoaderExecutions"] == 0
    return {"largeInertRoute": inert, "largeTransportRoutes": large_routes, "originalDataOnly": True, "instanceClient": instanceClient, "instanceServer": instanceServer, "oneShotUUIDPositiveCovered": enabled, "oneShotUUIDDenialCovered": positive and instanceDeny, "oneShotUUIDTimeoutCovered": positive and instanceTimeout, "passed": True, "role": role, "variant": variant, "directParentPID": pid, "observedParentWaitExit": wait, "spawnedChildPID": child, "observedChildWaitExit": 0, "childAbsent": True,
        "timeoutRequestOwnership": ownership, "instanceSetterDeadline": deadline, "exactRowCount": len(rows), "closedRecordSet": True,
        "summary": summary, "childSummary": childSummary, "providers": providers, "peerIdentities": identities, "registeredService": registered,
        "factoryGates": factoryGates, "serviceGates": serviceGates, "reverseServiceTransportProved": normal and positive, "originalCMainCalled": True, "originalCHandlerAndQueuePositiveCovered": normal and positive, "originalABI": abiRows[0], "originalClient": originalClient, "originalServer": originalServer, "explicitApprovedCodePositiveCovered": normal and positive,
        "ownedHandshakeRefusalCleanupProved": denied, "ownedHandshakeTimeoutCleanupProved": timeout, "completeBundleRegistration": False, "originalVMMExecuted": False}


def main(build):
    c = json.loads((build / "candidate.json").read_text())
    for field in ("deviceOperations", "iOSExecuted", "originalVMMExecuted", "completeBundleRegistration", "systemModified"): assert c[field] is False
    assert len(c["candidates"]) == 17 and c["bootstrapChanges"] == c["launchdRegistrations"] == 0
    for name, digest in c["sourceSHA256"].items(): assert sha((build / "source" / name).read_bytes()) == digest
    bindings, controls = [], []
    for row in c["candidates"]:
        if row["role"] == "data":
            assert row["code"] is row["trustcache"] is False and row["deploymentMode"] == "0600"
            assert row["bytes"] == 5206160 and sha(Path(row["path"]).read_bytes()) == row["sha256"]
            assert row["UUID"] == "4a6a588d1afd30f5a64d6304eb79be0b"
            assert row["unchanged"] is True and sha(Path(row["source"]).read_bytes()) == row["sha256"]
            cds = S.check(Path(row["path"]).read_bytes()); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
            continue
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
        if row["name"] not in (FACTORY, "VM27LargeOriginalTransport.dylib"):
            assert row["unchanged"] is True and sha(Path(row["source"]).read_bytes()) == row["sha256"]; continue
        security = "/System/Library/Frameworks/Security.framework/" + ("Security" if row["role"] == "ios" else "Versions/A/Security")
        foundation = "/System/Library/Frameworks/CoreFoundation.framework/" + ("CoreFoundation" if row["role"] == "ios" else "Versions/A/CoreFoundation")
        if row["name"] == "VM27LargeOriginalTransport.dylib":
            assert set(deps) == {CONSUMER, "@rpath/VM27LargeParent.dylib", A.APPROVED, security, foundation, X.SYSTEM}
            defined = set(R.defined_names(data)); assert {"_xpc_connection_create", "_xpc_main", "_VM27LargeOriginalTransportCopyABI", "_VM27LargeOriginalTransportInstallClientFactoryMessage", "_VM27LargeOriginalTransportCreateServer"} <= defined
            required = [("VM27LargePrivateServiceConsumerCheckMessage", CONSUMER), ("VM27LargeOriginalParentCheckFile", "@rpath/VM27LargeParent.dylib")]
            required += [(n, security) for n in ("SecTaskCreateWithAuditToken", "SecTaskCopyValueForEntitlement", "SecTaskEntitlementsValidated")]
            required += [(n, X.SYSTEM) for n in ("csops_audittoken", "dlopen", "dlsym", "dladdr", "xpc_connection_create_from_endpoint", "xpc_endpoint_create", "dispatch_main")]
            for name, provider in required: bindings.append({"role": row["role"], "file": row["name"], **V.require_binding(imports, deps, "_" + name, provider)})
            continue
        assert set(deps) == {TRANSPORT, CONSUMER, REGISTRY, ENDPOINT, "@rpath/VM27LargeParent.dylib", A.APPROVED, A.POLICY, security, X.SYSTEM}
        required = [("VM27LargeOriginalParentCheckFile", "@rpath/VM27LargeParent.dylib"), ("VM27LargePrivateServiceConsumerCopyState", CONSUMER)]
        required += [(n, CONSUMER) for n in ("VM27LargePrivateServiceConsumerCreate", "VM27LargePrivateServiceConsumerRelease", "VM27LargePrivateServiceConsumerSpawn", "VM27LargePrivateServiceConsumerCheckMessage", "VM27LargePrivateServiceConsumerWait", "VM27LargePrivateServiceConsumerCopyStats")]
        required += [(n, REGISTRY) for n in ("VM27LargeBundleRegistryCreate", "VM27LargeBundleRegistryRegister", "VM27LargeBundleRegistryRelease", "VM27LargeBundleRegistryCopyStats")]
        required += [(n, ENDPOINT) for n in X.ENDPOINT_API] + [(n, A.APPROVED) for n in A.API]
        required += [(n, A.POLICY) for n in ("VM27LWCRPolicyCreate", "VM27LWCRPolicyRelease", "VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRCopyStats")]
        required += [(n, X.SYSTEM) for n in ("csops_audittoken", "xpc_dictionary_get_audit_token", "xpc_endpoint_create", "xpc_connection_send_barrier", "xpc_connection_set_event_handler", "xpc_connection_resume", "dispatch_semaphore_wait", "uuid_generate", "clock_gettime", "xpc_retain", "xpc_release")]
        required += [(n, TRANSPORT) for n in ("xpc_connection_create", "xpc_main", "VM27LargeOriginalTransportCopyABI", "VM27LargeOriginalTransportCopyStats", "VM27LargeOriginalTransportInstallClientFactoryMessage", "VM27LargeOriginalTransportClearClient", "VM27LargeOriginalTransportCreateServer", "VM27LargeOriginalTransportStopServer", "VM27LargeOriginalTransportRequireServerInstance", "VM27LargeOriginalTransportBindServerInstanceMessage", "VM27LargeOriginalTransportCopyServerInstance", "VM27LargeOriginalTransportInjectEndpointFailureOnceForDiagnostic", "xpc_connection_set_oneshot_instance", "xpc_connection_get_instance")]
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
    assert len(bindings) == 122 and len(controls) == 392
    return {"passed": True, "exactBinaries": 16, "exactFilesIncludingInertData": 17, "strongBindings": bindings, "negativeBindingControls": controls, "actualMacNativeFixtures": natives,
        "iOSExecuted": False, "completeBundleRegistration": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
