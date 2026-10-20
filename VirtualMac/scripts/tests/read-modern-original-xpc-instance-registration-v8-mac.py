#!/usr/bin/env python3
"""Frozen standalone saved Mac v8 reader. No process/device/tool execution.

Public APIs: native_transcript(build,stdout,role,variant,pid,wait),
component_transcript(build,stdout,pid,wait), metadata_control(build,label,pid,wait).
The role must be macos. There is intentionally no native iOS success decoder.
"""
from pathlib import Path
from collections import Counter
import json
import os
import re
import stat
import struct
import sys
sys.dont_write_bytecode = True
if sys.flags.optimize != 0:
    raise RuntimeError("strict v8 saved reader requires assertions enabled")
FACTORY = "original-xpc-instance-transport-v8-probe"
VARIANTS = ("normal", "deny-handshake", "timeout-handshake", "deny-instance", "timeout-instance")
def mach_commands(data):
    assert len(data) >= 32 and struct.unpack_from("<I",data)[0] == 0xfeedfacf
    n, size = struct.unpack_from("<II",data,16); assert 0 < n <= 256 and size <= len(data)-32
    at, end = 32, 32+size
    for _ in range(n):
        assert at+8 <= end
        kind,count = struct.unpack_from("<II",data,at); assert count >= 8 and not count % 8 and at+count <= end
        yield kind,at,count
        at += count
    assert at == end
def symbol_rva(data, symbol):
    at = next(at for kind, at, size in mach_commands(data) if kind == 2)
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
    text = [at for kind, at, size in mach_commands(data) if kind == 0x19 and data[at + 8:at + 24].rstrip(b"\0") == b"__TEXT"]
    assert len(text) == 1
    return found[0] - struct.unpack_from("<Q", data, text[0] + 24)[0]



# Closed field sets for actual local receipts. No synthetic native/layout
# receipt, device receipt, or component success may enter the transport scope.
ROW_FIELDS = {
    "resourceLimits": "PID cpuSoft cpuHard alarmSeconds",
    "failure": "label",
    "originalABI": "role XPCUUID SecurityUUID createRVA mainRVA auditRVA entitlementRVA taskRVA taskCopyRVA validatedRVA",
    "instanceABI": "role oneShotRVA setInstanceRVA getInstanceRVA exactCode",
    "start": "role PID UID variant executedPath selfCDHash signedPluginBooleanTrue VMCalls GPUCalls bootstrapChanges launchdRegistrations",
    "endpointABI": "role UUID RVA exact",
    "provider": "role phase symbol path UUID RVA SHA256",
    "peerIdentity": "role phase PID PIDVersion kernelCDHash codeStatus codeQueryResult statusQueryResult matched",
    "endpointNegativeControls": "checks failures allRefused ownObjectsReleased",
    "listenerRollback": "started released finalInvalid injectedEndpointFailures busyRollbacks firstServerReleased",
    "registeredService": "path codeSHA256 codeUUID codeBytes service flags",
    "spawn": "parentPID childPID spawnResult",
    "factoryGate": "strictValidated nativeBooleanTrue explicitApproved nativeStatus transportOnlyOnMac",
    "serviceGate": "strictValidated nativeBooleanTrue explicitApproved",
    "timeoutRequestOwnership": "retained released realParentCloseEvents pending finalInvalidDrained",
    "childSummary": "PID checks failures passed serviceRequests applicationCalls protocolRefused tasksCreated tasksReleased kernelIdentityQueries ownObjectsReleased handshakeRejected handshakeTimeout",
    "originalRegistrationServer": "configured received committed titleCopies beforeInstance beforeHandler",
    "originalInstanceServer": "UUID bound nativeSetterCalls controlMessages",
    "originalServer": "mainCalls handlerCalls mask strictValidated tasksCreated tasksReleased kernelQueries auditPID auditPIDVersion peerError failures",
    "originalInstanceClientUUID": "UUID callerUUIDMemoryChanged",
    "originalActivation": "activated finalInvalid cancellationDrained",
    "instanceSetterDeadline": "attempted elapsedNanoseconds deadlineNanoseconds timeoutExpected",
    "originalInstanceClient": "requests replies callbacks committed copied pending tasksCreated tasksReleased lastStatus nativeSetterCalls auditPID auditPIDVersion kernelCDHash codeStatus codeQueryResult statusQueryResult mask strictValidated",
    "originalRegistrationClient": "requests replies callbacks committed pending bundleTitleCopies",
    "originalClient": "installed created forwarded",
    "summary": "parentPID spawnedChildPID observedChildWaitExit childAbsent checks failures passed handshakes handshakeRejected handshakeTimeout reverseReplies applicationAccepted deniedReplies kernelIdentityQueries parentRegisteredPortsUnchanged ownObjectsReleased ownTemporaryRemoved registryPlansReleased bootstrapChanges launchdRegistrations completeBundleRegistration",
    "componentRegistration": "PID call typedStatus rawStatus registered titleMatched originalHandlerCalled",
    "registrationComponentChildSummary": "PID checks failures typedRegistrationDenied rawRegistrationSuccesses actualHandlerDenials originalHandlerCalls instanceBindings nativeVMCalls originalVMMExecuted",
    "registrationComponentSummary": "parentPID childPID observedWaitExit checks failures actualReplies childAbsent liveTokenRefusedAfterReap nativeBooleanDenialKept parentRegisteredPortsUnchanged originalHandlerCalls originalVMMExecuted nativeVMCalls CPUProbeCalls",
}
BOOL_FIELDS = set("exactCode signedPluginBooleanTrue exact matched allRefused ownObjectsReleased firstServerReleased strictValidated nativeBooleanTrue explicitApproved transportOnlyOnMac finalInvalidDrained passed handshakeRejected handshakeTimeout beforeInstance beforeHandler callerUUIDMemoryChanged activated finalInvalid cancellationDrained attempted timeoutExpected childAbsent parentRegisteredPortsUnchanged ownTemporaryRemoved registryPlansReleased completeBundleRegistration registered titleMatched originalHandlerCalled originalVMMExecuted liveTokenRefusedAfterReap nativeBooleanDenialKept".split())
STR_FIELDS = set("record label role XPCUUID SecurityUUID createRVA mainRVA auditRVA entitlementRVA taskRVA taskCopyRVA validatedRVA oneShotRVA setInstanceRVA getInstanceRVA variant executedPath selfCDHash UUID RVA phase symbol path SHA256 kernelCDHash codeSHA256 codeUUID service".split())


def closed_rows(path):
    assert sys.flags.optimize == 0
    def object_hook(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result
    def no_constant(value):
        raise AssertionError(value)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        state = os.fstat(fd)
        assert stat.S_ISREG(state.st_mode) and state.st_nlink == 1 and 0 < state.st_size <= 262144
        chunks = []
        while True:
            part = os.read(fd, 262145)
            if not part:
                break
            chunks.append(part)
            assert sum(map(len, chunks)) <= 262144
        data = b"".join(chunks)
        after = os.fstat(fd)
        assert state.st_size == len(data) == after.st_size and state.st_mtime_ns == after.st_mtime_ns
    finally:
        os.close(fd)
    assert data.endswith(b"\n") and b"\r" not in data and b"\x00" not in data
    lines = data.decode("utf-8").splitlines()
    assert 1 <= len(lines) <= 160 and all(0 < len(line.encode("utf-8")) <= 16384 for line in lines)
    rows = [json.loads(line, object_pairs_hook=object_hook, parse_constant=no_constant) for line in lines]
    for row in rows:
        assert type(row) is dict and type(row.get("record")) is str and row["record"] in ROW_FIELDS
        assert set(row) == {"record", *ROW_FIELDS[row["record"]].split()}
        for field, value in row.items():
            expected = str if field in STR_FIELDS else bool if field in BOOL_FIELDS else int
            if row["record"] == "listenerRollback" and field == "finalInvalid":
                expected = int
            assert type(value) is expected
            if expected is int:
                assert -(1 << 63) <= value < (1 << 64)
    return rows


def native_transcript(build, path, role, variant, pid, wait):
    assert role == "macos" and variant in VARIANTS and type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    c = json.loads((build / "candidate.json").read_text()); files = {r["name"]: r for r in c["candidates"] if r["role"] == role}; binary = files[FACTORY]
    rows = closed_rows(path)
    assert not any(r["record"] in ("failure", "forbiddenImage") for r in rows)
    def one(name, process=None):
        values = [r for r in rows if r["record"] == name and (process is None or r["role"] == process)]; assert len(values) == 1; return values[0]
    parent, childStart, spawn = one("start", "parent"), one("start", "child"), one("spawn")
    instanceDeny, instanceTimeout = variant == "deny-instance", variant == "timeout-instance"
    child, positive, normal, denied, timeout = childStart["PID"], role == "ios", variant == "normal", variant == "deny-handshake", variant == "timeout-handshake"
    assert parent["PID"] == spawn["parentPID"] == pid and child != pid and child > 1 and spawn["childPID"] == child and spawn["spawnResult"] == 0
    limits = [r for r in rows if r["record"] == "resourceLimits"]
    assert len(limits) == 2 and {r["PID"] for r in limits} == {pid, child}
    assert all(0 < r["cpuSoft"] <= r["cpuHard"] <= 5 and r["alarmSeconds"] == 15 for r in limits)
    assert parent["UID"] == childStart["UID"]
    for start in (parent, childStart):
        assert start["variant"] == variant and start["selfCDHash"] == binary["CDHash"] and start["signedPluginBooleanTrue"] is positive
        for field in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert start[field] == 0
    expectedParentPaths = {"/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8/" + FACTORY, "/private/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8/" + FACTORY} if positive else {binary["path"]}
    assert parent["executedPath"] in expectedParentPaths
    registered = one("registeredService")
    assert registered["service"] == "com.apple.Virtualization.VirtualMachine" and registered["flags"] == 2
    assert registered["codeSHA256"] == binary["sha256"] and registered["codeUUID"] == binary["UUID"] and registered["codeBytes"] == binary["bytes"]
    assert childStart["executedPath"] == registered["path"] and re.fullmatch(r"/private/(?:var/)?tmp/VM27-OwnedFactory-[A-Za-z0-9]+/Owned\.bundle/Contents/XPCServices/One\.xpc/Contents/MacOS/ServiceExec", registered["path"])
    for process in ("parent", "child"):
        abi = one("endpointABI", process)
        assert abi["exact"] is True and abi["UUID"] == ("7a0ca8d2728537ddae972efaa1de763e" if positive else "0791121fb5fc3f84bf04115e86d2d882") and int(abi["RVA"], 16) > 0
    assert one("endpointABI", "parent")["RVA"] == one("endpointABI", "child")["RVA"]
    rollback = one("listenerRollback"); assert rollback["started"] == rollback["released"] == rollback["finalInvalid"] == 2 and rollback["injectedEndpointFailures"] == rollback["busyRollbacks"] == 1 and rollback["firstServerReleased"] is True
    negatives = one("endpointNegativeControls"); assert negatives["checks"] == 12 and negatives["failures"] == 0 and negatives["allRefused"] is negatives["ownObjectsReleased"] is True
    providers = [r for r in rows if r["record"] == "provider"]; assert len(providers) == 28
    for symbol, library in (("VM27OriginalV8TransportCopyABI", "VM27OriginalV8Transport.dylib"), ("VM27PrivateServiceConsumerCheckMessage", "VM27PrivateConsumer.dylib"), ("VM27BundleRegistryRegister", "VM27BundleRegistry.dylib"), ("VM27PrivateEndpointConnectSendRight", "VM27PrivateEndpoint.dylib"), ("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"), ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib"), ("VM27ClientRegistrationReceiveV1", "VM27ClientRegistration.dylib")):
        values = [dict(r) for r in providers if r["symbol"] == symbol]; assert len(values) == 4
        assert {(r.pop("role"), r.pop("phase")) for r in values} == {(p, phase) for p in ("parent", "child") for phase in ("before", "after")}
        assert all(r == values[0] for r in values); expected = files[library]
        assert values[0]["path"] == ("/private/var/root/VirtualMac2/testing/original-xpc-instance-registration-v8/" + library if positive else expected["path"])
        assert values[0]["SHA256"] == expected["sha256"] and values[0]["UUID"] == expected["UUID"] and int(values[0]["RVA"], 16) == symbol_rva(Path(expected["path"]).read_bytes(), symbol) > 0
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
    registrationServer, registrationClient = one("originalRegistrationServer"), one("originalRegistrationClient")
    assert set(registrationServer) == {"record", "configured", "received", "committed", "titleCopies", "beforeInstance", "beforeHandler"}
    assert registrationServer["configured"] == 1 and registrationServer["received"] == registrationServer["committed"] == registrationServer["titleCopies"] == 0
    assert registrationServer["beforeInstance"] is registrationServer["beforeHandler"] is True
    assert set(registrationClient) == {"record", "requests", "replies", "callbacks", "committed", "pending", "bundleTitleCopies"}
    assert all(type(registrationClient[f]) is int and registrationClient[f] == 0 for f in registrationClient if f != "record")
    exactRecords = Counter({"resourceLimits": 2, "originalABI": 2, "instanceABI": 2, "start": 2, "endpointABI": 2, "provider": 28, "originalRegistrationServer": 1, "originalRegistrationClient": 1,
        "endpointNegativeControls": 1, "listenerRollback": 1, "registeredService": 1, "spawn": 1,
        "originalActivation": 1, "originalInstanceClient": 1, "originalClient": 1, "childSummary": 1,
        "originalInstanceServer": 1, "originalServer": 1, "summary": 1, "instanceSetterDeadline": 1, "timeoutRequestOwnership": 1})
    if not timeout:
        exactRecords["factoryGate"] = 1
        exactRecords["peerIdentity"] = 5 if enabled else 3 if attempted else 2
    if enabled: exactRecords["serviceGate"] = exactRecords["originalInstanceClientUUID"] = 1
    assert Counter(r["record"] for r in rows) == exactRecords
    return {"instanceClient": instanceClient, "instanceServer": instanceServer, "oneShotUUIDPositiveCovered": enabled, "oneShotUUIDDenialCovered": positive and instanceDeny, "oneShotUUIDTimeoutCovered": positive and instanceTimeout, "passed": True, "role": role, "variant": variant, "directParentPID": pid, "observedParentWaitExit": wait, "spawnedChildPID": child, "observedChildWaitExit": 0, "childAbsent": True,
        "timeoutRequestOwnership": ownership, "instanceSetterDeadline": deadline, "exactRowCount": len(rows), "closedRecordSet": True,
        "summary": summary, "childSummary": childSummary, "providers": providers, "peerIdentities": identities, "registeredService": registered,
        "factoryGates": factoryGates, "serviceGates": serviceGates, "reverseServiceTransportProved": normal and positive, "originalCMainCalled": True, "originalCHandlerAndQueuePositiveCovered": normal and positive, "originalABI": abiRows[0], "originalClient": originalClient, "originalServer": originalServer, "explicitApprovedCodePositiveCovered": normal and positive,
        "ownedHandshakeRefusalCleanupProved": denied, "ownedHandshakeTimeoutCleanupProved": timeout, "completeBundleRegistration": False, "originalVMMExecuted": False}


def component_transcript(build, path, pid, wait):
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    rows = closed_rows(path)
    expected = Counter({"resourceLimits": 2, "originalABI": 1, "instanceABI": 1, "start": 1, "endpointABI": 1,
        "provider": 28, "peerIdentity": 19, "componentRegistration": 7,
        "registrationComponentChildSummary": 1, "registrationComponentSummary": 1})
    assert Counter(r["record"] for r in rows) == expected
    def one(name):
        found = [r for r in rows if r["record"] == name]
        assert len(found) == 1
        return found[0]
    summary, childSummary, start = one("registrationComponentSummary"), one("registrationComponentChildSummary"), one("start")
    child = summary["childPID"]
    assert summary["parentPID"] == start["PID"] == pid and childSummary["PID"] == child and child > 1 and child != pid
    limits = [r for r in rows if r["record"] == "resourceLimits"]
    assert len(limits) == 2 and {r["PID"] for r in limits} == {pid, child}
    assert all(0 < r["cpuSoft"] <= r["cpuHard"] <= 5 and r["alarmSeconds"] == 15 for r in limits)
    assert start["role"] == "parent" and start["variant"] == "registration-channel-only" and start["signedPluginBooleanTrue"] is False
    assert summary["observedWaitExit"] == summary["failures"] == childSummary["failures"] == 0
    assert summary["checks"] >= 96 and childSummary["checks"] >= 122 and summary["actualReplies"] == 7
    for field in ("childAbsent", "liveTokenRefusedAfterReap", "nativeBooleanDenialKept", "parentRegisteredPortsUnchanged"):
        assert summary[field] is True
    assert summary["originalVMMExecuted"] is childSummary["originalVMMExecuted"] is False
    assert summary["originalHandlerCalls"] == summary["nativeVMCalls"] == summary["CPUProbeCalls"] == 0
    assert childSummary["typedRegistrationDenied"] == 7 and childSummary["rawRegistrationSuccesses"] == childSummary["actualHandlerDenials"] == 2
    assert childSummary["originalHandlerCalls"] == childSummary["instanceBindings"] == childSummary["nativeVMCalls"] == 0
    candidate = json.loads((build / "candidate.json").read_text())
    files = {r["name"]: r for r in candidate["candidates"] if r["role"] == "macos"}
    assert start["executedPath"] == files[FACTORY]["path"] and start["selfCDHash"] == files[FACTORY]["CDHash"]
    for field in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"):
        assert start[field] == 0
    controls = [r for r in rows if r["record"] == "componentRegistration"]
    for index, (control, status) in enumerate(zip(controls, (100, 100, 22, 0, 0, 37, 100)), 1):
        assert control["PID"] == child and control["call"] == index and control["typedStatus"] == 13 and control["rawStatus"] == status
        assert control["registered"] is control["titleMatched"] is (index >= 4) and control["originalHandlerCalled"] is False
    identities = [r for r in rows if r["record"] == "peerIdentity"]
    for identity in identities:
        assert identity["role"] in ("registrationComponentParent", "registrationComponentChild")
        assert identity["PID"] == (child if identity["role"] == "registrationComponentParent" else pid)
        assert identity["PIDVersion"] > 0 and identity["kernelCDHash"] == files[FACTORY]["CDHash"]
        assert identity["codeStatus"] & 1 and identity["codeQueryResult"] == identity["statusQueryResult"] == 0 and identity["matched"] is True
    assert Counter((r["role"], r["phase"]) for r in identities) == Counter({
        ("registrationComponentParent", "ready"): 2, ("registrationComponentParent", "actual-reply"): 7,
        ("registrationComponentParent", "finish"): 1, ("registrationComponentChild", "actual-control"): 9})
    for role in ("registrationComponentParent", "registrationComponentChild"):
        assert len({r["PIDVersion"] for r in identities if r["role"] == role}) == 1
    providers = [r for r in rows if r["record"] == "provider"]
    for symbol, name in (("VM27OriginalV8TransportCopyABI", "VM27OriginalV8Transport.dylib"),
        ("VM27PrivateServiceConsumerCheckMessage", "VM27PrivateConsumer.dylib"), ("VM27BundleRegistryRegister", "VM27BundleRegistry.dylib"),
        ("VM27PrivateEndpointConnectSendRight", "VM27PrivateEndpoint.dylib"), ("VM27ApprovedCodeCheckReceivedMessage", "VM27ApprovedCode.dylib"),
        ("VM27LWCRPolicyCheckReceivedMessage", "VM27LWCRPolicy.dylib"), ("VM27ClientRegistrationReceiveV1", "VM27ClientRegistration.dylib")):
        selected = [r for r in providers if r["symbol"] == symbol]
        assert len(selected) == 4 and {(r["role"], r["phase"]) for r in selected} == {(p, phase) for p in ("parent", "child") for phase in ("before", "after")}
        for row in selected:
            assert row["path"] == files[name]["path"] and row["SHA256"] == files[name]["sha256"] and row["UUID"] == files[name]["UUID"]
            assert int(row["RVA"], 16) == symbol_rva(Path(files[name]["path"]).read_bytes(), symbol) > 0
    return {"passed": True, "role": "macos", "componentOnly": True, "directParentPID": pid, "actualChildPID": child,
        "actualReplies": 7, "rawRegistryPositiveCovered": True, "typedNativeBooleanDenialCovered": True,
        "liveTokenRefusalAfterReap": True, "oneShotPositiveCovered": False, "originalHandlerPositiveCovered": False,
        "originalVMMExecuted": False, "closedRecordSet": True, "exactRows": len(rows), "summary": summary, "childSummary": childSummary}


def metadata_control(build, label, pid, wait):
    assert label in ("missing-main-bundle", "wrong-type-main-bundle") and type(pid) is int and pid > 1 and wait == 78
    path = build / ("macos-" + label + "-native.stdout")
    rows = closed_rows(path)
    failures = [r for r in rows if r.get("record") == "failure"]
    assert failures == [{"record": "failure", "label": "actual-main-bundle-title-required-without-hard-default"}]
    assert Counter(r["record"] for r in rows) == Counter({"resourceLimits": 1, "originalABI": 1, "instanceABI": 1, "start": 1, "endpointABI": 1, "provider": 7, "failure": 1})
    start = next(r for r in rows if r["record"] == "start")
    assert start["PID"] == pid and start["signedPluginBooleanTrue"] is False
    limits = next(r for r in rows if r["record"] == "resourceLimits")
    assert limits["PID"] == pid and 0 < limits["cpuSoft"] <= limits["cpuHard"] <= 5 and limits["alarmSeconds"] == 15
    return {"label": label, "directChildPID": pid, "observedWaitExit": wait,
        "realMetadataFailureBeforeServiceCreation": True, "codeAndProviderPinsPassed": True, "exactRows": len(rows)}

