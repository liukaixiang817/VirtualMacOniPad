#!/usr/bin/env python3
"""Read-only actual direct-parent/nested-child Mach inheritance receipts."""
from pathlib import Path
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
s = importlib.util.spec_from_file_location("registry", ROOT / "scripts/tests/validate-modern-xpc-bundle-registry.py")
R = importlib.util.module_from_spec(s); s.loader.exec_module(R)
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True, "com.apple.private.security.no-sandbox": True}


def native_transcript(build, path, role, pid, wait):
    assert role in ("ios", "macos") and pid > 1 and wait == 0
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert not any(r["record"] == "failure" for r in rows)
    parents = [r for r in rows if r["record"] == "start" and r["role"] == "parent"]
    children = [r for r in rows if r["record"] == "start" and r["role"] == "child"]
    spawns = [r for r in rows if r["record"] == "spawn"]
    childResults = [r for r in rows if r["record"] == "childSummary"]
    assert len(parents) == len(children) == len(spawns) == len(childResults) == 1
    assert parents[0]["PID"] == spawns[0]["parentPID"] == pid and spawns[0]["spawnResult"] == 0
    child = children[0]["PID"]
    assert child > 1 and child != pid and spawns[0]["childPID"] == childResults[0]["PID"] == child
    assert children[0]["UID"] == parents[0]["UID"]
    for start in parents + children:
        for k in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert start[k] == 0
    result = childResults[0]
    assert result["passed"] is True and result["checks"] >= 6 and result["failures"] == 0 and result["sentMessages"] == 1 and result["ownedRightsReleased"] is True
    summary = rows[-1]
    assert summary["record"] == "summary" and summary["parentPID"] == pid and summary["spawnedChildPID"] == summary["actualAuditPID"] == child
    assert summary["observedChildWaitExit"] == 0 and summary["childAbsent"] is True and summary["passed"] is True
    assert summary["checks"] >= 20 and summary["failures"] == 0 and summary["actualMachMessages"] == 1
    assert summary["parentRegisteredPortsUnchanged"] is True and summary["ownRightsReleased"] is True
    for k in ("VMCalls", "GPUCalls", "bootstrapChanges", "launchdRegistrations"): assert summary[k] == 0
    return {"passed": True, "role": role, "directParentPID": pid, "observedParentWaitExit": wait,
        "spawnedChildPID": child, "observedChildWaitExit": 0, "childAbsent": True,
        "childSummary": result, "summary": summary, "crossProcessXPCProved": False, "originalVMMExecuted": False}


def main(build):
    c = json.loads((build / "candidate.json").read_text())
    assert c["deviceOperations"] is c["iOSExecuted"] is c["originalVMMExecuted"] is False
    assert len(c["candidates"]) == 2
    for name, digest in c["sourceSHA256"].items(): assert R.sha((build / "source" / name).read_bytes()) == digest
    bindings = []
    for row in c["candidates"]:
        data = Path(row["path"]).read_bytes(); assert R.sha(data) == row["sha256"] and len(data) == row["bytes"]
        cds = R.S.check(data); assert len(cds) == 1 and cds[0]["cdhash"] == row["CDHash"]
        expected = RIGHTS if row["role"] == "ios" else {}
        assert R.L.canonical(R.L.signed_entitlements(data)) == R.L.canonical(expected) == R.L.canonical(row["entitlements"])
        if row["role"] == "ios":
            assert struct.unpack_from("<II", data, 4) == (0x100000c, 0x80000002)
            at = next(at for k, at, size in R.M.commands(data) if k == 0x32)
            assert struct.unpack_from("<III", data, at + 8) == (2, 0x100100, 0x100100)
        imports, deps = R.V.imports(data), R.M.libraries(data)
        assert all(r["ordinal"] > 0 and not r["weak"] for r in imports)
        assert deps == ["/usr/lib/libSystem.B.dylib"]
        assert not any(any(n in r["symbol"] for n in ("task_for_pid", "task_set_special_port", "bootstrap_register", "mach_ports_register")) for r in imports)
        for name in ("posix_spawnattr_set_registered_ports_np", "posix_spawn", "waitpid", "mach_ports_lookup", "mach_msg"):
            bindings.append({"role": row["role"], **R.V.require_binding(imports, deps, "_" + name, "/usr/lib/libSystem.B.dylib")})
    p = next(r for r in c["processes"] if r["label"] == "macos-native")
    assert p["reaped"] is True
    return {"passed": True, "exactBinaries": 2, "strongBindings": bindings,
        "actualMacChildInheritance": native_transcript(build, build / "macos-native.stdout", "macos", p["directChildPID"], p["observedWaitExit"]),
        "iOSExecuted": False, "crossProcessXPCProved": False, "originalVMMExecuted": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
