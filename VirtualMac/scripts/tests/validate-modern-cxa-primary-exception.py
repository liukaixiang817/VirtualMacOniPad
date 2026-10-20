#!/usr/bin/env python3
"""Independent exact-file, positive strong import and lifecycle evidence checks.

This never runs iOS binaries or loads a VM. An optional native transcript is
accepted only with its actual observed child PID/wait result from the runner.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("macho", ROOT / "scripts/development/prepare-modern-vmm-runtime-imports.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
sha = lambda data: hashlib.sha256(data).hexdigest()


def imports(data):
    entries = [(at, struct.unpack_from("<II", data, at+8)) for cmd, at, _ in M.commands(data) if cmd == 0x80000034]
    assert len(entries) == 1
    _, (offset, size) = entries[0]
    assert offset+size <= len(data)
    version, starts, table, strings, count, form, symbolform = struct.unpack_from("<7I", data, offset)
    assert version == symbolform == 0 and form in (1, 2, 3)
    width = {1: 4, 2: 8, 3: 16}[form]
    assert table+count*width <= size
    result = []
    for index in range(count):
        at = offset+table+index*width
        if form in (1, 2):
            word = struct.unpack_from("<I", data, at)[0]
            ordinal = word & 255
            if ordinal >= 0xf1: ordinal -= 256
            weak, name = bool(word & 256), word >> 9
            addend = 0 if form == 1 else struct.unpack_from("<i", data, at+4)[0]
        else:
            word = struct.unpack_from("<Q", data, at)[0]
            ordinal = word & 65535
            if ordinal >= 0xfff1: ordinal -= 65536
            weak, name = bool(word & 65536), word >> 32
            addend = struct.unpack_from("<q", data, at+8)[0]
        assert strings+name < size
        result.append({"symbol": M.string(data, offset+strings+name, offset+size),
                       "ordinal": ordinal, "weak": weak, "addend": addend})
    return result


def require_binding(rows, deps, symbol, library):
    selected = [row for row in rows if row["symbol"] == symbol]
    assert len(selected) == 1
    row = selected[0]
    assert not row["weak"] and row["addend"] == 0 and 0 < row["ordinal"] <= len(deps)
    assert deps[row["ordinal"]-1] == library
    return row


def transcript(path, pid, wait, terminate=False):
    assert wait == (79 if terminate else 0) and pid > 1
    records = [json.loads(line) for line in path.read_text().splitlines()]
    starts = [row for row in records if row["record"] == "start"]
    assert len(starts) == 1 and starts[0]["PID"] == pid
    assert starts[0]["VMCalls"] == starts[0]["GPUCalls"] == 0
    checks = [row for row in records if row["record"] == "check"]
    assert all(row["passed"] is True for row in checks)
    assert sorted(row["id"] for row in checks) == list(range(1, len(checks)+1))
    if terminate:
        assert records[-1] == {"record": "saved-terminate", "expectedExit": 79, "passed": True}
        assert any(row["record"] == "terminate-control" and row["expectedSavedHandlerExit"] == 79 and
                   row["wrongCurrentHandlerExit"] == 80 for row in records)
        assert not any(row["record"] == "summary" for row in records)
        return {"savedHandlerExit": wait, "directChildPID": pid, "checks": len(checks), "passed": True}
    summary = [row for row in records if row["record"] == "summary"]
    assert len(summary) == 1
    summary = summary[0]
    assert summary["PID"] == pid and summary["checks"] == len(checks) >= 717
    assert summary["failures"] == summary["invalidDestructors"] == summary["VMCalls"] == summary["GPUCalls"] == 0
    assert summary["initialized"] == 70 and summary["created"] == summary["destroyed"] == 68
    assert summary["rethrows"] == 66 and summary["nativeCleanupCalls"] == 2
    assert summary["failedConstructions"] == 1 and summary["workers"] == 4 and not summary["full27Backend"]
    assert len([row for row in checks if row["name"] == "real destructor intact payload"]) == 68
    providers = [row for row in records if row["record"] == "provider"]
    assert len(providers) == 2 and providers[0]["phase"] == "before" and providers[1]["phase"] == "after"
    assert providers[0]["UUID"] == providers[1]["UUID"] and providers[0]["RVA"] == providers[1]["RVA"]
    assert providers[0]["strongImport"] and providers[1]["strongImport"]
    assert all(row["exact"] for row in records if row["record"] == "file")
    return summary


def main(build):
    manifest = json.loads((build / "candidate.json").read_text())
    spec = importlib.util.spec_from_file_location("signature", ROOT / "scripts/development/verify-macho-code-directory.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    bindings = []
    controls = []
    for candidate in manifest["candidates"]:
        for kind in ("library", "probe"):
            row = candidate[kind]
            data = Path(row["path"]).read_bytes()
            assert len(data) == row["bytes"] and sha(data) == row["sha256"]
            verifier.check(data)
        for row in candidate["backing"]:
            data = Path(row["path"]).read_bytes()
            assert len(data) == row["bytes"] and sha(data) == row["sha256"] and row["unchanged"]
            verifier.check(data)
        data = Path(candidate["probe"]["path"]).read_bytes()
        actual, deps = imports(data), M.libraries(data)
        init = require_binding(actual, deps, "___cxa_init_primary_exception", "@rpath/VM27PrimaryExceptionCompat.dylib")
        rethrow = require_binding(actual, deps, "___cxa_rethrow_primary_exception", "/usr/lib/libc++abi.dylib")
        factory = require_binding(actual, deps, "__ZNSt13exception_ptr31__from_native_exception_pointerEPv",
            "@rpath/VM27CxxProvider.dylib" if candidate["role"] == "ios" else "/usr/lib/libc++.1.dylib")
        assert not any(cmd == 0x8000001f for cmd, _, _ in M.commands(Path(candidate["library"]["path"]).read_bytes()))
        for mutation in ("weak", "flat", "wrongProvider", "missing"):
            changed = [dict(row) for row in actual]
            target = next(row for row in changed if row["symbol"] == "___cxa_init_primary_exception")
            if mutation == "weak": target["weak"] = True
            elif mutation == "flat": target["ordinal"] = -2
            elif mutation == "wrongProvider": target["ordinal"] = rethrow["ordinal"]
            else: changed.remove(target)
            try: require_binding(changed, deps, "___cxa_init_primary_exception", "@rpath/VM27PrimaryExceptionCompat.dylib")
            except AssertionError: controls.append({"role": candidate["role"], "control": mutation, "rejected": True})
            else: raise AssertionError("negative binding accepted")
        bindings.append({"role": candidate["role"], "strongPositiveBindings": [init, rethrow, factory], "passed": True})
    process = next(row for row in manifest["processes"] if row["label"] == "macos-lifecycle-native")
    assert process["reaped"]
    actual = transcript(build / "macos-lifecycle-native.stdout", process["directChildPID"], process["observedWaitExit"])
    process = next(row for row in manifest["processes"] if row["label"] == "macos-saved-terminate-control")
    assert process["reaped"]
    terminate = transcript(build / "macos-saved-terminate-control.stdout", process["directChildPID"], process["observedWaitExit"], True)
    print(json.dumps({"manifestSHA256": sha((build / "candidate.json").read_bytes()),
        "strongBindings": bindings, "bindingNegativeControls": controls,
        "actualMacLifecycle": actual, "actualMacSavedHandlerControl": terminate,
        "iOSExecuted": False, "full27Backend": False, "passed": True}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve())
