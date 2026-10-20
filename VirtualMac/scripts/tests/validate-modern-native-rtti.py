#!/usr/bin/env python3
"""Independent exact-file, strong positive binding and real transcript checks.

Does not execute iOS files, create a VM or call EFI. Native transcripts require
the actual child PID and observed wait status; a prepared file is not execution.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cxa_validator", ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
sha = lambda data: hashlib.sha256(data).hexdigest()
PROVIDER = "@rpath/VM27NativeRTTICompat.dylib"
D1 = "__ZN10__cxxabiv120__si_class_type_infoD1Ev"
D2 = "__ZN10__cxxabiv120__si_class_type_infoD2Ev"


def transcript(path, pid, wait):
    assert pid > 1 and wait == 0
    records = [json.loads(line) for line in path.read_text().splitlines()]
    starts = [r for r in records if r["record"] == "start"]
    assert len(starts) == 1 and starts[0]["PID"] == pid
    assert starts[0]["VMCalls"] == starts[0]["GPUCalls"] == starts[0]["staticRTTIDestructors"] == starts[0]["syntheticNativeClasses"] == 0
    checks = [r for r in records if r["record"] == "check"]
    assert all(r["passed"] is True for r in checks)
    assert sorted(r["id"] for r in checks) == list(range(1, len(checks)+1))
    summaries = [r for r in records if r["record"] == "summary"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["PID"] == pid and summary["checks"] == len(checks) >= 672
    assert summary["failures"] == summary["VMCalls"] == summary["GPUCalls"] == summary["staticRTTIDestructors"] == summary["syntheticNativeClasses"] == 0
    assert summary["completeCalls"] == summary["baseCalls"] == 64
    assert summary["constructedBaseSubobjects"] == summary["releasedRawOwners"] == 128 and summary["workers"] == 4
    assert summary["fullNativeSiConstructionVerified"] is False and summary["full27Backend"] is False
    for name in ("real SDK type_info constructor/name", "native type_infoD2 exact no-write/no-free contract including guards", "ended base lifetime raw owner released once"):
        assert sum(r["name"] == name for r in checks) == 128
    providers = [r for r in records if r["record"] == "provider"]
    assert len(providers) == 4
    for entry in range(2):
        pair = [r for r in providers if r["entry"] == entry]
        assert [r["phase"] for r in pair] == ["before", "after"]
        assert pair[0]["UUID"] == pair[1]["UUID"] and pair[0]["RVA"] == pair[1]["RVA"]
        assert all(r["strongImport"] is True for r in pair)
    assert all(r["exact"] is True for r in records if r["record"] == "file")
    return summary


def main(build):
    manifest = json.loads((build / "candidate.json").read_text())
    spec = importlib.util.spec_from_file_location("signature", ROOT / "scripts/development/verify-macho-code-directory.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    for original, expected in manifest["sourceSHA256"].items():
        assert sha((build / "source" / Path(original).name).read_bytes()) == expected
    bindings, controls = [], []
    for candidate in manifest["candidates"]:
        for kind in ("library", "probe"):
            row = candidate[kind]
            data = Path(row["path"]).read_bytes()
            assert sha(data) == row["sha256"] and len(data) == row["bytes"]
            signatures = verifier.check(data)
            assert len(signatures) == 1 and signatures[0]["cdhash"] == row["CDHash"]
            expected_subtype = 0x81000002 if candidate["role"] == "macos" and kind == "probe" else 0x80000002
            assert struct.unpack_from("<II", data, 4) == (0x100000c, expected_subtype)
            if candidate["role"] == "ios":
                at = next(at for cmd, at, _ in V.M.commands(data) if cmd == 0x32)
                assert struct.unpack_from("<III", data, at+8) == (2, 0x100100, 0x100100)
        lib = Path(candidate["library"]["path"]).read_bytes()
        assert not any(cmd in (0x80000018, 0x8000001f) for cmd, _, _ in V.M.commands(lib))
        data = Path(candidate["probe"]["path"]).read_bytes()
        actual, deps = V.imports(data), V.M.libraries(data)
        selected = [V.require_binding(actual, deps, symbol, PROVIDER) for symbol in (D1, D2)]
        for symbol in (D1, D2):
            for mutation in ("weak", "flat", "wrongProvider", "missing"):
                changed = [dict(r) for r in actual]
                target = next(r for r in changed if r["symbol"] == symbol)
                if mutation == "weak": target["weak"] = True
                elif mutation == "flat": target["ordinal"] = -2
                elif mutation == "wrongProvider": target["ordinal"] = next(i+1 for i, d in enumerate(deps) if d != PROVIDER)
                else: changed.remove(target)
                try: V.require_binding(changed, deps, symbol, PROVIDER)
                except AssertionError: controls.append({"role": candidate["role"], "symbol": symbol, "mutation": mutation, "rejected": True})
                else: raise AssertionError("negative binding accepted")
        bindings.append({"role": candidate["role"], "bindings": selected, "passed": True})
    process = next(r for r in manifest["processes"] if r["label"] == "macos-owned-base-native")
    assert process["reaped"] is True
    actual = transcript(build / "macos-owned-base-native.stdout", process["directChildPID"], process["observedWaitExit"])
    print(json.dumps({"candidateSHA256": sha((build / "candidate.json").read_bytes()), "strongBindings": bindings,
        "bindingNegativeControls": controls, "actualMacOwnedBaseFixture": actual,
        "iOSExecuted": False, "fullNativeSiConstructionVerified": False, "full27Backend": False, "passed": True}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve())
