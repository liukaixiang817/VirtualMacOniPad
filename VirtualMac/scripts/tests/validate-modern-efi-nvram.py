#!/usr/bin/env python3
"""Independent strong imports, exact signed files and real NVRAM transcript.

Does not execute binaries or access any device. Actual evidence requires direct
child PID/wait; the full EFI contract or backend is never inferred from smoke.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("v", ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py")
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)
sha = lambda data: hashlib.sha256(data).hexdigest()


def transcript(path, pid, wait):
    assert pid > 1 and wait == 0
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    starts = [r for r in rows if r["record"] == "start"]
    assert len(starts) == 1 and starts[0]["PID"] == pid and starts[0]["productionNVRAM"] is False
    checks = [r for r in rows if r["record"] == "check"]
    assert all(r["passed"] is True for r in checks) and sorted(r["id"] for r in checks) == list(range(1,len(checks)+1))
    summaries = [r for r in rows if r["record"] == "summary"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["PID"] == pid and summary["checks"] == len(checks) >= 561
    assert summary["failures"] == summary["VMCalls"] == summary["GPUCalls"] == 0
    assert summary["creates"] == summary["destroys"] == 2 and summary["EFICalls"] >= 28
    assert all(summary[k] is True for k in ("persistedRemap","ownedVariableDeleted","ownFilesRemoved"))
    assert all(summary[k] is False for k in ("productionNVRAM","fullEFIAPIContract","full27Backend"))
    calls = [r for r in rows if r["record"] == "efi-call"]
    for name in ("Create(memory)","Create(reopened)","Destroy(first)","Destroy(second)","Set(initial)","Set(replace)","Set(delete)"):
        assert sum(r["name"] == name and r["status"] == "0x0000000000000000" for r in calls) == 1
    assert sum(r["name"] == "Get(size query)" and r["status"] == "0x8000000000000005" for r in calls) == 3
    assert sum(r["name"] == "Get(undersized)" and r["status"] == "0x8000000000000005" for r in calls) == 3
    assert any(r["name"] == "Get(deleted)" and r["status"] == "0x800000000000000e" for r in calls)
    providers = [r for r in rows if r["record"] == "provider"]
    assert len(providers) == 14
    for entry in range(7):
        pair = [r for r in providers if r["entry"] == entry]
        assert [r["phase"] for r in pair] == ["before","after"]
        assert pair[0]["UUID"] == pair[1]["UUID"] == "10a81345e6c23aab8a107c6cdf0b2a64" and pair[0]["RVA"] == pair[1]["RVA"]
        assert all(r["strongImport"] is True for r in pair)
    modules = [r for r in rows if r["record"] == "module"]
    assert len(modules) == 6
    for entry in range(3):
        pair = [r for r in modules if r["entry"] == entry]
        assert [r["phase"] for r in pair] == ["first-create","second-create"]
        assert pair[0]["path"] == pair[1]["path"] and pair[0]["RVA"] == pair[1]["RVA"]
        assert all(r["actualLoaded"] is True for r in pair)
    assert all(r["exact"] is True for r in rows if r["record"] == "file")
    return summary


def main(build):
    manifest = json.loads((build / "candidate.json").read_text())
    spec = importlib.util.spec_from_file_location("signature", ROOT / "scripts/development/verify-macho-code-directory.py")
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    bindings, controls = [], []
    for name, expected in manifest["sourceSHA256"].items():
        assert sha((build / "source" / name).read_bytes()) == expected
    for candidate in manifest["candidates"]:
        for row in [candidate[k] for k in ("efi","rtti","probe","seed")]+candidate["modules"]:
            data = Path(row["path"]).read_bytes()
            assert sha(data) == row["sha256"] and len(data) == row["bytes"]
            if "CDHash" in row:
                checked = verifier.check(data)
                assert len(checked) == 1 and checked[0]["cdhash"] == row["CDHash"]
                assert struct.unpack_from("<II",data,4) == (0x100000c,0x81000002 if candidate["role"] == "macos" and row is candidate["probe"] else 0x80000002)
                if candidate["role"] == "ios":
                    at = next(at for cmd,at,_ in V.M.commands(data) if cmd == 0x32)
                    assert struct.unpack_from("<III",data,at+8) == (2,0x100100,0x100100)
        data = Path(candidate["probe"]["path"]).read_bytes()
        actual, deps = V.imports(data), V.M.libraries(data)
        for row in candidate["strongPositiveBindings"]:
            assert V.require_binding(actual,deps,row["symbol"],"@rpath/EfiSupport27.dylib") == row
            for mutation in ("weak","flat","missing"):
                changed = [dict(r) for r in actual]; target = next(r for r in changed if r["symbol"] == row["symbol"])
                if mutation == "weak": target["weak"] = True
                elif mutation == "flat": target["ordinal"] = -2
                else: changed.remove(target)
                try: V.require_binding(changed,deps,row["symbol"],"@rpath/EfiSupport27.dylib")
                except AssertionError: controls.append({"role":candidate["role"],"symbol":row["symbol"],"control":mutation,"rejected":True})
                else: raise AssertionError("invalid binding accepted")
        for module in candidate["modules"]:
            data = Path(module["path"]).read_bytes(); actual = V.imports(data); deps = V.M.libraries(data)
            assert len(actual) == len(module["review"]["routes"])
            assert not any(cmd == 0x80000018 for cmd,_,_ in V.M.commands(data))
            for row in actual:
                V.require_binding(actual,deps,row["symbol"],"/usr/lib/libSystem.B.dylib")
                assert row["ordinal"] == 2
            source = Path(module["review"]["source"])
            assert sha((source / "raw").read_bytes()) == module["review"]["rawSHA256"]
            before = (source / "strong-flat.mac").read_bytes()
            assert sha(before) == module["review"]["reconstructedSHA256"]
            for cmd,at,_ in V.M.commands(before):
                if cmd == 0x19:
                    for i in range(struct.unpack_from("<I",before,at+64)[0]):
                        s=at+72+i*80; length=struct.unpack_from("<Q",before,s+40)[0]; off=struct.unpack_from("<I",before,s+48)[0]; flags=struct.unpack_from("<I",before,s+64)[0]
                        if length and (flags & 255) not in (1,12,18): assert before[off:off+length] == data[off:off+length]
            bindings.append({"role":candidate["role"],"module":Path(module["path"]).name,"originalStrongPositiveImports":actual,"unchangedReconstructedCodeAndDataBytes":True})
    process=next(r for r in manifest["processes"] if r["label"] == "macos-own-nvram-native")
    assert process["reaped"] is True
    native=transcript(build / "macos-own-nvram-native.stdout",process["directChildPID"],process["observedWaitExit"])
    print(json.dumps({"candidateSHA256":sha((build / "candidate.json").read_bytes()),"originalModuleBindings":bindings,"bindingNegativeControls":controls,"actualMacOwnNVRAMFixture":native,"iOSExecuted":False,"fullEFIAPIContract":False,"full27Backend":False,"passed":True},indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve())
