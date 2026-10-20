#!/usr/bin/env python3
"""Restore evidenced VZ27 import ordinals in a new app-private local candidate.

Never dlopen or deploys anything. Original weak imports remain weak. Cache-only
imports without an exact owner oracle remain explicit unresolved rows; --require-
complete refuses to emit a binary while any diagnostic flat lookup remains.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
READER = R / "DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py"
ORIGINAL = READER.parent / "virtualization27-stack-audit-v1/reconstructed-macos/Virtualization"
V5_DIR = N / "vz-resilient-schema-root-v1/build-v5"
V5 = V5_DIR / "VZ27.relative-data.ios.dylib"
SOURCE_PINS = {
    READER: "87ac47aecb496d313fece77ebab6e64fa28c3bd1df563142da8aa56a40c509a3",
    ORIGINAL: "a55130db33e6b25a48bd7899f7f12d0c81cfb73095db5a4f5b1bf67c8701fccc",
    V5: "1a15b7d53082ac2b870f081d72de968e2a6aca9c743e8888c4588331566f9356",
}
DYLIB_COMMANDS = (12, 0x80000018, 0x8000001F, 0x80000023)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def undefined_symbols(reader, data):
    commands = [row for row in reader.commands(data) if row[0] == 2]
    assert len(commands) == 1
    offset, count, strings, strings_size = struct.unpack_from("<4I", data, commands[0][1] + 8)
    assert offset + count * 16 <= len(data) and strings + strings_size <= len(data)
    records = {}
    for index in range(count):
        at = offset + index * 16
        name_index, kind, section, description, value = struct.unpack_from("<IBBHQ", data, at)
        if kind & 0x0E or not kind & 1 or not name_index:
            continue
        name = reader.cstring(data, strings + name_index, strings + strings_size)
        assert name not in records, "ambiguous original nlist ownership: " + name
        records[name] = {"symbol": name, "nlistIndex": index, "nlistDescription": description,
                         "ordinal": description >> 8, "weak": bool(description & 0x40),
                         "kind": kind, "section": section, "value": value}
    return records


def dependencies(reader, data):
    rows = []
    for command, at, size in reader.commands(data):
        if command in DYLIB_COMMANDS:
            offset = struct.unpack_from("<I", data, at + 8)[0]
            rows.append({"ordinal": len(rows) + 1, "command": command, "fileoff": at,
                         "commandSize": size, "nameOffset": offset,
                         "path": reader.cstring(data, at + offset, at + size)})
    return rows


def exports(reader, path):
    data = path.read_bytes()
    commands = [row for row in reader.commands(data) if row[0] == 0x80000033]
    assert len(commands) == 1, str(path)
    offset, size = struct.unpack_from("<II", data, commands[0][1] + 8)
    assert offset + size <= len(data)
    # The presence ledger does not treat a reexport ordinal as a function RVA,
    # nor an absolute export's value as a dereferenceable data address.
    rows = reader.export_trie(data[offset:offset + size])
    return {row["symbol"]: {"flags": row["flags"], "kind": row["flags"] & 3,
                             "reexport": bool(row["flags"] & 8),
                             "valueIsAddressOnlyForRegularNonReexport": not bool(row["flags"] & 8) and row["flags"] & 3 != 2,
                             "rawValue": row["address"]} for row in rows}


def restore_imports(reader, original, current, v5_manifest):
    baseline = reader.imports(original)["imports"]
    imports = reader.imports(current)["imports"]
    nlist = undefined_symbols(reader, original)
    assert len(nlist) == 903 and sum(not row["weak"] for row in nlist.values()) == 844
    assert len(baseline) == 1016 and len(imports) == 1056
    for before, after in zip(baseline, imports[:1016]):
        assert before["name"] == after["name"]
    before_sites = list(reader.chain_entries(current))
    mutable = bytearray(current)
    restored, retained, unresolved = [], [], []
    for row in imports[:1016]:
        evidence = nlist.get(row["name"])
        if evidence is None:
            unresolved.append({"index": row["index"], "symbol": row["name"],
                               "ordinal": row["ordinal"], "weak": row["weak"],
                               "reason": "cache-optimized import has no original undefined-nlist owner/weak evidence",
                               "chainSites": [site["fileoff"] for site in before_sites if site["import_index"] == row["index"]]})
            continue
        if row["ordinal"] == 52:
            assert row["name"].startswith("_swift_cvw_") and not row["weak"]
            assert evidence["ordinal"] == 37 and not evidence["weak"]
            retained.append({**row, "originalEvidence": evidence,
                             "policy": "retain frozen explicit typed VZ-only CVW provider ordinal52"})
            continue
        assert row["ordinal"] == -2 and row["weak"]
        assert 1 <= evidence["ordinal"] <= 51
        old_word = struct.unpack_from("<I", mutable, row["command"])[0]
        new_word = old_word & ~0x1FF | evidence["ordinal"] | int(evidence["weak"]) << 8
        struct.pack_into("<I", mutable, row["command"], new_word)
        restored.append({"index": row["index"], "symbol": row["name"], "fileoff": row["command"],
                         "beforeWord": old_word, "afterWord": new_word,
                         "originalEvidence": evidence, "symbolPoolOffsetUnchanged": True})
    assert len(restored) == 839 and len(retained) == 6 and len(unresolved) == 171
    routes = v5_manifest["newStrongDataImports"]
    assert len(routes) == 40
    requirements = [row for row in routes if row["labels"] == ["resilientRequirement"]]
    assert len(requirements) == 17
    for index, route in enumerate(routes, 1016):
        entry = imports[index]
        assert entry["name"] == route["symbol"] and entry["ordinal"] == route["ordinal"] and not entry["weak"]
        sites = [site for site in before_sites if site["import_index"] == index]
        assert len(sites) == 1 and sites[0]["auth"] and sites[0]["bind"]
        word = sites[0]["word"]
        assert word >> 49 & 3 == 2 and word >> 48 & 1 == 1
        assert word >> 32 & 0xFFFF == int(route["discriminator"], 16)
        if route in requirements:
            assert route["discriminator"] == "0x7d4c"
    assert [row["word"] for row in reader.chain_entries(mutable)] == [row["word"] for row in before_sites]
    return mutable, restored, retained, unresolved, nlist, routes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--dikit-candidate", type=pathlib.Path,
                        help="New frozen DIKit+genuineDI2 candidate; only its own bundle files are copied")
    parser.add_argument("--require-complete", action="store_true",
                        help="Reject output binary until every diagnostic flat import has an exact owner oracle")
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(R) and not out.exists()
    out.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location("pinned_vz_reader", READER)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    inputs = []
    for path, expected in SOURCE_PINS.items():
        record = pin(path)
        assert record["sha256"] == expected
        inputs.append(record)
    inputs += [pin(V5_DIR / "candidate.json"), pin(pathlib.Path(__file__).resolve())]
    manifest = json.loads((V5_DIR / "candidate.json").read_text())
    current, original = V5.read_bytes(), ORIGINAL.read_bytes()
    mutable, restored, retained, unresolved, nlist, data_routes = restore_imports(reader, original, current, manifest)
    deps = dependencies(reader, mutable)
    assert len(deps) == 52
    provider_bindings, staged = [], []
    if args.dikit_candidate:
        provider_path = args.dikit_candidate.resolve()
        assert provider_path.is_relative_to(R)
        candidate = json.loads(provider_path.read_text())
        assert candidate["genuineDIKitUUID"] == "652b07a998be31d298d7ffcaf14aca5e"
        assert candidate["genuineDI2UUID"] == "a456d4a4d6ab3549965d0400f3552de3"
        inputs.append(pin(provider_path))
        files = {row["name"]: row for row in candidate["files"]}
        required = {25: "DiskImageKit27.dylib", 31: "DiskImages227.dylib"}
        bundle = out / "bundle"
        bundle.mkdir()
        for row in candidate["files"]:
            if not row["name"].endswith(".dylib"):
                continue
            path = pathlib.Path(row["path"])
            assert row["name"] == pathlib.Path(row["name"]).name
            record = pin(path)
            assert record["bytes"] == row["bytes"] and record["sha256"] == row["sha256"]
            inputs.append(record)
            target = bundle / row["name"]
            shutil.copy2(path, target)
            assert sha(target.read_bytes()) == row["sha256"]
            staged.append(pin(target))
        for ordinal, name in required.items():
            row = deps[ordinal - 1]
            assert row["command"] == 12
            file = files[name]
            direct = exports(reader, pathlib.Path(file["path"]))
            after = "@loader_path/" + name
            encoded = after.encode() + b"\0"
            assert len(encoded) <= row["commandSize"] - row["nameOffset"]
            at = row["fileoff"] + row["nameOffset"]
            mutable[at:row["fileoff"] + row["commandSize"]] = encoded + bytes(row["commandSize"] - row["nameOffset"] - len(encoded))
            selected = [entry for entry in reader.imports(mutable)["imports"] if entry["ordinal"] == ordinal]
            provider_bindings.append({"ordinal": ordinal, "beforePath": row["path"], "afterPath": after,
                                      "originalLoadCommandKindAndOrdinalPreserved": True,
                                      "provider": file, "selectedImports": [{"symbol": entry["name"],
                                          "weak": entry["weak"], "directExport": direct.get(entry["name"])} for entry in selected],
                                      "actualDIKitLoadProven": False,
                                      "DI2OwnedObjectAndPOSIXFDProofOnly": ordinal == 31})
    ledger = {"originalUndefinedNlist": 903, "originalNonweakNlistPresenceGate": 844,
              "chainedImportRows": 1056, "rowsRestoredFromOriginalNlist": restored,
              "existingScopedCVWRowsPreserved": retained, "originalMetadataDataRoutesPreserved": data_routes,
              "diagnosticFlatImportsUnresolved": unresolved, "privateProviderBindings": provider_bindings,
              "originalLegitimateWeakImportsAreNotRemoved": True,
              "completeStrongVZClosure": False, "nativeLoaded": False, "actualVZCalls": 0,
              "guestInstructions": 0, "originalVMMExecuted": False, "deviceOperations": False}
    save(out / "import-ledger.json", ledger)
    save(out / "inputs.json", inputs)
    if args.require_complete and unresolved:
        save(out / "blocked.json", {"reason": "171 original cache-optimized rows require exact owner/weak evidence",
                                   "diagnosticFlatImportsRemaining": len(unresolved),
                                   "binaryEmitted": False, "deviceOperations": False})
        return 78
    bundle = out / "bundle"
    bundle.mkdir(exist_ok=True)
    # Keep the two previously explicit app-owned ABI providers beside the new
    # copy. Neither is inferred as full CPU/USB functionality.
    old_provider_pins = {"VM27VZCVW.dylib": "49bb11d6417a93bc6d8c63f5505a98c6b718747cd64d8c7c6945322c1f2aa826",
                         "VM27USBUnavailable.dylib": "aa1c4213943516fa4237591b6131403fd0e92d36155ec0f0498ae0337e8976d6"}
    for name, expected in old_provider_pins.items():
        source = N / "virtualization27-native-closure-v2/load-only-scoped-cvw-v1" / name
        assert source.is_file(), str(source)
        assert sha(source.read_bytes()) == expected
        inputs.append(pin(source))
        target = bundle / name
        shutil.copy2(source, target)
        staged.append(pin(target))
    binary = bundle / "VZ27.original-imports-partial.ios.dylib"
    binary.write_bytes(mutable)
    processes = []
    for label, argv in [("sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", str(binary)]),
                        ("strict", ["codesign", "--verify", "--strict", str(binary)]),
                        ("dyld", ["xcrun", "dyld_info", "-validate_only", str(binary)]),
                        ("identity", ["codesign", "-d", "--verbose=4", str(binary)])]:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = child.communicate(timeout=30)
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        processes.append({"label": label, "argv": argv, "PID": child.pid,
                          "wait": child.returncode, "reaped": True})
        save(out / "processes.json", processes)
        assert child.returncode == 0, stderr.decode()
    final = binary.read_bytes()
    after_imports = reader.imports(final)["imports"]
    assert len(after_imports) == 1056
    assert sum(row["ordinal"] == -2 for row in after_imports) == 171
    assert sum(not row["weak"] for row in after_imports) == 841
    before_chains, after_chains = list(reader.chain_entries(current)), list(reader.chain_entries(final))
    assert [(row["fileoff"], row["word"]) for row in before_chains] == [(row["fileoff"], row["word"]) for row in after_chains]
    sections = []
    for segment in reader.segments(current):
        for section in segment["sections"]:
            offset, size = section["fileoff"], section["size"]
            if size and offset and section["flags"] & 0xFF not in (1, 12, 18):
                assert current[offset:offset + size] == final[offset:offset + size]
                sections.append({"segment": segment["name"], "section": section["name"],
                                 "fileoff": offset, "bytes": size, "sha256": sha(final[offset:offset + size])})
    for record in inputs:
        assert pin(pathlib.Path(record["path"])) == record
    save(out / "inputs.json", inputs)
    save(out / "candidate.json", {"scope": "local-partial-original-import-restoration-not-full-VZ-closure",
          "binary": pin(binary), "stagedPrivateLibraries": staged, "originalVZUUID": "418efc4809d93606918eb6f95baeffdc",
          "chainedImportRows": 1056, "originalNlistRowsRestored": 839,
          "strongImportRows": 841, "originalLegitimateWeakRows": 44,
          "diagnosticFlatImportsRemaining": 171, "allChainWordsAndPACUnchanged": True,
          "seventeenOriginalDA7d4cRequirementsPreserved": True, "allNonemptyFileBackedSectionsUnchanged": sections,
          "allOriginalInstructionAndRelativeMetadataBytesUnchanged": True,
          "originalNonweakNlistPresenceGateRequired": 844,
          "onlyTwoExplicitGenuineDIKitDI2DependencyPathsChanged": bool(args.dikit_candidate),
          "compiledAndSignedOnly": True, "nativeLoaded": False, "functionCallsAllowed": False,
          "completeStrongVZClosure": False, "completeMacOS27Backend": False,
          "originalVMMExecuted": False, "deviceOperations": False, "systemModified": False})
    print(json.dumps({"candidate": str(binary), "restoredRows": 839, "strongImportRows": 841,
                      "diagnosticFlatRemaining": 171, "completeStrongVZClosure": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
