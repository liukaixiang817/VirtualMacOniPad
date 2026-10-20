#!/usr/bin/env python3
"""Inert original VMM ordinal5 dependency path-only route; no image loaded."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
SOURCE = N / "vmm-headless-checkin-original-route-v1/build-v2/VMM27.headless-checkin-route.inert.macho-data"
SOURCE_SHA = "6eafccd0c032e9749549d8b87e375f6117bd199f69523ef1d3620bad6cfcf49a"
PROVIDERS = N / "vmm-client-services-reexport-contract-v1/build-v4"
PROVIDER_FREEZE_SHA = "4ba06eb323bd623f20c380140c48b86b391f1ae4081cee7bd3b7c9082c0759e1"
AGGREGATE_SHA = "2523f38dc890bc1986c2f8737319fa398e92b15af279a6579f8f3e52c5227197"
NEW = "@loader_path/VM27ClientServices.dylib"
OLD = "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
READER = N / "original-service-factory-caller-contract-v1/inspect.py"
spec = importlib.util.spec_from_file_location("vmm_client_services_readonly_image", READER)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
sys.path.insert(0, str(R / "VirtualMac/scripts/development"))
from vz_import_addend_image import imports


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pin(p):
    b = p.read_bytes()
    return {"path": str(p.resolve()), "bytes": len(b), "sha256": sha(b)}


def image(b, name):
    class Memory:
        def read_bytes(self):
            return b
    return M.Image(name, Memory())


def transform(b):
    assert sha(b) == SOURCE_SHA
    original = image(b, "source")
    assert len(original.commands) == 70 and len(original.libraries) == 54
    assert original.section("__text")["file"] == 8528
    assert struct.unpack_from("<II", b, 16) == (70, 8496)
    at, size = 4320, 104
    assert struct.unpack_from("<6I", b, at) == (12, size, 24, 2, 80347136, 65536)
    assert b[at + 24:at + size].split(b"\0")[0].decode() == OLD
    assert original.libraries[4] == OLD
    raw = b[at:at + size]
    name = NEW.encode() + b"\0"
    assert len(name) <= size - 24
    changed = bytearray(b)
    changed[at + 24:at + size] = name + bytes(size - 24 - len(name))
    return bytes(changed), {"commandOffset": at, "commandBytes": size,
        "oldCommandHex": raw.hex(), "newPath": NEW, "oldPath": OLD,
        "ordinal": 5, "requiredCompatibilityVersionEncoded": 65536,
        "originalCurrentVersionEncodedPreserved": 80347136}


def verify(source, target, record):
    expected, r = transform(source)
    assert target == expected and record == r and len(source) == len(target)
    a, b = image(source, "source"), image(target, "target")
    assert a.commands == b.commands and a.sections == b.sections and a.segments == b.segments
    assert a.imports == b.imports and a.nlist == b.nlist
    assert imports(source) == imports(target)
    assert b.libraries == a.libraries[:4] + [NEW] + a.libraries[5:]
    assert a.data[8528:] == b.data[8528:]
    assert a.data[:4344] == b.data[:4344] and a.data[4424:] == b.data[4424:]
    required = {91: "__LSCopyApplicationInformationItem", 92: "__LSCopyMatchingApplicationsWithItems",
        93: "__LSGetCurrentApplicationASN", 94: "__LSSetApplicationInformationItem",
        981: "__kLSDisplayNameKey", 982: "__kLSPIDKey"}
    actual = imports(target)["imports"]
    for i, name in required.items():
        assert actual[i]["name"] == name and actual[i]["ordinal"] == 5 and not actual[i]["weak"] and not actual[i]["addend"]
    assert [i for i, x in enumerate(actual) if x["ordinal"] == 5] == sorted(required)
    assert actual[90]["name"] == "__LSApplicationCheckIn" and actual[90]["ordinal"] == 54
    # Original authorizations, instructions, chained PAC/fixups, tables, all
    # metadata outside the one dependency pathname allocation remain exact.
    changes = [i for i in range(len(source)) if source[i] != target[i]]
    assert changes and all(4344 <= x < 4424 for x in changes)
    return {"onlyChangedByteOffsets": changes, "allOriginalImportsAndNlistsExact": True,
        "allStrongSixImportsRetainedAtOrdinal5": True, "existingCheckIn90Ordinal54Retained": True,
        "allSectionsInstructionsAuthPACAndFixupsExact": True,
        "allLoadCommandsMetadataExceptOrdinal5PathExact": True,
        "newHeaderBytes": 0, "newOrdinals": 0, "originalVMMExecuted": False,
        "wholeStrongClosureAudited": False, "full27Backend": False}


def inverse(source, target, record):
    verify(source, target, record)
    restored = bytearray(target)
    restored[4320:4424] = bytes.fromhex(record["oldCommandHex"])
    assert bytes(restored) == source and sha(restored) == SOURCE_SHA
    return bytes(restored)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    assert sha((PROVIDERS / "freeze.json").read_bytes()) == PROVIDER_FREEZE_SHA
    for row in json.loads((PROVIDERS / "freeze.json").read_bytes())["files"]:
        b = (PROVIDERS / row["path"]).read_bytes()
        assert len(b) == row["bytes"] and sha(b) == row["sha256"]
    source = SOURCE.read_bytes()
    target, record = transform(source)
    proof = verify(source, target, record)
    restored = inverse(source, target, record)
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    path = out / "VMM27.client-services-route.inert.macho-data"
    path.write_bytes(target)
    path.chmod(0o600)
    original = out / "VMM27.roundtrip-immediate-input.inert.macho-data"
    original.write_bytes(restored)
    original.chmod(0o600)
    copies = []
    for name in ("VM27ClientServices.dylib", "VM27ClientRegistration.dylib", "VM27PrivateProcessTitle.dylib"):
        origin, copy = PROVIDERS / "ios" / name, out / name
        shutil.copyfile(origin, copy)
        copy.chmod(0o600)
        assert copy.read_bytes() == origin.read_bytes() and stat.S_ISREG(copy.lstat().st_mode) and copy.lstat().st_nlink == 1 and not copy.is_symlink()
        copies.append({"source": pin(origin), "copy": pin(copy), "ordinaryByteExactFile": True})
    assert sha((out / "VM27ClientServices.dylib").read_bytes()) == AGGREGATE_SHA
    negative = []
    for label, at in (("code", 8528), ("original PAC slot", 0x4c6230),
        ("original import90", 5047120), ("dependency command", 4320),
        ("minimum version", 4340), ("new path", 4344), ("other dependency", 7240 + 24),
        ("header count", 16), ("original symbol descriptor", 5113903)):
        if label == "original PAC slot":
            at = image(target, "negative").offset(image(target, "negative").base + at)
        corrupted = bytearray(target)
        corrupted[at] ^= 1
        try:
            inverse(source, bytes(corrupted), record)
        except (AssertionError, ValueError, IndexError, UnicodeError):
            negative.append({"name": label, "rejected": True})
        else:
            raise AssertionError(label + " accepted")
    p = subprocess.run(["xcrun", "dyld_info", "-validate_only", str(path)], capture_output=True)
    (out / "metadata.stdout").write_bytes(p.stdout)
    (out / "metadata.stderr").write_bytes(p.stderr)
    assert p.returncode == 0
    shutil.copyfile(Path(__file__), out / Path(__file__).name)
    c = {"schema": "Original VMM six LS ordinal5 path-only inert route v1",
        "builder": pin(Path(__file__)), "source": pin(SOURCE), "target": pin(path),
        "providerFreeze": pin(PROVIDERS / "freeze.json"), "providers": copies,
        "transform": record, "verification": proof, "wholeByteInverseExact": True,
        "roundtripScope": "exact immediate already-routed CheckIn input; earlier routes remain",
        "badControls": negative, "metadataExit": p.returncode,
        "requiresActualAggregateNativeReceiptBeforeRuntimeLoad": True,
        "productionClientBootstrapIntegrated": False, "originalVMMExecuted": False,
        "originalVZLoaded": False, "nativeCPUCalls": 0, "nativeVMCalls": 0,
        "deviceOperations": 0, "signatureStatus": "original input and output have no LC_CODE_SIGNATURE; inert data requires future fresh signature",
        "wholeStrongDependencyClosureAudited": False, "full27Backend": False}
    (out / "candidate.json").write_text(json.dumps(c, indent=2) + "\n")
    files = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    (out / "freeze.json").write_text(json.dumps({"schema": "Inert six LS path-only route freeze v1", "files": files}, indent=2) + "\n")
    print(json.dumps({"candidate": pin(out / "candidate.json"), "target": pin(path), "freeze": pin(out / "freeze.json"), "executed": False}))


if __name__ == "__main__":
    main()
