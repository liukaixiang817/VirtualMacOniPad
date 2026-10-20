#!/usr/bin/env python3
"""Route thirteen real original VMM imports to an independently built provider.

The original executable and all code/data sections stay intact. No weak flags,
addends, chained PAC fields, callsites, capabilities or exception state change.
The signed iOS executable is a partial private load candidate, NOT a completed
closure and NOT authorized for execution by this build tool.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SEVEN_SHA = "52e67fa4036c09a762283e6fdc2f49a3567dad0fac98fcb8baa2728ae747ff9e"
ORIGINAL_SHA = "c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422"
TARGETS = {"__ZNSt3__18to_charsEPcS0_" + kind + suffix: 14
           for kind in ("f", "d", "e")
           for suffix in ("", "NS_12chars_formatE", "NS_12chars_formatEi")}
TARGETS.update({symbol: -3 for symbol in (
    "__ZnwmSt19__type_descriptor_t", "__ZnamSt19__type_descriptor_t",
    "__ZdlPvSt19__type_descriptor_t", "__ZdaPvSt19__type_descriptor_t")})
PROVIDER = "@rpath/VM27CxxABICompat.dylib"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
        ROOT / "scripts/development" / (name + ".py"))
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def ranges(tool, data):
    result = []
    for cmd, at, size in tool.commands(data):
        if cmd != 0x19:
            continue
        count = struct.unpack_from("<I", data, at + 64)[0]
        assert size == 72 + count * 80
        for i in range(count):
            pos = at + 72 + i * 80
            length = struct.unpack_from("<Q", data, pos + 40)[0]
            offset, flags = struct.unpack_from("<I", data, pos + 48)[0], struct.unpack_from("<I", data, pos + 64)[0]
            if length and offset and flags & 255 not in (1, 12, 18):
                assert offset + length <= len(data)
                name = data[pos:pos + 16].split(b"\0")[0].decode()
                result.append({"name": name, "offset": offset, "bytes": length,
                    "sha256": sha(data[offset:offset + length])})
    return result


def main(input_path, provider_path, output):
    tool = load_tool("prepare-modern-vmm-runtime-imports")
    source, lib = Path(input_path).resolve(), Path(provider_path).resolve()
    assert source.is_file() and not source.is_symlink() and lib.is_file() and not lib.is_symlink()
    before = source.read_bytes()
    assert sha(before) == SEVEN_SHA and len(before) == 5195312
    assert struct.unpack_from("<III", before, 4) == (0x100000c, 0x80000002, 2)
    nm = subprocess.run(["nm", "-gU", str(lib)], capture_output=True, check=True, timeout=20)
    exported = {parts[-1] for line in nm.stdout.decode().splitlines() if len(parts := line.split()) == 3}
    assert exported == set(TARGETS), "Every selected import must have an actual matching provider definition"
    assert struct.unpack_from("<I", lib.read_bytes(), 8)[0] == 0x80000002
    old = tool.import_rows(before)
    libraries = tool.libraries(before)
    assert len(old) == 1203 and sum(not row["weak"] for row in old) == 1064
    assert len(libraries) == 53 and PROVIDER not in libraries
    assert libraries[50] == "@rpath/VM27CxxProvider.dylib"
    new_ordinal = 51
    data = bytearray(before)
    edited = []
    for row in old:
        if row["symbol"] not in TARGETS:
            continue
        assert row["ordinal"] == TARGETS[row["symbol"]] and not row["weak"] and row["addend"] == 0
        word = struct.unpack_from("<I", data, row["offset"])[0]
        struct.pack_into("<I", data, row["offset"], (word & ~255) | new_ordinal)
        edited.append({**row, "newOrdinal": new_ordinal, "newProvider": PROVIDER})
    assert len(edited) == 13 and {row["symbol"] for row in edited} == set(TARGETS)
    symtab = [struct.unpack_from("<IIII", data, at + 8) for cmd, at, _ in tool.commands(data) if cmd == 2]
    assert len(symtab) == 1
    symoff, count, stroff, strsize = symtab[0]
    nlist = []
    for index in range(count):
        at = symoff + index * 16
        strx, kind, section, desc, value = struct.unpack_from("<IBBHQ", data, at)
        if kind & 0xe0 or kind & 0xe or not strx:
            continue
        assert strx < strsize
        symbol = tool.string(data, stroff + strx, stroff + strsize)
        if symbol not in TARGETS:
            continue
        # The original typed operators' nlist declares libc++14 even though
        # their actual chained records use strong weak-definition coalescing
        # (-3). Preserve this distinction; do not invent matching old owners.
        assert desc >> 8 == 14 and not desc & 0x40
        new = (desc & 255) | new_ordinal << 8
        struct.pack_into("<H", data, at + 6, new)
        nlist.append({"symbol": symbol, "offset": at + 6, "before": desc, "after": new})
    assert len(nlist) == 13 and {row["symbol"] for row in nlist} == set(TARGETS)
    old_commands = list(tool.commands(data))
    assert not any(cmd == 0x1d for cmd, _, _ in old_commands)
    all_commands = []
    dependency_index = 0
    changed_commands = []
    for cmd, at, size in old_commands:
        raw = bytes(data[at:at + size])
        if cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            dependency_index += 1
            if dependency_index == 51:
                replacement = tool.dylib_command(PROVIDER)
                assert len(replacement) == size, "Do not move original file-backed sections"
                raw = replacement
                changed_commands.append({"offset": at, "bytes": size,
                    "before": libraries[50], "after": PROVIDER})
        all_commands.append(raw)
    assert len(changed_commands) == 1
    command_bytes = b"".join(all_commands)
    old_end = 32 + struct.unpack_from("<I", before, 20)[0]
    new_end = 32 + len(command_bytes)
    sections = ranges(tool, before)
    first_section = min(row["offset"] for row in sections)
    assert old_end <= new_end <= first_section and not any(before[old_end:first_section])
    data[32:new_end] = command_bytes
    struct.pack_into("<II", data, 16, len(all_commands), len(command_bytes))
    after = tool.import_rows(data)
    for a, b in zip(old, after):
        expected = dict(a)
        if a["symbol"] in TARGETS:
            expected["ordinal"] = new_ordinal
        assert b == expected
    new_libraries = list(libraries)
    new_libraries[50] = PROVIDER
    assert ranges(tool, data) == sections and tool.libraries(data) == new_libraries
    allowed = set(range(16, 24)) | set(range(32, new_end))
    allowed.update(row["offset"] for row in edited)
    for row in nlist:
        allowed.update((row["offset"], row["offset"] + 1))
    changes = [at for at, (a, b) in enumerate(zip(before, data)) if a != b]
    assert len(data) == len(before) and set(changes) <= allowed
    out = Path(output).resolve()
    out.mkdir(mode=0o700, exist_ok=False)
    (out / "source").mkdir()
    (out / "source" / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    candidate = out / "VirtualMachine27.twenty-strong.macos.unsigned"
    candidate.write_bytes(data)

    def run(label, args):
        r = subprocess.run(args, capture_output=True, timeout=30)
        (out / (label + ".command.json")).write_text(json.dumps(args, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(r.stdout)
        (out / (label + ".stderr")).write_bytes(r.stderr)
        assert r.returncode == 0, label
        return r

    run("macos-static", ["xcrun", "dyld_info", "-validate_only", str(candidate)])
    # This changes only the declared platform/SDK, not the original dependency
    # names. Missing macOS frameworks remain genuine dyld load blockers.
    ios = bytearray(data)
    builds = [at for cmd, at, _ in tool.commands(ios) if cmd == 0x32]
    assert len(builds) == 1
    struct.pack_into("<III", ios, builds[0] + 8, 2, 0x100100, 0x100100)
    ipad = out / "VirtualMachine27.twenty-strong.iOS16.1"
    ipad.write_bytes(ios)
    ent = {"platform-application": True, "com.apple.private.security.no-container": True}
    (out / "Candidate.entitlements").write_bytes(plistlib.dumps(ent))
    run("ios-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none",
        "--identifier", "com.virtualmac.diagnostics.vmm27.twenty-strong",
        "--entitlements", str(out / "Candidate.entitlements"), str(ipad)])
    run("ios-strict", ["codesign", "--verify", "--strict", str(ipad)])
    run("ios-static", ["xcrun", "dyld_info", "-validate_only", str(ipad)])
    sig = run("ios-signature", ["codesign", "-dvvv", str(ipad)]).stderr
    assert plistlib.loads(run("ios-rights", ["codesign", "-d", "--entitlements", ":-", str(ipad)]).stdout) == ent
    checked = load_tool("verify-macho-code-directory").check(ipad.read_bytes())
    (out / "ios-code-directory.json").write_text(json.dumps(checked, indent=2) + "\n")
    assert ranges(tool, ipad.read_bytes()) == sections
    assert tool.import_rows(ipad.read_bytes()) == after
    assert tool.libraries(ipad.read_bytes()) == new_libraries
    result = {"originalVMMSourceSHA256": ORIGINAL_SHA, "inputSevenCandidateSHA256": SEVEN_SHA,
        "inputPath": str(source), "providerPath": str(lib), "providerSHA256": sha(lib.read_bytes()),
        "providerActualExports": sorted(exported), "selectedNewImports": edited,
        "matchingNlistChanges": nlist, "newPositiveOrdinal": new_ordinal,
        "changedLoadCommand": changed_commands,
        "loadCommandHeadroomBytesBeforeAndAfter": first_section - new_end,
        "oldCxxExportsMustBeSuppliedByUnchangedBackingReexport": True,
        "newTotalExplicitCompatibilityBindings": 20,
        "originalImportCount": 1203, "originalStrongCount": 1064,
        "allWeakFlagsAndAddendsPreserved": True, "allOtherImportsPreserved": True,
        "allFileBackedSectionBytesIdentical": True, "sections": sections,
        "newChangedBytesBeforePlatformPort": len(changes),
        "macos": {"path": str(candidate), "sha256": sha(candidate.read_bytes()), "bytes": candidate.stat().st_size},
        "ios": {"path": str(ipad), "sha256": sha(ipad.read_bytes()), "bytes": ipad.stat().st_size,
            "CDHash": re.search(rb"CDHash=([0-9a-f]{40})", sig)[1].decode(), "entitlements": ent,
            "platform": 2, "minOS": 1048832, "SDK": 1048832},
        "dependencies": new_libraries, "staticValidation": True,
        "systemModified": False, "deviceOperations": False, "executed": False,
        "completeVMMClosure": False,
        "executionGate": "Do not launch this executable: original macOS dependency paths remain deliberately unresolved; Root must assemble and verify a real complete loader closure first.",
        "remainingTypedRuntimeContracts": ["__cxa_init_primary_exception", "xpc_add_bundle_with_lwcr",
            "five exact AnyObject ContiguousArray Swift prespecializations"],
        "remainingFrameworkContracts": "VZ11 class/data + DI2 + CoreServices/IOUSB/vmnet and private framework routing; missing imports are not weakened"}
    (out / "candidate-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"macos": result["macos"], "ios": result["ios"],
        "newBindings": 13, "totalExplicitBindings": 20, "completeVMMClosure": False}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("Usage: prepare-modern-vmm-cxx-closure.py PINNED_SEVEN_IMPORT_VMM IOS_PROVIDER NEW_OUTPUT_DIRECTORY")
    main(*sys.argv[1:])
