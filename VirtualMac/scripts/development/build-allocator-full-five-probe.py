#!/usr/bin/env python3
"""Build strong private five-API probes and run only the macOS allocation fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess

NAMES = ["malloc_type_malloc", "malloc_type_calloc", "malloc_type_realloc",
         "malloc_type_posix_memalign", "malloc_type_zone_malloc_with_options"]
RIGHTS = {"com.apple.private.amfi.can-execute-cdhash": True,
          "com.apple.private.security.no-sandbox": True,
          "com.apple.private.security.no-container": True,
          "get-task-allow": True, "platform-application": True}
DEVICE = "/var/root/VirtualMac2/testing/allocator-full-five-v1"
ORIGINAL_SHA = "d037098b9c45882d54fba0cafb12d7e7c1d1d94fe46831389e1a370879e72503"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def macho(path):
    data = path.read_bytes()
    magic, cpu, subtype, kind, count, size = struct.unpack_from("<6I", data)
    if magic != 0xfeedfacf or cpu != 0x100000c or count > 128 or size > 16384:
        raise ValueError("unsupported Mach-O header")
    at, uuids, versions = 32, [], []
    for _ in range(count):
        cmd, length = struct.unpack_from("<II", data, at)
        if length < 8 or length % 8 or at + length > 32 + size:
            raise ValueError("invalid Mach-O command")
        if cmd == 0x1b:
            uuids.append(data[at + 8:at + 24].hex())
        elif cmd == 0x32:
            versions.append(struct.unpack_from("<III", data, at + 8))
        at += length
    if at != 32 + size or len(uuids) != 1 or len(versions) != 1:
        raise ValueError("missing exact Mach-O identity")
    return dict(bytes=len(data), sha256=sha(path), uuid=uuids[0], subtype=subtype,
                filetype=kind, platform=versions[0][0], minos=versions[0][1], sdk=versions[0][2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider", type=Path,
                        help="Exact pinned full-five project library; its bytes are never resigned")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    root = project.parent
    original = args.provider or (root / "DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/"
        "modern-allocator-provider-project-build-v1/build/VM27AllocatorProvider.dylib")
    if original.is_symlink() or not original.is_file() or sha(original) != ORIGINAL_SHA:
        raise ValueError("exact original full-five library required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(label, argv, execute=False):
        p = subprocess.run(argv, capture_output=True, timeout=45)
        (output / (label + ".stdout")).write_bytes(p.stdout)
        (output / (label + ".stderr")).write_bytes(p.stderr)
        commands.append(dict(label=label, argv=argv, exit=p.returncode,
                             macFixtureExecuted=execute, deviceContacted=False))
        if p.returncode:
            raise RuntimeError(label + ": " + p.stderr.decode(errors="replace"))
        return p

    clang = run("clang", ["xcrun", "--find", "clang"]).stdout.decode().strip()
    sdks = {kind: run(kind + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"]).stdout.decode().strip()
            for kind, sdk in (("ios", "iphoneos"), ("mac", "macosx"))}
    source = project / "scripts/tests/test-modern-allocator-full-five.c"
    source_copy = output / "source"
    source_copy.mkdir()
    shutil.copyfile(source, source_copy / source.name)
    for filename in ("modern_typed_allocator_compat.c", "modern_typed_allocator.h"):
        shutil.copyfile(project / "vz/host" / filename, source_copy / filename)
    base = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
            "-fno-typed-memory-operations-experimental"]
    generated = {}
    for kind, target in (("ios", "arm64e-apple-ios16.1"), ("mac", "arm64-apple-macos13.0")):
        folder = output / kind
        folder.mkdir()
        library = folder / "VM27AllocatorProvider.dylib"
        if kind == "ios":
            shutil.copyfile(original, library)
        else:
            run("mac-provider-compile", [clang, "-target", target, "-isysroot", sdks[kind],
                *base, "-fvisibility=hidden", "-dynamiclib", "-Wl,-install_name,@rpath/VM27AllocatorProvider.dylib",
                str(source_copy / "modern_typed_allocator_compat.c"), "-o", str(library)])
            run("mac-provider-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", str(library)])
        run(kind + "-provider-strict", ["codesign", "--verify", "--strict", str(library)])
        details = run(kind + "-provider-signature", ["codesign", "-d", "--verbose=4", str(library)]).stderr
        cdhash = re.search(rb"CDHash=([a-f0-9]{40})", details)[1].decode()
        exported = run(kind + "-provider-exports", ["xcrun", "nm", "-gU", str(library)]).stdout.decode()
        export_rvas = {line.split()[-1][1:]: int(line.split()[0], 16)
                       for line in exported.splitlines()}
        if set(export_rvas) != set(NAMES):
            raise ValueError("provider must have exactly the five real exported APIs")
        identity = macho(library)
        if kind == "ios" and (identity["subtype"] != 0x80000002 or identity["platform"] != 2 or
                              identity["minos"] != 0x100100 or identity["sdk"] != 0x100100):
            raise ValueError("exact previously built iOS arm64e ABI0 provider identity required")
        runtime_path = (DEVICE + "/" + library.name) if kind == "ios" else str(library)
        uuid = ",".join("0x" + identity["uuid"][i:i+2] for i in range(0, 32, 2))
        header = "// Exact generated private provider pins.\n"
        header += "static const char PinPath[] = " + json.dumps(runtime_path) + ";\n"
        header += "static const char PinSHA[] = " + json.dumps(identity["sha256"]) + ";\n"
        header += "static const char PinTarget[] = " + json.dumps(kind) + ";\n"
        header += "static const char PinUUIDHex[] = " + json.dumps(identity["uuid"]) + ";\n"
        header += "static const unsigned char PinUUID[16] = {" + uuid + "};\n"
        for name, value in (("PinBytes", identity["bytes"]), ("PinSubtype", identity["subtype"]),
                            ("PinPlatform", identity["platform"]), ("PinMinOS", identity["minos"]),
                            ("PinSDK", identity["sdk"])):
            header += "static const unsigned long long " + name + " = " + str(value) + "ULL;\n"
        header += "static const uintptr_t PinRVAs[5] = {" + ",".join(
            "0x%x" % export_rvas[name] for name in NAMES) + "};\n"
        (folder / "allocator-full-five-pins.h").write_text(header)
        probe = folder / "allocator-full-five-probe"
        run(kind + "-probe-compile", [clang, "-target", target, "-isysroot", sdks[kind], *base,
            "-I", str(folder), str(source_copy / source.name), str(library),
            "-Wl,-rpath,@executable_path", "-o", str(probe)])
        rights_path = folder / "Probe.entitlements"
        rights_path.write_bytes(plistlib.dumps(RIGHTS if kind == "ios" else {}))
        sign = ["codesign", "--force", "--sign", "-", "--timestamp=none",
                "--identifier", "com.virtualmac.diagnostics.allocator-full-five-v1"]
        if kind == "ios":
            sign += ["--entitlements", str(rights_path)]
        run(kind + "-probe-sign", sign + [str(probe)])
        run(kind + "-probe-strict", ["codesign", "--verify", "--strict", str(probe)])
        signature = run(kind + "-probe-signature", ["codesign", "-d", "--verbose=4", str(probe)]).stderr
        imports = run(kind + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)]).stdout.decode()
        selected = [line for line in imports.splitlines() if any("_" + name in line for name in NAMES)]
        if len(selected) != 5 or any("weak" in line.lower() or "VM27AllocatorProvider" not in line
                                     for line in selected):
            raise ValueError("five exact strong two-level provider imports required")
        run(kind + "-probe-validate", ["xcrun", "dyld_info", "-validate_only", str(probe)])
        probe_identity = macho(probe)
        if kind == "ios" and probe_identity["subtype"] != 0x80000002:
            raise ValueError("probe arm64e ABI0 required")
        generated[kind] = dict(provider={**identity, "path": str(library), "runtimePath": runtime_path,
            "cdhash": cdhash, "exports": export_rvas},
            probe={**probe_identity, "path": str(probe), "cdhash": re.search(
                rb"CDHash=([a-f0-9]{40})", signature)[1].decode()}, strongImportRows=selected,
            entitlements=RIGHTS if kind == "ios" else {}, deviceExecuted=False)
    local = run("mac-real-allocation-fixture", [generated["mac"]["probe"]["path"], "--library",
                generated["mac"]["provider"]["runtimePath"]], execute=True)
    validator = project / "scripts/tests/validate-modern-allocator-full-five.py"
    run("mac-fixture-validation", ["python3", str(validator), "--stdout",
        str(output / "mac-real-allocation-fixture.stdout"), "--native-exit", "0",
        "--target", "mac", "--provider-sha", generated["mac"]["provider"]["sha256"]])
    report = dict(schemaVersion=1, files=generated, originalIOSProviderSHA=ORIGINAL_SHA,
                  sourceSHA=sha(source), providerSourceSHA=sha(source_copy / "modern_typed_allocator_compat.c"),
                  localMacAllocationFixturePassed=True, deviceContacted=False, deviceExecuted=False,
                  full27VMMProved=False, commands=commands)
    (output / "build-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"built": True, "localMacFixturePassed": True, "ios": generated["ios"],
                      "deviceExecuted": False}, indent=2))


if __name__ == "__main__":
    main()
