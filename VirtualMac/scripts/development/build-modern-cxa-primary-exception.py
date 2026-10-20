#!/usr/bin/env python3
"""Build an exact old-system exception initializer and bounded strong probe.

The native system code pins come from read-only collectors, never a guessed
layout. Only the separate Mac fixture is executed here; iOS files are prepared.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import plistlib
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
REMOTE = "/var/root/VirtualMac2/testing/cxa-primary-exception-v1"
SOURCES = [ROOT / "vz/host/modern_cxa_primary_exception_compat.cpp",
           ROOT / "vz/host/modern_cxa_primary_exception_compat.h",
           ROOT / "scripts/tests/test-modern-cxa-primary-exception.cpp",
           ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py",
           Path(__file__)]
EXPORTS = ["___cxa_init_primary_exception", "_VM27PrimaryExceptionNativeABIStatus",
           "_VM27PrimaryExceptionInitializeCalls", "_VM27PrimaryExceptionNativeCleanupAddress"]
RIGHTS = {"platform-application": True,
          "com.apple.private.security.no-container": True,
          "com.apple.private.security.no-sandbox": True,
          "com.apple.private.amfi.can-execute-cdhash": True}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def commands(data):
    assert struct.unpack_from("<I", data)[0] == 0xfeedfacf
    at = 32
    end = 32 + struct.unpack_from("<I", data, 20)[0]
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, at)
        assert size >= 8 and not size % 8 and at + size <= end
        yield command, at, size
        at += size
    assert at == end


def literal(hex_value):
    return "{" + ",".join("0x" + hex_value[i:i+2] for i in range(0, len(hex_value), 2)) + "}"


def main(destination):
    out = Path(destination).resolve()
    out.mkdir(mode=0o700, exist_ok=False)
    source = out / "source"
    source.mkdir()
    source_hashes = {}
    for path in SOURCES:
        dest = source / path.name
        shutil.copyfile(path, dest)
        assert sha(path) == sha(dest)
        source_hashes[str(path)] = sha(path)
    upstream = []
    for version in ("upstream-llvm14", "upstream-llvm21"):
        origin = N / "cxa-primary-exception-v1" / version
        dest = source / version
        shutil.copytree(origin, dest)
        for row in json.loads((origin / "sources.json").read_text()):
            assert "error" not in row
            actual = dest / row["file"]
            assert sha(actual) == row["sha256"] and actual.stat().st_size == row["bytes"]
            upstream.append(row)
    records = []

    def run(label, arguments, expected=0, timeout=40):
        child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            raise
        (out / (label + ".argv.json")).write_text(json.dumps(arguments, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        records.append({"label": label, "directChildPID": child.pid,
                        "observedWaitExit": child.returncode, "reaped": True})
        if child.returncode != expected:
            raise RuntimeError(label + ": exit=" + str(child.returncode) + " " + stderr.decode(errors="replace")[-2500:])
        return stdout, stderr, child.pid

    def sign(label, path, rights=None):
        arguments = ["codesign", "--force", "--sign", "-", "--timestamp=none",
                     "--identifier", "com.virtualmac.diagnostics.cxa-primary-exception." + label]
        if rights is not None:
            ent = out / (label + ".entitlements")
            ent.write_bytes(plistlib.dumps(rights))
            arguments += ["--entitlements", str(ent)]
        run(label + "-sign", arguments + [str(path)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label + "-dyld-validate", ["xcrun", "dyld_info", "-validate_only", str(path)])
        _, signature, _ = run(label + "-signature", ["codesign", "-dvvv", str(path)])
        actual_rights, _, _ = run(label + "-rights", ["codesign", "-d", "--entitlements", ":-", str(path)])
        assert plistlib.loads(actual_rights) == rights if rights is not None else not actual_rights
        spec = importlib.util.spec_from_file_location("code_directory", ROOT / "scripts/development/verify-macho-code-directory.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        checked = checker.check(path.read_bytes())
        (out / (label + "-code-directory.json")).write_text(json.dumps(checked, indent=2) + "\n")
        return re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode()

    candidates = []
    for role, sdk, target in [("ios", "iphoneos", "arm64e-apple-ios16.1"),
                              ("macos", "macosx", "arm64e-apple-macos13.0")]:
        folder = out / role
        folder.mkdir()
        capture = (N / "cxa-code-native-v2/native.stdout" if role == "ios" else
                   N / "cxa-primary-exception-v1/collector-macos-v1/helpers.stdout")
        captured = rows(capture)
        identity = next(row for row in captured if row["record"] == "image")
        if role == "ios":
            assert identity["UUID"] == "fa871417be083e90b33ca6aa89813f3b"
            cleanup_rva, unexpected_rva, terminate_rva = 0x13bd8, 0x10e7c, 0x10f04
        else:
            assert identity["UUID"] == "a21743ee6e1c3e7497ea7af793de4bdf"
            cleanup_rva, unexpected_rva, terminate_rva = 0x156c4, 0x2228, 0x2238
        code = [row for row in captured if row["record"] == "code"]
        for row in code:
            assert row["functionBoundsKnown"] and row["entryIsStart"] and row["readSucceeded"]
            assert len(bytes.fromhex(row["hex"])) == row["bytes"] <= 2048
            assert hashlib.sha256(bytes.fromhex(row["hex"])).hexdigest() == row["SHA256"]
        native_functions = [row for row in code if row["symbol"] != "explicit-libcxxabi-internal-RVA" and
                            row["symbol"] != "__cxa_init_primary_exception"]
        assert len(native_functions) == 7
        for rva, name in [(unexpected_rva, "_ZSt14get_unexpectedv"), (terminate_rva, "_ZSt13get_terminatev")]:
            row = dict(next(row for row in code if int(row["RVA"], 16) == rva))
            row["symbol"] = name
            native_functions.append(row)
        cleanup = next(row for row in code if int(row["RVA"], 16) == cleanup_rva)
        pin = source / (role + "-native-pins.json")
        pin.write_text(json.dumps({"capture": str(capture), "captureSHA256": sha(capture),
                                  "identity": identity, "functions": native_functions,
                                  "cleanup": cleanup, "fixtureOnly": role == "macos"}, indent=2) + "\n")
        text = "#ifndef VM27_NATIVE_CXA_PINS_H\n#define VM27_NATIVE_CXA_PINS_H\n"
        text += "struct NativeFunctionPin {const char *name;uintptr_t rva;size_t bytes;unsigned char sha256[32];};\n"
        text += "static constexpr unsigned char NativeUUID[16]=" + literal(identity["UUID"]) + ";\n"
        text += "static constexpr NativeFunctionPin NativeFunctions[]={\n"
        for row in native_functions:
            text += "{" + json.dumps(row["symbol"]) + "," + row["RVA"] + "," + str(row["bytes"]) + "," + literal(row["SHA256"]) + "},\n"
        text += "};\nstatic constexpr NativeFunctionPin NativeCleanup={\"native_cleanup\"," + cleanup["RVA"] + "," + str(cleanup["bytes"]) + "," + literal(cleanup["SHA256"]) + "};\n#endif\n"
        (folder / "cxa-native-pins.h").write_text(text)
        shutil.copyfile(capture, folder / "native-code-source.jsonl")
        export_file = folder / "exports.list"
        export_file.write_text("\n".join(EXPORTS) + "\n")
        sdk_path = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        flags = ["xcrun", "clang++", "-target", target, "-isysroot", sdk_path,
                 "-fptrauth-abi-version=0", "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-Wno-deprecated-declarations", "-D_LIBCPP_DISABLE_AVAILABILITY",
                 "-D_LIBCPP_ENABLE_CXX17_REMOVED_UNEXPECTED_FUNCTIONS",
                 "-fno-typed-cxx-new-delete", "-fno-typed-memory-operations-experimental",
                 "-I" + str(source), "-I" + str(folder)]
        if role == "macos":
            flags += ["-DVM27_PRIMARY_EXCEPTION_NEW_PAC"]
        library = folder / "VM27PrimaryExceptionCompat.dylib"
        run(role + "-provider-build", flags + ["-dynamiclib", "-Wl,-no_adhoc_codesign",
            "-Wl,-exported_symbols_list," + str(export_file), "-install_name",
            "@rpath/VM27PrimaryExceptionCompat.dylib",
            str(source / "modern_cxa_primary_exception_compat.cpp"), "-o", str(library)])
        if role == "ios":
            data = bytearray(library.read_bytes())
            at = next(at for cmd, at, _ in commands(data) if cmd == 0x32)
            struct.pack_into("<III", data, at + 8, 2, 0x100100, 0x100100)
            library.write_bytes(data)
        library_cd = sign(role + "-provider", library)
        exports, _, _ = run(role + "-exports", ["xcrun", "dyld_info", "-exports", str(library)])
        init_match = re.search(rb"(0x[0-9A-Fa-f]+)\s+___cxa_init_primary_exception\b", exports)
        assert init_match, exports.decode()
        init_rva = int(init_match[1], 16)
        data = library.read_bytes()
        provider_uuid = next(data[at+8:at+24].hex() for cmd, at, _ in commands(data) if cmd == 0x1b)
        all_files = [(library, sha(library), library.stat().st_size)]
        backing = []
        if role == "ios":
            for name in ["VM27CxxProvider.dylib", "ModernCPURuntimeCompat.dylib"]:
                original = ROOT.parent / "DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-cpu-provider-routing-v3" / name
                dest = folder / name
                shutil.copyfile(original, dest)
                assert sha(original) == sha(dest)
                run(role + "-backing-" + name + "-strict", ["codesign", "--verify", "--strict", str(dest)])
                backing.append({"name": name, "path": str(dest), "sha256": sha(dest),
                                "bytes": dest.stat().st_size, "unchanged": True})
                all_files.append((dest, sha(dest), dest.stat().st_size))
        expected = "struct PrivateFilePin{const char *path;const char *sha256;size_t bytes;};\nstatic constexpr PrivateFilePin PrivateFiles[]={\n"
        for path, digest, size in all_files:
            stage = REMOTE + "/" + path.name if role == "ios" else str(path)
            expected += "{" + json.dumps(stage) + "," + json.dumps(digest) + "," + str(size) + "},\n"
        expected += "};\nstatic constexpr unsigned char ProviderUUID[16]=" + literal(provider_uuid) + ";\n"
        expected += "static constexpr char ProviderUUIDString[]=" + json.dumps(provider_uuid) + ";\n"
        expected += "static constexpr uintptr_t ProviderInitRVA=" + hex(init_rva) + ";\n"
        (folder / "cxa-provider-pins.h").write_text(expected)
        probe = folder / "modern-cxa-primary-exception-probe"
        # SDK27 no longer lists this genuine exported libc++abi extension.
        # This link-only declaration emits a normal strong positive-ordinal
        # import to the real system image; it supplies no runtime code/stub.
        native_tbd = folder / "NativeSystemCxxABI.tbd"
        native_tbd.write_text("--- !tapi-tbd-v3\narchs: [ arm64e ]\nplatform: " +
            ("ios" if role == "ios" else "macosx") +
            "\ninstall-name: '/usr/lib/libc++abi.dylib'\ncurrent-version: 1\ncompatibility-version: 1\n" +
            "exports:\n  - archs: [ arm64e ]\n    symbols: [ '___cxa_rethrow_primary_exception' ]\n...\n")
        extra = [str(folder / "VM27CxxProvider.dylib"), "-DVM27_PRIMARY_EXCEPTION_IOS"] if role == "ios" else []
        run(role + "-probe-build", flags + [str(source / "test-modern-cxa-primary-exception.cpp"),
            str(library), str(native_tbd), *extra, "-Wl,-rpath,@loader_path", "-Wl,-no_adhoc_codesign", "-o", str(probe)])
        if role == "ios":
            data = bytearray(probe.read_bytes())
            at = next(at for cmd, at, _ in commands(data) if cmd == 0x32)
            struct.pack_into("<III", data, at + 8, 2, 0x100100, 0x100100)
            probe.write_bytes(data)
        probe_cd = sign(role + "-probe", probe, RIGHTS if role == "ios" else None)
        run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)])
        candidates.append({"role": role, "library": {"path": str(library), "sha256": sha(library),
            "bytes": library.stat().st_size, "CDHash": library_cd, "UUID": provider_uuid, "initRVA": init_rva},
            "probe": {"path": str(probe), "sha256": sha(probe), "bytes": probe.stat().st_size,
            "CDHash": probe_cd, "entitlements": RIGHTS if role == "ios" else {}, "deviceExecuted": False},
            "backing": backing, "nativeSourcePin": str(pin), "nativeSourcePinSHA256": sha(pin),
            "macFixtureNewPAC": role == "macos", "iOSOldNativePAC": role == "ios"})
        if role == "macos":
            stdout, _, pid = run("macos-lifecycle-native", [str(probe), sha(probe), str(probe.stat().st_size)], timeout=15)
            summary = next(row for row in [json.loads(line) for line in stdout.decode().splitlines()] if row["record"] == "summary")
            assert summary["PID"] == pid and summary["failures"] == 0 and summary["initialized"] == 70
            assert summary["created"] == summary["destroyed"] == 68
            assert summary["rethrows"] == 66 and summary["nativeCleanupCalls"] == 2
            candidates[-1]["actualMacFixture"] = summary
            run("macos-saved-terminate-control", [str(probe), sha(probe), str(probe.stat().st_size), "--terminate-control"], expected=79, timeout=15)
    manifest = {"sourceSHA256": source_hashes, "upstream": upstream,
                "candidates": candidates, "processes": records,
                "deviceOperations": False, "actualOriginal27VMMExecuted": False,
                "full27Backend": False, "iOSNativeLifecycleExecuted": False}
    (out / "candidate.json").write_text(json.dumps(manifest, indent=2) + "\n")
    run("independent-static-and-lifecycle-validation", [sys.executable,
        str(ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py"), str(out)])
    print(json.dumps({"candidate": str(out / "candidate.json"), "SHA256": sha(out / "candidate.json")}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2, "tracked script OUTPUT_NEW_DIRECTORY"
    main(sys.argv[1])
