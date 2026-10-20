#!/usr/bin/env python3
"""Build thirteen real CPU-only ABI additions and a strong-import semantic probe.

The separate macOS fixture is actually run. The signed iOS candidate is never
run or deployed here. Neither system libraries nor existing candidates change.
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
VENDOR = ROOT / "vendor/llvm-charconv"
FLOAT = ["__ZNSt3__18to_charsEPcS0_" + kind + suffix
         for kind in ("f", "d", "e")
         for suffix in ("", "NS_12chars_formatE", "NS_12chars_formatEi")]
TYPED = ["__ZnwmSt19__type_descriptor_t", "__ZnamSt19__type_descriptor_t",
         "__ZdlPvSt19__type_descriptor_t", "__ZdaPvSt19__type_descriptor_t"]
EXPORTS = FLOAT + TYPED
REMOTE = "/var/root/VirtualMac2/testing/vmm-loader-closure-v2/VM27CxxABICompat.dylib"
BACKING = ROOT.parent / "DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-cpu-provider-routing-v3"
RIGHTS = {"platform-application": True,
          "com.apple.private.security.no-container": True,
          "com.apple.private.security.no-sandbox": True}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commands(data):
    assert struct.unpack_from("<I", data)[0] == 0xfeedfacf
    at = 32
    end = at + struct.unpack_from("<I", data, 20)[0]
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        cmd, size = struct.unpack_from("<II", data, at)
        assert size >= 8 and not size % 8 and at + size <= end
        yield cmd, at, size
        at += size
    assert at == end


def main(output):
    out = Path(output).resolve()
    out.mkdir(mode=0o700, exist_ok=False)
    src = out / "source"
    src.mkdir()
    rows = json.loads((VENDOR / "SOURCE.json").read_text())["files"]
    pins = []
    for row in rows:
        path = VENDOR / row["path"]
        assert sha(path) == row["sha256"] and path.stat().st_size == row["bytes"]
        dest = src / "llvm-charconv" / row["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        pins.append({"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size})
    for name in ("SOURCE.json", "README.txt"):
        shutil.copyfile(VENDOR / name, src / "llvm-charconv" / name)
    copied = {}
    for name, path in {
        "modern_vmm_cxx_abi_compat.cpp": ROOT / "vz/host/modern_vmm_cxx_abi_compat.cpp",
        "test-modern-vmm-cxx-closure.cpp": ROOT / "scripts/tests/test-modern-vmm-cxx-closure.cpp",
        "build-modern-vmm-cxx-closure.py": Path(__file__),
    }.items():
        dest = src / name
        shutil.copyfile(path, dest)
        assert sha(dest) == sha(path)
        copied[name] = sha(path)
    raw = (src / "llvm-charconv/src/charconv.cpp").read_text()
    generated = src / "to_chars_backport.cpp"
    generated.write_text(raw[:raw.index("#include <charconv>")] +
        '#include <charconv>\n#include "include/to_chars_floating_point.h"\n' +
        "_LIBCPP_BEGIN_NAMESPACE_STD\n" +
        raw[raw.index("// The original version of floating-point to_chars"):raw.index("template <class _Fp>")] +
        "_LIBCPP_END_NAMESPACE_STD\n")
    export_file = src / "exports.list"
    export_file.write_text("\n".join(EXPORTS) + "\n")
    libraries = []
    records = []

    def run(label, args, timeout=40):
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            raise
        result = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
        result.childPID = child.pid
        (out / (label + ".command.json")).write_text(json.dumps(args, indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(result.stdout)
        (out / (label + ".stderr")).write_bytes(result.stderr)
        records.append({"label": label, "directChildPID": child.pid, "exitCode": result.returncode})
        if result.returncode:
            raise RuntimeError(label + ": " + result.stderr.decode(errors="replace")[-1800:])
        return result

    def sign(label, path, identifier, rights=None):
        args = ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", identifier]
        if rights is not None:
            ent = out / (label + ".entitlements")
            ent.write_bytes(plistlib.dumps(rights))
            args += ["--entitlements", str(ent)]
        run(label + "-sign", args + [str(path)])
        run(label + "-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label + "-dyld", ["xcrun", "dyld_info", "-validate_only", str(path)])
        sig = run(label + "-signature", ["codesign", "-dvvv", str(path)]).stderr
        ent = run(label + "-rights", ["codesign", "-d", "--entitlements", ":-", str(path)]).stdout
        if rights is None:
            assert not ent
        else:
            assert plistlib.loads(ent) == rights
        checker = ROOT / "scripts/development/verify-macho-code-directory.py"
        spec = importlib.util.spec_from_file_location("code_directory", checker)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        verified = module.check(path.read_bytes())
        (out / (label + "-code-directory.json")).write_text(json.dumps(verified, indent=2) + "\n")
        return re.search(rb"CDHash=([0-9a-f]{40})", sig)[1].decode()

    for role, sdk, target in [("ios", "iphoneos", "arm64e-apple-ios16.1"),
                              ("macos", "macosx", "arm64-apple-macos13.0")]:
        folder = out / role
        folder.mkdir()
        lib = folder / "VM27CxxABICompat.dylib"
        sdk_path = run(role + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"]).stdout.decode().strip()
        args = ["xcrun", "clang++", "-target", target, "-isysroot", sdk_path,
                "-std=c++20", "-O2", "-fno-typed-cxx-new-delete",
                "-fno-typed-memory-operations-experimental", "-D_LIBCPP_BUILDING_LIBRARY",
                "-D_LIBCPP_DISABLE_AVAILABILITY", "-Wall", "-Wextra", "-Werror",
                "-Wno-deprecated-declarations", "-I" + str(src / "llvm-charconv/src")]
        if role == "ios":
            args += ["-fptrauth-abi-version=0"]
        lib_args = args + ["-dynamiclib", "-Wl,-no_adhoc_codesign",
                    "-Wl,-exported_symbols_list," + str(export_file),
                    "-install_name", "@rpath/VM27CxxABICompat.dylib",
                    str(generated), str(src / "llvm-charconv/src/ryu/d2s.cpp"),
                    str(src / "llvm-charconv/src/ryu/f2s.cpp"),
                    str(src / "llvm-charconv/src/ryu/d2fixed.cpp"),
                    str(src / "modern_vmm_cxx_abi_compat.cpp"), "-o", str(lib)]
        backing_rows = []
        if role == "ios":
            # The original VMM has only32 bytes of remaining load-command
            # space. Reuse ordinal51 by forwarding the already proven exact
            # Cxx provider; no old API implementation or old file is changed.
            for name in ("VM27CxxProvider.dylib", "ModernCPURuntimeCompat.dylib"):
                original = BACKING / name
                dest = folder / name
                shutil.copyfile(original, dest)
                assert sha(original) == sha(dest)
                run(role + "-backing-" + name + "-strict", ["codesign", "--verify", "--strict", str(dest)])
                sig = run(role + "-backing-" + name + "-signature", ["codesign", "-dvvv", str(dest)]).stderr
                backing_rows.append({"path": str(dest), "sourcePath": str(original),
                    "bytes": dest.stat().st_size, "sha256": sha(dest),
                    "CDHash": re.search(rb"CDHash=([0-9a-f]{40})", sig)[1].decode(),
                    "exactUnchangedCopy": True})
            lib_args += ["-Wl,-reexport_library," + str(folder / "VM27CxxProvider.dylib"),
                         "-Wl,-rpath,@loader_path"]
        run(role + "-provider-compile", lib_args)
        data = bytearray(lib.read_bytes())
        build = [at for cmd, at, _ in commands(data) if cmd == 0x32]
        assert len(build) == 1
        if role == "ios":
            # Match the native16.1 dyld stamp, not the compiling SDK's future stamp.
            struct.pack_into("<III", data, build[0] + 8, 2, 0x100100, 0x100100)
            lib.write_bytes(data)
        cd = sign(role + "-provider", lib, "com.virtualmac.diagnostics.vmm-cxx-closure." + role)
        data = lib.read_bytes()
        uuids = [data[at + 8:at + 24].hex() for cmd, at, _ in commands(data) if cmd == 0x1b]
        assert len(uuids) == 1
        uuid = uuids[0]
        nm = run(role + "-provider-exports", ["nm", "-gU", str(lib)]).stdout.decode()
        exports = {parts[-1]: int(parts[0], 16) for line in nm.splitlines() if len(parts := line.split()) == 3}
        assert set(exports) == set(EXPORTS)
        subtype = struct.unpack_from("<I", data, 8)[0]
        assert subtype == (0x80000002 if role == "ios" else 0)
        platform, minos, sdk_stamp = struct.unpack_from("<III", data, build[0] + 8)
        dependencies = run(role + "-provider-linked", ["xcrun", "dyld_info", "-linked_dylibs", str(lib)]).stdout.decode()
        assert "Metal" not in dependencies and "Foundation" not in dependencies
        run(role + "-provider-imports", ["xcrun", "dyld_info", "-imports", str(lib)])
        pinpath = REMOTE if role == "ios" else str(lib)
        header = folder / "vmm-cxx-closure-pins.h"
        header.write_text("#include <stddef.h>\n#include <stdint.h>\n" +
            "static const char PinPath[]=" + json.dumps(pinpath) + ";\n" +
            "static const char PinSHA[]=" + json.dumps(sha(lib)) + ";\n" +
            "static const char PinUUIDHex[]=" + json.dumps(uuid) + ";\n" +
            "static const unsigned char PinUUID[]={" + ",".join("0x" + uuid[i:i + 2] for i in range(0, 32, 2)) + "};\n" +
            "static const size_t PinBytes=" + str(lib.stat().st_size) + ";\n" +
            "static const uint32_t PinSubtype=" + hex(subtype) + ";\n" +
            "static const uint32_t PinPlatform=" + str(platform) + ";\n" +
            "static const uint32_t PinMinOS=" + str(minos) + ";\n" +
            "static const uint32_t PinSDK=" + str(sdk_stamp) + ";\n" +
            "static const uintptr_t PinRVAs[]={" + ",".join(hex(exports[x]) for x in EXPORTS) + "};\n")
        probe = folder / "vmm-cxx-closure-probe"
        probe_args = args + ["-I" + str(folder), str(src / "test-modern-vmm-cxx-closure.cpp"),
            str(lib), "-Wl,-rpath,@loader_path", "-o", str(probe)]
        run(role + "-probe-compile", probe_args)
        pcd = sign(role + "-probe", probe, "com.virtualmac.diagnostics.vmm-cxx-closure-probe." + role,
                   RIGHTS if role == "ios" else None)
        imports = run(role + "-probe-imports", ["xcrun", "dyld_info", "-imports", str(probe)]).stdout.decode()
        for symbol in EXPORTS:
            matches = [line for line in imports.splitlines() if len(line.split()) > 1 and line.split()[1] == symbol]
            assert len(matches) == 1 and "VM27CxxABICompat" in matches[0] and "weak" not in matches[0].lower(), symbol
        actual = None
        if role == "macos":
            fixture = run("actual-macos-probe", [str(probe)], timeout=15)
            records_json = [json.loads(line) for line in fixture.stdout.decode().splitlines()]
            start, summary = records_json[0], records_json[-1]
            assert start["record"] == "start" and start["pid"] == fixture.childPID and fixture.childPID > 1
            assert summary["record"] == "summary" and summary["passed"] and summary["failures"] == 0
            checks = [r for r in records_json if r["record"] == "check"]
            assert len(checks) == summary["checks"] and all(r["passed"] for r in checks)
            assert all(n > 0 for n in summary["calls"]) and len(summary["calls"]) == 13
            assert summary["created"] == summary["released"] == 8
            actual = {"PID": fixture.childPID, "PIDMatchesChildSelfReport": True,
                      "directChildWaitObserved": True, "exitCode": 0, "summary": summary,
                      "stdoutSHA256": sha(out / "actual-macos-probe.stdout")}
        libraries.append({"role": role, "provider": {"path": str(lib), "sha256": sha(lib),
            "CDHash": cd, "UUID": uuid, "bytes": lib.stat().st_size, "RVAs": exports,
            "entitlements": {}, "platform": platform, "minOS": minos, "SDK": sdk_stamp,
            "subtype": subtype}, "probe": {"path": str(probe), "sha256": sha(probe),
            "CDHash": pcd, "bytes": probe.stat().st_size,
            "entitlements": RIGHTS if role == "ios" else {}, "strongImports": EXPORTS},
            "actualExecution": actual, "unchangedBackingLibraries": backing_rows,
            "deviceExecuted": False})
    result = {"scope": "13 exact CPU-only ABI definitions; strong iOS probe and actual independent macOS fixture",
              "sourceSHA256": copied, "upstreamFiles": pins, "exports": EXPORTS,
              "libraries": libraries, "commands": records, "deviceOperations": False,
              "originalVMMExecuted": False, "completeVMMClosure": False,
              "remainingCxxContract": "__cxa_init_primary_exception is not supplied or guessed"}
    (out / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"libraries": libraries, "completeVMMClosure": False}, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: build-modern-vmm-cxx-closure.py NEW_OUTPUT_DIRECTORY")
    main(sys.argv[1])
