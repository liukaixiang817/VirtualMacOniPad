#!/usr/bin/env python3
"""Build an app-private, code-free CoreServices re-export closure, local only.

Two immutable providers retain their real state and distinct ownership domains.
This does not register a host LS service, run original VMM, or start a guest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
BRIDGE = N / "vmm-client-registration-bridge-development-v1"
TITLE = N / "process-title-state-contract-v1"
BRIDGE_FREEZE = "19e5b79c0881644f476f2eacf6d72226e5e0d0f528c97f883ba2d98b93568604"
NAME = "VM27ClientServices.dylib"
ID = "@rpath/" + NAME


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    b = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(b), "sha256": sha(b)}


def commands(b):
    assert struct.unpack_from("<I", b)[0] == 0xfeedfacf
    at = 32
    result = []
    for _ in range(struct.unpack_from("<I", b, 16)[0]):
        c, z = struct.unpack_from("<II", b, at)
        assert z >= 8 and not z % 8 and at + z <= 32 + struct.unpack_from("<I", b, 20)[0]
        result.append((c, at, z))
        at += z
    assert at == 32 + struct.unpack_from("<I", b, 20)[0]
    return result


def inspect(path):
    b = path.read_bytes()
    deps, ids, rpaths, uuids, code_sections = [], [], [], [], []
    for c, at, z in commands(b):
        if c in (12, 13, 0x8000001f, 0x80000018, 0x80000023):
            offset, timestamp, current, compat = struct.unpack_from("<4I", b, at + 8)
            item = {"command": c, "path": b[at + offset:at + z].split(b"\0")[0].decode(), "timestamp": timestamp, "currentVersion": current, "compatibilityVersion": compat}
            (ids if c == 13 else deps).append(item)
        if c == 0x8000001c:
            offset = struct.unpack_from("<I", b, at + 8)[0]
            rpaths.append(b[at + offset:at + z].split(b"\0")[0].decode())
        if c == 0x1b:
            assert z == 24
            uuids.append(b[at + 8:at + 24].hex())
        if c == 0x19:
            count = struct.unpack_from("<I", b, at + 64)[0]
            assert z == 72 + count * 80
            for i in range(count):
                s = at + 72 + 80 * i
                name = b[s:s + 16].split(b"\0")[0].decode()
                size = struct.unpack_from("<Q", b, s + 40)[0]
                if name in ("__text", "__mod_init_func", "__init_offsets", "__interpose"):
                    code_sections.append({"name": name, "bytes": size})
    assert len(ids) == len(uuids) == 1
    return {"dependencies": deps, "ID": ids[0], "rpaths": rpaths, "UUID": uuids[0], "codeOrInitSections": code_sections}


def main(out):
    assert sha((BRIDGE / "freeze.json").read_bytes()) == BRIDGE_FREEZE
    for row in json.loads((BRIDGE / "freeze.json").read_bytes())["files"]:
        assert (BRIDGE / row["path"]).read_bytes().__len__() == row["bytes"]
        assert sha((BRIDGE / row["path"]).read_bytes()) == row["sha256"]
    bridge = json.loads((BRIDGE / "candidate.json").read_bytes())
    title = json.loads((TITLE / "candidate.json").read_bytes())
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    logs = []
    def run(label, argv, timeout=30):
        env = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            stdout, stderr = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            (out / (label + ".stdout")).write_bytes(stdout)
            (out / (label + ".stderr")).write_bytes(stderr)
            raise
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        logs.append({"label": label, "argv": argv, "actualPID": p.pid, "waitExit": p.returncode})
        assert p.returncode == 0, (label, stderr[-3000:])
        return stdout, stderr
    source = out / "aggregate.c"
    source.write_text("/* Empty translation unit: genuine state lives only in the two\n * immutable re-exported app-private providers. No init or helper bodies. */\n")
    shutil.copyfile(Path(__file__), out / Path(__file__).name)
    records = []
    title_reference_source = out / "mac-reference-source"
    title_reference_source.mkdir()
    for name in ("vm27_process_title_state_v1.c", "vm27_process_title_state_v1.h"):
        shutil.copyfile(TITLE / "source" / name, title_reference_source / name)
        assert (title_reference_source / name).read_bytes() == (TITLE / "source" / name).read_bytes()
    shutil.copyfile(TITLE / "exports.txt", title_reference_source / "exports.txt")
    for platform, sdk, target in (("mac", "macosx", "arm64e-apple-macos13.0"), ("ios", "iphoneos", "arm64e-apple-ios16.1")):
        folder = out / platform
        folder.mkdir(mode=0o700)
        original_bridge = next(x for x in bridge["files"] if x["platform"] == platform and x["role"] == "provider")
        original_title = title["macBinary" if platform == "mac" else "binary"]
        copies = []
        for item in (original_bridge, original_title):
            origin = Path(item["path"])
            assert sha(origin.read_bytes()) == item["sha256"]
            copy = folder / origin.name
            shutil.copyfile(origin, copy)
            copy.chmod(0o600)
            assert copy.lstat().st_nlink == 1 and copy.is_file() and not copy.is_symlink()
            assert copy.read_bytes() == origin.read_bytes()
            mac_reference = platform == "mac" and origin.name == "VM27PrivateProcessTitle.dylib"
            if mac_reference:
                # The immutable Mac baseline is generic arm64 and cannot load
                # in the arm64e bridge process. Build a separate same-source
                # arm64e Mac reference; the iOS provider is never rebuilt.
                reference_sdk = run("mac-reference-sdk", ["xcrun", "--sdk", "macosx", "--show-sdk-path"])[0].decode().strip()
                run("mac-title-reference-build", ["xcrun", "clang", "-target", "arm64e-apple-macos13.2",
                    "-isysroot", reference_sdk, "-fptrauth-abi-version=0", "-std=c11", "-O0",
                    "-Wall", "-Wextra", "-Werror", "-dynamiclib", "-framework", "CoreFoundation",
                    "-I", str(title_reference_source), str(title_reference_source / "vm27_process_title_state_v1.c"),
                    "-Wl,-install_name,@rpath/VM27PrivateProcessTitle.dylib", "-Wl,-current_version,1.0.0",
                    "-Wl,-compatibility_version,1.0.0", "-Wl,-exported_symbols_list," + str(title_reference_source / "exports.txt"),
                    "-o", str(copy)])
                run("mac-title-reference-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", str(copy)])
            run(platform + "-" + copy.name + "-strict", ["codesign", "--verify", "--strict", str(copy)])
            meta = inspect(copy)
            assert meta["ID"]["compatibilityVersion"] == meta["ID"]["currentVersion"] == 65536
            copies.append({"source": pin(origin), "copy": pin(copy), "metadata": meta, "unchanged": not mac_reference,
                "sameFrozenSourceMacARM64EReference": mac_reference,
                "macReferenceSource": [pin(x) for x in sorted(title_reference_source.iterdir())] if mac_reference else []})
        sdk_path = run(platform + "-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        aggregate = folder / NAME
        reexport_flags = ["-Wl,-reexport_library," + str(folder / "VM27ClientRegistration.dylib")]
        if platform in ("mac", "ios"):
            reexport_flags.append("-Wl,-reexport_library," + str(folder / "VM27PrivateProcessTitle.dylib"))
        run(platform + "-build", ["xcrun", "clang", "-target", target, "-isysroot", sdk_path,
            "-fptrauth-abi-version=0", "-std=c11", "-Wall", "-Wextra", "-Werror", "-dynamiclib",
            "-Wl,-no_adhoc_codesign", "-Wl,-headerpad,0x100", "-Wl,-install_name," + ID, "-Wl,-current_version,1.0.0",
            "-Wl,-compatibility_version,1.0.0", "-Wl,-rpath,@loader_path"] + reexport_flags +
            [str(source), "-o", str(aggregate)])
        run(platform + "-sign", ["codesign", "--force", "--sign", "-", "--timestamp=none", str(aggregate)])
        run(platform + "-strict", ["codesign", "--verify", "--strict", str(aggregate)])
        _, desc = run(platform + "-identity", ["codesign", "-d", "--verbose=4", str(aggregate)])
        run(platform + "-metadata", ["xcrun", "dyld_info", "-platform", "-dependents", "-imports", "-exports", "-validate_only", str(aggregate)])
        m = inspect(aggregate)
        assert m["ID"]["path"] == ID and m["ID"]["currentVersion"] == m["ID"]["compatibilityVersion"] == 65536
        assert m["rpaths"] == ["@loader_path"]
        reexports = [x for x in m["dependencies"] if x["command"] == 0x8000001f]
        assert [x["path"] for x in reexports] == ["@rpath/VM27ClientRegistration.dylib", "@rpath/VM27PrivateProcessTitle.dylib"]
        assert all(x["compatibilityVersion"] == 65536 for x in reexports)
        assert not any(x["bytes"] for x in m["codeOrInitSections"])
        records.append({"platform": platform, "aggregate": pin(aggregate), "UUID": m["UUID"], "CDHash": re.search(rb"CDHash=([a-f0-9]{40})", desc)[1].decode(), "metadata": m, "providerCopies": copies,
            "allReexportsFromActualLinker": True})
    candidate = {"schema": "App-private original VMM six CoreServices imports re-export closure v1",
        "records": records, "source": pin(source), "steps": logs,
        "nativeExecuted": False, "originalVMMExecuted": False, "originalVZLoaded": False,
        "productionClientBootstrapIntegrated": False, "hostGlobalLSRegistration": False,
        "nativeVMCalls": 0, "nativeCPUCalls": 0, "deviceOperations": 0, "full27Backend": False}
    (out / "candidate.json").write_text(json.dumps(candidate, indent=2) + "\n")
    print(json.dumps({"candidate": pin(out / "candidate.json"), "records": records}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args().output.resolve())
