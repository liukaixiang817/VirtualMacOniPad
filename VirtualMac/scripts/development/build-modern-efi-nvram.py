#!/usr/bin/env python3
"""Build seven strong genuine27 EFI APIs and actually execute own-file Mac smoke.

Only local scoped artifacts; does not deploy, execute iOS, touch guest/system
NVRAM or operate devices. Mac's copy changes only platform metadata/signature.
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
REMOTE = "/var/root/VirtualMac2/testing/efi-owned-nvram-v1"
SYMBOLS = ["_CreateEfiVariableStoreRuntimeFromMemory", "_DestroyEfiVariableStoreRuntime",
           "_EfiVariableGetVariable", "_EfiVariableSetVariable", "_EfiVariableGetNextVariableName",
           "_EfiVariableQueryVariableInfo", "_GetCurrentEfiVariableStoreRuntimeState"]
RVAS = [0x22b8, 0x24ac, 0x2820, 0x29b8, 0x28f8, 0x2a90, 0x25d8]
MODULES = ["libPcdDxe.dylib", "libVariableRuntimeDxe.dylib", "libFaultTolerantWriteDxe.dylib"]
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
          "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True}
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location("cxa_validator", ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def positive_module(source, role):
    """Restore each original strong nlist ordinal, no weakened/unknown imports."""
    original = (source / "raw").read_bytes()
    data = bytearray((source / "strong-flat.mac").read_bytes())
    at = next(at for cmd,at,_ in V.M.commands(original) if cmd == 2)
    symoff, count, stroff, strsize = struct.unpack_from("<IIII", original, at+8)
    nlist = {}
    for i in range(count):
        string, typ, sect, desc, value = struct.unpack_from("<IBBHQ", original, symoff+i*16)
        if (typ & 14) == 0 and (typ & 1):
            nlist[V.M.string(original, stroff+string, stroff+strsize)] = {"ordinal":desc >> 8, "weak":bool(desc & 0x40)}
    at = next(at for cmd,at,_ in V.M.commands(data) if cmd == 0x80000034)
    offset, size = struct.unpack_from("<II", data, at+8)
    _, starts, table, strings, count, form, symbolform = struct.unpack_from("<7I", data, offset)
    assert form == 1 and symbolform == 0
    routes = []
    for index, row in enumerate(V.imports(data)):
        old = nlist[row["symbol"]]
        assert not row["weak"] and not row["addend"] and old == {"ordinal":2,"weak":False}
        at = offset+table+index*4; word = struct.unpack_from("<I", data, at)[0]
        struct.pack_into("<I", data, at, (word & ~0x1ff) | old["ordinal"])
        routes.append({"symbol":row["symbol"],"beforeOrdinal":row["ordinal"],"originalAndFinalOrdinal":2,"weak":False})
    metadata_fixes = []
    # Compact reconstruction opens a pool at the original zero-size __got's
    # start, but its >= split comparison moves that section header by one
    # insertion page. Correct only this proven stale header; pool bytes, code,
    # actual chains/PAC and segment extents already describe the proper pool.
    for cmd,at,_ in V.M.commands(data):
        if cmd == 0x19:
            address, extent, fileoff, filesize = struct.unpack_from("<4Q", data, at+24)
            for i in range(struct.unpack_from("<I", data, at+64)[0]):
                s = at+72+i*80; name = data[s:s+16].split(b"\0")[0]
                sa, length, off = struct.unpack_from("<QQI", data, s+32)
                if name == b"__got" and length and sa+length > address+extent:
                    assert sa == address+extent and extent == filesize == 0x4000 and length == count*8
                    original_size = struct.unpack_from("<Q", original, s+40)[0]
                    assert original_size == 0
                    assert all(struct.unpack_from("<Q", data, fileoff+j*8)[0] & (1 << 62) for j in range(count))
                    struct.pack_into("<Q", data, s+32, address)
                    struct.pack_into("<I", data, s+48, fileoff)
                    metadata_fixes.append({"section":"__got","oldAddress":hex(sa),"oldFileOffset":off,"newAddress":hex(address),"newFileOffset":fileoff,"bytes":length,"reason":"zero-sized insertion section header incorrectly shifted across its own inserted pool; existing pool bind words preserved"})
    at = next(at for cmd,at,_ in V.M.commands(data) if cmd == 0x32)
    struct.pack_into("<III", data, at+8, *( (2,0x100100,0x100100) if role == "ios" else (1,0xd0000,0xd0000) ))
    for row in V.imports(data):
        V.require_binding(V.imports(data), V.M.libraries(data), row["symbol"], "/usr/lib/libSystem.B.dylib")
    # No code, DATA/PAC chains or original export/function-start sections change.
    before = (source / "strong-flat.mac").read_bytes(); sections = []
    for cmd,at,_ in V.M.commands(before):
        if cmd == 0x19:
            for i in range(struct.unpack_from("<I", before, at+64)[0]):
                s = at+72+i*80; name = before[s:s+16].split(b"\0")[0].decode()
                length = struct.unpack_from("<Q", before, s+40)[0]; fileoff = struct.unpack_from("<I", before, s+48)[0]
                flags = struct.unpack_from("<I", before, s+64)[0]
                if length and (flags & 0xff) not in (1,12,18):
                    assert before[fileoff:fileoff+length] == data[fileoff:fileoff+length]
                    sections.append({"name":name,"bytes":length,"unchanged":True})
    uuid = next(data[at+8:at+24].hex() for cmd,at,_ in V.M.commands(data) if cmd == 0x1b)
    return data, {"source":str(source),"rawSHA256":sha(source/"raw"),"reconstructedSHA256":sha(source/"strong-flat.mac"),"UUID":uuid,"routes":routes,"sectionMetadataFixes":metadata_fixes,"sections":sections,"nativeExecution":False}


def main(destination):
    out = Path(destination).resolve(); out.mkdir(mode=0o700, exist_ok=False)
    source = out / "source"; source.mkdir(); processes = []
    for path in (ROOT / "scripts/tests/test-modern-efi-nvram.cpp", Path(__file__)):
        shutil.copyfile(path, source / path.name); assert sha(path) == sha(source / path.name)
    def run(label, args, expected=0):
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label+".argv.json")).write_text(json.dumps(args, indent=2)+"\n")
        (out / (label+".stdout")).write_bytes(stdout); (out / (label+".stderr")).write_bytes(stderr)
        processes.append({"label":label, "directChildPID":child.pid, "observedWaitExit":child.returncode, "reaped":True})
        assert child.returncode == expected, label+" exit="+str(child.returncode)+" "+stderr.decode(errors="replace")[-2000:]
        return stdout, stderr, child.pid
    def sign(label, path, rights=None):
        args = ["codesign", "--force", "--sign", "-", "--timestamp=none", "--identifier", "com.virtualmac.diagnostics.efi-nvram."+label]
        if rights is not None:
            ent = out / (label+".entitlements"); ent.write_bytes(plistlib.dumps(rights)); args += ["--entitlements", str(ent)]
        run(label+"-sign", args+[str(path)])
        run(label+"-strict", ["codesign", "--verify", "--strict", str(path)])
        run(label+"-validate", ["xcrun", "dyld_info", "-validate_only", str(path)])
        _, signature, _ = run(label+"-signature", ["codesign", "-dvvv", str(path)])
        ent, _, _ = run(label+"-rights", ["codesign", "-d", "--entitlements", ":-", str(path)])
        assert plistlib.loads(ent) == rights if rights is not None else not ent
        return re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode()
    candidates = []
    for role, sdk, target in (("ios", "iphoneos", "arm64e-apple-ios16.1"), ("macos", "macosx", "arm64e-apple-macos13.0")):
        folder = out / role; folder.mkdir()
        efi_original = N / "efi-support-strong-v1/signed/EfiSupport27.dylib"
        efi = folder / efi_original.name; shutil.copyfile(efi_original, efi)
        raw = bytearray(efi.read_bytes())
        uuid = next(raw[at+8:at+24].hex() for cmd,at,_ in V.M.commands(raw) if cmd == 0x1b)
        assert uuid == "10a81345e6c23aab8a107c6cdf0b2a64"
        if role == "macos":
            at = next(at for cmd,at,_ in V.M.commands(raw) if cmd == 0x32)
            struct.pack_into("<III", raw, at+8, 1, 0xd0000, 0xd0000); efi.write_bytes(raw)
            efi_cd = sign(role+"-efi", efi)
        else:
            assert sha(efi) == sha(efi_original)
            _, signature, _ = run(role+"-efi-signature", ["codesign", "-dvvv", str(efi)])
            efi_cd = re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode()
        rtti_original = N / ("efi-support-strong-v1/signed/VM27NativeRTTICompat.dylib" if role == "ios" else "efi-native-rtti-v1/build-v2/macos/VM27NativeRTTICompat.dylib")
        rtti = folder / rtti_original.name; shutil.copyfile(rtti_original, rtti); assert sha(rtti) == sha(rtti_original)
        _, signature, _ = run(role+"-rtti-signature", ["codesign", "-dvvv", str(rtti)])
        rtti_cd = re.search(rb"CDHash=([0-9a-f]{40})", signature)[1].decode()
        seed_original = N / "efi-owned-nvram-v1/oracle-v1/apple-created.bin"
        seed = folder / "apple-created.bin"; shutil.copyfile(seed_original, seed)
        assert seed.stat().st_size == 0x20000 and sha(seed) == sha(seed_original)
        modules = []
        for name in MODULES:
            binary, review = positive_module(N / "efi-owned-nvram-v1/modules-v1" / name, role)
            module = folder / name; module.write_bytes(binary)
            cd = sign(role+"-"+name, module)
            exports = run(role+"-"+name+"-exports", ["xcrun", "dyld_info", "-exports", str(module)])[0]
            entry = re.search(rb"(0x[0-9A-Fa-f]+)\s+__ModuleEntryPoint\b", exports)
            assert entry
            modules.append({"path":str(module),"sha256":sha(module),"bytes":module.stat().st_size,"CDHash":cd,"ModuleEntryPointRVA":int(entry[1],16),"review":review})
        (folder / "efi-probe-pins.h").write_text(
            "static constexpr char EfiPath[]="+json.dumps(REMOTE+"/"+efi.name if role == "ios" else str(efi))+";\n"+
            "static constexpr char EfiSHA[]="+json.dumps(sha(efi))+";\nstatic constexpr size_t EfiBytes="+str(efi.stat().st_size)+";\n"+
            "static constexpr unsigned char EfiUUID[16]={"+",".join("0x"+uuid[i:i+2] for i in range(0,32,2))+"};\n"+
            "static constexpr uintptr_t EfiRVAs[]={"+",".join(hex(x) for x in RVAS)+"};\n"+
            "static constexpr char RTTIPath[]="+json.dumps(REMOTE+"/"+rtti.name if role == "ios" else str(rtti))+";\n"+
            "static constexpr char RTTISHA[]="+json.dumps(sha(rtti))+";\nstatic constexpr size_t RTTIBytes="+str(rtti.stat().st_size)+";\n"+
            "static constexpr char SeedPath[]="+json.dumps(REMOTE+"/"+seed.name if role == "ios" else str(seed))+";\n"+
            "static constexpr char SeedSHA[]="+json.dumps(sha(seed))+";\nstatic constexpr unsigned char SeedDigest[32]={"+",".join("0x"+sha(seed)[i:i+2] for i in range(0,64,2))+"};\n"+
            "static constexpr struct {const char *path,*sha;size_t bytes;unsigned char uuid[16];uintptr_t rva;} Modules[]={"+",".join("{"+json.dumps(REMOTE+"/"+Path(m["path"]).name if role == "ios" else m["path"])+","+json.dumps(m["sha256"])+","+str(m["bytes"])+",{"+",".join("0x"+m["review"]["UUID"][i:i+2] for i in range(0,32,2))+"},"+hex(m["ModuleEntryPointRVA"])+"}" for m in modules)+"};\n"+
            "static constexpr char WorkParent[]="+json.dumps(REMOTE if role == "ios" else str(folder))+";\n")
        sdk_path = run(role+"-sdk", ["xcrun", "--sdk", sdk, "--show-sdk-path"])[0].decode().strip()
        probe = folder / "modern-efi-nvram-probe"
        flags = ["xcrun", "clang++", "-target", target, "-isysroot", sdk_path, "-fptrauth-abi-version=0", "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-fno-typed-cxx-new-delete", "-fno-typed-memory-operations-experimental", "-I"+str(folder)]
        run(role+"-probe-build", flags+(["-DVM27_EFI_IOS"] if role == "ios" else [])+[str(source / "test-modern-efi-nvram.cpp"), str(efi), "-Wl,-rpath,@loader_path", "-Wl,-no_adhoc_codesign", "-o", str(probe)])
        if role == "ios":
            raw = bytearray(probe.read_bytes()); at = next(at for cmd,at,_ in V.M.commands(raw) if cmd == 0x32)
            struct.pack_into("<III", raw, at+8, 2, 0x100100, 0x100100); probe.write_bytes(raw)
        probe_cd = sign(role+"-probe", probe, RIGHTS if role == "ios" else None)
        bindings = [V.require_binding(V.imports(probe.read_bytes()), V.M.libraries(probe.read_bytes()), symbol, "@rpath/EfiSupport27.dylib") for symbol in SYMBOLS]
        candidates.append({"role":role, "efi":{"path":str(efi),"sha256":sha(efi),"bytes":efi.stat().st_size,"CDHash":efi_cd,"UUID":uuid,"unchangedIOSCandidate":role == "ios"},
            "rtti":{"path":str(rtti),"sha256":sha(rtti),"bytes":rtti.stat().st_size,"CDHash":rtti_cd,"unchanged":True},
            "probe":{"path":str(probe),"sha256":sha(probe),"bytes":probe.stat().st_size,"CDHash":probe_cd,"entitlements":RIGHTS if role == "ios" else {},"iOSExecuted":False},
            "seed":{"path":str(seed),"sha256":sha(seed),"bytes":seed.stat().st_size,"unchangedOwnOracle":True}, "modules":modules, "strongPositiveBindings":bindings})
        if role == "macos":
            stdout, _, pid = run("macos-own-nvram-native", [str(probe), sha(probe), str(probe.stat().st_size)])
            records = [json.loads(line) for line in stdout.decode().splitlines()]
            summary = next(row for row in records if row["record"] == "summary")
            assert summary["PID"] == pid and summary["failures"] == 0 and summary["creates"] == summary["destroys"] == 2
            assert summary["persistedRemap"] and summary["ownFilesRemoved"] and not summary["productionNVRAM"]
            candidates[-1]["actualMacOwnNVRAMFixture"] = summary
    manifest = {"sourceSHA256":{p.name:sha(p) for p in source.iterdir()}, "candidates":candidates, "processes":processes, "deviceOperations":False, "productionNVRAM":False, "fullEFIAPIContract":False, "full27Backend":False}
    (out / "candidate.json").write_text(json.dumps(manifest, indent=2)+"\n")
    print(json.dumps({"candidate":str(out / "candidate.json"), "SHA256":sha(out / "candidate.json")}, indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(sys.argv[1])
