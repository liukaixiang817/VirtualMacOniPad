#!/usr/bin/env python3
"""Assemble exact C++ providers and one more original VMM strong binding.

No device access and no original VMM execution. The unsigned VMM retains its
original macOS platform, LC_MAIN and incomplete framework dependencies. Scoped
Mac provider probes exercise real functions through the new explicit reexport.
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

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
CXX = N / "vmm-loader-closure-v2/cxx-build-v6"
CXA = N / "cxa-primary-exception-v1/build-v4"
TWENTY = N / "vmm-loader-closure-v2/twenty-bindings-v3"
REMOTE = "/var/root/VirtualMac2/testing/vmm-runtime-aggregate-v1"
REEXPORT = "@rpath/VM27PrimaryExceptionCompat.dylib"
WRAPPER = "@rpath/VM27CxxABICompat.dylib"
RIGHTS = {"platform-application": True,
          "com.apple.private.security.no-container": True,
          "com.apple.private.security.no-sandbox": True,
          "com.apple.private.amfi.can-execute-cdhash": True}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


M = load(ROOT / "scripts/development/prepare-modern-vmm-runtime-imports.py", "routes")
P = load(ROOT / "scripts/development/prepare-modern-vmm-cxx-closure.py", "sections")
V = load(ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py", "bindings")


def append_reexport(original):
    before = bytes(original)
    data = bytearray(before)
    old_commands = list(M.commands(data))
    old_end = 32 + struct.unpack_from("<I", data, 20)[0]
    sections = P.ranges(M, data)
    first_section = min(row["offset"] for row in sections)
    command = bytearray(M.dylib_command(REEXPORT))
    struct.pack_into("<I", command, 0, 0x8000001f)
    assert REEXPORT not in M.libraries(data)
    assert old_end + len(command) <= first_section
    assert not any(data[old_end:first_section])
    data[old_end:old_end + len(command)] = command
    count, size, flags = struct.unpack_from("<III", data, 16)
    assert flags & 0x80  # MH_TWOLEVEL is required.
    struct.pack_into("<III", data, 16, count + 1, size + len(command), flags & ~0x100000)
    assert P.ranges(M, data) == sections
    assert M.libraries(data) == M.libraries(before) + [REEXPORT]
    assert [bytes(data[a:a+z]) for c,a,z in M.commands(before)] == [before[a:a+z] for c,a,z in old_commands]
    assert V.imports(data) == V.imports(before)
    return bytes(data), {"appendedStrongReexport": REEXPORT,
        "commandBytes": len(command), "originalDependenciesPreserved": True,
        "originalImportsAndAddendsPreserved": True, "reconstructedCodeAndDataUnchanged": True,
        "UUIDPreserved": True, "oldFlags": flags, "newFlags": flags & ~0x100000,
        "sections": sections}


def route_original_vmm(original):
    assert sha(original) == "6edd853f8d1bdcca597adde53b06b678aa05faa549404bdd5c1330f564411ce1"
    assert len(original) == 5195312
    data = bytearray(original)
    imports = M.import_rows(data)
    target = next(row for row in imports if row["symbol"] == "___cxa_init_primary_exception")
    assert target["ordinal"] == 14 and not target["weak"] and target["addend"] == 0
    dependencies = M.libraries(data)
    assert len(dependencies) == 53 and dependencies[50] == WRAPPER
    word = struct.unpack_from("<I", data, target["offset"])[0]
    struct.pack_into("<I", data, target["offset"], (word & ~255) | 51)
    symtab = next(struct.unpack_from("<IIII", data, at + 8) for cmd,at,_ in M.commands(data) if cmd == 2)
    symoff,count,stroff,strsize = symtab
    changed_nlist = []
    for index in range(count):
        at = symoff + index * 16
        name,kind,section,desc,value = struct.unpack_from("<IBBHQ", data, at)
        if kind & 0xe0 or kind & 0xe or not name:
            continue
        if M.string(data, stroff + name, stroff + strsize) == target["symbol"]:
            assert desc >> 8 == 14 and not desc & 0x40
            struct.pack_into("<H", data, at + 6, (desc & 255) | (51 << 8))
            changed_nlist.append({"offset": at + 6, "old": desc,
                                  "new": (desc & 255) | (51 << 8)})
    assert len(changed_nlist) == 1
    after = M.import_rows(data)
    for a,b in zip(imports,after):
        expected = dict(a)
        if a["symbol"] == target["symbol"]:
            expected["ordinal"] = 51
        assert b == expected
    assert P.ranges(M,data) == P.ranges(M,original)
    assert M.libraries(data) == dependencies
    changed = [i for i,(a,b) in enumerate(zip(original,data)) if a != b]
    assert set(changed) <= {target["offset"], changed_nlist[0]["offset"] + 1}
    assert len(data) == len(original)
    return bytes(data), {"sourceSHA256": sha(original), "newBinding": target,
        "newPositiveOrdinal": 51, "provider": WRAPPER, "nlistChanges": changed_nlist,
        "changedOffsets": changed, "totalExplicitCompatibilityBindings": 21,
        "allOtherImportsAndAddendsAndWeakFlagsUnchanged": True,
        "fileBackedSectionsUnchanged": True, "allLoadCommandsAndPlatformUnchanged": True,
        "originalVMMExecuted": False, "completeVMMClosure": False,
        "executionGate": "Do not execute: original framework paths and other typed contracts remain unresolved."}


def main(destination):
    out = Path(destination).resolve()
    out.mkdir(mode=0o700, exist_ok=False)
    source = out / "source"
    source.mkdir()
    for path in [Path(__file__), ROOT / "scripts/tests/test-modern-vmm-cxx-closure.cpp",
                 ROOT / "scripts/tests/test-modern-cxa-primary-exception.cpp",
                 ROOT / "scripts/tests/validate-modern-vmm-runtime-aggregate.py",
                 ROOT / "vz/host/modern_cxa_primary_exception_compat.h"]:
        shutil.copyfile(path, source / path.name)
    shutil.copytree(CXX / "source",source / "cxx")
    for path in (CXX / "source").rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (source / "cxx" / path.relative_to(CXX / "source")).read_bytes()
    process = []

    def run(label, args, expected=0):
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); raise
        (out / (label + ".argv.json")).write_text(json.dumps(args,indent=2) + "\n")
        (out / (label + ".stdout")).write_bytes(stdout)
        (out / (label + ".stderr")).write_bytes(stderr)
        process.append({"label":label,"directChildPID":child.pid,
                        "observedWaitExit":child.returncode,"reaped":True})
        if child.returncode != expected:
            raise RuntimeError(label + ": " + str(child.returncode) + " " + stderr.decode(errors="replace")[-2500:])
        return stdout,stderr,child.pid

    def sign(label,path,rights=None):
        args = ["codesign","--force","--sign","-","--timestamp=none",
                "--identifier","com.virtualmac.diagnostics.vmm-runtime-aggregate." + label]
        if rights:
            ent = out / (label + ".entitlements")
            ent.write_bytes(plistlib.dumps(rights)); args += ["--entitlements",str(ent)]
        run(label + "-sign",args + [str(path)])
        run(label + "-strict",["codesign","--verify","--strict",str(path)])
        run(label + "-validate",["xcrun","dyld_info","-validate_only",str(path)])
        _,sig,_ = run(label + "-signature",["codesign","-dvvv",str(path)])
        ent,_,_ = run(label + "-rights",["codesign","-d","--entitlements",":-",str(path)])
        assert plistlib.loads(ent) == rights if rights else not ent
        check = load(ROOT / "scripts/development/verify-macho-code-directory.py","codesign_check").check(path.read_bytes())
        cd = re.search(rb"CDHash=([0-9a-f]{40})",sig)[1].decode()
        assert len(check) == 1 and check[0]["cdhash"] == cd
        return {"path":str(path),"sha256":sha(path.read_bytes()),"bytes":path.stat().st_size,
                "CDHash":cd,"entitlements":rights or {}}

    candidates = []
    for role,sdk,target in (("ios","iphoneos","arm64e-apple-ios16.1"),
                            ("macos","macosx","arm64e-apple-macos13")):
        folder = out / role; folder.mkdir()
        wrapper = folder / "VM27CxxABICompat.dylib"
        original = (CXX / role / wrapper.name).read_bytes()
        if role == "ios":
            patched,review = append_reexport(original); wrapper.write_bytes(patched)
        else:
            # The original Mac fixture has only 24 bytes of header padding.
            # Rebuild its retained source rather than moving original sections
            # or weakening metadata preservation for the actual iOS artifact.
            args = json.loads((CXX / "macos-provider-compile.command.json").read_text())
            args = [a.replace(str(CXX / "source"),str(source / "cxx")) for a in args]
            args[args.index("-target") + 1] = target
            args[args.index("-o") + 1] = str(wrapper)
            args += ["-Wl,-reexport_library," + str(CXA / role / "VM27PrimaryExceptionCompat.dylib"),
                     "-Wl,-headerpad,0x200","-fptrauth-abi-version=0"]
            run("macos-wrapper-rebuild",args)
            review = {"appendedStrongReexport":REEXPORT,"MacFixtureOnlyRebuiltFromExactRetainedCxxSource":True,
                      "iOSReconstructionPreservationRuleUnchanged":True}
        wrapper_row = sign(role + "-wrapper",wrapper)
        if role == "ios":
            assert P.ranges(M,wrapper.read_bytes()) == P.ranges(M,original)
            assert V.imports(wrapper.read_bytes()) == V.imports(original)
        files = []
        names = ["VM27PrimaryExceptionCompat.dylib"]
        if role == "ios": names += ["VM27CxxProvider.dylib","ModernCPURuntimeCompat.dylib"]
        for name in names:
            src = CXA / role / name; dest = folder / name
            shutil.copyfile(src,dest)
            assert sha(src.read_bytes()) == sha(dest.read_bytes())
            run(role + "-" + name + "-strict",["codesign","--verify","--strict",str(dest)])
            check = load(ROOT / "scripts/development/verify-macho-code-directory.py","original_signature").check(dest.read_bytes())
            files.append({"path":str(dest),"sha256":sha(dest.read_bytes()),"bytes":dest.stat().st_size,
                          "CDHash":check[0]["cdhash"],"source":str(src),"unchanged":True})
        pins = (CXX / role / "vmm-cxx-closure-pins.h").read_text()
        previous = ("/var/root/VirtualMac2/testing/vmm-loader-closure-v2" if role == "ios" else str(CXX / role))
        pins = pins.replace(previous,REMOTE if role == "ios" else str(folder))
        pins = pins.replace(sha(original),sha(wrapper.read_bytes()))
        pins = re.sub(r"PinBytes=\d+", "PinBytes=" + str(wrapper.stat().st_size),pins)
        if role == "macos":
            data = wrapper.read_bytes()
            uuid = next(data[a+8:a+24].hex() for c,a,z in M.commands(data) if c == 0x1b)
            pins = re.sub(r'PinUUIDHex\[\]="[0-9a-f]+"','PinUUIDHex[]=' + json.dumps(uuid),pins)
            literal = "{" + ",".join("0x" + uuid[i:i+2] for i in range(0,len(uuid),2)) + "}"
            pins = re.sub(r'PinUUID\[\]=\{[^}]+\}','PinUUID[]=' + literal,pins)
            pins = re.sub(r'PinSubtype=0x[0-9a-fA-F]+',
                          'PinSubtype=' + hex(struct.unpack_from("<I",data,8)[0]),pins)
            exports = run("macos-wrapper-exports",["xcrun","dyld_info","-exports",str(wrapper)])[0]
            rvas = []
            for name in P.TARGETS:
                match = re.search(rb"(0x[0-9a-fA-F]+)\s+" + re.escape(name.encode()) + rb"\b",exports)
                assert match,name
                rvas.append(match[1].decode())
            pins = re.sub(r'PinRVAs\[\]=\{[^}]+\}', 'PinRVAs[]={' + ",".join(rvas) + '}',pins)
        (folder / "vmm-cxx-closure-pins.h").write_text(pins)
        pins = (CXA / role / "cxa-provider-pins.h").read_text()
        previous = ("/var/root/VirtualMac2/testing/cxa-primary-exception-v1" if role == "ios" else str(CXA / role))
        pins = pins.replace(previous,REMOTE if role == "ios" else str(folder))
        extra = "{" + json.dumps((REMOTE if role == "ios" else str(folder)) + "/" + wrapper.name) + "," + json.dumps(sha(wrapper.read_bytes())) + "," + str(wrapper.stat().st_size) + "},\n"
        pins = pins.replace("};\nstatic constexpr unsigned char ProviderUUID",extra + "};\nstatic constexpr unsigned char ProviderUUID",1)
        (folder / "cxa-provider-pins.h").write_text(pins)
        sdkpath = run(role + "-sdk",["xcrun","--sdk",sdk,"--show-sdk-path"])[0].decode().strip()
        flags = ["xcrun","clang++","-target",target,"-isysroot",sdkpath,
            "-fptrauth-abi-version=0","-std=c++20","-O2","-Wall","-Wextra","-Werror",
            "-Wno-deprecated-declarations","-D_LIBCPP_DISABLE_AVAILABILITY",
            "-D_LIBCPP_ENABLE_CXX17_REMOVED_UNEXPECTED_FUNCTIONS","-fno-typed-cxx-new-delete",
            "-fno-typed-memory-operations-experimental","-I" + str(source),"-I" + str(folder),
            "-L" + str(folder),"-Wl,-rpath,@loader_path","-Wl,-no_adhoc_codesign"]
        probes = []
        for kind,name in (("cxx","test-modern-vmm-cxx-closure.cpp"),("cxa","test-modern-cxa-primary-exception.cpp")):
            probe = folder / ("vmm-aggregate-" + kind + "-probe")
            args = flags + [str(source / name),str(wrapper)]
            if kind == "cxa":
                native = folder / "NativeSystemCxxABI.tbd"
                shutil.copyfile(CXA / role / native.name,native)
                args += [str(native)]
                if role == "ios": args += ["-DVM27_PRIMARY_EXCEPTION_IOS"]
            run(role + "-" + kind + "-compile",args + ["-o",str(probe)])
            if role == "ios":
                data = bytearray(probe.read_bytes())
                at = next(a for c,a,z in M.commands(data) if c == 0x32)
                struct.pack_into("<III",data,at+8,2,0x100100,0x100100); probe.write_bytes(data)
            row = sign(role + "-" + kind + "-probe",probe,RIGHTS if role == "ios" else None)
            imports,deps = V.imports(probe.read_bytes()),M.libraries(probe.read_bytes())
            symbols = list(P.TARGETS) if kind == "cxx" else ["___cxa_init_primary_exception"]
            if role == "ios" and kind == "cxa": symbols.append("__ZNSt13exception_ptr31__from_native_exception_pointerEPv")
            row["strongBindings"] = [V.require_binding(imports,deps,sym,WRAPPER) for sym in symbols]
            probes.append(row)
            if role == "macos":
                arguments = [str(probe)] if kind == "cxx" else [str(probe),row["sha256"],str(row["bytes"])]
                stdout,_,pid = run("macos-" + kind + "-actual",arguments)
                summary = next(json.loads(line) for line in stdout.decode().splitlines() if json.loads(line)["record"] == "summary")
                assert summary["failures"] == 0
                row["actualMacFixture"] = {"directChildPID":pid,"observedWaitExit":0,"summary":summary}
                if kind == "cxa": run("macos-cxa-saved-terminate",arguments + ["--terminate-control"],expected=79)
        candidates.append({"role":role,"wrapper":wrapper_row,"reexportReview":review,
                           "unchangedBacking":files,"probes":probes,"iOSExecuted":False})

    original = (TWENTY / "VirtualMachine27.twenty-strong.macos.unsigned").read_bytes()
    final,review = route_original_vmm(original)
    vmm = out / "VirtualMachine27.twenty-one-strong.macos.unsigned"; vmm.write_bytes(final)
    run("original-vmm-static",["xcrun","dyld_info","-validate_only",str(vmm)])
    manifest = {"candidates":candidates,"originalVMM":{"path":str(vmm),"bytes":len(final),
        "sha256":sha(final),"review":review},"processes":process,
        "sourceSHA256":{str(p.relative_to(source)):sha(p.read_bytes()) for p in source.rglob("*") if p.is_file()},
        "deviceOperations":False,"completeVMMClosure":False,"originalVMMExecuted":False}
    (out / "candidate.json").write_text(json.dumps(manifest,indent=2) + "\n")
    run("independent-aggregate-validation",[sys.executable,
        str(ROOT / "scripts/tests/validate-modern-vmm-runtime-aggregate.py"),str(out)])
    print(json.dumps({"candidate":str(out / "candidate.json"),"SHA256":sha((out / "candidate.json").read_bytes()),
                      "originalVMMExecuted":False,"completeVMMClosure":False},indent=2))


if __name__ == "__main__":
    assert len(sys.argv) == 2, "tracked builder NEW_OUTPUT_DIRECTORY"
    main(sys.argv[1])
