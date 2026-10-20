#!/usr/bin/env python3
"""Build scoped native RTTI forwarding and real owned-base lifecycle probe.

No device operations. The independent Mac fixture is actually executed. The
private iOS candidate is only built, signed and validated for Root to execute.
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
REMOTE = "/var/root/VirtualMac2/testing/efi-native-rtti-v1"
EXPORTS = ["__ZN10__cxxabiv120__si_class_type_infoD1Ev", "__ZN10__cxxabiv120__si_class_type_infoD2Ev",
           "_VM27NativeRTTIABIStatus", "_VM27NativeRTTICompleteCalls", "_VM27NativeRTTIBaseCalls"]
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
          "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True}
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
literal = lambda text: "{" + ",".join("0x"+text[i:i+2] for i in range(0,len(text),2)) + "}"


def commands(data):
    assert struct.unpack_from("<I",data)[0] == 0xfeedfacf
    at=32
    for _ in range(struct.unpack_from("<I",data,16)[0]):
        command,size=struct.unpack_from("<II",data,at)
        assert size>=8 and not size%8 and at+size<=32+struct.unpack_from("<I",data,20)[0]
        yield command,at,size
        at+=size
    assert at==32+struct.unpack_from("<I",data,20)[0]


def main(destination):
    out=Path(destination).resolve();out.mkdir(mode=0o700,exist_ok=False)
    source=out/"source";source.mkdir();pins={};processes=[]
    for path in [ROOT/"vz/host/modern_native_rtti_compat.cpp",ROOT/"vz/host/modern_native_rtti_compat.h",
                 ROOT/"scripts/tests/test-modern-native-rtti.cpp",Path(__file__)]:
        shutil.copyfile(path,source/path.name);assert sha(path)==sha(source/path.name);pins[str(path)]=sha(path)
    shutil.copytree(N/"efi-native-rtti-v1/upstream",source/"upstream")
    shutil.copyfile(N/"cxa-primary-exception-v1/upstream-llvm21/LICENSE.TXT",source/"upstream/LICENSE.TXT")
    def run(label,arguments,expected=0):
        child=subprocess.Popen(arguments,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=30)
        except subprocess.TimeoutExpired:child.kill();child.communicate();raise
        (out/(label+".argv.json")).write_text(json.dumps(arguments,indent=2)+"\n")
        (out/(label+".stdout")).write_bytes(stdout);(out/(label+".stderr")).write_bytes(stderr)
        processes.append({"label":label,"directChildPID":child.pid,"observedWaitExit":child.returncode,"reaped":True})
        assert child.returncode==expected,label+" exit="+str(child.returncode)+" "+stderr.decode(errors="replace")[-2200:]
        return stdout,stderr,child.pid
    def sign(label,path,rights=None):
        args=["codesign","--force","--sign","-","--timestamp=none","--identifier","com.virtualmac.diagnostics.native-rtti."+label]
        if rights is not None:
            ent=out/(label+".entitlements");ent.write_bytes(plistlib.dumps(rights));args += ["--entitlements",str(ent)]
        run(label+"-sign",args+[str(path)]);run(label+"-strict",["codesign","--verify","--strict",str(path)])
        run(label+"-validate",["xcrun","dyld_info","-validate_only",str(path)])
        _,signature,_=run(label+"-signature",["codesign","-dvvv",str(path)])
        ent,_,_=run(label+"-rights",["codesign","-d","--entitlements",":-",str(path)])
        assert plistlib.loads(ent)==rights if rights is not None else not ent
        spec=importlib.util.spec_from_file_location("signature",ROOT/"scripts/development/verify-macho-code-directory.py")
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        (out/(label+"-code-directory.json")).write_text(json.dumps(verifier.check(path.read_bytes()),indent=2)+"\n")
        return re.search(rb"CDHash=([0-9a-f]{40})",signature)[1].decode()
    candidates=[]
    for role,sdk,target in [("ios","iphoneos","arm64e-apple-ios16.1"),("macos","macosx","arm64e-apple-macos13.0")]:
        folder=out/role;folder.mkdir()
        capture=N/("rtti-code-native-v1/native.stdout" if role=="ios" else "efi-native-rtti-v1/collector-macos-v1/native.stdout")
        rows=[json.loads(line) for line in capture.read_text().splitlines()]
        image=next(row for row in rows if row["record"]=="image")
        table=next(row for row in rows if row["record"]=="vtable")
        complete=next(row for row in rows if row.get("symbol")=="native-si-complete-destructor-vtable-entry")
        deleting=next(row for row in rows if row.get("symbol")=="native-si-deleting-destructor-vtable-entry")
        base=next(row for row in rows if row.get("symbol")=="_ZNSt9type_infoD2Ev" and row["record"]=="code")
        for row in [complete,deleting,base]:
            assert row["readSucceeded"] and row["entryIsStart"] and row["functionBoundsKnown"]
            assert len(bytes.fromhex(row["hex"]))==row["bytes"]<=2048 and hashlib.sha256(bytes.fromhex(row["hex"])).hexdigest()==row["SHA256"]
        assert table["dataBounds"] and not table["offsetToTop"] and complete["bytes"]==base["bytes"]==4
        word=int.from_bytes(bytes.fromhex(complete["hex"]),"little");assert word&0xfc000000==0x14000000
        delta=word&0x3ffffff;delta-=0x4000000 if delta&0x2000000 else 0
        assert int(complete["RVA"],16)+delta*4==int(base["RVA"],16)
        assert image["UUID"]==("fa871417be083e90b33ca6aa89813f3b" if role=="ios" else "a21743ee6e1c3e7497ea7af793de4bdf")
        text="static constexpr unsigned char NativeUUID[16]="+literal(image["UUID"])+";\n"
        text += "static constexpr uintptr_t NativeTableRVA="+table["RVA"]+";\n"
        for label,row in [("Complete",complete),("Deleting",deleting),("TypeBase",base)]:
            text += "static constexpr uintptr_t Native"+label+"RVA="+row["RVA"]+";\n"
            text += "static constexpr size_t Native"+label+"Bytes="+str(row["bytes"])+";\n"
            text += "static constexpr unsigned char Native"+label+"SHA[32]="+literal(row["SHA256"])+";\n"
        (folder/"native-rtti-pins.h").write_text(text)
        shutil.copyfile(capture,folder/"native-code-source.jsonl")
        exports=folder/"exports.list";exports.write_text("\n".join(EXPORTS)+"\n")
        sdk_path=run(role+"-sdk",["xcrun","--sdk",sdk,"--show-sdk-path"])[0].decode().strip()
        flags=["xcrun","clang++","-target",target,"-isysroot",sdk_path,"-fptrauth-abi-version=0","-std=c++20",
               "-O2","-Wall","-Wextra","-Werror","-Wno-deprecated-declarations","-D_LIBCPP_DISABLE_AVAILABILITY",
               "-fno-typed-cxx-new-delete","-fno-typed-memory-operations-experimental","-I"+str(source),"-I"+str(folder)]
        lib=folder/"VM27NativeRTTICompat.dylib"
        run(role+"-provider-build",flags+["-dynamiclib","-Wl,-no_adhoc_codesign","-Wl,-exported_symbols_list,"+str(exports),
            "-install_name","@rpath/VM27NativeRTTICompat.dylib",str(source/"modern_native_rtti_compat.cpp"),"-o",str(lib)])
        def stamp(path):
            if role=="ios":
                data=bytearray(path.read_bytes());at=next(at for cmd,at,_ in commands(data) if cmd==0x32)
                struct.pack_into("<III",data,at+8,2,0x100100,0x100100);path.write_bytes(data)
        stamp(lib);lib_cd=sign(role+"-provider",lib)
        export_text=run(role+"-exports",["xcrun","dyld_info","-exports",str(lib)])[0]
        rvas=[]
        for name in EXPORTS[:2]:
            match=re.search(rb"(0x[0-9a-fA-F]+)\s+"+name.encode()+rb"\b",export_text);assert match;rvas.append(int(match[1],16))
        data=lib.read_bytes();uuid=next(data[at+8:at+24].hex() for cmd,at,_ in commands(data) if cmd==0x1b)
        path=REMOTE+"/"+lib.name if role=="ios" else str(lib)
        text="static constexpr char ProviderPath[]="+json.dumps(path)+";\nstatic constexpr char ProviderSHA[]="+json.dumps(sha(lib))+";\n"
        text += "static constexpr size_t ProviderBytes="+str(lib.stat().st_size)+";\nstatic constexpr unsigned char ProviderUUID[16]="+literal(uuid)+";\n"
        text += "static constexpr char ProviderUUIDString[]="+json.dumps(uuid)+";\nstatic constexpr uintptr_t ProviderRVA[]={"+",".join(hex(x) for x in rvas)+"};\n"
        (folder/"rtti-provider-pins.h").write_text(text)
        probe=folder/"modern-native-rtti-probe"
        run(role+"-probe-build",flags+(["-DVM27_RTTI_IOS"] if role=="ios" else [])+[str(source/"test-modern-native-rtti.cpp"),str(lib),"-Wl,-rpath,@loader_path","-Wl,-no_adhoc_codesign","-o",str(probe)])
        stamp(probe);probe_cd=sign(role+"-probe",probe,RIGHTS if role=="ios" else None)
        run(role+"-probe-imports",["xcrun","dyld_info","-imports",str(probe)])
        candidates.append({"role":role,"nativeSource":str(capture),"nativeSourceSHA256":sha(capture),
            "library":{"path":str(lib),"sha256":sha(lib),"bytes":lib.stat().st_size,"CDHash":lib_cd,"UUID":uuid,"RVAs":rvas,"installName":"@rpath/VM27NativeRTTICompat.dylib","exports":EXPORTS},
            "probe":{"path":str(probe),"sha256":sha(probe),"bytes":probe.stat().st_size,"CDHash":probe_cd,"entitlements":RIGHTS if role=="ios" else {},"deviceExecuted":False}})
        if role=="macos":
            stdout,_,pid=run("macos-owned-base-native",[str(probe),sha(probe),str(probe.stat().st_size)])
            summary=next(json.loads(line) for line in stdout.decode().splitlines() if json.loads(line)["record"]=="summary")
            assert summary["PID"]==pid and not summary["failures"] and summary["completeCalls"]==summary["baseCalls"]==64
            assert summary["constructedBaseSubobjects"]==summary["releasedRawOwners"]==128
            candidates[-1]["actualMacOwnedBaseFixture"]=summary
    manifest={"sourceSHA256":pins,"candidates":candidates,"processes":processes,"deviceOperations":False,
              "fullNativeSiConstructionVerified":False,"originalEfiAPIExecuted":False,"original27VMMExecuted":False,"full27Backend":False}
    (out/"candidate.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"candidate":str(out/"candidate.json"),"sha256":sha(out/"candidate.json")},indent=2))


if __name__=="__main__":
    assert len(sys.argv)==2
    main(sys.argv[1])
