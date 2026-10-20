#!/usr/bin/env python3
"""Build a bounded read-only system libxpc collector; execute only Mac copy."""
from pathlib import Path
import hashlib
import json
import plistlib
import re
import shutil
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
RIGHTS={"platform-application":True,"com.apple.private.security.no-container":True,
        "com.apple.private.security.no-sandbox":True}


def main(output):
    out=Path(output).resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=out / "source";source.mkdir()
    for path in (Path(__file__),ROOT / "scripts/tests/native-xpc-code-collector.c"):
        shutil.copyfile(path,source / path.name)
    records=[]

    def run(label,args):
        child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=20)
        except subprocess.TimeoutExpired:child.kill();child.communicate();raise
        (out / (label+".argv.json")).write_text(json.dumps(args,indent=2)+"\n")
        (out / (label+".stdout")).write_bytes(stdout);(out / (label+".stderr")).write_bytes(stderr)
        records.append({"label":label,"directChildPID":child.pid,"observedWaitExit":child.returncode,"reaped":True})
        assert child.returncode==0,(label,stderr.decode(errors="replace")[-2000:])
        return stdout,stderr,child.pid

    candidates=[]
    for role,sdk,target in (("ios","iphoneos","arm64e-apple-ios16.1"),("macos","macosx","arm64e-apple-macos13")):
        folder=out / role;folder.mkdir();binary=folder / "native-xpc-code-collector"
        sdkpath=run(role+"-sdk",["xcrun","--sdk",sdk,"--show-sdk-path"])[0].decode().strip()
        run(role+"-compile",["xcrun","clang","-target",target,"-isysroot",sdkpath,
            "-fptrauth-abi-version=0","-O2","-Wall","-Wextra","-Werror","-Wno-deprecated-declarations",
            str(source / "native-xpc-code-collector.c"),"-Wl,-no_adhoc_codesign","-o",str(binary)])
        if role=="ios":
            data=bytearray(binary.read_bytes());at=32
            for _ in range(struct.unpack_from("<I",data,16)[0]):
                cmd,size=struct.unpack_from("<II",data,at)
                if cmd==0x32:struct.pack_into("<III",data,at+8,2,0x100100,0x100100)
                at+=size
            binary.write_bytes(data)
        rights=RIGHTS if role=="ios" else {}
        ent=folder / "Probe.entitlements";ent.write_bytes(plistlib.dumps(rights))
        run(role+"-sign",["codesign","--force","--sign","-","--timestamp=none",
            "--identifier","com.virtualmac.diagnostics.native-xpc-collector-v1","--entitlements",str(ent),str(binary)])
        run(role+"-strict",["codesign","--verify","--strict",str(binary)])
        run(role+"-validate",["xcrun","dyld_info","-validate_only",str(binary)])
        _,sig,_=run(role+"-signature",["codesign","-dvvv",str(binary)])
        actual=run(role+"-rights",["codesign","-d","--entitlements",":-",str(binary)])[0]
        assert plistlib.loads(actual)==rights
        row={"role":role,"path":str(binary),"bytes":binary.stat().st_size,
            "sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
            "CDHash":re.search(rb"CDHash=([0-9a-f]{40})",sig)[1].decode(),"entitlements":rights,"iOSExecuted":False}
        if role=="macos":
            stdout,_,pid=run("macos-readonly-native",[str(binary)])
            logs=[json.loads(line) for line in stdout.decode().splitlines()]
            assert logs[0]["PID"]==pid and logs[0]["registrationCalls"]==0
            summary=logs[-1];assert summary["passed"] and summary["registrationCalls"]==0
            for code in (r for r in logs if r["record"]=="code"):
                assert code["readSucceeded"] and len(bytes.fromhex(code["hex"]))==code["bytes"]<=2048
                assert hashlib.sha256(bytes.fromhex(code["hex"])).hexdigest()==code["SHA256"]
            row["actualMacReadonly"]=summary
        candidates.append(row)
    manifest={"candidates":candidates,"processes":records,"sourceSHA256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()},
        "deviceOperations":False,"registrationCalls":0,"nativeOldIOSProviderCaptured":False,"full27Backend":False}
    (out / "candidate.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps(manifest,indent=2))


if __name__=="__main__":
    assert len(sys.argv)==2
    main(sys.argv[1])
