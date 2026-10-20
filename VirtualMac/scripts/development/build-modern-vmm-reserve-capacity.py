#!/usr/bin/env python3
"""Add the missing exact Swift specialization; no device or original VMM run."""
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
ROOT = Path(__file__).resolve().parents[3]
HOST = ROOT / "VirtualMac/vz/host"
N = ROOT / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
OLD = N / "swift-anyobject-array-build-v5"
SYMBOL = "$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5"
SIBLINGS = [
 "$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5",
 "$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5",
 "$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5",
 "$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5"]
RIGHTS = {"platform-application": True, "com.apple.private.security.no-container": True,
 "com.apple.private.security.no-sandbox": True, "com.apple.private.amfi.can-execute-cdhash": True}

def sha(data): return hashlib.sha256(data).hexdigest()
def load(path, name):
 spec = importlib.util.spec_from_file_location(name, path)
 module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
M = load(ROOT / "VirtualMac/scripts/development/prepare-modern-vmm-runtime-imports.py", "route")
V = load(ROOT / "VirtualMac/scripts/tests/validate-modern-cxa-primary-exception.py", "imports")

def main(destination):
 out = Path(destination).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
 source = out / "source"; source.mkdir()
 inputs = []
 def pin(path):
  item = {"path":str(path.resolve()), "bytes":path.stat().st_size, "sha256":sha(path.read_bytes())}
  inputs.append(item); return item
 for name in ["modern_swift_vmm_reserve_capacity_compat.swift", "modern_swift_vmm_reserve_capacity_fixture.swift",
              "modern_swift_vmm_reserve_capacity_identity.cpp", "modern_swift_vmm_reserve_capacity_identity.h"]:
  p = HOST / name; pin(p); shutil.copy2(p, source / name)
 pin(Path(__file__)); shutil.copy2(__file__, source / Path(__file__).name)
 old = json.loads((OLD / "manifest.json").read_text()); pin(OLD / "manifest.json")
 old_native = json.loads((N / "swift-anyobject-array-native-v1/result.json").read_text())
 assert old_native["passed"] is True and old_native["childPID"] == 34088 and old_native["observedWaitExit"] == 0
 pin(N / "swift-anyobject-array-native-v1/result.json")
 commands = []
 def run(label, argv, env=None, success=True):
  p = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
  try: stdout, stderr = p.communicate(timeout=45)
  except subprocess.TimeoutExpired:
   p.kill(); stdout, stderr = p.communicate(); raise
  item = {"label":label, "argv":list(map(str,argv)), "directChildPID":p.pid, "observedWait":p.returncode,
          "stdoutSHA256":sha(stdout), "stderrSHA256":sha(stderr)}
  commands.append(item); (out / "commands.json").write_text(json.dumps(commands,indent=2)+"\n")
  (out / (label+".stdout")).write_bytes(stdout); (out / (label+".stderr")).write_bytes(stderr)
  if success: assert p.returncode == 0, (label,stderr.decode())
  return p.pid,p.returncode,stdout,stderr
 def signature(p):
  _,_,stdout,stderr = run(p.name+"-"+p.parent.name+"-signature", ["codesign","-dvvv",p])
  s = re.search(rb"CDHash=([a-f0-9]{40})",stderr); assert s
  return s[1].decode()
 def identity(p):
  b = p.read_bytes(); uuids = [b[a+8:a+24].hex() for c,a,z in M.commands(b) if c == 27]; assert len(uuids)==1
  _,_,exports,_=run(p.name+"-"+p.parent.name+"-exports",["xcrun","dyld_info","-exports",p])
  exported = {n.decode():int(r,16) for r,n in re.findall(rb"0x([A-Fa-f0-9]+)\s+(_\$s\S+)\s*$",exports,re.M)}
  return {"path":str(p),"bytes":len(b),"sha256":sha(b),"UUID":uuids[0],"exports":exported,"CDHash":signature(p)}
 roles = []
 for role,target,sdk in [("mac","arm64e-apple-macos13.0","macosx"),("ios","arm64e-apple-ios16.1","iphoneos")]:
  folder = out / role; folder.mkdir();
  _,_,sdko,_=run(role+"-sdk",["xcrun","--sdk",sdk,"--show-sdk-path"]); sdkpath=sdko.decode().strip()
  interface=Path(sdkpath)/("usr/lib/swift/Swift.swiftmodule/arm64e-apple-"+("macos" if role=="mac" else "ios")+".swiftinterface")
  pin(interface)
  # Retain the serialized source window that supplies reserveCapacity's body.
  text=interface.read_text(); needle="public mutating func reserveCapacity(_ minimumCapacity: Swift::Int) {"
  starts=[m.start() for m in re.finditer(re.escape(needle),text)]
  windows=[text[x:x+1700] for x in starts if "_reserveCapacityImpl" in text[x:x+180] and "_createNewBuffer" in text[x:x+1700]]
  assert windows; (out/(role+"-serialized-source-windows.txt")).write_text("\n".join(windows))
  existing=OLD/role/"VM27AnyObjectArray.dylib"
  expected=next(f for f in old["files"] if f["path"]==str(existing))
  assert sha(existing.read_bytes())==expected["sha256"]
  pin(existing); shutil.copy2(existing,folder/existing.name)
  for suffix in ["swiftmodule","swiftdoc","swiftsourceinfo","abi.json"]:
   p=OLD/role/("VM27AnyObjectArray."+suffix)
   if p.exists(): pin(p); shutil.copy2(p,folder/p.name)
  base=["xcrun","--sdk",sdk,"swiftc","-parse-as-library","-target",target,"-sdk",sdkpath,
        "-Xfrontend","-disable-access-control","-Xfrontend","-disable-layout-string-value-witnesses",
        "-Xfrontend","-disable-layout-string-value-witnesses-instantiation","-module-name","VM27VMMArrayReserve",
        "-module-cache-path",out/(role+"-cache"),"-O",HOST/"modern_swift_vmm_reserve_capacity_compat.swift"]
  ir=out/(role+".ll")
  run(role+"-ir",base+["-emit-ir","-o",ir])
  raw=ir.read_text(); definition=re.search(r'^define .*@"'+re.escape(SYMBOL)+r'"\([^\n]+',raw,re.M)
  assert definition and "swiftcc" in definition[0] and "i64" in definition[0] and "swiftself" in definition[0]
  # Neither IR nor linked imports may call the identical exported API.
  assert not re.search(r'^.*\b(?:call|invoke)\b.*@"'+re.escape(SYMBOL)+r'"',raw,re.M) and "tailrecurse" not in raw
  run(role+"-module",base+["-emit-module","-emit-module-path",folder/"VM27VMMArrayReserve.swiftmodule"])
  run(role+"-object",["xcrun","--sdk",sdk,"clang","-target",target,"-isysroot",sdkpath,"-x","ir","-c",ir,"-o",out/(role+".o")])
  exports=out/"exports.list"; exports.write_text("_"+SYMBOL+"\n")
  provider=folder/"VM27VMMArrayReserve.dylib"
  run(role+"-link",["xcrun","--sdk",sdk,"swiftc","-target",target,"-sdk",sdkpath,out/(role+".o"),"-emit-library",
      "-Xlinker","-exported_symbols_list","-Xlinker",exports,"-Xlinker","-install_name","-Xlinker","@rpath/VM27VMMArrayReserve.dylib","-o",provider])
  run(role+"-sign",["codesign","--force","--sign","-","--timestamp=none",provider]); run(role+"-strict",["codesign","--verify","--strict",provider])
  run(role+"-dyld",["xcrun","dyld_info","-validate_only",provider])
  _,_,ipo,_=run(role+"-imports",["xcrun","dyld_info","-imports","-linked_dylibs",provider])
  assert SYMBOL.encode() not in ipo and all(x not in ipo for x in [b"Virtualization",b"Hypervisor",b"flat-namespace",b"_swift_cvw_"])
  new=identity(provider); oldpin=identity(folder/"VM27AnyObjectArray.dylib")
  assert set(new["exports"])=={"_"+SYMBOL} and set(oldpin["exports"])=={"_"+n for n in old["exports"]}
  header=folder/"reserve-capacity-pins.h"
  rows=[new,oldpin]; hp=["#pragma once","struct ProviderPin { const char *file,*uuid,*sha; unsigned long long bytes; };",
       "struct EntryPin { const char *name; unsigned provider; unsigned long long rva; };",
       'static const char *RoleDirectory="'+role+'";',"static const ProviderPin ProviderPins[]={"]
  hp += ['{"'+Path(r["path"]).name+'","'+r["UUID"]+'","'+r["sha256"]+'",'+str(r["bytes"])+"}," for r in rows]
  hp += ["};","static const EntryPin EntryPins[]={"]
  hp += ['{"'+name[1:]+'",'+str(i)+","+str(rva)+"}," for i,r in enumerate(rows) for name,rva in r["exports"].items()]
  hp += ["};"]; header.write_text("\n".join(hp)+"\n")
  obj=out/(role+"-identity.o")
  run(role+"-identity",["xcrun","--sdk",sdk,"clang++","-target",target,"-isysroot",sdkpath,"-std=c++17","-O2",
      "-Wall","-Wextra","-Werror","-Wno-deprecated-declarations","-fno-exceptions","-fno-rtti","-I",folder,
      "-c",HOST/"modern_swift_vmm_reserve_capacity_identity.cpp","-o",obj])
  probe=out/("vmm-reserve-capacity-"+role)
  run(role+"-fixture",["xcrun","--sdk",sdk,"swiftc","-target",target,"-sdk",sdkpath,"-O","-I",folder,
       "-Xfrontend","-disable-access-control","-Xfrontend","-disable-layout-string-value-witnesses",
       "-Xfrontend","-disable-layout-string-value-witnesses-instantiation","-module-cache-path",out/("fixture-"+role+"-cache"),
       "-import-objc-header",HOST/"modern_swift_vmm_reserve_capacity_identity.h",obj,provider,folder/"VM27AnyObjectArray.dylib",
       "-Xlinker","-rpath","-Xlinker","@executable_path/"+role,HOST/"modern_swift_vmm_reserve_capacity_fixture.swift","-o",probe])
  rights=out/"Probe.entitlements"; rights.write_bytes(plistlib.dumps(RIGHTS))
  run(role+"-sign-probe",["codesign","--force","--sign","-","--timestamp=none"]+(["--entitlements",rights] if role=="ios" else [])+[probe])
  run(role+"-strict-probe",["codesign","--verify","--strict",probe]); run(role+"-dyld-probe",["xcrun","dyld_info","-validate_only",probe])
  b=probe.read_bytes(); imports=V.imports(b); deps=M.libraries(b)
  V.require_binding(imports,deps,"_"+SYMBOL,"@rpath/VM27VMMArrayReserve.dylib")
  for sibling in SIBLINGS: V.require_binding(imports,deps,"_"+sibling,"@rpath/VM27AnyObjectArray.dylib")
  info={"role":role,"provider":new,"unchangedSiblingProvider":oldpin,"probe":{"path":str(probe),"bytes":len(b),"sha256":sha(b),
       "CDHash":signature(probe),"entitlements":RIGHTS if role=="ios" else {},"strongPrivateImports":1,"strongSiblingImports":4},
       "recursiveSameSymbolCallAbsent":True,"IRSignature":definition[0],"deviceExecuted":False}
  if role=="mac":
   env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","VM27_PROBE_SHA256":sha(b),"VM27_PROBE_BYTES":str(len(b))}
   pid,wait,stdout,stderr=run("mac-positive",[probe],env=env)
   rec=[json.loads(l) for l in stdout.splitlines()]; assert rec[0]["PID"]==pid
   summary=rec[-1]; assert summary=={"record":"summary","checks":10753,"failures":0,"iterations":128,"reserveCalls":1664,
       "stockCalls":1664,"siblingCalls":512,"destroyedObjects":768,"VMCalls":0,"GPUCalls":0,"diskCalls":0,"full27Backend":False}
   info["actualMac"]={"directChildPID":pid,"observedWait":wait,"stdoutSHA256":sha(stdout),"summary":summary}
   negatives=[]
   for mode in ["--private-allocation-failure","--stock-allocation-failure"]:
    pid,wait,stdout,stderr=run("mac-"+mode[2:],[probe,mode],env=env,success=False)
    assert wait==-6 and json.loads(stdout.splitlines()[0])["PID"]==pid and b'"record":"summary"' not in stdout
    assert stderr == b"Fatal error: failed to allocate 9007199254741024 bytes of memory with alignment 8\n"
    negatives.append({"mode":mode,"directChildPID":pid,"observedWait":wait,"stdoutSHA256":sha(stdout),"stderrSHA256":sha(stderr)})
   info["actualMacRejectedVirtualAllocationControls"]=negatives
  roles.append(info)
 assert all(sha(Path(r["path"]).read_bytes())==r["sha256"] for r in inputs)
 result={"scope":"one missing original VMM specialization plus four unchanged sibling consumers; real Swift COW/ownership",
   "roles":roles,"inputs":inputs,"originalVMMExecuted":False,"completeVMMClosure":False,"full27Backend":False,
   "deviceOperations":False,"productionModified":False,"physicalMemoryExhaustionTested":False,
   "allocationBoundary":"2^50 elements requests 8 PiB plus header without arithmetic wrap; stock/private real allocator rejection controls",
   "oldNativeSiblingProof":{"PID":34088,"wait":0,"checks":5120},"deploymentReady":False}
 (out/"candidate.json").write_text(json.dumps(result,indent=2)+"\n")
 print(json.dumps({"candidateSHA256":sha((out/"candidate.json").read_bytes()),"actualMac":roles[0]["actualMac"],"iOSCompiled":True,"deviceOperations":False},indent=2))

if __name__=="__main__":
 assert len(sys.argv)==2, "Usage: build-modern-vmm-reserve-capacity.py NEW_OUTPUT_DIRECTORY"
 main(sys.argv[1])
