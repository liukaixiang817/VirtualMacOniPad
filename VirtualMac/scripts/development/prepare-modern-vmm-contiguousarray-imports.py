#!/usr/bin/env python3
"""Bind five exact strong original VMM imports to private real Swift providers.

Only inert data is prepared. Never changes original platform, executes VMM, or
modifies system/production libraries. A private Cxx wrapper receives reexports.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
N = ROOT / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
BASE = N / "vmm-runtime-aggregate-v1/build-v4"
RESERVE = N / "vmm-contiguousarray-reserve-contract-v1/build-v6"
TARGETS = {
 948:"_$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5",
 949:"_$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5",
 950:"_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5",
 951:"_$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5",
 952:"_$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5"}
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=load(ROOT/"VirtualMac/scripts/development/prepare-modern-vmm-runtime-imports.py","imports")
P=load(ROOT/"VirtualMac/scripts/development/prepare-modern-vmm-cxx-closure.py","sections")
V=load(ROOT/"VirtualMac/scripts/tests/validate-modern-cxa-primary-exception.py","generic")
S=load(ROOT/"VirtualMac/scripts/development/verify-macho-code-directory.py","signature")

def main(destination):
 out=Path(destination).resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 source=BASE/"VirtualMachine27.twenty-one-strong.macos.unsigned"; original=source.read_bytes()
 assert sha(original)=="42df45e72778512a2ea5054d01e2c940650e7a836f580b99723f8bce5f02266d" and len(original)==5195312
 data=bytearray(original); rows=M.import_rows(data); deps=M.libraries(data)
 assert len(deps)==53 and deps[50]=="@rpath/VM27CxxABICompat.dylib" and sum(not r["weak"] for r in rows)==1064
 selected=[]
 for index,symbol in TARGETS.items():
  r=rows[index]; assert r["symbol"]==symbol and r["ordinal"]==41 and r["weak"] is False and r["addend"]==0
  word=struct.unpack_from("<I",data,r["offset"])[0];struct.pack_into("<I",data,r["offset"],(word&~255)|51)
  selected.append(r)
 symoff,count,stroff,strsize=next(struct.unpack_from("<4I",data,a+8) for c,a,z in M.commands(data) if c==2)
 changed_nlist=[]
 for i in range(count):
  a=symoff+i*16;strx,kind,section,desc,value=struct.unpack_from("<IBBHQ",data,a)
  if kind&0xe0 or kind&0xe or not strx:continue
  name=M.string(data,stroff+strx,stroff+strsize)
  if name in TARGETS.values():
   assert desc>>8==41 and not desc&0x40
   struct.pack_into("<H",data,a+6,(desc&255)|(51<<8));changed_nlist.append({"symbol":name,"offset":a+7,"before":desc,"after":(desc&255)|(51<<8)})
 # These five names exist only in the genuine chained-import table. The
 # original 1,070-entry nlist is not a mirror of all 1,203 chained imports.
 assert len(changed_nlist)==0
 after=M.import_rows(data)
 for a,b in zip(rows,after):
  expected=dict(a)
  if a["index"] in TARGETS:expected["ordinal"]=51
  assert b==expected
 expected_offsets={r["offset"] for r in selected}|{r["offset"] for r in changed_nlist}
 changes=[i for i,(a,b) in enumerate(zip(original,data)) if a!=b]
 assert len(data)==len(original) and set(changes)==expected_offsets and len(changes)==5
 assert M.libraries(data)==deps and P.ranges(M,data)==P.ranges(M,original)
 assert all(data[r["offset"]:r["offset"]+r["bytes"]]==original[r["offset"]:r["offset"]+r["bytes"]] for r in P.ranges(M,original))
 assert all(data[a:a+z]==original[a:a+z] for c,a,z in M.commands(original))
 artifact=out/"VirtualMachine27.twenty-six-strong.macos.unsigned.data";artifact.write_bytes(data);artifact.chmod(0o600)
 folder=out/"ios";folder.mkdir()
 cand=json.loads((RESERVE/"candidate.json").read_text()); role=next(r for r in cand["roles"] if r["role"]=="ios")
 providers=[]
 for p in [role["provider"],role["unchangedSiblingProvider"]]:
  path=Path(p["path"]);raw=path.read_bytes();assert sha(raw)==p["sha256"] and len(raw)==p["bytes"]
  copied=folder/path.name;shutil.copy2(path,copied);providers.append({"path":str(copied),"sourcePath":str(path),"sha256":sha(raw),"bytes":len(raw),"CDHash":p["CDHash"],"unchanged":True})
 # There is insufficient space for another original-VMM dependency. Preserve
 # all 53 ordinals and append real reexports to the separate private wrapper.
 wrapper_source=BASE/"ios/VM27CxxABICompat.dylib"; old=wrapper_source.read_bytes()
 assert sha(old)=="cb5e52b6dc494d2423dac460f99d7b6ec79aa60299378dedd075a514f6822d8f"
 edited=bytearray(old);end=32+struct.unpack_from("<I",old,20)[0];first=min(r["offset"] for r in P.ranges(M,old))
 added=[]
 for name in ["@rpath/VM27VMMArrayReserve.dylib","@rpath/VM27AnyObjectArray.dylib"]:
  assert name not in M.libraries(old);cmd=bytearray(M.dylib_command(name));struct.pack_into("<I",cmd,0,0x8000001f)
  assert end+len(cmd)<=first and not any(edited[end:end+len(cmd)])
  edited[end:end+len(cmd)]=cmd;end+=len(cmd);added.append(name)
 struct.pack_into("<II",edited,16,struct.unpack_from("<I",old,16)[0]+2,end-32)
 assert M.libraries(edited)==M.libraries(old)+added and V.imports(edited)==V.imports(old)
 assert all(edited[r["offset"]:r["offset"]+r["bytes"]]==old[r["offset"]:r["offset"]+r["bytes"]] for r in P.ranges(M,old))
 wrapper=folder/"VM27CxxABICompat.dylib";wrapper.write_bytes(edited)
 commands=[]
 for label,args in [("sign-wrapper",["codesign","--force","--sign","-","--timestamp=none",wrapper]),
      ("strict-wrapper",["codesign","--verify","--strict",wrapper]),("dyld-wrapper",["xcrun","dyld_info","-validate_only",wrapper]),
      ("dyld-inert-vmm",["xcrun","dyld_info","-validate_only",artifact])]:
  p=subprocess.Popen(list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=p.communicate(timeout=30)
  commands.append({"label":label,"PID":p.pid,"wait":p.returncode,"argv":list(map(str,args))})
  (out/(label+".stdout")).write_bytes(stdout);(out/(label+".stderr")).write_bytes(stderr);assert p.returncode==0
 signed=wrapper.read_bytes();assert V.imports(signed)==V.imports(old) and M.libraries(signed)==M.libraries(old)+added
 assert P.ranges(M,signed)==P.ranges(M,old)
 assert all(signed[r["offset"]:r["offset"]+r["bytes"]]==old[r["offset"]:r["offset"]+r["bytes"]] for r in P.ranges(M,old))
 record=S.check(signed);assert len(record)==1
 report={"sourceVMM":{"path":str(source),"sha256":sha(original),"bytes":len(original)},
   "inertVMM":{"path":str(artifact),"sha256":sha(data),"bytes":len(data),"mode":"0600"},
   "newFiveChainedImports":selected,"newOrdinal":51,"newOwner":"@rpath/VM27CxxABICompat.dylib","matchingNlistChanges":changed_nlist,
   "originalNlistContainsTheseFiveNames":False,"entireOriginalNlistUnchanged":True,
   "changedOffsets":changes,"originalDependenciesCount":53,"actualImportsCount":1203,"strongImportsCount":1064,
   "allOtherImportsWeakAddendsUnchanged":True,"allOriginalCodeDataChainWordsUnchanged":True,
   "allOriginalLoadCommandsPlatformMainUnchanged":True,"explicitPrivateRuntimeRoutes":26,
   "privateWrapper":{"path":str(wrapper),"sha256":sha(signed),"bytes":len(signed),"signature":record,
       "addedRealReexports":added,"originalWrapperCodeDataImportsUnchanged":True,"originalWrapperReexportsPreserved":True,"executed":False},
   "unchangedProviders":providers,"commands":commands,"originalVMMExecuted":False,"completeVMMClosure":False,
   "full27Backend":False,"deviceOperations":False,"productionModified":False,
   "executionGate":"Do not execute VMM: original macOS framework paths, full CPU and service contracts remain unresolved."}
 (out/"candidate.json").write_text(json.dumps(report,indent=2)+"\n")
 print(json.dumps({"candidateSHA256":sha((out/"candidate.json").read_bytes()),"inertVMM":report["inertVMM"],"explicitRoutes":26,"deviceOperations":False},indent=2))

if __name__=="__main__":
 assert len(sys.argv)==2;main(sys.argv[1])
