#!/usr/bin/env python3
"""Independent binary/signature/strong-import and actual transcript verifier."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import plistlib
import re
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
N=ROOT/"DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=load(ROOT/"VirtualMac/scripts/development/prepare-modern-vmm-runtime-imports.py","macho")
V=load(ROOT/"VirtualMac/scripts/tests/validate-modern-cxa-primary-exception.py","generic")
S=load(ROOT/"VirtualMac/scripts/development/verify-macho-code-directory.py","signature")
NEW="_$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5"
OLD=["_$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5",
 "_$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5",
 "_$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5",
 "_$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5"]
RIGHTS={"platform-application":True,"com.apple.private.security.no-container":True,
 "com.apple.private.security.no-sandbox":True,"com.apple.private.amfi.can-execute-cdhash":True}
SUMMARY={"record":"summary","checks":10753,"failures":0,"iterations":128,"reserveCalls":1664,"stockCalls":1664,
 "siblingCalls":512,"destroyedObjects":768,"VMCalls":0,"GPUCalls":0,"diskCalls":0,"full27Backend":False}

def same(a,b):
 if type(a) is not type(b):return False
 if isinstance(a,dict):return a.keys()==b.keys() and all(same(a[k],b[k])for k in a)
 if isinstance(a,list):return len(a)==len(b) and all(same(x,y)for x,y in zip(a,b))
 return a==b

def entitlements(data):
 start,size=next(struct.unpack_from("<II",data,a+8)for c,a,z in M.commands(data)if c==0x1d)
 blob=data[start:start+size]; count=struct.unpack_from(">I",blob,8)[0];result={}
 for i in range(count):
  kind,at=struct.unpack_from(">II",blob,12+i*8)
  if kind==5:
   magic,length=struct.unpack_from(">II",blob,at);assert magic==0xfade7171
   result=plistlib.loads(blob[at+8:at+length])
 return result

def native(rows,role,pid,wait,negative=False):
 assert type(pid) is int and pid>1 and type(wait) is int and wait==(-6 if negative else 0)
 assert same(rows[0],{"record":"start","PID":pid,"VMCalls":0,"GPUCalls":0,"diskCalls":0,"CPUsoft":5,"CPUhard":6,"wallSeconds":10})
 expected=[role["provider"],role["unchangedSiblingProvider"]]
 phases=["before"] if negative else ["before","after"]
 for phase in phases:
  providers=[r for r in rows if r.get("record")=="provider" and r.get("phase")==phase]
  assert len(providers)==2
  for i,pin in enumerate(expected):
   assert same(providers[i],{"record":"provider","phase":phase,"index":i,"UUID":pin["UUID"],"fileSHA256":pin["sha256"],
        "exactFile":True,"exactOwnerAndRVA":True})
  identities=[r for r in rows if r.get("record")=="identity" and r.get("phase")==phase]
  assert len(identities)==1 and same(identities[0],{"record":"identity","phase":phase,"entries":9,"selfFileExact":True,"entryCallsDuringIdentity":0})
 if negative:
  assert len(rows)==4 and not any(r.get("record")=="summary" for r in rows)
  return {"directChildPID":pid,"wait":wait,"actualAllocatorRejection":True,"physicalMemoryExhaustionTested":False}
 assert len(rows)==16 and same(rows[-1],SUMMARY)
 cap=[r for r in rows if r.get("record")=="capacity"]
 assert [r["requested"]for r in cap]==[-2**63,-1,0,2,3,4,17,64] and len(cap)==8
 for r in cap:
  assert set(r)=={"record","requested","private","stock","count"}
  assert all(type(r[k])is int for k in ["requested","private","stock","count"])
  assert r["count"]==3 and r["private"]>=max(r["requested"],3) and r["stock"]>=max(r["requested"],3)
 return SUMMARY

def validate(build):
 manifest=json.loads((build/"candidate.json").read_text()); commands=json.loads((build/"commands.json").read_text())
 assert manifest["originalVMMExecuted"] is False and manifest["full27Backend"] is False and manifest["deviceOperations"] is False
 assert manifest["physicalMemoryExhaustionTested"] is False
 for pin in manifest["inputs"]:
  p=Path(pin["path"]);assert p.is_file()and not p.is_symlink()and p.stat().st_size==pin["bytes"]and sha(p.read_bytes())==pin["sha256"]
 bindings=[];signature_rows=[]
 for role in manifest["roles"]:
  files=[role["provider"],role["unchangedSiblingProvider"],role["probe"]]
  for index,pin in enumerate(files):
   p=Path(pin["path"]);b=p.read_bytes();assert len(b)==pin["bytes"]and sha(b)==pin["sha256"]
   signed=S.check(b);assert len(signed)==1 and signed[0]["cdhash"]==pin["CDHash"]
   expected_rights=RIGHTS if role["role"]=="ios" and index==2 else {}
   assert same(entitlements(b),expected_rights)
   expected_subtype=0x81000002 if role["role"]=="mac" and index==2 else 0x80000002
   assert struct.unpack_from("<II",b,4)==(0x100000c,expected_subtype)
   version=next(struct.unpack_from("<III",b,a+8)for c,a,z in M.commands(b)if c==0x32)
   assert version[0]==(2 if role["role"]=="ios" else 1) and version[1]==(0x100100 if role["role"]=="ios" else 0xd0000)
   signature_rows.append({"role":role["role"],"file":p.name,"CodeDirectory":signed[0],"entitlements":expected_rights,
        "ABI0":expected_subtype==0x80000002,"cpuSubtype":expected_subtype,"buildVersion":version})
  for name,owner in [(NEW,"@rpath/VM27VMMArrayReserve.dylib")]+[(n,"@rpath/VM27AnyObjectArray.dylib")for n in OLD]:
   row=V.require_binding(V.imports(Path(role["probe"]["path"]).read_bytes()),M.libraries(Path(role["probe"]["path"]).read_bytes()),name,owner)
   bindings.append({"role":role["role"],"symbol":name,"owner":owner,"ordinal":row["ordinal"]})
  b=Path(role["provider"]["path"]).read_bytes();assert not any(r["symbol"]==NEW for r in V.imports(b))
  ir=(build/(role["role"]+".ll")).read_text()
  assert re.search(r'^define swiftcc void @"'+re.escape(NEW[1:])+r'"\(i64 %0, ptr swiftself .*dereferenceable\(8\) %1\)',ir,re.M)
  assert not re.search(r'^.*\b(?:call|invoke)\b.*@"'+re.escape(NEW[1:])+r'"',ir,re.M)
  assert "@swift_isUniquelyReferenced_nonNull_native" in ir and "@swift_allocObject" in ir and "@swift_getTypeByMangledNameInContext(" in ir
  assert not any(x in name for name in M.libraries(b)for x in ["Virtualization","Hypervisor"])
  assert role["deviceExecuted"] is False
 mac=next(r for r in manifest["roles"]if r["role"]=="mac")
 actual=next(c for c in commands if c["label"]=="mac-positive")
 stdout=(build/"mac-positive.stdout").read_bytes();rows=[json.loads(l)for l in stdout.splitlines()]
 assert sha(stdout)==actual["stdoutSHA256"]==mac["actualMac"]["stdoutSHA256"]
 result=native(rows,mac,actual["directChildPID"],actual["observedWait"])
 controls=[]
 for mode in ["private-allocation-failure","stock-allocation-failure"]:
  actual=next(c for c in commands if c["label"]=="mac-"+mode)
  stdout=(build/("mac-"+mode+".stdout")).read_bytes();stderr=(build/("mac-"+mode+".stderr")).read_bytes()
  assert sha(stdout)==actual["stdoutSHA256"]and sha(stderr)==actual["stderrSHA256"]
  assert stderr==b"Fatal error: failed to allocate 9007199254741024 bytes of memory with alignment 8\n"
  controls.append(native([json.loads(l)for l in stdout.splitlines()],mac,actual["directChildPID"],actual["observedWait"],negative=True))
 bad=[]
 for change in ["wrongPID","wrongWait","missingAfter","missingSummary","falseOwnership","boolCounter","missingSiblingCalls","falseFile","wrongUUID","wrongRowCount"]:
  altered=copy.deepcopy(rows);pid=mac["actualMac"]["directChildPID"];wait=0
  if change=="wrongPID":pid+=1
  elif change=="wrongWait":wait=1
  elif change=="missingAfter":altered=[r for r in altered if r.get("phase")!="after"]
  elif change=="missingSummary":altered.pop()
  elif change=="falseOwnership":altered[-1]["destroyedObjects"]=767
  elif change=="boolCounter":altered[-1]["failures"]=False
  elif change=="missingSiblingCalls":altered[-1]["siblingCalls"]=0
  elif change=="falseFile":altered[1]["exactFile"]=False
  elif change=="wrongUUID":altered[1]["UUID"]="0"*32
  elif change=="wrongRowCount":altered.append(copy.deepcopy(altered[-1]))
  try:native(altered,mac,pid,wait)
  except (AssertionError,KeyError):bad.append({"name":change,"rejected":True})
  else:raise AssertionError("Bad model accepted: "+change)
 return {"candidateSHA256":sha((build/"candidate.json").read_bytes()),"signatures":signature_rows,"actualStrongImports":bindings,
  "actualMac":result,"actualMacAllocationFailureControls":controls,"badModels":bad,"deviceOperations":False,
  "originalVMMExecuted":False,"full27Backend":False,"passed":True}

if __name__=="__main__":
 assert len(sys.argv)==2;print(json.dumps(validate(Path(sys.argv[1]).resolve()),indent=2))
