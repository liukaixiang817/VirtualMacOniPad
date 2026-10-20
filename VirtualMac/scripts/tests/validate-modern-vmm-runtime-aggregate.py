#!/usr/bin/env python3
"""Independent exact reexport,21 strong routes and actual fixture validation.

No device access, framework loading or process launch. Native transcript input
requires the runner's observed PID/wait, not a PID inferred from child output.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
N = ROOT.parent / "DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm"


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


V=load(ROOT / "scripts/tests/validate-modern-cxa-primary-exception.py","cxa")
P=load(ROOT / "scripts/development/prepare-modern-vmm-cxx-closure.py","cxx")
C=load(ROOT / "scripts/tests/validate-modern-vmm-cxx-closure.py","cxx_log")
M=V.M
sha=lambda data:hashlib.sha256(data).hexdigest()
WRAPPER="@rpath/VM27CxxABICompat.dylib"
CXA="@rpath/VM27PrimaryExceptionCompat.dylib"


def identity_manifest(build):
    candidate=json.loads((build / "candidate.json").read_text())
    providers=[]
    for row in candidate["candidates"]:
        pins=(build / row["role"] / "vmm-cxx-closure-pins.h").read_text()
        uuid=re.search(r'PinUUIDHex\[\]="([0-9a-f]{32})"',pins)[1]
        rvas=re.search(r'PinRVAs\[\]=\{([^}]+)\}',pins)[1].split(',')
        assert len(rvas)==len(P.TARGETS)==13
        provider=dict(row["wrapper"])
        provider.update({"UUID":uuid,"RVAs":{n:int(r,16) for n,r in zip(P.TARGETS,rvas)}})
        providers.append({"role":row["role"],"provider":provider})
    return {"libraries":providers,"exports":list(P.TARGETS),"deviceOperations":False,
            "originalVMMExecuted":False,"completeVMMClosure":False}


def native_transcript(build,path,role,kind,pid,wait,terminate=False):
    assert role in ("ios","macos") and kind in ("cxx","cxa")
    if kind=="cxx":
        assert not terminate
        return C.validate(path,build / "probe-identity-manifest.json",role,pid,wait)
    return V.transcript(Path(path),pid,wait,terminate)


def main(build):
    candidate=json.loads((build / "candidate.json").read_text())
    assert candidate["deviceOperations"] is candidate["completeVMMClosure"] is candidate["originalVMMExecuted"] is False
    for name,digest in candidate["sourceSHA256"].items():
        assert sha((build / "source" / name).read_bytes())==digest
    verifier=load(ROOT / "scripts/development/verify-macho-code-directory.py","code_directory")
    controls=[]
    for row in candidate["candidates"]:
        for entry in [row["wrapper"],*row["unchangedBacking"],*row["probes"]]:
            data=Path(entry["path"]).read_bytes()
            assert sha(data)==entry["sha256"] and len(data)==entry["bytes"]
            code=verifier.check(data)
            assert len(code)==1 and code[0]["cdhash"]==entry["CDHash"]
            if "source" in entry:
                assert Path(entry["source"]).read_bytes()==data and entry["unchanged"]
            assert struct.unpack_from("<I",data,24)[0]&0x80
        wrapper=Path(row["wrapper"]["path"]).read_bytes()
        commands=list(M.commands(wrapper))
        reexports=[M.string(wrapper,a+24,a+z) for c,a,z in commands if c==0x8000001f]
        assert CXA in reexports and not struct.unpack_from("<I",wrapper,24)[0]&0x100000
        if row["role"]=="ios":
            assert reexports==["@rpath/VM27CxxProvider.dylib",CXA]
            old=(N / "vmm-loader-closure-v2/cxx-build-v6/ios/VM27CxxABICompat.dylib").read_bytes()
            assert sha(old)=="d521c72b3e058ba24cee9347c2e2990a595f2dc834c3f3d1827c3d1a351bce21"
            assert V.imports(wrapper)==V.imports(old) and P.ranges(M,wrapper)==P.ranges(M,old)
            assert M.libraries(wrapper)==M.libraries(old)+[CXA]
            for c,a,z in M.commands(old):
                if c!=0x1d and c!=0x19:
                    assert wrapper[a:a+z]==old[a:a+z]
            at=next(a for c,a,z in commands if c==0x32)
            assert struct.unpack_from("<III",wrapper,at+8)==(2,0x100100,0x100100)
        for probe in row["probes"]:
            data=Path(probe["path"]).read_bytes()
            imports,deps=V.imports(data),M.libraries(data)
            for expected in probe["strongBindings"]:
                assert V.require_binding(imports,deps,expected["symbol"],WRAPPER)==expected
                for mutation in ("weak","flat","missing","wrong-provider"):
                    changed=[dict(r) for r in imports];changed_deps=list(deps)
                    index=next(i for i,r in enumerate(changed) if r["symbol"]==expected["symbol"])
                    if mutation=="weak":changed[index]["weak"]=True
                    elif mutation=="flat":changed[index]["ordinal"]=-2
                    elif mutation=="missing":changed.pop(index)
                    else:changed_deps[changed[index]["ordinal"]-1]="/usr/lib/libSystem.B.dylib"
                    try:V.require_binding(changed,changed_deps,expected["symbol"],WRAPPER)
                    except AssertionError:controls.append({"role":row["role"],"symbol":expected["symbol"],"mutation":mutation,"rejected":True})
                    else:raise AssertionError("invalid strong binding accepted")
    actual=Path(candidate["originalVMM"]["path"]).read_bytes()
    old=(N / "vmm-loader-closure-v2/twenty-bindings-v3/VirtualMachine27.twenty-strong.macos.unsigned").read_bytes()
    assert sha(old)=="6edd853f8d1bdcca597adde53b06b678aa05faa549404bdd5c1330f564411ce1"
    assert sha(actual)==candidate["originalVMM"]["sha256"] and len(actual)==len(old)==5195312
    assert [i for i,(a,b) in enumerate(zip(old,actual)) if a!=b]==[5048360,5117215]
    assert P.ranges(M,actual)==P.ranges(M,old)
    assert M.libraries(actual)==M.libraries(old)
    end=32+struct.unpack_from("<I",old,20)[0]
    assert actual[:end]==old[:end]
    imports,deps=V.imports(actual),M.libraries(actual)
    assert len(imports)==1203 and sum(not r["weak"] for r in imports)==1064
    assert sum(r["ordinal"]>=51 for r in imports)==21
    expected=dict(V.require_binding(V.imports(old),deps,"___cxa_init_primary_exception","/usr/lib/libc++.1.dylib"))
    expected["ordinal"]=51
    assert V.require_binding(imports,deps,"___cxa_init_primary_exception",WRAPPER)==expected
    identity=identity_manifest(build)
    identity_path=build / "probe-identity-manifest.json"
    identity_bytes=(json.dumps(identity,indent=2)+"\n").encode()
    if identity_path.exists():
        assert identity_path.read_bytes()==identity_bytes
    else:
        identity_path.write_bytes(identity_bytes)
    fixtures=[]
    for kind in ("cxx","cxa"):
        record=next(r for r in candidate["processes"] if r["label"]=="macos-"+kind+"-actual")
        assert record["reaped"]
        fixtures.append(native_transcript(build,build/("macos-"+kind+"-actual.stdout"),"macos",kind,
            record["directChildPID"],record["observedWaitExit"]))
    record=next(r for r in candidate["processes"] if r["label"]=="macos-cxa-saved-terminate")
    assert record["reaped"]
    saved=native_transcript(build,build/"macos-cxa-saved-terminate.stdout","macos","cxa",
        record["directChildPID"],record["observedWaitExit"],True)
    print(json.dumps({"candidateSHA256":sha((build/"candidate.json").read_bytes()),
        "strongBindingNegativeControls":controls,"actualMacFixtures":fixtures,"savedTerminateControl":saved,
        "originalVMM21StrongRoutes":True,"iOSExecuted":False,"originalVMMExecuted":False,
        "completeVMMClosure":False,"passed":True},indent=2))


if __name__=="__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]).resolve())
