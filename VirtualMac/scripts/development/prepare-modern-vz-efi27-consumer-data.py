#!/usr/bin/env python3
"""Route only original VZ's EFI dependency as inert data, never execute it.

The exact tested genuine27 EFI provider keeps its own implementations. This
does not implement or claim full Secure Boot, original VZ startup, or guest run.
"""
import argparse
import hashlib
import json
import pathlib
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER=R/'VirtualMac/scripts/development/vz_import_addend_image.py'
BASE_READER=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py'
assert hashlib.sha256(READER.read_bytes()).hexdigest()=='935831f5c3af6d56e3504d0c8ec3f0de9583284585213517469e1d56c9535cb8'
assert hashlib.sha256(BASE_READER.read_bytes()).hexdigest()=='87ac47aecb496d313fece77ebab6e64fa28c3bd1df563142da8aa56a40c509a3'
sys.path.insert(0,str(READER.parent))
from vz_import_addend_image import commands,imports,segments,chain_entries,export_trie

SOURCE=N/'original-vz-current-barriers-audit-v1/typed-allocator-route-v2/VZ27.sixteen-runtime-routes.inert.macho-data'
SOURCE_SHA='1536e4dad30df8419640ba85e6805d6112d84c4ed4a91c4e1bc3b17ddd04cd10'
EFI=N/'efi-owned-nvram-v1/build-v5/ios/EfiSupport27.dylib'
OLD_PATH='/System/Library/PrivateFrameworks/EfiSupport.framework/EfiSupport'
NEW_PATH='@loader_path/EfiSupport27.dylib'
NATIVE=N/'efi27-owned-nvram-native-v1'
SELECTED={220:'_CreateEfiVariableStoreRuntimeFromMemory',221:'_DestroyEfiVariableStoreRuntime',
222:'_EfiVariableGetVariable',223:'_EfiVariableSetVariable',224:'_EfiVariableStoreEnrollDefaultKeys',
225:'_EfiVariableStoreSecureBootEnrollSignature',226:'_EfiVariableStoreSecureBootFreeSignatureList',
227:'_EfiVariableStoreSecureBootFreeState',228:'_EfiVariableStoreSecureBootGetState',
229:'_EfiVariableStoreSecureBootParseFile',230:'_EfiVariableStoreSecureBootReset'}
PINNED_DYLIBS={
'EfiSupport27.dylib':('faecd5502e07d043d4f71a62f6e0a8bf43cc9d0f4e987f11bbf5d07ebb52f227',169104),
'VM27NativeRTTICompat.dylib':('1c0306585978aa103821182fbf439bc32803114ea53df547f64de900a48d25e7',51472),
'libPcdDxe.dylib':('ab9637de7332db754f3700fcde142459e8430893e40debd7194b4fe9c4b88165',115456),
'libVariableRuntimeDxe.dylib':('84961be6243008ade2e8eedf28d522c91fd3c336a31454016207311665723f0f',1149728),
'libFaultTolerantWriteDxe.dylib':('d2c4241517252d0c0dcd14dd9afc6c0c7829ce82ca8a7a7dca97fc9310d658e1',115456)}
DYLIB_COMMANDS={12,0x80000018,0x8000001f,0x80000023}

def sha(b):return hashlib.sha256(b).hexdigest()

def pin(p):
    assert p.is_file() and not p.is_symlink()
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=sha(b))

def unique(pairs):
    out={}
    for k,v in pairs:
        assert k not in out
        out[k]=v
    return out

def read_json(p):return json.loads(p.read_bytes(),object_pairs_hook=unique)

def dylibs(b,include_id=False):
    out=[]
    for c,a,z in commands(b):
        if c in DYLIB_COMMANDS or include_id and c==13:
            no=struct.unpack_from('<I',b,a+8)[0];assert 24<=no<z
            end=b.find(b'\0',a+no,a+z);assert end>=a+no
            out.append(dict(ordinal=len(out)+1,command=c,at=a,size=z,nameOffset=no,
                            path=b[a+no:end].decode(),metadata=list(struct.unpack_from('<3I',b,a+12))))
    return out

def provider_proof(binary):
    assert sha(binary)==PINNED_DYLIBS['EfiSupport27.dylib'][0]
    ids=[d for d in dylibs(binary,True) if d['command']==13]
    assert len(ids)==1 and ids[0]['path']=='@rpath/EfiSupport27.dylib' and ids[0]['metadata']==[2,65536,65536]
    deps=dylibs(binary)
    assert [(d['command'],d['path']) for d in deps]==[(12,'/usr/lib/libc++.1.dylib'),(12,'/usr/lib/libSystem.B.dylib'),(12,'@loader_path/VM27NativeRTTICompat.dylib')]
    at=next(a for c,a,z in commands(binary) if c==0x80000033)
    lo,ln=struct.unpack_from('<II',binary,at+8);symbols=export_trie(binary[lo:lo+ln])
    selected=[e for e in symbols if e['symbol'] in SELECTED.values()]
    assert len(selected)==11 and {e['symbol'] for e in selected}==set(SELECTED.values()) and all(e['flags']==0 and e['address'] for e in selected)
    return dict(ID=ids[0],dependencies=deps,exports=selected,totalExports=len(symbols),requiredCompatibilityPreserved=65536,
                exactCurrentVersionMeetsOriginalRequirement=True,secureBootCallsInOriginalVZValidated=False)

def derive(source):
    assert len(source)==4212080 and sha(source)==SOURCE_SHA
    deps=dylibs(source);assert len(deps)==59
    dep=deps[31];assert dep==dict(ordinal=32,command=12,at=7656,size=96,nameOffset=24,path=OLD_PATH,metadata=[2,65536,65536])
    capacity=dep['size']-dep['nameOffset'];path=NEW_PATH.encode()+b'\0';assert len(path)<=capacity
    result=bytearray(source);start=dep['at']+dep['nameOffset'];result[start:start+capacity]=path+bytes(capacity-len(path))
    return bytes(result),dict(dependency=dep,newPath=NEW_PATH,allowedByteRange=[start,start+capacity])

def verify(source,candidate,provider):
    expected,detail=derive(source);assert candidate==expected
    proof=provider_proof(provider)
    before=imports(source);after=imports(candidate);assert before==after and len(before['imports'])==1056
    selected=[]
    for i,name in SELECTED.items():
        row=before['imports'][i]
        assert row['name']==name and row['ordinal']==32 and row['weak'] is False and row['addend']==0
        selected.append(row)
    old=dylibs(source);new=dylibs(candidate)
    for a,b in zip(old,new):
        want=dict(a)
        if a['ordinal']==32:want['path']=NEW_PATH
        assert b==want
    assert segments(source)==segments(candidate)
    a=list(chain_entries(source));b=list(chain_entries(candidate));assert a==b and len(a)==26993
    assert all(sum(x['bind'] and x['import_index']==i for x in a)==1 for i in SELECTED)
    changes=[i for i,(a,b) in enumerate(zip(source,candidate))if a!=b]
    assert changes and min(changes)>=detail['allowedByteRange'][0] and max(changes)<detail['allowedByteRange'][1]
    assert source[:detail['allowedByteRange'][0]]==candidate[:detail['allowedByteRange'][0]] and source[detail['allowedByteRange'][1]:]==candidate[detail['allowedByteRange'][1]:]
    return dict(**detail,provider=proof,selectedImports=selected,changedBytes=len(changes),changedOffsets=changes,
                importsAndNlistsAllUnchanged=True,originalCodeDataAndSelectorABIBytesUnchanged=True,
                chainWordsAndPACUnchanged=True,chainCount=26993,sectionAndLinkeditPositionsUnchanged=True,
                signatureCommandAndPayloadUnchanged=True,signatureExpectedStale=True)

def negative_controls(source,candidate,provider):
    checks=[]
    def bad(name,b,p=provider):
        try:verify(source,b,p)
        except(AssertionError,ValueError,struct.error,IndexError):checks.append(dict(name=name,rejected=True));return
        raise AssertionError('accepted damaged control '+name)
    parsed=imports(source)['imports'];chain=next(x for x in chain_entries(source)if x['bind'] and x['import_index']==220)
    for name,at,mask in [('unselected old route',16,1),('path',7680,1),('original instruction',9584,1),('original PAC',chain['fileoff']+7,128),('platform',next(a for c,a,z in commands(source)if c==0x32)+8,1),('metadata current',7656+16,1),('metadata compatibility',7656+20,1)]:
        q=bytearray(candidate);q[at]^=mask;bad(name,bytes(q))
    for index in SELECTED:
        for name,k,mask in [('ordinal',0,1),('weak',1,1),('addend',4,1)]:
            q=bytearray(candidate);q[parsed[index]['command']+k]^=mask;bad(f'import{index} '+name,bytes(q))
    q=bytearray(candidate);struct.pack_into('<I',q,7656,0x80000018);bad('genuine weak EFI dependency',bytes(q))
    bad('source extra trailingbyte',candidate+b'\0')
    q=bytearray(provider);q[0]^=1;bad('wrong provider bytes',candidate,bytes(q))
    return checks

def saved_provider_closure():
    plan=read_json(NATIVE/'plan.json');receipt=read_json(NATIVE/'result.json')
    assert sha((NATIVE/'plan.json').read_bytes())=='9b8963adb2bfa7b6b8724a83b8d31da72ef12ec183e0f1b010d9a73ccbec8cd4'
    assert receipt['passed'] is True and receipt['childPID']==32039 and receipt['observedWaitExit']==0 and receipt['childAbsent'] is True
    assert receipt['native']['checks']==562 and receipt['native']['EFICalls']==28 and receipt['native']['fullEFIAPIContract'] is False
    rows=[]
    for name,(wanted,bytes_) in PINNED_DYLIBS.items():
        path=EFI.parent/name;b=path.read_bytes();assert sha(b)==wanted and len(b)==bytes_
        match=[f for f in plan['files'] if f['name']==name];assert len(match)==1 and match[0]['sha256']==wanted and match[0]['bytes']==bytes_ and match[0]['entitlements']=={}
        rows.append(dict(binary=pin(path),IDAndDependencies=dylibs(b,True),exactPreviouslyDeployedNativeFile=True))
    stdout=(NATIVE/'native.stdout').read_bytes();rs=[json.loads(l,object_pairs_hook=unique) for l in stdout.splitlines()]
    assert rs[0]['PID']==32039 and rs[-1]==receipt['native']
    checks=[r for r in rs if r['record']=='check'];assert len(checks)==562 and [r['id'] for r in checks]==list(range(1,563)) and all(r['passed'] is True for r in checks)
    modules=[r for r in rs if r['record']=='module'];assert len(modules)==6 and all(r['actualLoaded'] is True for r in modules)
    return dict(files=rows,savedNativeReceipt=pin(NATIVE/'result.json'),savedNativeStdout=pin(NATIVE/'native.stdout'),
                savedNativePlan=pin(NATIVE/'plan.json'),savedNativePID=32039,savedNativeChecks=562,savedNativeEFICalls=28,
                savedNativeReexecuted=False,threeDXEModulesAreDynamicDependencies=True,
                dynamicModulesMustRemainDiscoverableToUnchangedOriginalEFILoader=True,
                originalVZModuleLoaderSearchContextValidated=False,originalVZRuntimeBindingValidated=False,
                sixImportedCoreAPIContractsExercised=True,remainingSecureBootAndPolicyAPIsUntested=True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--check',action='store_true');args=ap.parse_args()
    root=N.resolve();out=args.output.expanduser().absolute();assert root in out.parents
    assert out.resolve()==out and not out.is_symlink()
    source=SOURCE.read_bytes();provider=EFI.read_bytes();target=out/'VZ27.efi27-original-route.inert.macho-data'
    if args.check:
        c=read_json(out/'candidate.json');assert c['binary']==pin(target)
        assert verify(source,target.read_bytes(),provider)==c['verification']
        assert stat.S_IMODE(target.stat().st_mode)==0o600 and c['originalVZLoaded'] is False
        assert negative_controls(source,target.read_bytes(),provider)==read_json(out/'negative-controls.json')
        print(json.dumps(dict(passed=True,binary=pin(target),deviceOperations=0)));return
    assert not out.exists();out.mkdir(parents=True)
    data,_=derive(source);target.write_bytes(data);target.chmod(0o600)
    proof=verify(source,data,provider);bad=negative_controls(source,data,provider);closure=saved_provider_closure()
    static=[]
    for name,flags in [('validate',['-validate_only']),('imports',['-imports','-linked_dylibs'])]:
        argv=['xcrun','dyld_info',*flags,str(target)];r=subprocess.run(argv,capture_output=True)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        assert r.returncode==0 and not r.stderr;static.append(dict(argv=argv,exit=r.returncode,inputImageExecuted=False))
    candidate=dict(schema='Original VZ dependency32 genuine27 EFI path inert contract v1',source=pin(SOURCE),binary=pin(target),
                   builder=pin(pathlib.Path(__file__)),readers=[pin(READER),pin(BASE_READER)],verification=proof,
                   providerClosure=closure,staticTools=static,negativeControlCount=len(bad),signingCalls=0,deviceOperations=0,
                   providerExecuted=False,originalVZLoaded=False,originalVMMExecuted=False,guestInstructions=0,full27Backend=False,
                   remainingDependenciesInitializationAndEFIAPIContractsUnknown=True)
    (out/'negative-controls.json').write_text(json.dumps(bad,indent=2)+'\n')
    (out/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),binary=pin(target),negativeControls=len(bad),originalVZLoaded=False)))

if __name__=='__main__':main()
