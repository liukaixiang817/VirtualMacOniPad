#!/usr/bin/env python3
"""Create an inert iOS-singleton selection port with exactly two branch changes.

No framework is loaded. The original VZ ownership/PAC epilogue and all other
bytes are retained. This does not claim macOS multi-GPU selection semantics.
"""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec = importlib.util.spec_from_file_location('singleton_frontier',HERE/'audit-modern-genuine-hid-current-frontier-v19.py')
f = importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
p,n = f.p,f.NODE
BASE = n/'vz-metal-array-real-reexport-data-v4/candidate.json'
ORIGINAL = n/'metal-copyall-original-contract-readonly-v1/audit.json'
GPU = n/'ordinary-metal-array-gpu-device-result-v1/verdict.json'
FIXTURE = n/'metal-singleton-selection-source-fixture-v1/candidate.json'
OUT = n/'vz-metal-singleton-selection-data-v3'
OLD_START,OLD_TEXT,SIZE = 0x226197dd0,0x225f38570,620
SITES = {0x3c:(0x340004f4,0x14000027,0xd8),
         0x15c:(0xaa1703e0,0x1400000f,0x198)}


def signed(value,bits): return value-(1<<bits) if value>>(bits-1) else value
def branch(pc,word): return pc+4*signed(word&0x3ffffff,26)
def freeze(path,pins):
    for row in json.loads(path.read_bytes())['files']:
        assert p.pin(Path(row['path']))==row;pins.append(row)
    pins.append(p.pin(path))


def starts(raw):
    base=next(row for row in p.segments(raw) if row['name']=='__TEXT')['address']
    rows=[row for row in p.commands(raw) if row[0]==0x26];assert len(rows)==1
    _,at,size=rows[0];assert size==16
    offset,length=struct.unpack_from('<II',raw,at+8);data=raw[offset:offset+length]
    assert len(data)==length
    values=[];cursor=0;address=base
    while cursor<len(data):
        value=shift=0
        while True:
            assert cursor<len(data) and shift<=63
            part=data[cursor];cursor+=1;value|=(part&127)<<shift
            if not part&128:break
            shift+=7
        if not value:break
        address+=value;values.append(address)
    assert data[cursor:]==bytes(len(data)-cursor)
    return values,dict(command=at,dataOffset=offset,dataBytes=length)


def cfg(body):
    """Finite normal intraprocedural paths; external calls may return or throw.

    Exception tables and cleanup bodies are byte-preserved, not reinterpreted.
    This graph makes no claim of executing any original VZ instruction.
    """
    todo=[0];seen=set();calls=[];outside=[]
    while todo:
        at=todo.pop()
        if at in seen:continue
        assert 0<=at<SIZE and at%4==0;seen.add(at)
        word=struct.unpack_from('<I',body,at)[0];targets=[]
        if word&0xfc000000==0x14000000:targets=[branch(at,word)]
        elif word&0xfc000000==0x94000000:
            calls.append(at);targets=[at+4]
        elif word&0xff000010==0x54000000 or word&0x7e000000==0x34000000:
            targets=[at+4,at+4*signed((word>>5)&0x7ffff,19)]
        elif word&0x7e000000==0x36000000:
            targets=[at+4,at+4*signed((word>>5)&0x3fff,14)]
        elif word&0xffe0001f==0xd4200000 or word&0xfffffc1f==0xd65f0000:pass
        else:targets=[at+4]
        for target in targets:
            if 0<=target<SIZE:todo.append(target)
            else:outside.append(dict(fromOffset=at,toRelativeOffset=target))
    return dict(reachableOffsets=sorted(seen),reachableExternalCallOffsets=sorted(calls),tailEdges=outside,
                staticNormalPathsOnly=True,exceptionTablesAndCleanupBytesUnchanged=True)


def contract(before,after,offset):
    assert len(before)==len(after)
    permitted={offset+at+i for at in SITES for i in range(4)}
    assert all(a==b for i,(a,b) in enumerate(zip(before,after)) if i not in permitted)
    for at,(old,new,target) in SITES.items():
        assert struct.unpack_from('<I',before,offset+at)[0]==old
        assert struct.unpack_from('<I',after,offset+at)[0]==new
        assert branch(at,new)==target
    original=before[offset:offset+SIZE];modified=after[offset:offset+SIZE]
    assert len(original)==len(modified)==SIZE
    assert struct.unpack_from('<I',modified)[0]==0xd503237f
    assert struct.unpack_from('<I',modified,0x208)[0]==0xd50323ff
    assert modified[0x20c:0x21c]==original[0x20c:0x21c] # PAC integrity + original autorelease tail.
    assert list(p.commands(before))==list(p.commands(after))
    a,b=cfg(original),cfg(modified)
    unsafe={0xa0,0x160,0x16c}
    assert unsafe<=set(a['reachableExternalCallOffsets'])
    assert not unsafe&set(b['reachableOffsets'])
    # Both paths rejoin before the original selected-object retain and release.
    assert {0x198,0x19c,0x1c4,0x1cc,0x218}<=set(b['reachableOffsets'])
    return a,b


def main():
    assert not OUT.exists();pins=[]
    for src in (BASE,ORIGINAL,GPU,FIXTURE):freeze(src.parent/'freeze.json',pins)
    base,original,gpu,fixture=[json.loads(x.read_bytes()) for x in (BASE,ORIGINAL,GPU,FIXTURE)]
    assert gpu['actualGenuineGPUValidated'] and gpu['actualOwnedGPUArrayLifetimePassed']
    assert gpu['actualBothConsumerSelectorsAbsentFor64Devices'] and not gpu['originalVZCallerExecuted']
    assert gpu['summary']['nonNilNativeDefaults']==gpu['summary']['ownedArrays']==64
    assert gpu['summary']['registryIdentityComparisons']==64 and gpu['summary']['isLowPowerResponses']==gpu['summary']['isRemovableResponses']==0
    assert len(fixture['normalAndSanitizedGenuineResults'])==2
    for role in fixture['normalAndSanitizedGenuineResults']:
        assert role['exit']==0 and role['actual']['genuineSingletonComparisons']==256
        assert role['actual']['sameNativeRegistryAfterArrayAndPoolRelease']==256 and role['actual']['portedSourcePowerOrRemovableCalls']==0
    before=Path(base['frontendCandidate']['path']).read_bytes()
    assert p.pin(Path(base['frontendCandidate']['path']))==base['frontendCandidate']
    assert base['frontendCandidate']['sha256']=='64fc5a58674cb6e0df3af75d429698e30733cc3629ca8baccefa7dcf9884af77'
    text=next(row for segment in p.segments(before) for row in segment['sections'] if row['name']=='__text')
    assert text['size']==2510260 and text['address']==0x100002570
    offset=text['fileoff']+OLD_START-OLD_TEXT;address=text['address']+OLD_START-OLD_TEXT
    assert offset==2498000 and address==0x100261dd0
    functions,table=starts(before);index=functions.index(address)
    assert index==7521 and functions[index+1]-functions[index]==SIZE
    captured=Path(original['originalVZConsumer']['data']['path']).read_bytes()
    assert p.pin(Path(original['originalVZConsumer']['data']['path']))==original['originalVZConsumer']['data']
    assert len(captured)==SIZE and original['originalVZConsumer']['start']==OLD_START
    for at,(old,_,_) in SITES.items():assert struct.unpack_from('<I',captured,at)[0]==old
    after=bytearray(before)
    for at,(_,new,_) in SITES.items():struct.pack_into('<I',after,offset+at,new)
    after=bytes(after);old_cfg,new_cfg=contract(before,after,offset)
    negatives=[]
    probes=[('wrong first target',offset+0x3c,0x14000028),
            ('wrong second target',offset+0x15c,0x14000010),
            ('second branch links LR',offset+0x15c,0x9400000f),
            ('power call still reachable',offset+0x15c,0xaa1703e0),
            ('PAC entry changed',offset,0xd503201f),
            ('PAC exit changed',offset+0x208,0xd503201f),
            ('selected retain argument removed',offset+0x198,0xd503201f),
            ('original autorelease tail removed',offset+0x218,0xd503201f),
            ('MachO header changed',0,0),('unrelated text changed',text['fileoff'],0)]
    for label,at,word in probes:
        bad=bytearray(after);struct.pack_into('<I',bad,at,word)
        try:contract(before,bytes(bad),offset)
        except (AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted unsafe port '+label)
    for label,bad in [('truncated file',after[:-1]),('extended file',after+b'\0')]:
        try:contract(before,bad,offset)
        except (AssertionError,ValueError):negatives.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted wrong extent')
    for kind,at,_ in p.commands(before):
        if kind in (0x80000034,0x80000033,0x26,0x2e):
            off,size=struct.unpack_from('<II',before,at+8);assert before[off:off+size]==after[off:off+size]
    schema=f.import_records(before,p.commands)
    assert schema==f.import_records(after,p.commands) and len(schema['imports'])==1056
    assert len([row for row in schema['imports'] if not row['weak']])==1011
    dep=next(row for row in p.dependencies(after) if row['ordinal']==26)
    assert dep['path']=='@loader_path/MD'
    OUT.mkdir();destination=OUT/'VZ27.ios-singleton-selection.mac.inert.macho-data';destination.write_bytes(after);destination.chmod(0o600)
    result=subprocess.run(['xcrun','dyld_info','-validate_only',str(destination)],capture_output=True,timeout=30)
    (OUT/'dyld-validate.stdout').write_bytes(result.stdout);(OUT/'dyld-validate.stderr').write_bytes(result.stderr)
    assert result.returncode==0
    p.save(OUT/'candidate.json',dict(schema='Finite original VZ iOS singleton Metal selection data port v3',
        sourceFrontend=p.pin(BASE),sourceFrontendImage=base['frontendCandidate'],frontendCandidate=p.pin(destination),
        originalMachineContract=p.pin(ORIGINAL),ordinaryGenuineSourceComparison=p.pin(FIXTURE),priorActualIPadGPU=p.pin(GPU),
        currentExtractedFunction=dict(address=address,fileOffset=offset,size=SIZE,functionStartIndex=index,functionTable=table),
        originalCacheFunction=dict(address=OLD_START,size=SIZE,data=original['originalVZConsumer']['data']),
        extractionAlreadyRelocatedInstructionByteDifferences=sum(a!=b for a,b in zip(captured,before[offset:offset+SIZE])),
        instructionPatches=[dict(functionOffset=at,fileOffset=offset+at,oldWord=old,newWord=new,targetFunctionOffset=target)
                            for at,(old,new,target) in SITES.items()],
        changedInstructionWords=2,changedWholeFileBytes=sum(a!=b for a,b in zip(before,after)),
        allOtherWholeFileBytesPreserved=True,originalNormalCFG=old_cfg,portedNormalCFG=new_cfg,
        originalAllPACWordsAndFixupsNlistMetadataHeadersAndImportsPreserved=True,originalRetainReleaseAndPlusZeroAutoreleaseTailPreserved=True,
        originalInstructionBytesEntirelyPreserved=False,actualMDPublisherPin=base['unchangedRuntimeProvider'],
        requiredPublisherShape='Owned NSArray containing the original native default device, or empty if genuine default is nil.',
        acceptsMacMultipleDeviceCatalog=False,preferenceIrrelevantOnlyWithinSingletonDomain=True,
        nativeObjectIdentityPreserved=True,syntheticGPUObjectsUsed=False,devicePropertiesFabricated=False,systemMethodsAdded=0,
        unsafeMacPropertyCallSitesUnreachableOnNormalPaths=True,newStrongImportsAdded=0,totalOriginalImports=1056,originalStrongImports=1011,
        negativeControls=negatives,structuralValidationExit=result.returncode,originalVZCallerExecuted=False,
        actualMDDSOLoaded=False,newIPadPortExecuted=False,codeSigned=False,preexistingSignatureInvalidAfterInstructionMutation=True,
        nativeCPUCalls=0,nativeVMCalls=0,deviceOperations=0,metadataCompatibilityProven=False,
        currentCompleteProviderDependencyGraphValidated=False,candidateReadyForNativeLoading=False,full27Backend=False))
    pins += [p.pin(x) for x in (Path(__file__),BASE,ORIGINAL,GPU,FIXTURE,destination,OUT/'candidate.json',
              OUT/'dyld-validate.stdout',OUT/'dyld-validate.stderr')]
    unique={row['path']:row for row in pins};assert all(unique[row['path']]==row for row in pins)
    p.save(OUT/'freeze.json',dict(files=list(unique.values()),deviceOperations=0,nativeCPUCalls=0))
    print(json.dumps(dict(candidate=p.pin(OUT/'candidate.json'),freeze=p.pin(OUT/'freeze.json'),changedBytes=7,
                         negativeControls=len(negatives),originalVZExecuted=False)))


if __name__=='__main__':main()
