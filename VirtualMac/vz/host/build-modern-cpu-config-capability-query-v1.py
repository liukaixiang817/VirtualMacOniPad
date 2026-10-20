#!/usr/bin/env python3
"""Prepare a distinct unsigned query-only fixture, never execute it here."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
R=Path(__file__).resolve().parents[3];S=Path(__file__).resolve().parent
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-config-capability-query-local-v1'
def need(v,w):
    if not v:raise ValueError(w)
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(label,args,env=None):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
    steps.append(dict(label=label,args=args,exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr'))))
    need(p.returncode==0,label+' exit '+str(p.returncode));return p.stdout
def main():
    global steps
    steps=[];D.mkdir(exist_ok=True);need(not (D/'candidate.json').exists(),'new candidate only')
    model=S/'test-modern-cpu-tlbi-capability-values-v1.c';values=S/'modern_cpu_tlbi_capability_values_v1.c'
    flags=['-Wall','-Wextra','-Werror','-I',str(S)]
    for label,extra in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        executable=D/(label+'-pure-values')
        run(label+'-compile',['xcrun','--sdk','macosx','clang',*flags,*extra,str(values),str(model),'-o',str(executable)])
        env=dict(os.environ);env['ASAN_OPTIONS']='detect_leaks=0'
        out=run(label+'-run',[str(executable)],env);need(json.loads(out)['checks']==159,'finite model actual checks')
    helper=D/'ordinary-cpu-config-capability-v1'
    run('ios-compile-link',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.0',*flags,str(S/'modern_cpu_config_capability_query_fixture_v1.c'),str(S/'modern_cpu_config_capability_query_v1.S'),str(values),'-Wl,-no_adhoc_codesign','-o',str(helper)])
    b=bytearray(helper.read_bytes());need(struct.unpack_from('<I',b)[0]==0xfeedfacf,'actual Mach-O');at=32;uuid=None;sections=[];deps=[]
    count,size=struct.unpack_from('<II',b,16)
    for _ in range(count):
        cmd,n=struct.unpack_from('<II',b,at);need(n>=8 and at+n<=32+size,'actual commands')
        if cmd==0x1b:need(uuid is None,'uniqueUUID');uuid=bytes(b[at+8:at+24])
        if cmd==0x19:
            va,vs,fo,fs=struct.unpack_from('<4Q',b,at+24);sc=struct.unpack_from('<I',b,at+64)[0]
            for i in range(sc):
                p=at+72+80*i;name=bytes(b[p:p+16]).rstrip(b'\0').decode();sv,ss=struct.unpack_from('<QQ',b,p+32);so=struct.unpack_from('<I',b,p+48)[0];sections.append(dict(name=name,VA=sv,bytes=ss,fileOffset=so))
        if cmd in [12,0x80000018,0x8000001f,0x80000023]:
            no=struct.unpack_from('<I',b,at+8)[0];end=b.index(0,at+no,at+n);deps.append(bytes(b[at+no:end]).decode())
        need(cmd!=0x1d,'unsigned no code signature');at+=n
    need(at==32+size and uuid,'actual complete commands')
    need(deps==['/usr/lib/libSystem.B.dylib'],'sole system dependency noHV/VMM/VZ')
    sentinel=bytes.fromhex('564d4346475155455259318c317ae569');need(b.count(sentinel)==1,'unique self identity placeholder');po=b.index(sentinel)
    const=next(x for x in sections if x['fileOffset']<=po and po+16<=x['fileOffset']+x['bytes']);need(const['name']=='__const','identitydata section')
    b[po:po+16]=uuid;helper.write_bytes(b)
    run('ios-dyld',['xcrun','dyld_info','-validate_only',str(helper)])
    run('ios-nm',['xcrun','nm','-a',str(helper)]);run('ios-imports',['xcrun','nm','-u',str(helper)])
    text=next(x for x in sections if x['name']=='__text');nm=(D/'ios-nm.stdout').read_text();trap=None
    for line in nm.splitlines():
        if line.endswith(' _VM27CPUConfigCapabilityKernelQueryV1'):trap=int(line.split()[0],16)
    need(trap is not None,'exact own trap symbol');off=text['fileOffset']+trap-text['VA'];need(b[off:off+12]==bytes.fromhex('90008092011000d4c0035fd6'),'actual exact native kernel trap words')
    textBytes=bytes(b[text['fileOffset']:text['fileOffset']+text['bytes']]);svc=bytes.fromhex('011000d4');need(sum(textBytes[i:i+4]==svc for i in range(0,len(textBytes),4))==1,'onlyone actual SVC80 instruction')
    run('ios-disassembly',['xcrun','llvm-objdump','--macho','--disassemble',str(helper)])
    imports=(D/'ios-imports.stdout').read_text();need(not any(x in imports for x in ['_hv_','_VZ','Hypervisor','Virtualization','VirtualMachineMonitor']),'no native framework imports')
    source=[Path(__file__),values,S/'modern_cpu_tlbi_capability_values_v1.h',model,S/'modern_cpu_config_capability_query_fixture_v1.c',S/'modern_cpu_config_capability_query_v1.S']
    scope=dict(schema='Distinct bounded query-only scope v1',remoteDirectory='/var/root/VirtualMac2/diagnostics/cpu-config-capability-v1',basename=helper.name,nativeOperationsAllowed=[0],nativeQueryCallsMaximum=1,logicalCapacityBytes=352,capacityIsKernelWriteWidth=False,kernelWriteWidthKnown=False,originalAlignment32=True,zeroInput=True,guardPages=2,canaryBytes=32,wholeExteriorChecked=True,exactMaskOffset=64,mask='0x2c0000000000',sysctl='kern.hv_vmm_present',sysctlSuccessRequired=True,sysctlBytesRequired=4,sysctlValuesAllowed=[0,1],missingSysctlMeansUnknown=True,externalPreMainTimeoutSeconds=20,externalKillAfterSeconds=1,externalCPUSeconds=5,externalCoreBytes=0,remoteSSHTimeoutSeconds=55,preAndPostHealthRequired=True,productionMustBeOff=True,permanentLocalAndDeviceOnceRequired=True,guardedMappingReleasedBeforeSuccess=True,oldHelperReexecution=False,old13Forwarding=False,AppleObjectConstructed=False,CPUOrVMCreation=False,nativeRun=False,guestInstructionOracle=False,configMutationAuthorizedByThisFixture=False,full27Backend=False,readyWritten=False,deviceDispatch=False)
    (D/'scope.json').write_text(json.dumps(scope,indent=2)+'\n')
    candidate=dict(schema='Unsigned distinct CPU config native0 query-only candidate v1',finiteLocalScopePassed=True,helper=pin(helper),UUID=uuid.hex(),identityDataPatch=dict(fileOffset=po,bytes=16,section=const['name']),nativeTrap=dict(VA=trap,fileOffset=off,bytes=12,exactWords='90008092011000d4c0035fd6',SVC80InstructionCount=1),dependencies=deps,sourceInputs=[pin(x) for x in source],scope=pin(D/'scope.json'),steps=steps,pureValueChecks=159,nativeQueriesExecutedLocally=0,deviceOperations=0,signed=False,readyWritten=False,controllerPrepared=False,currentTLBISupportProven=False,full27Backend=False)
    (D/'candidate.json').write_text(json.dumps(candidate,indent=2)+'\n');print(json.dumps(dict(candidate=pin(D/'candidate.json'),helper=pin(helper),UUID=uuid.hex(),scope=pin(D/'scope.json'),deviceOperations=0)))
if __name__=='__main__':main()
