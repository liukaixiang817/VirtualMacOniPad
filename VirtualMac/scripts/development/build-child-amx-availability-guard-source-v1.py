#!/usr/bin/env python3
"""HOST-only exact caller guards for genuinely absent owned guest AMX state."""
import argparse, hashlib, importlib.util, json, pathlib, plistlib, struct, subprocess, sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
BASE=pathlib.Path(__file__).with_name('build-independent27-signed-runtime-product-v10.py')
sp=importlib.util.spec_from_file_location('amx_child_profile_primitives',BASE)
base=importlib.util.module_from_spec(sp); sp.loader.exec_module(base)
def need(v,w):
    if not v: raise ValueError(w)
def pin(p):
    p=pathlib.Path(p).resolve(); b=base.regular_bytes(p)
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v): p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=pathlib.Path,required=True)
    a=ap.parse_args(); o=a.output.resolve(); need(o.parent==N and not o.exists(),'fresh owned host output'); o.mkdir(mode=0o700)
    rp=N/'independent27-signed-runtime-native-run-admission-diagnostic-product-v37-attempt1/candidate.json'
    need(pin(rp)['sha256']=='924a11a2baf94ee624b5efcf45c41ee6e015c74872cd77c01d578b4c3d299787','actual Runtime37 signed baseline')
    runtime=json.loads(base.regular_bytes(rp)); manifest_path=pathlib.Path(runtime['manifest']['path'])
    need(pin(manifest_path)==runtime['manifest'],'actual manifest current pin')
    manifest=plistlib.loads(base.regular_bytes(manifest_path)); row=next(x for x in manifest['files']if x['id']=='child:com.apple.Virtualization.VirtualMachine')
    child=pathlib.Path(runtime['runtimeRoot'])/row['path']; original=base.regular_bytes(child)
    need((len(original),hashlib.sha256(original).hexdigest())==(5576368,'9ffaf6320f56e0639f0cfb73746e1a59bf563400f7bf71bbbdfeeaf5a1beee89'),'actual R37 Child exact bytes')
    need((row['bytes'],row['sha256'])==(len(original),hashlib.sha256(original).hexdigest()),'manifest actual Child row')
    ci=base.image_profile(original,child.name); need(ci.uuid=='4a6a588d1afd30f5a64d6304eb79be0b','actual Child UUID')
    textindex=next(i for i,x in enumerate(ci.segments)if x['name']=='__TEXT'); text=ci.segments[textindex]
    cmd=next(c for c in ci.commands if c['cmd']==25 and original[c['at']+8:c['at']+24].rstrip(b'\0')==b'__TEXT')
    need(text['fileoff']==0 and text['filesize']==text['size']==0x4a4000 and struct.unpack_from('<II',original,cmd['at']+56)==(5,5),'actual mapped RX TEXT padding')
    need(not any(original[0x4a396c:0x4a4000]),'all exact remaining 1684 bytes are zero')
    fix=next(c for c in ci.commands if c['cmd']==0x80000034); fo,fs=struct.unpack_from('<II',original,fix['at']+8)
    raw=original[fo:fo+fs]; starts=struct.unpack_from('<I',raw,4)[0]; count=struct.unpack_from('<I',raw,starts)[0]
    need(count==len(ci.segments),'actual chained starts segment count')
    starts_rows=[struct.unpack_from('<I',raw,starts+4+4*i)[0]for i in range(count)]
    need(starts_rows[textindex]==0,'no chained rebase/bind writes anywhere in TEXT')
    for section in ci.sections:
        if section['segment']=='__TEXT':
            need(section['fileoff']+section['size']<=0x4a3a00,'new caves overlap no actual section')
    expected_gates={'save':'281200b00861513928050037342206941f0c65f2c0040054','restore':'081200d00861513988040037ea1606941f0c65f220040054'}
    need(original[0x289c38:0x289c50].hex()==expected_gates['save'] and original[0x28c960:0x28c978].hex()==expected_gates['restore'],'original sysctl and host CPU capability gates')
    commands=[]
    def run(label,argv):
        p=subprocess.run(argv,capture_output=True); so=o/(label+'.stdout'); se=o/(label+'.stderr')
        so.write_bytes(p.stdout); se.write_bytes(p.stderr)
        commands.append(dict(label=label,argv=argv,exit=p.returncode,stdout=pin(so),stderr=pin(se))); save(o/'commands.json',commands)
        need(p.returncode==0,label+' '+p.stderr.decode(errors='replace')[-1200:]); return p
    sources=[S/'modern_vmm_amx_availability_guards_v1.S',S/'test-modern-vmm-amx-availability-guard-v1.c']
    asm=o/'modern_vmm_amx_availability_guards_v1.o'
    run('ios-arm64e-guards',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-c',str(sources[0]),'-o',str(asm)])
    host=o/'actual-A64-amx-guard-test'
    run('host-actual-A64-compile',['xcrun','--sdk','macosx','clang','-arch','arm64','-march=armv8.3-a','-Wall','-Wextra','-Werror','-DVM27_HOST_AMX_FIXTURE=1',str(sources[1]),str(sources[0]),'-o',str(host)])
    result=run('host-actual-A64-run',[str(host)]); tests=json.loads(result.stdout)
    need(tests['cases']==18 and all(v is True for k,v in tests.items()if k not in ('cases','nativeCallsExecuted','deviceOperations')),'actual A64 absent/present/error and register tests')
    ab=base.regular_bytes(asm); at=32; assembled=None; relocs=None
    for _ in range(struct.unpack_from('<I',ab,16)[0]):
        c,z=struct.unpack_from('<II',ab,at)
        if c==25:
            for j in range(struct.unpack_from('<I',ab,at+64)[0]):
                q=at+72+j*80
                if ab[q:q+16].split(b'\0')[0]==b'__text':
                    va,size,off=struct.unpack_from('<QQI',ab,q+32); assembled=ab[off:off+size]; relocs=struct.unpack_from('<I',ab,q+60)[0]
        at+=z
    need(assembled is not None and len(assembled)==0x570 and relocs==0,'two696-byte position-fixed guards and zero unresolved relocations')
    pieces=[assembled[:0x2b8],assembled[0x2b8:]]; names=['save','restore']; prefixes=[0x289c50,0x28c978]; caves=[0x4a3a00,0x4a3d00]
    expected_prefix=['000340f9','77ae44f9']; out=bytearray(original); ranges=[]
    for name,at,target,word in zip(names,prefixes,caves,expected_prefix):
        old=original[at:at+4]; need(old.hex()==word,'exact '+name+' original instruction')
        new=struct.pack('<I',0x14000000|(((target-at)//4)&0x3ffffff)); out[at:at+4]=new
        ranges.append(dict(type='AMX-'+name+'-prefix',fileoff=at,bytes=4,oldHex=old.hex(),newHex=new.hex()))
    for name,at,new in zip(names,caves,pieces):
        need(len(new)<=0x300 and at+len(new)<=0x4a4000,'bounded mapped RX stub extent')
        old=original[at:at+len(new)]; need(not any(old),'exact zero '+name+' mapped RX cave')
        out[at:at+len(new)]=new; ranges.append(dict(type='AMX-'+name+'-stub',fileoff=at,bytes=len(new),oldHex=old.hex(),newHex=new.hex()))
    patched=o/'com.apple.Virtualization.VirtualMachine.AMX-availability.unsigned'; patched.write_bytes(out)
    pi=base.image_profile(bytes(out),child.name)
    need(pi.commands==ci.commands and pi.uuid==ci.uuid and pi.segments==ci.segments and pi.sections==ci.sections and pi.imports==ci.imports and pi.loads==ci.loads and pi.exports==ci.exports and pi.binds==ci.binds,'all current Child LC/namespace/PAC binds whole')
    expected=bytearray(original)
    for rr in ranges:
        at=rr['fileoff']; old=bytes.fromhex(rr['oldHex']); new=bytes.fromhex(rr['newHex'])
        need(len(old)==len(new)==rr['bytes'] and original[at:at+len(old)]==old,'exact replacement extent')
        expected[at:at+len(old)]=new
    need(bytes(expected)==bytes(out),'complete Child file differs only in exact four ranges')
    run('validate-patched-child',['xcrun','dyld_info','-validate_only',str(patched)])
    dis=run('disassemble-actual-ios-guard-object',['xcrun','llvm-objdump','-d',str(asm)])
    need(dis.stdout.count(b'blraaz\tx16')==2 or dis.stdout.count(b'blraaz x16')==2,'two actual authenticated typed calls in assembled production body')
    contract=dict(typedQuery='VM27VMMGetAMXAvailabilityV1(uint64_t identity,uint32_t *out)',statusZeroOnlyComplete=True,explicitAbsentValue=0,explicitPresentValue=1,unknownOutputFatal=True,sentinelRejectsUnwrittenSuccess=True,realCPUIdentitySaveRegister='[x24]',realCPUIdentityRestoreRegister='[x26]',originalHostCPUCapabilitiesAndSysctlPredicateUnchanged=True,guardRunsOnlyAfterOriginalHostCapabilityGates=True,absentOnlyWithFrame958And960ZeroAndValidity1d68Zero=True,invalidPayload968Through1d67NeverRead=True,originalFrameBytesNeverWritten=True,presentOriginalTypedAMXCallsAndFailurePreserved=True,queryFailureAndNullDlsymTakeOriginalFatal=True,nonzeroInactiveControlsOrValidityTakeOriginalFatal=True,allGPRAndQ0Through31AndNZCVAndLRAndSPPreserved=True,originalPACStateUnchanged=True,noNewChildImportsExportsLoadsOrPACBinds=True,allExistingSCXTReservedAndPMUGuardsWholeUnchanged=True,noNativeAMXStateSynthesized=True,snapshotMigrationAndEnabledAMXDeferred=True,guestBootUnproven=True)
    recipe=dict(schema='Owned guest AMX real availability, two caller guards exact four ranges V1',original=pin(child),patched=pin(patched),baselineActualRuntime37=pin(rp),ranges=ranges,prefixRVA=prefixes,stubRVA=caves,stubBytes=[len(x)for x in pieces],presentContinuationRVA=[0x289c54,0x28c97c],absentContinuationRVA=[0x289ce4,0x28c9f8],originalFatalRVA=[0x289e58,0x28cb8c],actualDlsymStubRVA=0x4129f4,typedQueryName='VM27VMMGetAMXAvailabilityV1',originalCapabilityGateBytes=expected_gates,frameControlOffsets=[0x958,0x960],frameValidityOffset=0x1d68,invalidPayloadRangeNeverRead=[0x968,0x1d68],constructorControlZeroRVA=0x3996a4,constructorConditionalValidityClearRVA=0x3996b8,actualMappedRXSegment=text,actualTEXTMaxInitProt=[5,5],actualTEXTChainedFixupStartsOffset=starts_rows[textindex],noSectionOrFixupOverlap=True,allOtherChildBytesWholeUnchanged=True,originalSignatureBytesAndExtentPreservedButStaleUntilRootResigns=True,codeSigned=False,deviceOperations=0)
    save(o/'child-AMX-availability-guard-recipe.json',recipe)
    candidate=dict(schema='Child owned guest AMX availability caller guards source V1',patchedChildMain=pin(patched),childAMXAvailabilityGuardRecipe=pin(o/'child-AMX-availability-guard-recipe.json'),sourceFiles=[pin(x)for x in sources],amxCallerGuardContract=contract,targetedHostTest=pin(o/'host-actual-A64-run.stdout'),targetedHostResults=tests,actualIOSGuardObject=pin(asm),actualIOSCompileAndChildDyldPassed=True,baselineActualRuntime37=pin(rp),originalChild=pin(child),deviceOperations=0,codeSigned=False)
    save(o/'candidate.json',candidate)
    inputs=[pin(__file__),pin(BASE),pin(base.READER),pin(rp),pin(rp.parent/'freeze.json'),runtime['manifest'],pin(child)]+candidate['sourceFiles']
    save(o/'freeze.json',dict(files=[pin(x)for x in o.iterdir()if x.is_file()]+inputs,deviceOperations=0,codeSigned=False))
    print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),child=candidate['patchedChildMain'],recipe=candidate['childAMXAvailabilityGuardRecipe'],actualA64Cases=tests['cases'])))
if __name__=='__main__':main()
