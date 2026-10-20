#!/usr/bin/env python3
"""Finite read-only Root18/Acquisition3 source, object and native-export review."""
from pathlib import Path
import argparse, difflib, hashlib, importlib.util, json, plistlib, struct, sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
checks = 0

def need(value, reason):
    global checks
    checks += 1
    if not value:
        raise ValueError(reason)

def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def check_row(row):
    need(pin(row['path']) == row, 'actual immutable pin: '+row['path'])

def frozen(path):
    rows = json.loads(Path(path).read_bytes())['files']
    for row in rows:
        check_row(row)
    return len(rows)

def load_commands(data):
    need(len(data) >= 32 and struct.unpack_from('<I',data)[0] == 0xfeedfacf, 'actual 64-bit Mach-O header')
    ncmds, extent = struct.unpack_from('<II',data,16)
    need(ncmds <= 1024 and 32+extent <= len(data), 'bounded complete command bytes')
    at, loads, uuid, exports, base = 32, [], None, None, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II',data,at)
        need(size >= 8 and size % 8 == 0 and at+size <= 32+extent, 'actual packed command extent')
        payload = data[at:at+size]
        if cmd == 0x1b:
            need(size == 24 and uuid is None, 'one actual LC_UUID')
            uuid = payload[8:24].hex()
        if cmd == 0x19:
            need(size >= 72, 'actual 64-bit segment')
            if payload[8:24].split(b'\0')[0] == b'__TEXT':
                base = struct.unpack_from('<Q',payload,24)[0]
        if cmd in (0xc,0x80000018,0x8000001f,0x80000023):
            name_at = struct.unpack_from('<I',payload,8)[0]
            need(24 <= name_at < size and b'\0' in payload[name_at:], 'actual dependency string')
            path = payload[name_at:].split(b'\0')[0].decode()
            loads.append(dict(ordinal=len(loads)+1,command=cmd,path=path))
        if cmd == 0x80000033:
            need(size == 16 and exports is None, 'one actual exports-trie command')
            exports = list(struct.unpack_from('<II',payload,8))
        at += size
    need(at == 32+extent, 'complete true command extent')
    return dict(UUID=uuid, base=base, dependencies=loads, exportExtent=exports)

def uleb(data, at):
    value, shift = 0, 0
    for _ in range(10):
        need(at < len(data), 'bounded actual export ULEB')
        byte = data[at]; at += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, at
        shift += 7
    raise ValueError('oversized ULEB')

def find_export(data, name):
    at, prefix, visited = 0, '', set()
    while True:
        need(at not in visited and at < len(data), 'bounded actual selected export path')
        visited.add(at)
        size, terminal = uleb(data,at)
        end = terminal+size
        need(end < len(data), 'actual terminal/children extent')
        if prefix == name:
            need(size > 0, 'actual selected export terminal exists')
            flags, cursor = uleb(data,terminal)
            if flags & 8:
                ordinal,cursor = uleb(data,cursor)
                stop=data.find(b'\0',cursor,end)
                need(stop >= cursor, 'actual export renamed reexport')
                return dict(flags=flags,ordinal=ordinal,importedName=data[cursor:stop].decode())
            offset,cursor = uleb(data,cursor)
            need(cursor == end and flags == 0, 'actual regular nonweak native export')
            return dict(flags=flags,offset=offset)
        children, cursor = data[end], end+1
        found = []
        for _ in range(children):
            stop=data.find(b'\0',cursor)
            need(stop >= cursor, 'actual export edge terminator')
            edge=data[cursor:stop].decode(); child,cursor=uleb(data,stop+1)
            if name.startswith(prefix+edge):
                found.append((child,prefix+edge))
        need(len(found) == 1, 'one actual selected native export edge')
        at,prefix=found[0]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    out=ap.parse_args().out.resolve()
    need(out.parent==N and not out.exists(),'fresh independent review output')
    folder=N/'vm-hv-production-root18-mobile-capability-local-v1-attempt1'
    adopted=N/'vm-hv-production-root18-mobile-capability-adoption-v1'
    candidate, freeze = folder/'candidate.json',folder/'freeze.json'
    final, final_freeze = adopted/'finalization.json',adopted/'freeze.json'
    need(pin(candidate)['sha256']=='c22fbe5f326dfb7383d7ab46cf2baf2a956719e271380ff64bc0c66d27f37b43','exact Root18 candidate')
    need(pin(final)['sha256']=='0807e1303f8613fcc682afdffd5b5120d3e5fa437154eb2e907da8d68506e9ed','exact Root18 source adoption')
    root, adoption = json.loads(candidate.read_bytes()),json.loads(final.read_bytes())
    frozen_counts={str(path):frozen(path) for path in [freeze,final_freeze]}
    for key in ['candidate','sourceFreeze','provider','inheritedF21Candidate','inheritedF21Freeze','acquisitionCandidate','acquisitionFreeze','acquisitionObject','factory21Object','factory22Object','inheritedCurrentNativeDefinitionClosure','inheritedCurrentNativeDefinitionFreeze','addedCurrentNativeDefinitionProof']:
        check_row(adoption[key])
    acquisition_path=Path(adoption['acquisitionCandidate']['path'])
    acquisition=json.loads(acquisition_path.read_bytes())
    frozen_counts[str(Path(adoption['acquisitionFreeze']['path']))]=frozen(adoption['acquisitionFreeze']['path'])
    for row in adoption['acquisitionSourceFiles']+adoption['acquisitionActualIncludeClosure']:
        check_row(row)
    need(adoption['acquisitionSourceFiles']==acquisition['sourceFiles'] and adoption['acquisitionActualIncludeClosure']==acquisition['actualIncludeClosure'],'adoption expands exact actual sourceFiles/includeClosure')
    need(root['acquisitionSourcePins']==[] and adoption['sourcePinSchemaFallbackExplained'],'old empty sourcePins metadata explicitly repaired in new adoption')
    prior=json.loads(Path(adoption['inheritedF21Candidate']['path']).read_bytes())
    frozen_counts[str(Path(adoption['inheritedF21Freeze']['path']))]=frozen(adoption['inheritedF21Freeze']['path'])
    need(Path(adoption['factory21Object']['path']).read_bytes()==Path(adoption['factory22Object']['path']).read_bytes(),'actual F21/F22 object byte identity')
    need((S/'modern_cpu_native_public_factory_v22.c').read_text()=='#include "modern_cpu_native_public_factory_v22.h"\n#include "modern_cpu_native_public_factory_v21.c"\n','no second registry or new CPU owner semantics')
    commands=json.loads((folder/'commands.json').read_bytes())
    old_commands=json.loads(Path(adoption['inheritedF21Candidate']['path']).parent.joinpath('commands.json').read_bytes())
    link=next(row['argv'] for row in commands if row['label']=='ios-link')
    old_link=next(row['argv'] for row in old_commands if row['label']=='ios-link')
    objects=[value for value in link if value.endswith('.o')]
    old_objects=[value for value in old_link if value.endswith('.o')]
    need(len(objects)==len(old_objects) and len(objects)==len(set(objects)),'same true object count without duplicate acquisitions/registries')
    changed=[]
    for old,new in zip(old_objects,objects):
        if old!=new:changed.append((old,new))
        else:check_row(pin(old))
    need(len(changed)==2 and {Path(old).name for old,new in changed}=={'modern_cpu_config_capability_acquisition_v2.o','modern_cpu_native_public_factory_v21.o'},'only acquisition2 and factory21 link objects replaced')
    need({Path(new).name for old,new in changed}=={'modern_cpu_config_capability_acquisition_v3.ios.o','modern_cpu_native_public_factory_v22.o'},'actual Acquisition3 and Factory22 link inputs')
    need(objects.count(adoption['acquisitionObject']['path'])==1 and not any('acquisition_v2.o' in value for value in objects),'one real separately frozen Acquisition3 object')
    need('-DVM27_HV_VM_GUARD_LINKED=1' in link and '-Wl,-undefined,error' in link and '-Wl,-no_adhoc_codesign' in link,'real shared-operation guard/strong link/no signing preserved')
    need(link.count('Security')==1 and link[link.index('Security')-1]=='-framework','actual native Security framework dependency')
    for row in commands:need(row['returncode']==0,'actual Root18 link/validate/typed link completed')
    acquisition_commands=json.loads((acquisition_path.parent/'commands.json').read_bytes())
    production_command=next(row for row in acquisition_commands if row['label']=='ios-modern_cpu_config_capability_acquisition_v3')
    need('-DVM27_CPU_CAPABILITY_TESTING=1' not in production_command['argv'] and '-DVM27_CPU_CAPABILITY_ADMISSION_TESTING=1' not in production_command['argv'],'no host fixture hooks in actual production compilation')
    need(next(row for row in acquisition_commands if row['label']=='fixture-ios-refused')['exit']==1,'fixture build actually rejected on iOS')
    need('Capability admission fixture hooks are forbidden on iOS' in (acquisition_path.parent/'fixture-ios-refused.stderr').read_text(),'actual intentional source error, not unrelated compile failure')
    for mode in ['normal','san']:
        need(acquisition['models'][mode]['checks']==373 and acquisition['models'][mode]['actualNativeOperations']==0 and acquisition['models'][mode]['guardedNative0ModelCalls']==1,'reuse existing true 373 host admission observations, not device evidence')
        need(json.loads((acquisition_path.parent/(mode+'-run.stdout')).read_bytes())==acquisition['models'][mode],'actual recorded model stdout matches copied receipt')

    source=Path(acquisition['source']['path']);text=source.read_text()
    old_source=S/'modern_cpu_config_capability_acquisition_v2.c'
    expected_diff=''.join(difflib.unified_diff(old_source.read_text().splitlines(True),text.splitlines(True),fromfile=str(old_source),tofile=str(source)))
    need(expected_diff==Path(acquisition['sourceDiff']['path']).read_text(),'complete exact original acquisition2 to admission3 delta')
    identity=text[text.index('static bool IdentityV3('):text.index('static bool NativeTrueV3(')]
    for term in ['uid==0 || uid==501','SELF_EUID_V3()==uid','SELF_UID_V3()==uid','SELF_PID_V3()==pid','token->val[5]==(uint32_t)pid','token->val[1]==uid','token->val[3]==uid','token->val[7]!=0']:
        need(term in identity,'actual matching mobile/root identity component')
    for term in ['task_info(mach_task_self(),TASK_AUDIT_TOKEN','count!=TASK_AUDIT_TOKEN_COUNT','SELF_CODE_V3(pid,0,&status','status&UINT32_C(1)','SELF_CODE_V3(pid,5,digest','!nonzero','SecTaskCreateWithAuditToken','CFGetTypeID(value)==CFBooleanGetTypeID()','CFBooleanGetValue((CFBooleanRef)value)','if(error){*failed=true;CFRelease(error);}','if(value)CFRelease(value)','CFRelease(task);','!memcmp(&token,&after,sizeof(token))','!memcmp(digest,again,sizeof(digest))']:
        need(term in text,'true native audit/code-status/CDHash/Boolean entitlement admission')
    keys=['platform-application','com.apple.private.hypervisor','com.apple.security.hypervisor','com.apple.private.virtualization','com.apple.security.virtualization']
    for key in keys:need('CFSTR("'+key+'")' in text,'actual native entitlement key')
    need('if(failed || !platform || !hypervisor || !virtualization)return false;' in text,'any native entitlement error or missing Boolean capability refuses')
    for term in ['sysconf(_SC_PAGESIZE)==16384','!strcmp(release,"22.1.0")','!strcmp(build,"20B101")','iPad14,3','iPad14,4','iPad14,5','iPad14,6']:
        need(term in text,'exact inherited actual kernel/page/device profile')
    need('geteuid()==0' not in text and not any(term in text for term in ['setuid(', 'seteuid(', 'CS_PLATFORM_BINARY |', 'VM27CPUConfigCapabilityKernelQueryV1(1,']),'no identity change, root-only gate or platform/native-create spoof')
    need(text.count('VM27CPUConfigCapabilityKernelQueryV1(0,buffer)')==1 and 'pthread_once(&OnceV2,AcquireV2)' in text and '_Thread_local bool AcquiringV2' in text,'one guarded Native0 attempt with once cache and recursion refusal')
    need('const size_t page=16384,capacity=352,tail=32,total=3*page;' in text and 'PROT_NONE' in text and 'mprotect(middle,page,PROT_READ|PROT_WRITE)' in text,'true native0 three-page guard geometry')
    need(text.count('CanaryV2(')>=5 and 'if(ACQUIRE_UNMAP(region,total)!=0)kernelKnown=false;' in text and 'if(kernelKnown)ValueV2=staged;' in text,'no canary/owner/cleanup failure publishes capability seed')
    need('kernelKnown=OwnerV2()==owner && pthread_equal(thread,pthread_self()) && NativeQueryAdmissionV3();' in text,'same CPU owner thread and native identity rechecked before cache publication')
    need(text.index('if(!ProfileV2() || !owner)return;') < text.index('VM27CPUConfigCapabilityKernelQueryV1(0,buffer)'),'actual identity/profile refuses before native0')
    need(text.index('ACQUIRE_UNMAP(region,total)') < text.index('if(kernelKnown)ValueV2=staged;'),'guard mapping release verified before publication')
    entitlements=plistlib.loads((S/'VirtualMac.entitlements').read_bytes())
    need(all(entitlements[key] is True for key in ['platform-application','com.apple.private.hypervisor','com.apple.private.virtualization']),'actual App signed entitlement source satisfies strict private/native Boolean profile')
    need((S/'modern_cpu_config_capability_query_v1.S').read_text().count('svc #0x80')==1 and 'mov x16, #-5' in (S/'modern_cpu_config_capability_query_v1.S').read_text(),'real inherited native query trampoline unchanged')

    parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec=importlib.util.spec_from_file_location('independent_root18_reader',parser);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    actual=module.MachO(Path(root['provider']['path']).read_bytes());before=module.MachO(Path(prior['provider']['path']).read_bytes())
    need(len(actual.exports)==153 and set(actual.exports)==set(before.exports)==set(root['exactExports']),'actual exact 153 strong public/private exports preserved')
    need(not any('VM27CPUCapabilityAdmissionTest' in name or 'VM27CPUCapabilityTest' in name for name in actual.exports),'no model-only export in actual provider')
    def import_id(image,row):return (image.loads[row['ordinal']-1]['path'],row['name'],row['weak'],row['addend'])
    old_imports={import_id(before,row)for row in before.imports};new_imports={import_id(actual,row)for row in actual.imports}
    need(len(actual.imports)==82 and len(before.imports)==71 and old_imports<=new_imports and len(new_imports-old_imports)==11,'actual 71 native imports retained and exactly 11 genuine additions')
    need(all(row['weak']==0 for row in actual.imports),'actual 82 native imports remain strong')
    need({row['path']for row in actual.loads}=={'/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation','/System/Library/Frameworks/Security.framework/Security','/usr/lib/libobjc.A.dylib','/usr/lib/libSystem.B.dylib'},'actual Root18 only four genuine native dependency namespaces')
    delta_path=Path(root['addedCurrentNativeDefinitionProof']['path']);delta=json.loads(delta_path.read_bytes())
    check_row(delta['currentNativeIndex']);index=json.loads(Path(delta['currentNativeIndex']['path']).read_bytes())
    need(len(delta['definitions'])==11 and not delta['missingDefinitions'],'exact finite 11 native definition rows')
    verified_images={};native_files=[];verified_symbols=[]
    for row in delta['definitions']:
        imported,definition=row['imported'],row['currentDefinition']
        need((imported['library'],imported['name'],imported['weak'],imported['addend']) in new_imports-old_imports,'actual added import joins one definition')
        route=definition['route'];need(route[0]==dict(path=imported['library'],name=imported['name']) and route[-1]==dict(path=definition['path'],name=definition['name']),'actual namespace route endpoints')
        for hop_index,hop in enumerate(route):
            image=index['images'][hop['path']]
            if hop['path'] not in verified_images:
                for q in [image['actualCompleteCommands'],image['actualCompleteExportSource']['rangePin'],*[part['rangePin']for part in image['actualCommandSourceRanges']]]:
                    check_row(q);native_files.append(Path(q['path']))
                parsed=load_commands(Path(image['actualCompleteCommands']['path']).read_bytes())
                need(parsed['UUID']==image['UUID'] and parsed['base']==image['base'] and parsed['dependencies']==image['dependencies'] and parsed['exportExtent']==image['exportExtent'],'reparsed actual native UUID/base/LC namespaces and export extent')
                need(image['actualCompleteExportSource']['offset']==parsed['exportExtent'][0] and image['actualCompleteExportSource']['rangePin']['bytes']==parsed['exportExtent'][1],'actual complete native export capture exactly matches load command')
                verified_images[hop['path']]=parsed
            if hop_index+1<len(route):
                following=route[hop_index+1]
                need(any(dep['path']==following['path'] and dep['command']==0x8000001f for dep in verified_images[hop['path']]['dependencies']),'actual selected namespace hop is a real LC_REEXPORT_DYLIB')
            else:
                decoded=find_export(Path(image['actualCompleteExportSource']['rangePin']['path']).read_bytes(),hop['name'])
                need(decoded==definition['definition']==image['definitions'][hop['name']] and definition['UUID']==image['UUID'] and definition['base']==image['base'],'independently decoded true native regular export terminal')
                verified_symbols.append(dict(imported=imported,definitionPath=hop['path'],UUID=image['UUID'],actualTrieTerminal=decoded,actualNamespaceRoute=route))
    need({(r['imported']['library'],r['imported']['name'],r['imported']['weak'],r['imported']['addend'])for r in delta['definitions']}==new_imports-old_imports,'all actual eleven added imports covered exactly')
    frozen_counts[str(Path(adoption['inheritedCurrentNativeDefinitionFreeze']['path']))]=frozen(adoption['inheritedCurrentNativeDefinitionFreeze']['path'])
    need(not root['codeSigned'] and not root['mobileNativeCapabilityExecuted'] and not adoption['mobileNativeCapabilityExecuted'],'does not claim real mobile kernel admission/native execution')

    out.mkdir(mode=0o700)
    review=dict(schema='Root18 mobile-capability adoption independent finite review v1',finiteLocalScopePassed=True,findings=[],checks=checks,
        candidate=pin(candidate),inputFreeze=pin(freeze),adoptionFinalization=pin(final),adoptionFreeze=pin(final_freeze),
        acquisitionCandidate=pin(acquisition_path),acquisitionSource=pin(source),acquisitionObject=adoption['acquisitionObject'],
        provider=root['provider'],verifiedFrozenPinCounts=frozen_counts,
        factory21Factory22ObjectsByteIdentical=True,exactlyTwoLinkObjectsReplaced=True,singleCPURegistryPreserved=True,
        actualMobileRealEffectiveUIDAndNativeAuditIdentityVerified=True,actualCSValidAndStableKernelCDHashVerified=True,
        actualNativeBooleanEntitlementsRequired=True,actualKernelPermissionNotInferredFromSignature=True,
        noUIDChangeOrNativePlatformFlagSpoof=True,sameNative0GuardAndOnceCache=True,
        native0MaxAttemptsPerFreshProcess=1,failedOwnerCanaryNativeReturnOrGuardUnmapCannotPublish=True,
        oldRootOnlyObjectNotLinked=True,actualProductionFixtureHooksAbsent=True,
        actualExports=153,actualStrongNativeImports=82,actualInheritedStrongNativeImports=71,
        addedNativeDefinitionsIndependentlyReparsed=verified_symbols,actualNativeImagesReparsed=list(verified_images),
        sourceAdoptionSchemaExpansionVerified=True,modelsReused373NormalAndSan=True,inherited689ModelsRepeated=False,
        readyForFreshStageAndHostLocalProductSigning=True,codeSigned=False,deviceOperations=0,nativeOperations=0,trustCacheOperations=0,
        mobileKernelQueryExecuted=False,actualGuestBoot=False,
        limitations=['Native SecTask Boolean platform-application does not establish CS_PLATFORM_BINARY. Real kernel authorization still controls the Native0 return.',
        'UID0/mobile501 profile admission does not bind the self CDHash to the product manifest; the separate actual Runtime3 signed-anchor/child bootstrap gates enforce owned-product identity before VM creation.',
        'NativeQueryAdmission guards only the first acquisition per fresh process. A failed first acquisition leaves a real UNKNOWN cache and is not retried. Successful cache reuse preserves its original receipt; it is not a fresh kernel query.',
        'Existing normal/SAN373 admission models and F21 source proof are reused, not rerun or promoted to device evidence. This review does not execute any iPad/native/sign/trust-cache operation.'])
    (out/'review.json').write_text(json.dumps(review,indent=2)+'\n')
    files=[candidate,freeze,final,final_freeze,acquisition_path,Path(adoption['acquisitionFreeze']['path']),source,old_source,
        Path(acquisition['sourceDiff']['path']),Path(root['provider']['path']),Path(adoption['factory21Object']['path']),
        Path(adoption['factory22Object']['path']),Path(adoption['acquisitionObject']['path']),folder/'commands.json',
        S/'modern_cpu_native_public_factory_v22.c',S/'modern_cpu_native_public_factory_v22.h',S/'modern_cpu_config_capability_query_v1.S',
        S/'VirtualMac.entitlements',parser,delta_path,Path(delta['currentNativeIndex']['path']),Path(adoption['inheritedCurrentNativeDefinitionClosure']['path']),
        Path(adoption['inheritedCurrentNativeDefinitionFreeze']['path']),Path(__file__).resolve(),out/'review.json',*native_files]
    files=list(dict.fromkeys(files))
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in files],deviceOperations=0,nativeOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=[])))

if __name__=='__main__':main()
