#!/usr/bin/env python3
"""Inert VMM singleton-GPU / explicit unavailable Mac display profile port.

The recipe is independently composable with other ports of the frozen stage.
Only two GPU instructions, two load paths and four selected import/nlist
names change. No original image is loaded, signed or written to a device.
"""
import argparse, hashlib, importlib.util, json, pathlib, runpy, struct, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
READER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
spec = importlib.util.spec_from_file_location('gpu_display_macho', READER)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
BASE = 0x100000000
LOAD = '@loader_path/VM27DisplayUnavailableV1.dylib'
RENAMES = {
    463: ('_xpc_add_bundle_with_lwcr', 15, '_VM27PluginUnavailableV1'),
    597: ('_CGDisplayCopyColorSpace', 20, '_VM27CGUnavailableV1'),
    840: ('_SLSDisplayGetPotentialHeadroom', 35, '_VM27HeadroomUnavailableV1'),
    1134: ('_OBJC_CLASS_$_DisplayServicesClient', 29, '_OBJC_CLASS_$_VM27DSClientV1'),
}
SITES = {0x14813c: (0x710006df, 0x1400002d, 0x1481f0),
         0x14827c: (0xaa1a03e0, 0x1400000f, 0x1482b8)}

def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, v): p.write_text(json.dumps(v, indent=2, ensure_ascii=False) + '\n')
def need(v, why):
    if not v: raise ValueError(why)
def sx(v, n): return v - (1 << n) if v & (1 << (n-1)) else v
def target(at, w):
    if w & 0x7c000000 == 0x14000000: return at + 4*sx(w & 0x3ffffff, 26)
    if w & 0xff000010 == 0x54000000 or w & 0x7e000000 == 0x34000000:
        return at + 4*sx((w >> 5) & 0x7ffff, 19)
    if w & 0x7e000000 == 0x36000000: return at + 4*sx((w >> 5) & 0x3fff, 14)
    return None

def cfg(b, im):
    start, end = 0x147fd0, 0x149368
    todo = [start]; seen = set(); calls = []; outside = []
    while todo:
        pc = todo.pop()
        if pc in seen: continue
        seen.add(pc); w = struct.unpack_from('<I', b, im.file(BASE+pc))[0]
        to = target(pc, w)
        if w & 0xfc000000 == 0x14000000: dest = [to]
        elif w & 0xfc000000 == 0x94000000:
            calls.append(dict(rva=pc, targetRVA=to)); dest = [pc+4]
        elif to is not None: dest = [pc+4, to]
        elif w & 0xffe0001f == 0xd4200000 or w & 0xfffffc1f in (0xd65f0000, 0xd61f0000) or w == 0xd65f0fff:
            dest = []
        else: dest = [pc+4]
        for p in dest:
            if start <= p < end: todo.append(p)
            else: outside.append(dict(rva=pc, targetRVA=p))
    return dict(functionStartRVA=start, functionEndRVA=end, reachableRVAs=sorted(seen),
                calls=calls, outsideEdges=outside, normalIntraproceduralPathsOnly=True,
                originalExceptionAndUnwindBytesPreserved=True)

def transform(before):
    im = m.MachO(before); need(im.base == BASE, 'exact VMM base')
    need(len(im.imports) == 1203, 'actual original import count')
    need([(r['index'], r['name']) for r in im.imports if r['ordinal'] == 29] ==
         [(1134, RENAMES[1134][0])], 'CoreBrightness has only the selected class import')
    need(im.imports[85]['name'] == '_MTLCopyAllDevices' and im.imports[85]['ordinal'] == 3,
         'real Metal enumeration binding')
    b = bytearray(before); recipe = []; extents = []
    def write(at, old, new, role):
        need(len(old) == len(new) and before[at:at+len(old)] == old, 'exact '+role)
        b[at:at+len(old)] = new; extents.append((at, len(old)))
        recipe.append(dict(role=role, fileOffset=at, oldHex=old.hex(), newHex=new.hex()))
    for rva, (old, new, dest) in SITES.items():
        need(target(rva, new) == dest, 'true branch target')
        write(im.file(BASE+rva), struct.pack('<I', old), struct.pack('<I', new), 'GPU branch '+hex(rva))
    for ordinal, path in ((3, '@loader_path/MD'), (29, LOAD)):
        c = next(r for r in im.loads if r['ordinal'] == ordinal)
        no = struct.unpack_from('<I', before, c['at']+8)[0]; size = c['size']-no
        new = path.encode()+b'\0'; need(len(new) <= size, 'load name capacity')
        write(c['at']+no, before[c['at']+no:c['at']+c['size']],
              new+bytes(size-len(new)), 'load path ordinal '+str(ordinal))
    c = next(c for c in im.commands if c['cmd'] == 0x80000034)
    fo, z = struct.unpack_from('<II', before, c['at']+8)
    version, starts, imp, symbols, count, form, compression = struct.unpack_from('<7I', before, fo)
    need(version == compression == 0 and form == 2 and count == 1203, 'exact import format2')
    pool_intervals = []
    imports_recipe = [dict(originalIndex=85, originalName='_MTLCopyAllDevices', originalOrdinal=3,
        newName='_MTLCopyAllDevices', newOrdinal=3, requiredLoad='@loader_path/MD',
        bindingWordChanged=False, nativeMetalReexportPreserved=True)]
    for index, (old, ordinal, new) in RENAMES.items():
        r = im.imports[index]
        need(r['name'] == old and r['ordinal'] == ordinal and not r['weak'] and r['addend'] == 0,
             'selected real strong import '+str(index))
        at = fo+imp+8*index; w = struct.unpack_from('<I', before, at)[0]
        p = fo+symbols+(w >> 9)
        oldBytes = old.encode()+b'\0'; newBytes = new.encode()+b'\0'
        need(len(newBytes) <= len(oldBytes), 'bounded shorter own import name')
        for other in im.imports:
            op = fo+symbols+(struct.unpack_from('<I', before, other['at'])[0] >> 9)
            need(not (p <= op < p+len(oldBytes)) or other['index'] == index,
                 'selected name is not a shared suffix')
        write(p, oldBytes, newBytes+bytes(len(oldBytes)-len(newBytes)), 'import name '+str(index))
        if ordinal != 29:
            write(at, struct.pack('<I', w), struct.pack('<I', (w & ~255) | 29), 'import ordinal '+str(index))
        pool_intervals.append((p, p+len(oldBytes)))
        imports_recipe.append(dict(originalIndex=index, originalName=old, originalOrdinal=ordinal,
            newName=new, newOrdinal=29, requiredLoad=LOAD, bindingWordChanged=False,
            originalNameFileOffset=p, originalNameExtent=len(oldBytes)))
    sc = next(c for c in im.commands if c['cmd'] == 2)
    symoff, nsyms, strings, stringsize = struct.unpack_from('<4I', before, sc['at']+8)
    matched = set()
    for i in range(nsyms):
        at = symoff+16*i; ix, kind, section, desc, value = struct.unpack_from('<IBBHQ', before, at)
        p = strings+ix; name = before[p:strings+stringsize].split(b'\0')[0].decode()
        selected = next((k for k, v in RENAMES.items() if v[0] == name), None)
        if selected is None: continue
        old, ordinal, new = RENAMES[selected]
        need(kind == 1 and section == value == 0 and desc >> 8 == ordinal, 'real undefined nlist')
        oldBytes = old.encode()+b'\0'; newBytes = new.encode()+b'\0'
        for j in range(nsyms):
            op = strings+struct.unpack_from('<I', before, symoff+16*j)[0]
            need(not (p <= op < p+len(oldBytes)) or j == i, 'nlist name not a shared suffix')
        write(p, oldBytes, newBytes+bytes(len(oldBytes)-len(newBytes)), 'nlist name '+str(selected))
        if ordinal != 29:
            write(at+6, struct.pack('<H', desc), struct.pack('<H', (desc & 255) | (29 << 8)),
                  'nlist ordinal '+str(selected))
        matched.add(selected)
    need(matched == set(RENAMES), 'all selected nlist declarations match')
    after = bytes(b); ported = m.MachO(after)
    need(ported.uuid == im.uuid and ported.sections == im.sections and ported.segments == im.segments,
         'original UUID, geometry, ObjC/Swift metadata sections retained')
    for a, c in zip(im.imports, ported.imports):
        expected = dict(a)
        if a['index'] in RENAMES: expected.update(name=RENAMES[a['index']][2], ordinal=29)
        need(expected == c, 'selected import change only')
    for a, c in zip(im.binds, ported.binds):
        expected = dict(a)
        if a['index'] in RENAMES: expected['name'] = RENAMES[a['index']][2]
        need(expected == c, 'all original chain/PAC words retained')
    allowed = {i for at, length in extents for i in range(at, at+length)}
    need(len(before) == len(after) and all(i in allowed for i, (a, c) in enumerate(zip(before, after)) if a != c),
         'whole-file changes bounded by recipe')
    originalCFG, portedCFG = cfg(before, im), cfg(after, ported)
    unsafe = {0x1481ac, 0x148280, 0x14828c}
    need(unsafe <= set(originalCFG['reachableRVAs']) and not unsafe & set(portedCFG['reachableRVAs']),
         'three absent native Mac GPU property methods unreachable')
    need({0x148134, 0x1481e8, 0x1482b8, 0x1482bc, 0x1482e8, 0x1482f0, 0x148300, 0x148308} <=
         set(portedCFG['reachableRVAs']), 'actual enumeration, ownership and failure paths retained')
    # Actual macOS display-ID gates, unchanged. Never fabricate either ID.
    gates = {0x14f094: 0x940b339c, 0x140a24: 0x940b45c0}
    gate_words = []
    for lo, hi in ((0x14f074, 0x14f0a4), (0x140790, 0x140814), (0x140a18, 0x140a34)):
        off = im.file(BASE+lo); need(before[off:off+hi-lo] == after[off:off+hi-lo], 'real display gate preserved')
        gate_words.append(dict(startRVA=lo, endRVA=hi, exactBytes=before[off:off+hi-lo].hex()))
    return after, dict(byteWrites=recipe, imports=imports_recipe,
        codeWords=[dict(rva=rva, oldWord=old, newWord=new, targetRVA=dest) for rva,(old,new,dest) in SITES.items()],
        loadPaths=[dict(ordinal=3, path='@loader_path/MD'),dict(ordinal=29,path=LOAD)],
        originalCFG=originalCFG, portedCFG=portedCFG, preservedDisplayIDGateWindows=gate_words,
        originalCoreBrightnessImports=1, originalChainedBindWords=len(im.binds),
        allOriginalChainWordsAndPACUnchanged=True, changedWholeFileBytes=sum(a != c for a,c in zip(before,after)))

def graph(stage, provider, vmm):
    indexPath = N/'current-native-header-export-index-v3/index.json'
    need(pin(indexPath)['sha256'] == '60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019', 'current native67')
    native = json.loads(indexPath.read_bytes())['images']; own = {}
    for row in stage['stagedImages']:
        p = pathlib.Path(row['staged']['path']); need(pin(p) == row['staged'], 'actual staged bytes')
        own[row['key']] = dict(pin=pin(p), image=m.MachO(p.read_bytes()))
    own['com.apple.Virtualization.VirtualMachine'] = dict(pin=pin(vmm), image=m.MachO(vmm.read_bytes()))
    own['VM27DisplayUnavailableV1.dylib'] = dict(pin=pin(provider),image=m.MachO(provider.read_bytes()))
    def select(path):
        if path in native: return 'native',path
        if path.startswith('@loader_path/') and path[13:] in own: return 'own',path[13:]
        return 'missing',path
    def deps(kind,key):
        if kind == 'native': return native[key]['dependencies']
        return [dict(ordinal=r['ordinal'],command=r['cmd'],path=r['path']) for r in own[key]['image'].loads]
    def definition(kind,key,symbol,seen=()):
        if kind == 'missing': return dict(resolved=False,cause='missingImage',path=key,symbol=symbol)
        ident=(kind,key,symbol)
        if ident in seen: return dict(resolved=False,cause='reexportCycle',path=key,symbol=symbol)
        seen=seen+(ident,); im=native[key] if kind=='native' else own[key]['image']
        exports=im['definitions'] if kind=='native' else im.exports; row=exports.get(symbol)
        step=dict(kind=kind,path=key,symbol=symbol)
        if row:
            step['actualExport']=row
            if row['flags'] & 8:
                dep=next(r for r in deps(kind,key) if r['ordinal']==row['ordinal'])
                rest=definition(*select(dep['path']),row.get('alias',row.get('importedName','')) or symbol,seen)
                rest['route']=[step]+rest.get('route',[]); return rest
            step['UUID']=im['UUID'] if kind=='native' else im.uuid
            return dict(resolved=True,route=[step])
        for dep in deps(kind,key):
            if dep['command']==0x8000001f:
                rest=definition(*select(dep['path']),symbol,seen)
                if rest['resolved']: rest['route']=[step]+rest.get('route',[]);return rest
        return dict(resolved=False,cause='missingStrongDefinition',path=key,symbol=symbol)
    rows=[]; loads=[]; weak=[]
    for key, entry in sorted(own.items()):
        for dep in deps('own',key):
            kind,t=select(dep['path']); required=dep['command']!=0x80000018 or any(
                not r['weak'] and r['ordinal']==dep['ordinal'] for r in entry['image'].imports)
            loads.append(dict(importer=key,**dep,targetKind=kind,target=t,required=required))
            need(not required or kind!='missing','every required first load exists')
        for imp in entry['image'].imports:
            if imp['weak']: continue
            if imp['ordinal']>0:
                dep=next(r for r in deps('own',key) if r['ordinal']==imp['ordinal'])
                res=definition(*select(dep['path']),imp['name'])
            elif imp['ordinal']==0: res=definition('own',key,imp['name'])
            elif imp['ordinal']==-3:
                res=definition('native','/usr/lib/libc++.1.dylib',imp['name'])
                need(res['resolved'] and res['route'][-1]['actualExport']['flags'] & 4, 'true native weak definition')
                weak.append(dict(importer=key,actualImport=imp,resolution=res,scopeExecuted=False)); continue
            else: res=dict(resolved=False,cause='unprovedSpecialOrdinal')
            rows.append(dict(importer=key,actualImport=imp,resolution=res))
    missing=[r for r in rows if not r['resolution']['resolved']]
    need(len(missing)==1 and missing[0]['actualImport']['name']=='_IOSurfaceAcceleratorParavirtProcessGuestData',
         'only Root IOSurface strong definition remains')
    need(len(weak)==13, 'thirteen unchanged actual weak definitions')
    return dict(actualImages=len(own), actualStrongImports=len(rows)+len(weak),
        actualStrongImportRows=rows, actualLoadRows=loads, actualNativeWeakDefinitions=weak,
        unresolvedStrongImportRows=missing, remainingActualStrongSymbols=1,
        allRequiredSelectedFirstLoadsAvailable=True, finalStrongDefinitionGraphClosed=False,
        actualWeakCoalescingExecuted=False, loaderExecuted=False, deviceOperations=0,
        sources=[pin(indexPath),READER and pin(READER)]+[row['pin'] for row in own.values()])

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path)
    o=ap.parse_args().output.resolve(); need(o.parent==N.resolve() and not o.exists(),'fresh output')
    stagePath=N/'independent27-flat-graph-stage-v1-attempt3/candidate.json'
    need(pin(stagePath)['sha256']=='97d9def83ebe8c240bfe3b752d25e28365ffe6bec51f95a25d3150f3a308a206','frozen actual stage71')
    stage=json.loads(stagePath.read_bytes()); vm=next(r for r in stage['stagedImages'] if r['key']=='com.apple.Virtualization.VirtualMachine')
    beforePath=pathlib.Path(vm['staged']['path']); need(pin(beforePath)==vm['staged'],'exact stage VMM')
    need(pin(beforePath)['sha256']=='4282dd7ac3693052d0f0fbdaedf506ac97fd6e65bd8b686992aebe57a82bdd38','same authoring base')
    before=beforePath.read_bytes(); after,recipe=transform(before); o.mkdir(); commands=[]
    def run(label,args):
        args=list(map(str,args)); p=subprocess.run(args,capture_output=True,timeout=60)
        (o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=args,exit=p.returncode));save(o/'commands.json',commands)
        need(p.returncode==0,label+': '+p.stderr.decode());return p.stdout
    source=S/'vm27_display_services_unavailable_v1.m';header=source.with_suffix('.h')
    fixture=S/'test-vm27-display-services-unavailable-v1.m'
    try:
        mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
        ios=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
        results=[]
        for mode in ('normal','sanitized'):
            exe=o/('unavailable-'+mode); flags=['xcrun','clang','-target','arm64e-apple-macos13','-isysroot',mac,
                '-fobjc-arc','-O2','-Wall','-Wextra','-Werror']
            if mode=='sanitized': flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            run('compile-'+mode,flags+[source,fixture,'-framework','Foundation','-o',exe])
            result=json.loads(run('run-'+mode,[exe])); need(result['failures']==0 and result['caughtUnavailable']==3,'actual typed refusal/lifetime fixture')
            results.append(dict(mode=mode,result=result,executable=pin(exe)))
        dylib=o/'VM27DisplayUnavailableV1.ios.inert.dylib'
        run('link-ios',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',ios,'-fobjc-arc','-fvisibility=hidden',
            '-O2','-Wall','-Wextra','-Werror',source,'-dynamiclib','-framework','Foundation',
            '-Wl,-no_adhoc_codesign','-Wl,-undefined,error','-Wl,-install_name,'+LOAD,'-o',dylib])
        run('validate-ios',['xcrun','dyld_info','-validate_only',dylib])
        exports=m.MachO(dylib.read_bytes()).exports
        expected={'_OBJC_CLASS_$_VM27DSClientV1','_OBJC_METACLASS_$_VM27DSClientV1',
                  '_VM27PluginUnavailableV1','_VM27CGUnavailableV1','_VM27HeadroomUnavailableV1'}
        need(set(exports)==expected and all(v['flags']==0 for v in exports.values()),'exact own strong typed exports')
        helper=R/'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
        h=runpy.run_path(str(helper)); compiled=[]
        for rva,(old,new,dest) in SITES.items():
            asm=o/(hex(rva)+'.s'); obj=asm.with_suffix('.o')
            asm.write_text('.text\n.globl _VM27GPUBranchOracleV1\n_VM27GPUBranchOracleV1:\n b . + '+str(dest-rva)+'\n')
            run('assemble-'+hex(rva),['xcrun','clang','-target','arm64e-apple-ios16.1','-c',asm,'-o',obj])
            code=h['object_text'](obj.read_bytes()); need(code==struct.pack('<I',new),'true assembler branch')
            compiled.append(pin(obj))
        candidate=o/'VMM27.gpu-display-profile.inert.macho-data';candidate.write_bytes(after)
        run('validate-vmm',['xcrun','dyld_info','-validate_only',candidate])
        # C++ actual compiler must retain these pointer/float/int own C ABIs.
        typed=o/'typed-caller.cc'; typed.write_text('#include "vm27_display_services_unavailable_v1.h"\n'
            'extern "C" int32_t VM27TypedPluginCallerV1(const char*p,uint64_t f,const void*r) { return VM27PluginUnavailableV1(p,f,r); }\n'
            'extern "C" struct CGColorSpace* VM27TypedColorCallerV1(uint32_t d) { return VM27CGUnavailableV1(d); }\n'
            'extern "C" float VM27TypedHeadroomCallerV1(uint32_t d) { return VM27HeadroomUnavailableV1(d); }\n')
        obj=o/'typed-caller.ios.o';joined=o/'typed-caller.ios.inert.dylib'
        run('compile-cxx',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',ios,'-I',S,'-O2','-c',typed,'-o',obj])
        run('link-cxx',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',ios,'-dynamiclib',obj,dylib,
            '-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',joined])
        typedImports=m.MachO(joined.read_bytes()).imports
        need({r['name'] for r in typedImports} >= expected-{'_OBJC_CLASS_$_VM27DSClientV1','_OBJC_METACLASS_$_VM27DSClientV1'},'C++ unmangled actual linkage')
        verification=graph(stage,dylib,candidate);save(o/'actual-graph.json',verification)
        negative=[]
        for label,at in [('GPU actual branch',0x14813c),('GPU selection branch',0x14827c),('original canary',0x148300)]:
            bad=bytearray(before);bad[m.MachO(before).file(BASE+at)]^=1
            try:
                transformed,_=transform(bytes(bad))
                need(transformed==after,'contract damaged byte')
            except (ValueError,AssertionError): negative.append(dict(label=label,rejected=True))
            else: raise ValueError('accepted '+label)
        gpu=N/'ordinary-metal-array-gpu-device-result-v1/verdict.json'
        publisher=N/'vz-metal-array-real-reexport-data-v4/candidate.json'
        singleton=N/'metal-singleton-selection-source-fixture-v1/candidate.json'
        gpuProof=json.loads(gpu.read_bytes());need(gpuProof['actualBothConsumerSelectorsAbsentFor64Devices'],'actual current properties absent')
        need(gpuProof['actualOwnedGPUArrayLifetimePassed'] and gpuProof['summary']['registryIdentityComparisons']==64,'actual zero/singleton genuine array')
        md=next(r['staged'] for r in stage['stagedImages'] if r['key']=='MD')
        need(md['sha256']=='ff0d25b4464f9d23c27d9754a3b21c8e967e62345dcbacf4da95b9c305001500','unchanged true MD publisher')
        save(o/'patch-recipe.json',dict(schema='Composable exact original VMM GPU/display own profile patches v1',
            authoringBase=pin(beforePath),**recipe,requiredProvider=pin(dylib),unchangedMD=md,
            ownObjectClassName='VM27DSClientV1',fakeAppleClassDefined=False,
            pluginValidInputResult='ENOTSUP, nonzero original error path',colorSpaceResult='actual noreturn exception',
            headroomResult='actual noreturn exception',originalDisplayIDProducersAndGatesPreserved=True))
        save(o/'candidate.json',dict(schema='Independent original27 singleton GPU and explicit unavailable Mac display source port v1',
            sourceStage=pin(stagePath),sourceImage=pin(beforePath),candidate=pin(candidate),sourceProvider=pin(dylib),
            patchRecipe=pin(o/'patch-recipe.json'),actualDefinitionGraph=pin(o/'actual-graph.json'),
            sources=[pin(source),pin(header),pin(fixture)],normalAndSanitizedResults=results,negativeControls=negative,
            assemblerOracles=compiled,actualIOSCXXTypedSymbolsJoined=True,exactOwnExports=sorted(exports),
            inheritedGenuineIPadGPU=pin(gpu),inheritedPublisher=pin(publisher),inheritedGenuineSelectionFixture=pin(singleton),
            singletonProfileOnly=True,devicePropertyCallsUnreachable=True,syntheticGPU=False,systemGPUPropertiesAdded=0,
            originalDisplayServicesClassReplacedByOwnNamedObject=True,MacPhysicalDisplayServicesImplemented=False,
            unsupportedDisplayQueriesThrow=True,unsupportedPluginRegistrationReturnsRealError=True,
            remainingStrongSymbols=1,remainingStrongNames=['_IOSurfaceAcceleratorParavirtProcessGuestData'],
            actualOriginalVMMExecuted=False,originalChildStarted=False,originalLoaderExecuted=False,
            readyForActualLoading=False,codeSigned=False,preexistingVMMCodeSignatureInvalid=True,
            deviceOperations=0,nativeHVCalls=0,guestBoot=False,independent27Complete=False))
        references=[stagePath,beforePath,READER,source,header,fixture,pathlib.Path(__file__),helper,gpu,publisher,singleton,
            S/'vm27_mac_display_unavailable_v1.h',S/'vm27_mac_display_unavailable_v1.m']
        references += [pathlib.Path(row['path']) for row in verification['sources']]
        pins=[pin(p) for p in references+[p for p in o.iterdir() if p.is_file()]]
        save(o/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,
            actualOriginalVMMExecuted=False,codeSigned=False))
        print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),vmm=pin(candidate),
            sourceProvider=pin(dylib),patchRecipe=pin(o/'patch-recipe.json'),remainingStrongSymbols=1)))
    except Exception as error:
        failed=o/'failed-sources';failed.mkdir(exist_ok=True)
        for p in (pathlib.Path(__file__),source,header,fixture): (failed/p.name).write_bytes(p.read_bytes())
        save(o/'failure.json',dict(error=repr(error),deviceOperations=0));raise
if __name__ == '__main__': main()
