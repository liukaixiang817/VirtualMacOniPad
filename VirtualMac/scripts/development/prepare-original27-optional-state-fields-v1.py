#!/usr/bin/env python3
"""Finite fail-closed source port for eight unsupported original CPU methods.

The real native CPU constructor initializes model 4; original complete frame
save/restore skips these four fields for that model. Other virtual consumers
are not proved unreachable. They retain an actual original error outcome.
This builder never accesses a device, installs a provider or claims boot.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, runpy, struct, subprocess, sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(p):
    p = Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def need(v, m):
    if not v: raise ValueError(m)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--out', type=Path, required=True)
    out = ap.parse_args().out.resolve()
    need(out.parent == N and not out.exists(), 'fresh local output directory')
    stage = N / 'independent27-essential-dtr-stage-v3-attempt1/candidate.json'
    source = stage.parent / 'flat/com.apple.Virtualization.VirtualMachine'
    need(pin(stage)['sha256'] == '3fa967eaff477b81774e48d72736f7bad31eccf141f921176f5db63cfa184701', 'exact merged stage73')
    need(pin(source)['sha256'] == '91f1e6f44ecff93c7a58ee66b30cd2b3581c8329f588e634c1af7b4ed4bcadeb', 'exact actual VMM')
    parser = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    # Resolve the independently frozen decoder from its existing DTR caller.
    dtr_builder = R / 'VirtualMac/scripts/development/prepare-original27-dtr-methods-v1.py'
    import re
    match = re.search(r"helperPath=R/'([^']+)'", dtr_builder.read_text())
    need(match is not None, 'actual existing decoder reference')
    helper = R / match.group(1)
    a = runpy.run_path(str(parser)); h = runpy.run_path(str(helper))
    m = a['MachO'](source.read_bytes()); original = a['MachO'](a['VM'].read_bytes())
    need(m.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'actual original VMM UUID')
    rows = [(0x390, 'read', 0x2926d0, 0x2926f0, 0x4b7458, 0x7dc5),
            (0x390, 'write',0x2926f0, 0x29271c, 0x4b7460, 0xb29a),
            (0xca8, 'read', 0x292768, 0x2927b8, 0x4b7478, 0xd8e0),
            (0xca8, 'write',0x2927b8, 0x292818, 0x4b7480, 0x49f4),
            (0xaf8, 'read', 0x293930, 0x293950, 0x4b7648, 0xeb7d),
            (0xaf8, 'write',0x293950, 0x29397c, 0x4b7650, 0x2337),
            (0xbc0, 'read', 0x29397c, 0x2939cc, 0x4b7658, 0x8845),
            (0xbc0, 'write',0x2939cc, 0x293a2c, 0x4b7660, 0xbb90)]
    need(m.raw(0x40fe48, 0x60) == original.raw(0x40fe48, 0x60), 'actual original noreturn error helper unchanged')
    methods = []; fragments = []; incoming = {}
    for section in m.sections:
        if not section['flags'] & 0x80000400: continue
        data = m.raw(section['va'] - m.base, section['bytes'])
        for k in range(0, len(data), 4):
            pc = section['va'] - m.base + k
            target = h['target'](struct.unpack_from('<I', data, k)[0], pc)
            if target is not None: incoming.setdefault(target, []).append(pc)
    for field, operation, start, end, slot, discriminator in rows:
        before = m.raw(start, end-start)
        need(m.bounds(start) == (start,end) and before == original.raw(start,end-start), 'actual untouched complete original method')
        words = list(struct.unpack('<'+'I'*((end-start)//4), before))
        need(words[0] == 0xd503237f, 'actual PACIBSP prefix')
        short = field in (0x390,0xaf8) and operation == 'read'
        prefix = 3 if short else 4
        need(words[1:prefix] == ([0xa9bf7bfd,0x910003fd] if short else [0xa9be4ff4,0xa9017bfd,0x910043fd]), 'actual original frame geometry')
        ret = words.index(0xd65f0fff)
        epilogue = ret - (1 if short else 2)
        need(words[epilogue:ret] == ([0xa8c17bfd] if short else [0xa9417bfd,0xa8c24ff4]), 'actual original PAC return epilogue')
        pointer = struct.unpack('<Q',m.raw(slot,8))[0]
        need(pointer & 0xffffffff == start and (pointer>>32)&0xffff == discriminator, 'actual authenticated virtual table entry')
        calls = [start+4*i for i,w in enumerate(words) if w&0xfc000000 == 0x94000000 and h['target'](w,start+4*i) == 0x4125b4]
        need(len(calls) == 1, 'one actual GetContext per method')
        external = [dict(source=pc,target=target) for target in range(start+4,end,4) for pc in incoming.get(target,[]) if not start<=pc<end]
        need(not external, 'no actual direct external interior entry')
        h['rebase_interior_entries'].__globals__.update(BEGIN=start, END=end)
        chained = h['rebase_interior_entries'](m)
        need(not chained['interior'], 'no actual chained interior entry')
        instructions = [f'.inst {w:#x}' for w in words[:prefix]]
        call = start + prefix*4
        instructions += [f'bl . + {0x40fe48-call}', 'brk #1']
        need(prefix+2 <= epilogue, 'bounded actual failure lane before preserved epilogue')
        fragments.append(dict(rva=start,instructions=instructions))
        methods.append(dict(field=field,operation=operation,startRVA=start,endRVA=end,
            functionSignature='uint64_t(this*)' if operation=='read' else 'void(this*,uint64_t)',
            originalHex=before.hex(),prefixWords=prefix,epilogueWord=epilogue,retWord=ret,
            removedGetContextCall=calls[0],originalVtableSlotRVA=slot,originalVtableWord=hex(pointer),
            PACDiscriminator=discriminator,externalDirectInteriorEntries=external,chainedInteriorAudit=chained,
            errorHelperRVA=0x40fe48, failureIsActualOriginalError=True,successStateImplemented=False))
    out.mkdir(mode=0o700); commands=[]
    def run(label, argv):
        p=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(p.stdout); (out/(label+'.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),returncode=p.returncode))
        need(not p.returncode,label+': '+p.stderr.decode()); return p.stdout
    asm=out/'methods.s'
    asm.write_text('.text\n'+''.join(f'.globl _optional_field_{i}\n_optional_field_{i}:\n'+'\n'.join(f['instructions'])+'\n' for i,f in enumerate(fragments)))
    obj=out/'methods.o'; run('assemble',['xcrun','clang','-target','arm64e-apple-ios16.1','-c',asm,'-o',obj])
    compiled=h['object_text'](obj.read_bytes()); cursor=0; changed=bytearray(m.b); allowed=set(); patches=[]
    for q,f in zip(methods,fragments):
        size=4*len(f['instructions']); code=compiled[cursor:cursor+size]; cursor+=size
        words=list(struct.unpack('<'+'I'*((q['endRVA']-q['startRVA'])//4),bytes.fromhex(q['originalHex'])))
        after=bytearray(struct.pack('<I',0xd503201f)*len(words)); after[:size]=code
        ep=q['epilogueWord']*4; ret=q['retWord']*4
        after[ep:ret+4]=bytes.fromhex(q['originalHex'])[ep:ret+4]
        need(after[:q['prefixWords']*4] == bytes.fromhex(q['originalHex'])[:q['prefixWords']*4], 'original PAC prologue unchanged')
        call=q['startRVA']+q['prefixWords']*4
        need(h['target'](struct.unpack_from('<I',after,q['prefixWords']*4)[0],call)==0x40fe48, 'actual assembled BL original failure')
        seg=next(s for s in m.segments if s['va']<=m.base+q['startRVA'] and m.base+q['endRVA']<=s['va']+s['bytes'])
        off=seg['offset']+m.base+q['startRVA']-seg['va']
        need(not allowed.intersection(range(off,off+len(after))), 'eight disjoint method bodies')
        allowed.update(range(off,off+len(after))); changed[off:off+len(after)]=after
        q['afterHex']=after.hex(); patches.append(dict(startRVA=q['startRVA'],endRVA=q['endRVA'],originalFileOffset=off,beforeHex=q['originalHex'],afterHex=q['afterHex'],functionSignature=q['functionSignature'],field=q['field'],successStateImplemented=False))
    need(cursor==len(compiled) and len(changed)==len(m.b), 'exact compiled fragment and unchanged file length')
    need(all(x==y or i in allowed for i,(x,y) in enumerate(zip(m.b,changed))), 'only eight method bodies change')
    after=a['MachO'](changed)
    need(after.imports==m.imports and after.binds==m.binds and after.libs==m.libs and after.starts==m.starts and after.uuid==m.uuid and after.sections==m.sections and after.segments==m.segments, 'all original metadata, PAC chain words and loads remain')
    anchors=[(0xb2438,0x52800088),(0xb243c,0xb9003008),(0xb25a8,0xf9000f14),
             (0x289274,0xb9403288),(0x289278,0x51000509),(0x28927c,0x71000d3f),(0x289280,0x54004b02),(0x289be0,0x35000f88),
             (0x28bd3c,0xb9403288),(0x28bd40,0x51000509),(0x28bd44,0x71000d3f),(0x28bd48,0x54005e02),(0x28c908,0x35001008)]
    for r,w in anchors: need(struct.unpack('<I',m.raw(r,4))[0]==w and after.raw(r,4)==m.raw(r,4), 'actual constructor and original model branch unchanged')
    windows=[]
    for start,end,label in [(0xb2310,0xb25c0,'actual-native-CPU-constructor'),(0x289274,0x2892b8,'actual-Save-model-gate'),(0x289bdc,0x289bf4,'actual-Save-special-gate'),(0x28bd3c,0x28bda8,'actual-Restore-model-gate'),(0x28c904,0x28c924,'actual-Restore-special-gate')]:
        p=out/(label+'.bin'); p.write_bytes(m.raw(start,end-start)); windows.append(dict(startRVA=start,endRVA=end,label=label,pin=pin(p)))
    text=next(s for s in after.sections if s['name']=='__text'); calls=[]
    for k in range(0,text['bytes'],4):
        pc=text['va']-after.base+k; w=struct.unpack_from('<I',changed,text['offset']+k)[0]
        if w&0xfc000000==0x94000000 and h['target'](w,pc)==0x4125b4: calls.append(pc)
    need(len(calls)==20, 'actual 28 minus eight unsupported method view calls')
    target=out/'VMM27.optional-state-fail-closed.inert.macho-data'; target.write_bytes(changed)
    run('disassembly',['xcrun','llvm-objdump','--disassemble',obj]); run('validate',['xcrun','dyld_info','-validate_only',target])
    recipe=dict(schema='Finite eight optional unknown state method failure source recipe v1',sourceVMM=pin(source),sourceStageCandidate=pin(stage),mainUUID=m.uuid,codePatches=patches,importChanges=[],newRequiredLoads=[],replacementProvider=None,preserveUUIDFunctionStartsUnwindPACChainedFixups=True,applyAfterAnyHeaderEditsByRealSectionRVATranslation=True,successStateImplemented=False,unknownVirtualConsumersMayActuallyFail=True)
    (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2)+'\n')
    cases=[dict(model=q,completeSuccessfulFrameFields390Ca8Af8Bc0Reached=q<=3) for q in [0,1,2,3,4,5,0xffffffff]]
    evidence=[N/'modern27-native-cpu-model-construction-offline-v1/report.json',N/'modern27-native-cpu-model-construction-offline-v1/freeze.json',N/'modern27-remaining-field-gates-semantic-offline-v1/report.json',N/'modern27-remaining-field-gates-semantic-offline-v1/freeze.json']
    record=dict(schema='Eight genuine optional unknown original VMM methods fail-closed source port v1',finiteLocalScopePassed=True,findings=[],source=pin(source),candidate=pin(target),sourceStageCandidate=pin(stage),methods=methods,patchRecipe=pin(out/'patch-recipe.json'),originalErrorHelper=dict(rva=0x40fe48,noreturn=True,preservesOriginalErrorOutcome=True,statusArgumentConsumed=False),actualFreshNativeCPUConstructorModel=4,modelWordFieldOffset=0x30,actualModelGateCases=cases,originalEvidence=[pin(p) for p in evidence],actualWindows=windows,allOriginalPACProloguesAndReturnEpiloguesPreserved=True,defaultFreshModel4SuccessfulCompleteSaveRestoreSkipsAllFourFields=True,allVirtualConsumersProvedUnreachable=False,externalOrAliasedFutureModelMutationsExcluded=False,semanticNamesFor390Af8Unknown=True,modernPhysicalIDs=dict(ca8='0xcf8d',bc0='0xf7c7'),physicalIDsHaveProvedCurrentNativeHardwareRoutes=False,oldContextOffsetMappingOrShadowSuccessUsed=False,removedActualContextCalls=8,remainingActualContextCalls=20,remainingActualContextCallRVAs=list(map(hex,calls)),typedStateFunctionalityImplemented=False,originalVMMExecuted=False,actualColdBootObserved=False,fullIndependent27GuestBoot=False,deviceOperations=0,nativeOperations=0,signingCalls=0)
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n'); (out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n')
    paths={Path(__file__).resolve(),stage,source,parser,helper,dtr_builder,a['VM']}|set(evidence)|set(out.iterdir())
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(paths) if Path(p).is_file()],deviceOperations=0,nativeOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),recipe=pin(out/'patch-recipe.json'),freeze=pin(out/'freeze.json'),remainingGetContextCalls=20)))

if __name__=='__main__': main()
