#!/usr/bin/env python3
"""Finite original EL2/TSO failure recipe; offline, no guest or native execution."""
from pathlib import Path
import argparse, hashlib, json, re, runpy, struct, subprocess, sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
FATAL = 0x40fe48

def need(ok, message):
    if not ok:
        raise ValueError(message)

def pin(path):
    path = Path(path).resolve()
    need(path.is_file() and not path.is_symlink(), 'regular exact input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    out = ap.parse_args().out.resolve()
    need(out.parent == N and not out.exists(), 'fresh finite host output')
    stagePath = N / 'independent27-essential-dtr-stage-v3-attempt1/candidate.json'
    need(pin(stagePath)['sha256'] == '3fa967eaff477b81774e48d72736f7bad31eccf141f921176f5db63cfa184701', 'actual stage73')
    stage = json.loads(stagePath.read_text())
    row = next(x for x in stage['stagedImages'] if x['key'] == 'com.apple.Virtualization.VirtualMachine')
    source = Path(row['staged']['path'])
    need(pin(source) == row['staged'], 'actual stage73 VMM bytes')
    parserPath = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    helperPath = R / 'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
    a = runpy.run_path(str(parserPath))
    h = runpy.run_path(str(helperPath))
    m = a['MachO'](source.read_bytes())
    old = a['MachO'](a['VM'].read_bytes())
    need(m.uuid == old.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'genuine UUID')
    pairs = [(0x29684c, 0x29686c, 0x296898, 0x11d0),
             (0x296898, 0x2968b8, 0x2968e4, 0x11d8),
             (0x2968e4, 0x296904, 0x296930, 0x11c8),
             (0x296930, 0x296950, 0x29697c, 0x11b8),
             (0x29697c, 0x29699c, 0x2969c8, 0x11c0)]
    methods = []
    for index, (read, write, end, field) in enumerate(pairs):
        methods += [dict(start=read, end=write, kind='read', field=field, slot=0x410+index*0x10,
                         prologueBytes=12, epilogueStart=read+24, contextCalls=[read+16]),
                    dict(start=write, end=end, kind='write', field=field, slot=0x418+index*0x10,
                         prologueBytes=16, epilogueStart=write+32, contextCalls=[write+24])]
    methods.append(dict(start=0x30673c, end=0x306784, kind='TSO frozen closure invoke', field=0xa00,
                        prologueBytes=20, epilogueStart=0x306774, contextCalls=[0x30675c, 0x30676c]))
    # This is a refusal, not an architectural register or native-control implementation.
    # The true method entry retains its original frame and authenticated return metadata.
    for q in methods:
        need(m.bounds(q['start']) == (q['start'], q['end']), 'exact LC_FUNCTION_STARTS method bounds')
        need(m.raw(q['start'], q['end']-q['start']) == old.raw(q['start'], q['end']-q['start']), 'unchanged genuine original body')
        need(struct.unpack('<I', m.raw(q['start'], 4))[0] == 0xd503237f, 'original PACIBSP')
        for pc in q['contextCalls']:
            need(h['target'](struct.unpack('<I', m.raw(pc, 4))[0], pc) == 0x4125b4, 'genuine private view call')
        q['originalHex'] = m.raw(q['start'], q['end']-q['start']).hex()
        if 'slot' in q:
            q['vtableSlotRVA'] = 0x4b6a20+q['slot']
            value = struct.unpack('<Q', m.raw(q['vtableSlotRVA'], 8))[0]
            need(value >> 63 == 1 and value & 0xffffffff == q['start'], 'actual authenticated virtual entry')
            q['actualVtableWord'] = hex(value)
    # An unchanged real error path constructs "assertion failed", reports it,
    # invokes the original __os_crash import and itself guards with BRK #1.
    need(m.raw(FATAL, 0x60) == old.raw(FATAL, 0x60), 'actual fatal helper unchanged')
    need(m.raw(0x44ef0c, 22).split(b'\0')[0] == b'assertion failed', 'true error literal')
    fatalImports = []
    for pc in [0x40fe78, 0x40fe84]:
        stub = h['target'](struct.unpack('<I', m.raw(pc, 4))[0], pc)
        slot, bind = a['authenticated_stub'](m, m.raw(stub, 16), stub)
        fatalImports.append(dict(callRVA=pc, stubRVA=stub, slot=slot, bind=bind))
    need(fatalImports[-1]['bind']['importRecord']['name'] == '__os_crash', 'true original crash path')
    incoming = {}
    for s in m.sections:
        if not s['flags'] & 0x80000400:
            continue
        data = m.raw(s['va']-m.base, s['bytes'])
        for offset in range(0, len(data), 4):
            pc = s['va']-m.base+offset
            to = h['target'](struct.unpack_from('<I', data, offset)[0], pc)
            if to is not None:
                incoming.setdefault(to, []).append(pc)
    for q in methods:
        q['externalDirectInteriorEntries'] = [dict(sourceRVA=pc, targetRVA=to)
            for to in range(q['start']+4, q['end'], 4) for pc in incoming.get(to, [])
            if not q['start'] <= pc < q['end']]
        need(not q['externalDirectInteriorEntries'], 'no actual external direct interior entry')
        h['rebase_interior_entries'].__globals__.update(BEGIN=q['start'], END=q['end'])
        q['chainedInteriorEntries'] = h['rebase_interior_entries'](m)
    out.mkdir(mode=0o700)
    commands = []
    def run(label, argv):
        argv = list(map(str, argv))
        cp = subprocess.run(argv, capture_output=True, timeout=60)
        (out/(label+'.stdout')).write_bytes(cp.stdout)
        (out/(label+'.stderr')).write_bytes(cp.stderr)
        commands.append(dict(label=label, argv=argv, returncode=cp.returncode))
        need(cp.returncode == 0, label)
        return cp.stdout
    asm = out/'refusal.s'
    asm.write_text('.text\n'+''.join(
        f'.globl _vm27_refusal_{i}\n_vm27_refusal_{i}:\nbl . + {FATAL-q["start"]-q["prologueBytes"]}\nbrk #1\n'
        for i,q in enumerate(methods)))
    obj = out/'refusal.o'
    run('assemble', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-c', asm, '-o', obj])
    compiled = h['object_text'](obj.read_bytes())
    need(len(compiled) == 8*len(methods), 'exact compiled finite BL/BRK blocks')
    afterBytes = bytearray(m.b)
    allowed = set()
    patches = []
    for i,q in enumerate(methods):
        start, stop = q['start']+q['prologueBytes'], q['epilogueStart']
        code = compiled[8*i:8*i+8]
        need(h['target'](struct.unpack('<I',code[:4])[0],start) == FATAL and code[4:] == struct.pack('<I',0xd4200020), 'real assembled error target')
        replacement = code + struct.pack('<I',0xd503201f)*((stop-start-8)//4)
        need(len(replacement) == stop-start, 'exact original body capacity')
        fo = next(s['offset']+m.base+start-s['va'] for s in m.sections
                  if s['va'] <= m.base+start and m.base+stop <= s['va']+s['bytes'])
        need(not allowed.intersection(range(fo,fo+len(replacement))), 'disjoint methods')
        allowed.update(range(fo,fo+len(replacement)))
        afterBytes[fo:fo+len(replacement)] = replacement
        q['afterHex'] = bytes(afterBytes[fo-q['prologueBytes']:fo-q['prologueBytes']+q['end']-q['start']]).hex()
        need(bytes.fromhex(q['afterHex'])[:q['prologueBytes']] == bytes.fromhex(q['originalHex'])[:q['prologueBytes']], 'original prologue retained')
        epilogue = q['epilogueStart']-q['start']
        need(bytes.fromhex(q['afterHex'])[epilogue:] == bytes.fromhex(q['originalHex'])[epilogue:], 'original authenticated epilogue retained')
        patches.append(dict(startRVA=q['start'],endRVA=q['end'],beforeHex=q['originalHex'],afterHex=q['afterHex'],
                            patchStartRVA=start,patchEndRVA=stop,originalFileOffset=fo-q['prologueBytes'],
                            operation=q['kind'],nativeField=q['field'],successStateProduced=False))
    need(all(x==y or i in allowed for i,(x,y) in enumerate(zip(m.b,afterBytes))), 'only finite method bodies')
    result = out/'VMM27.el2-tso-explicit-refusal.inert.macho-data'
    result.write_bytes(afterBytes)
    after = a['MachO'](afterBytes)
    need(after.imports == m.imports and after.binds == m.binds and after.libs == m.libs and after.starts == m.starts
         and after.uuid == m.uuid and after.sections == m.sections and after.segments == m.segments, 'all real ABI and header/fixup metadata retained')
    def census(image):
        return [s['va']-image.base+offset for s in image.sections if s['flags']&0x80000400
                for offset in range(0,s['bytes'],4)
                if h['target'](struct.unpack('<I',image.raw(s['va']-image.base+offset,4))[0],s['va']-image.base+offset)==0x4125b4]
    beforeCalls, afterCalls = census(m), census(after)
    removed = sorted(pc for q in methods for pc in q['contextCalls'])
    need(len(beforeCalls) == 28 and len(removed) == 12 and afterCalls == [pc for pc in beforeCalls if pc not in removed], 'true 28 to16 private view call census')
    windows = []
    for label,begin,stop in [('cpu-feature-ctor-gates',0x2b6654,0x2b6708),('cpu-feature-pointer',0x28d41c,0x28d428),
            ('coldboot-feature-ctor-input',0x21f14,0x21f24),('native-vm-feature-copy',0x2327c,0x2328c),
            ('variant0-copy',0x398dc,0x398f4),('config-variant-construct',0x2c4650,0x2c46b0),
            ('nested-key-read',0x2c05a4,0x2c0638),('nested-field-producer',0x2c077c,0x2c07d0),
            ('config-variant-output',0x2c131c,0x2c1328),('ordinary-el1-debug-gates',0x3a708c,0x3a7278),
            ('tso-foreach-main',0x2f5858,0x2f5940),('tso-foreach-secondary',0x2f5940,0x2f5a28),
            ('tso-true-job-rtti',0x4ba0e8,0x4ba180),('fatal-helper',FATAL,0x40fe8c)]:
        path=out/(label+'.bin');path.write_bytes(m.raw(begin,stop-begin));windows.append(dict(label=label,startRVA=begin,endRVA=stop,pin=pin(path)))
    for label,begin,stop in [('original-el2',0x29684c,0x2969c8),('ported-el2',0x29684c,0x2969c8),
                            ('original-tso',0x30673c,0x306784),('ported-tso',0x30673c,0x306784)]:
        path=result if label.startswith('ported') else source
        data=run(label,['xcrun','llvm-objdump','--disassemble','--start-address='+hex(m.base+begin),'--stop-address='+hex(m.base+stop),path])
        lines=[line for line in data.decode().splitlines() if re.match(r'^[0-9a-f]+:\s+[0-9a-f]{8}',line)]
        need(len(lines)==(stop-begin)//4,'all finite machine words disassembled')
    for q in methods:
        need(struct.pack('<I',0xd4200020) in bytes.fromhex(q['afterHex']), 'explicit no-success BRK guard')
    recipe = dict(schema='Finite genuine original27 EL2 and TSO explicit refusal patch recipe v1',sourceImage=pin(source),
        sourceCandidate=pin(stagePath),genuineUUID=m.uuid,patches=patches,requiredNewImports=[],requiredNewLoads=[],
        requiredProviderExports=[],existingActualFatalHelper=FATAL,originalFramesAndEpiloguesAndPACUnchanged=True,
        nativeFieldMappingImplemented=False,ownSoftwareFrozenFlagInvented=False,successOutputsInvented=False,
        nativeOperationsAdded=0,zeroGetContextInPatchedMethods=True,otherCodeBytesUnchanged=True,
        authoringInputAlreadyContainsDTRAndGPUAndIOSurface=True,mergeRequiresExactBeforeHexAndActualSectionTranslation=True)
    (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2)+'\n')
    record = dict(schema='Original27 EL2/TSO finite failure closure v1',builder=pin(Path(__file__)),sourceCandidate=pin(stagePath),
        sourceImage=pin(source),output=pin(result),patchRecipe=pin(out/'patch-recipe.json'),actualMethods=methods,
        fatalImports=fatalImports,actualFailureLiteral='assertion failed',failureIsNoReturnOSCrash=True,
        failureIsRecoverableUnsupportedStatus=False,windows=windows,originalPrivateCalls=beforeCalls,removedPrivateCalls=removed,remainingPrivateCalls=afterCalls,
        checks=dict(exactFunctionBounds=True,exactCompilerBLAndBRK=True,actualVirtualEntries=True,
                    originalFramesAndPACAndEpilogues=True,noOtherCodeChanges=True,allImportsAndFixupsUnchanged=True),
        mode0Producer=dict(configurationVariantBase=0x58,variantFieldOffset=0x18,configurationByte=0x70,
            sourceKey='nested_virtualization_enabled',keyRVA=0x448ac8,readResultStackCell=0x38,
            fieldStoreRVA=0x2c07b4,constructorReadRVA=0x2b6678,featureByte=0x38,
            publicEL2SetterUsesDifferentConfigurationByte=0x72,publicSetterKey='emulate_fine_grained_traps'),
        mode1Producer=dict(configurationByte=0x89,constructorReadRVA=0x2b66ac,featureByte=0x38,
            sourceKeyAndDefaultFullyProven=False),
        ordinaryEL1AccessGate='True feature38==1, CPSR bit3 clear, feature7f low nibble nonzero before slot410 example3a708c',
        TSOSemantics=dict(actualJobRTTI='VirtualMachine::set_tso_frozen(bool)',jobBoolOffset=8,nativeField=0xa00,bit=1,
            realForeachCallers=[0x2f5858,0x2f5940],actualVMVtableEntries=[0x4b8a60,0x4b8c40],
            oldNative740IdentityProven=False,NativeControl10Valid=False,defaultColdBootInvokeAbsenceProven=False),
        noDirectCallAbsenceUsedAsVirtualReachabilityProof=True,asynchronousUnwindRuntimeVerified=False,
        defaultColdBootAllEL2PathsInaccessibleProven=False,remainingOther8FieldsOwnedByIndependentPeer=True,
        originalVMMExecuted=False,deviceOperations=0,nativeOperations=0,codeSigned=False,readyForDeviceExecution=False,
        fullIndependent27GuestBoot=False,finiteLocalScopePassed=True,findings=[])
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    (out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n')
    inputs=[Path(__file__),stagePath,source,parserPath,helperPath,a['VM'],N/'cpu-model4-original-context-boot-closure-v1/closure.json']
    files=[pin(p) for p in inputs+list(out.iterdir()) if p.is_file()]
    (out/'freeze.json').write_text(json.dumps(dict(schema='Frozen offline finite refusal source v1',files=files,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),patchRecipe=pin(out/'patch-recipe.json'),remainingGetContext=16)))

if __name__=='__main__':
    main()
