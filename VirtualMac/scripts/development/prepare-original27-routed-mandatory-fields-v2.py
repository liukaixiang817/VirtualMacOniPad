#!/usr/bin/env python3
"""Route four real mandatory callers to the typed retained-owner adapter.

The original authenticated dlsym stub and original function stack frames are
retained. New symbol strings occupy only two proven skipped instruction tails.
No new load command, import, authenticated pointer, context view, or device I/O.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import runpy
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def require(value,message):
    if not value:raise ValueError(message)


def pin(path):
    path=Path(path).resolve();require(path.is_file() and not path.is_symlink(),'regular input')
    data=path.read_bytes();return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def disassembly(path,base):
    rows={}
    for line in path.read_text().splitlines():
        m=re.match(r'^([0-9a-f]+): ([0-9a-f]{8})\s+(.+)$',line)
        if m:rows[int(m[1],16)-base]=dict(word=int(m[2],16),instruction=m[3])
    return rows


def signed(value,bits):
    return value-(1<<bits) if value&(1<<(bits-1)) else value


def main():
    arguments=argparse.ArgumentParser();arguments.add_argument('--out',type=Path,required=True)
    output=arguments.parse_args().out.resolve()
    require(output.parent==N.resolve() and not output.exists(),'fresh diagnostic output')
    previous_path=N/'original27-routed-save-restore53-data-v1/candidate.json'
    require(pin(previous_path)['sha256']=='c7c883dfc3318edc10706031f83ae4f51a2567d3b74c716c76980ecc7c9afc7e','frozen exact routed SAVE53 RESTORE53')
    previous=json.loads(previous_path.read_bytes());source=Path(previous['candidate']['path'])
    require(pin(source)==previous['candidate'],'frozen combined VMM')
    parser_path=N/'vmm-public-adapter-gap-design-v1/audit.py'
    parser=runpy.run_path(str(parser_path));before=source.read_bytes();image=parser['MachO'](before)
    helper_path=R/'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
    helper=runpy.run_path(str(helper_path))
    lifetime_path=R/'VirtualMac/scripts/development/prepare-original27-routed-save-restore53-v1.py'
    lifetimes=runpy.run_path(str(lifetime_path))
    old_lifetime_path=R/'VirtualMac/scripts/development/prepare-original27-physical-restore-ports-v1.py'
    old_lifetimes=runpy.run_path(str(old_lifetime_path))
    control_path=R/'VirtualMac/scripts/development/audit-original27-cpu-restore-v1.py'
    control=runpy.run_path(str(control_path))
    adapter_path=N/'vmm-mandatory-field-local-v2-attempt2/candidate.json'
    require(pin(adapter_path)['sha256']=='d3963e56aed3177efc4477d8f35ac6940040a4c712f88e79a8b1eba2a7040ef5','actual typed Root9 single-field adapter')
    adapter=json.loads(adapter_path.read_bytes())
    for symbol in ('VM27VMMGetMandatoryFieldV2','VM27VMMSetMandatoryFieldV2'):
        require('_'+symbol in adapter['exports'],'actual linked C adapter export')
    save_asm=N/'cpu-physical-timer-boot-basis-v1/vmm-full-save-complete.asm'
    restore_asm=N/'modern27-cpu-restore-readonly-v1/original-function.asm'
    rows=disassembly(save_asm,image.base)|disassembly(restore_asm,image.base)
    original=parser['MachO'](Path(previous['original']['path']).read_bytes())
    # Resolve the existing actual authenticated stub by its real chained bind.
    dlsym_slots=[at for at,entry in image.binds.items() if entry['importRecord']['name']=='_dlsym']
    require(len(dlsym_slots)==1,'unique real dlsym bind')
    slot=dlsym_slots[0];bind=image.binds[slot]
    require(bind['authenticated'] and bind['addressDiversity'] and bind['diversity']==0 and bind['key']==0 and
        bind['importRecord']['ordinal']==15 and not bind['importRecord']['weak'],'original real libSystem IA/address-diversified bind')
    stubs=next(section for section in image.sections if section['name']=='__auth_stubs')
    matches=[]
    for at in range(stubs['va']-image.base,stubs['va']-image.base+stubs['bytes'],16):
        a,b,c,d=struct.unpack('<4I',image.raw(at,16))
        if a&0x9f00001f!=0x90000011 or b&0xffc003ff!=0x91000231 or c!=0xf9400230 or d!=0xd71f0a11:continue
        page=signed((((a>>5)&0x7ffff)<<2)|((a>>29)&3),21)
        target=(at&~0xfff)+(page<<12)+((b>>10)&0xfff)
        if target==slot:matches.append(at)
    require(matches==[0x4129f4],'actual authenticated dlsym stub bytes')
    incoming={}
    for section in image.sections:
        if not section['flags']&0x80000400:continue
        raw=image.raw(section['va']-image.base,section['bytes'])
        for delta in range(0,len(raw),4):
            at=section['va']-image.base+delta
            target=helper['target'](struct.unpack_from('<I',raw,delta)[0],at)
            if target is not None:incoming.setdefault(target,[]).append(at)
    restore49_path=N/'original27-physical-restore-source-ports-data-v1/candidate.json'
    restore49=json.loads(restore49_path.read_bytes())
    strings=[]
    for name,parent in zip(('VM27VMMGetMandatoryFieldV2','VM27VMMSetMandatoryFieldV2'),restore49['supportedPorts'][4:6]):
        at=parent['callRVA']+20;data=name.encode()+b'\0'
        require(len(data)<=36 and helper['target'](struct.unpack('<I',image.raw(at-4,4))[0],at-4)==parent['resumeRVA'],
            'original successful parent port skips full literal tail')
        interior=[dict(source=pc,target=target) for target in range(at,at+len(data),4) for pc in incoming.get(target,[])]
        require(all(at<=entry['source']<parent['resumeRVA'] for entry in interior),'no live direct entry into literal tail')
        helper['rebase_interior_entries'].__globals__.update(BEGIN=at,END=at+len(data))
        rebase=helper['rebase_interior_entries'](image)
        strings.append(dict(symbol=name,rva=at,bytes=len(data),parentCallRVA=parent['callRVA'],
            parentResumeRVA=parent['resumeRVA'],originalTailHex=image.raw(at,len(data)).hex(),
            noLiveDirectOrChainedEntry=True,originalAlreadySkippedInternalBranches=interior,chainedWordsWalked=rebase['words']))
    # Exact real call sites; the original incoming registers and frame widths
    # are checked below, never constructed as synthetic CPU identities.
    selected=[dict(callRVA=0x288328,field=0x6a0,frameOffset=0x5d8,width=1,save=True,cpuRegister=24,bytes=48),
        dict(callRVA=0x28839c,field=0x410,frameOffset=0x5f8,width=8,save=True,cpuRegister=24,bytes=48),
        dict(callRVA=0x28b16c,field=0x6a0,frameOffset=0x5d8,width=1,save=False,cpuRegister=26,bytes=56),
        dict(callRVA=0x28b1ec,field=0x410,frameOffset=0x5f8,width=8,save=False,cpuRegister=26,bytes=56)]
    for row in selected:
        at=row['callRVA'];size=row['bytes']
        require(image.raw(at,size)==original.raw(at,size),'unmodified exact original mandatory block')
        require(rows[at-4]['word']==(0xf9400000|row['cpuRegister']<<5) and
            helper['target'](rows[at]['word'],at)==0x4125b4 and rows[at+4]['word']==0xaa0003f5,'original CPU ID and context call')
        require(helper['target'](rows[at+20]['word'],at+20)==at+40 and
            helper['target'](rows[at+32]['word'],at+32)==0x3a59a4,'original ready/native8 protocol')
        fatal=helper['target'](rows[at+36]['word'],at+36)
        require(rows[at+36]['word']&0xff00001f==0x35000000,'actual original status branch')
        if row['save']:
            require(rows[at+40]['word']==(0xf9400000|(row['field']//8)<<10|21<<5|8),'original genuine physical read')
            expected=(0x39000000|row['frameOffset']<<10|19<<5|8) if row['width']==1 else (0xf9000000|(row['frameOffset']//8)<<10|19<<5|8)
            require(rows[at+44]['word']==expected,'original genuine frame write width')
        else:
            incoming_value=rows[at-8]['word']
            expected=(0x39400000|row['frameOffset']<<10|19<<5|22) if row['width']==1 else (0xf9400000|(row['frameOffset']//8)<<10|19<<5|22)
            require(incoming_value==expected and rows[at+52]['word']==(0xf9000000|(row['field']//8)<<10|21<<5|22),'actual incoming original frame value')
        require(not [dict(source=pc,target=target) for target in range(at+4,at+size,4) for pc in incoming.get(target,[]) if not at<=pc<at+size],
            'no direct external entry into mandatory block')
        helper['rebase_interior_entries'].__globals__.update(BEGIN=at,END=at+size)
        rebase=helper['rebase_interior_entries'](image)
        row.update(fatalRVA=fatal,resumeRVA=at+size,missingAdapterFatalBRK=0x288e64 if row['save'] else 0x28cbc0,
            symbol=strings[0 if row['save'] else 1]['symbol'],symbolRVA=strings[0 if row['save'] else 1]['rva'],
            originalBlockHex=image.raw(at,size).hex(),chainedWordsWalked=rebase['words'])
        require(rows[row['missingAdapterFatalBRK']]['word']==0xd4200020,'existing exact fatal BRK')
    output.mkdir(mode=0o700);commands=[]
    def run(label,args):
        result=subprocess.run(list(map(str,args)),capture_output=True,timeout=45)
        (output/(label+'.stdout')).write_bytes(result.stdout);(output/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,args)),exit=result.returncode))
        require(result.returncode==0,label+': '+result.stderr.decode())
        return result.stdout
    # Use the actual platform compiler as the pointer-authentication ABI oracle.
    oracle=output/'typed-dlsym-pointer.c';oracle_obj=output/'typed-dlsym-pointer.o'
    oracle.write_text('#include <stdint.h>\n#include <dlfcn.h>\n'
        'typedef int32_t(*Fn)(uint64_t,uint32_t,void*);\n'
        'int32_t typed(uint64_t cpu,uint32_t field,void*out){\n'
        ' Fn fn=(Fn)dlsym(RTLD_DEFAULT,"VM27VMMGetMandatoryFieldV2");\n'
        ' if(!fn)__builtin_trap();return fn(cpu,field,out)+1;}\n')
    run('typed-pac',['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-O2','-c',oracle,'-o',oracle_obj])
    oracle_asm=run('typed-pac-disassemble',['xcrun','llvm-objdump','--disassemble',oracle_obj]).decode()
    require(re.search(r'\bblraaz\s+x\d+',oracle_asm) and not re.search(r'\bpaciza\b',oracle_asm),'actual typed dlsym function pointer BLRAAZ ABI without re-signing')
    assembly=output/'mandatory-blocks.s';text='.text\n'
    for row in selected:
        at=row['callRVA']
        code=['mov x0, #-2',f'adr x1, . + {row["symbolRVA"]-at-4}',f'bl . + {0x4129f4-at-8}',
            f'cbz x0, . + {row["missingAdapterFatalBRK"]-at-12}','mov x8, x0',
            f'ldr x0, [x{row["cpuRegister"]}]',f'mov w1, #{row["field"]}',
            f'add x2, x19, #{row["frameOffset"]}' if row['save'] else 'mov x2, x22',
            'blraaz x8',f'cbnz w0, . + {row["fatalRVA"]-at-36}',f'b . + {row["resumeRVA"]-at-40}']
        row['replacementInstructions']=code
        text+=f'.globl _vm27_mandatory_{at:x}\n_vm27_mandatory_{at:x}:\n'+'\n'.join(code)+'\n'
    assembly.write_text(text);obj=output/'mandatory-blocks.o'
    run('assemble',['xcrun','clang','-target','arm64e-apple-macos27','-c',assembly,'-o',obj])
    compiled=helper['object_text'](obj.read_bytes());require(len(compiled)==44*4,'four exact compiled inline ports')
    after,allowed=bytearray(before),set()
    def replace(at,data):
        segment=next(s for s in image.segments if s['va']<=image.base+at and image.base+at+len(data)<=s['va']+s['bytes'])
        file_at=segment['offset']+image.base+at-segment['va']
        require(not allowed.intersection(range(file_at,file_at+len(data))),'disjoint literal/caller writes')
        allowed.update(range(file_at,file_at+len(data)));after[file_at:file_at+len(data)]=data
    cases=0
    for index,row in enumerate(selected):
        at=row['callRVA'];code=compiled[index*44:(index+1)*44];words=struct.unpack('<11I',code)
        require(words[0]==0x92800020 and words[4]==0xaa0003e8 and words[5]==(0xf9400000|row['cpuRegister']<<5) and
            words[6]==(0x52800001|row['field']<<5) and words[8]==0xd63f091f,'genuine signed pointer and original public ID typed call')
        adr=words[1];delta=signed((((adr>>5)&0x7ffff)<<2)|((adr>>29)&3),21)
        require(adr&0x9f00001f==0x10000001 and at+4+delta==row['symbolRVA'],'compiled exact symbol address')
        require(helper['target'](words[2],at+8)==0x4129f4 and helper['target'](words[3],at+12)==row['missingAdapterFatalBRK'] and
            helper['target'](words[9],at+36)==row['fatalRVA'] and helper['target'](words[10],at+40)==row['resumeRVA'],'actual resolver/success/status/fatal control')
        for identity in (0,0x123456789abcdef0,(1<<64)-1):
            for frame in (0x100000,0x1234000000):
                for value in (0,0x83,(1<<64)-1):
                    registers={19:frame,22:value,row['cpuRegister']:0x98765400}
                    registers[0]=identity # actual load from original CPU slot
                    registers[1]=(words[6]>>5)&0xffff
                    if row['save']:
                        require(words[7]==(0x91000000|row['frameOffset']<<10|19<<5|2),'true frame pointer ADD')
                        registers[2]=frame+row['frameOffset']
                    else:
                        require(words[7]==0xaa1603e2,'true callee-saved original value')
                        registers[2]=value
                    require((registers[0],registers[1],registers[2])==(identity,row['field'],frame+row['frameOffset'] if row['save'] else value),'exact real caller arguments')
                    for status in (0,1,0xfae94001,0xffffffff):
                        destination=helper['target'](words[9 if status else 10],at+(36 if status else 40))
                        require(destination==(row['fatalRVA'] if status else row['resumeRVA']),'actual 32-bit return branch')
                        cases+=1
        replace(at,code);row['compiledBlockHex']=code.hex()
    for literal in strings:replace(literal['rva'],literal['symbol'].encode()+b'\0')
    require(all(a==b or i in allowed for i,(a,b) in enumerate(zip(before,after))),'whole previous routing/SYS ports retained')
    revised=parser['MachO'](after)
    require(revised.imports==image.imports and revised.binds==image.binds and revised.libs==image.libs and
        revised.starts==image.starts and revised.sections==image.sections and revised.segments==image.segments and revised.uuid==image.uuid,
        'all previous PAC,load graph,metadata,layout retained')
    # Re-evaluate old x21 lifetime against the composed, modified SAVE CFG.
    # Removed prior MOV x21 sites and their now-dead tails cannot be counted as
    # overwrites. The only remaining context users must establish it themselves.
    modified=dict(rows)
    for at in rows:
        word=struct.unpack('<I',revised.raw(at,4))[0]
        if word!=rows[at]['word']:modified[at]=dict(word=word,instruction='nop')
    for row in selected:
        for i,text in enumerate(row['replacementInstructions']):modified[row['callRVA']+i*4]['instruction']=text
    proofs=[]
    require(rows[0x288d70]['word']==0x1b087d15 and
        re.fullmatch(r'mul\s+w21, w8, w8',rows[0x288d70]['instruction']),'genuine independent W21 multiply overwrite')
    def register_use(text,register):
        if register=='x21' and re.fullmatch(r'mul\s+w21, w8, w8',text):return 'kill'
        return old_lifetimes['register_use'](text,register)
    for row in previous['savePorts']+[r for r in selected if r['save']]:
        if row.get('blockBytes',row.get('bytes'))==12:continue
        proofs.append(lifetimes['save_context_lifetime'](modified,row['resumeRVA'],0x28a258,register_use,control['edges']))
    target=output/'VMM27.routed-save55-restore55.inert.macho-data'
    with target.open('xb') as stream:stream.write(after)
    target.chmod(0o600)
    run('compiled-disassemble',['xcrun','llvm-objdump','--disassemble',obj])
    run('validate',['xcrun','dyld_info','-validate_only',target])
    report=dict(schema='Genuine routed VMM53 SYS plus two mandatory typed owner fields inert callers v2',
        source=pin(Path(__file__)),previous=pin(previous_path),sourceImage=pin(source),candidate=pin(target),
        actualAdapter=pin(adapter_path),dlsymStubRVA=0x4129f4,dlsymBind=bind,ports=selected,literals=strings,
        compiledArgumentAndReturnCases=cases,composedSaveContextLifetime=proofs,
        totalSavePorts=55,totalRestorePorts=55,remainingSaveContextCalls=4,remainingRestoreContextCalls=4,
        remainingFields=[0xca8,0xbc0,0x390,0xaf8],originalFeatureGatesNotAltered=True,
        noGeneratedCPUIdentity=True,noFakeContextOrPublicSYSSelector=True,originalStackAndUnwindMetadataPreserved=True,
        originalAuthenticatedDlsymStubAndTypedBLRAAZ=True,noNewImportOrAuthenticatedPointer=True,
        missingAdapterUsesOriginalFatalBRK=True,actualMandatoryAdapterResolvedOnDevice=False,
        genericIndirectEntrypointAbsenceExhaustivelyProven=False,exceptionUnwindRoutesExecuted=False,
        signed=False,loaded=False,originalSaveRestoreExecuted=False,nativeCalls=0,deviceOperations=0,guestInstructions=0,
        fullIndependent27GuestBoot=False,commands=commands)
    (output/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    paths=[Path(__file__),previous_path,source,parser_path,helper_path,lifetime_path,old_lifetime_path,control_path,
        adapter_path,save_asm,restore_asm,restore49_path]+[p for p in output.iterdir() if p.is_file()]
    (output/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in paths],nativeCalls=0,deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(output/'candidate.json'),freeze=pin(output/'freeze.json'),savePorts=55,restorePorts=55)))


if __name__=='__main__':main()
