"""Pin complete public old SYS dispatch and original27 caller error blocks.

Only integer classification, local disassembly and host synthetic mocks run.
This never invokes an Apple image, a native CPU API, or a device operation.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
T = R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3'
OLD = N/'native-system-register-contract-v1/audit/contract.json'
NEW = T/'modern-cpu-system-state-contract-audit-v1/contract.json'
READER = N/'native-init-contract-v1/audit.py'
INPUT_PINS = [(OLD,'15792fb8b96bb59bd04b4aae5f5a28cec376e259aacd9f401f86461eca67c281'),
              (NEW,'960bc2bbbf2995014a38c51cd25632f5900ed82734806a6c14a0bc833b993c2e'),
              (READER,'aebcb8a809c935739683b7ff75109bc11afbf7581cd1da86a823f85f82b02323')]


def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def prefix_route(data,image,rows,start,fallback,endpoints,physical,typed,reader):
    """Interpret only the actual public selector prefix up to its first route.

    All loads are immutable jump-table bytes; there are no native/context loads.
    No instruction outside this closed branch subset can silently succeed.
    """
    code={row['rva']:row['instruction'].split(';')[0].split('<')[0].strip() for row in rows}
    regs={'x1':typed,'x8':typed};comparison=None;pc=start;trace=[]
    def read(name):
        if name in ('xzr','wzr'):return 0
        return regs['x'+name[1:]] & ((1<<(32 if name[0]=='w' else 64))-1)
    def write(name,value):regs['x'+name[1:]]=value&((1<<(32 if name[0]=='w' else 64))-1)
    def operand(s):return int(s.lstrip('#'),0) if s.startswith(('#','0x','-')) else read(s)
    def cond(name):
        a,b,bits=comparison;sa=a-(1<<bits) if a&(1<<(bits-1)) else a;sb=b-(1<<bits) if b&(1<<(bits-1)) else b
        return {'eq':a==b,'ne':a!=b,'hi':a>b,'ls':a<=b,'gt':sa>sb,'le':sa<=sb}[name]
    for _ in range(64):
        trace.append(pc)
        if pc in endpoints:return dict(**endpoints[pc],trace=trace)
        if pc==fallback:
            row=physical.get(typed)
            return dict(kind='physical' if row else 'unsupported',
                        nativeOffset=row['nativeOffset'] if row else None,
                        originalHVStatus=0 if row else 0xfae94003,trace=trace)
        text=code[pc];parts=text.split(None,1);mnemonic=parts[0];args=parts[1] if len(parts)>1 else ''
        ops=[v.strip() for v in args.split(',')];next_pc=pc+4
        if mnemonic=='mov':write(ops[0],operand(ops[1]))
        elif mnemonic=='add':write(ops[0],read(ops[1])+operand(ops[2]))
        elif mnemonic=='cmp':
            value=operand(ops[1]);value<<=int(ops[2].split()[1].lstrip('#'),0) if len(ops)>2 else 0
            bits=32 if ops[0][0]=='w' else 64;comparison=(read(ops[0]),value&((1<<bits)-1),bits)
        elif mnemonic=='csel':write(ops[0],read(ops[1]) if cond(ops[3]) else read(ops[2]))
        elif mnemonic in ('adr','adrp'):write(ops[0],operand(ops[1]))
        elif mnemonic=='ldrsw':
            m=re.fullmatch(r'(x\d+), \[(x\d+), (x\d+), lsl #2\]',args);assert m,args
            rva=read(m[2])+4*read(m[3])-image['imageBase']
            write(m[1],struct.unpack('<i',reader.raw(data,image,rva,rva+4))[0])
        elif mnemonic=='br':next_pc=read(ops[0])-image['imageBase']
        elif mnemonic=='b':next_pc=operand(ops[0])-image['imageBase']
        elif mnemonic.startswith('b.'):
            if cond(mnemonic[2:]):next_pc=operand(ops[0])-image['imageBase']
        else:raise AssertionError((hex(pc),text))
        pc=next_pc
    raise AssertionError('closed public selector-prefix step limit')


def main():
    assert sys.flags.optimize==0
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    for p,expected in INPUT_PINS:assert pin(p)['sha256']==expected
    old=json.loads(OLD.read_text());new=json.loads(NEW.read_text())
    spec=importlib.util.spec_from_file_location('pinned_native_reader',READER);reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    old_data,old_image=reader.pin(Path(old['input']['path']),old['input']['sha256'])
    modern_data,modern_image=reader.pin(Path(new['sourcePins'][0]['path']),new['sourcePins'][0]['sha256'])
    vmm_data,vmm_image=reader.pin(Path(new['sourcePins'][2]['path']),new['sourcePins'][2]['sha256'])
    for row in new['sourcePins']:
        assert pin(Path(row['path']))['sha256']==row['sha256']
    assert pin(Path(new['officialSDK']['path']))['sha256']==new['officialSDK']['sha256']
    out=args.output.resolve();assert out.is_relative_to(N);out.mkdir(mode=0o700,exist_ok=False)
    source=out/'source';source.mkdir(mode=0o700);frames=out/'frames';frames.mkdir(mode=0o700)
    (out/'prepare-snapshot.py').write_bytes(Path(__file__).read_bytes())
    physical={r['identifier']:r for r in old['physicalDescriptors']}
    assert len(physical)==154
    endpoints={'get':{0x5d5c:dict(kind='control',identifier=0xc000,nativeOffset=0x698),0x5c10:dict(kind='control',identifier=0xc005,nativeOffset=0x690)},
               'set':{0x6c54:dict(kind='control',identifier=0xc000,nativeOffset=0x698),0x6b20:dict(kind='control',identifier=0xc005,nativeOffset=0x690)}}
    jump_tables=[]
    for action,tables in [('get',[(0xc020,0x5dd8,10,0x5b88,0x5cf4),(0xc030,0x5e00,11,0x5bd4,0x5cf4)]),
                          ('set',[(0xc020,0x6ce4,10,0x6a98,0x6bf0),(0xc030,0x6d0c,11,0x6ae4,0x6bf0)])]:
        code={r['rva']:r['instruction'] for r in old['frames']['old-'+action+'-sys']['instructions']}
        for base,at,count,origin,fallback in tables:
            b=reader.raw(old_data,old_image,at,at+count*4)
            jump_tables.append(dict(action=action,rva=at,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),exactBytes=b.hex()))
            for i,delta in enumerate(struct.unpack('<'+'i'*count,b)):
                target=origin+delta
                if target==fallback:continue
                rows=[code[x] for x in range(target,target+28,4)]
                found=[re.search(r'(?:ldr\s+x8|str\s+x19), \[x8, #0x([0-9a-f]+)\]',text) for text in rows]
                found=[m for m in found if m];assert len(found)==1
                endpoints[action][target]=dict(kind='feature-cache',identifier=base+i,tableOffset=int(found[0][1],16))
    coverage={};complete_counts={}
    for action,start,fallback in [('get',0x5b58,0x5cf4),('set',0x6a68,0x6bf0)]:
        frame=old['frames']['old-'+action+'-sys'];begin=int(frame['begin'],16);end=int(frame['end'],16)
        b=reader.raw(old_data,old_image,begin,end);assert hashlib.sha256(b).hexdigest()==frame['machineSHA256']
        for row in frame['instructions']:
            assert reader.raw(old_data,old_image,row['rva'],row['rva']+4).hex()==bytes.fromhex(row['machineWord'])[::-1].hex()
        (frames/('old13-public-'+action+'.json')).write_text(json.dumps(frame,indent=2)+'\n')
        all_routes={typed:prefix_route(old_data,old_image,frame['instructions'],start,fallback,endpoints[action],physical,typed,reader) for typed in range(65536)}
        supported={i:r for i,r in all_routes.items() if r['kind']!='unsupported'}
        assert len(supported)==165 and sum(r['kind']=='physical' for r in supported.values())==154
        assert sum(r['kind']=='feature-cache' for r in supported.values())==9 and sum(r['kind']=='control' for r in supported.values())==2
        coverage[action]=all_routes;complete_counts[action]=dict(exhaustiveIDs=65536,supported=165,physical=154,featureCache=9,control=2)
    assert set(i for i,r in coverage['get'].items() if r['kind']!='unsupported')==set(i for i,r in coverage['set'].items() if r['kind']!='unsupported')
    # Complete relevant public27 wrapper and dispatch-chain windows. The
    # reconstructed HV image has no LC_FUNCTION_STARTS; no such claim is made.
    modern_frames={}
    windows=[('public-get',0x85448,0x854a8),('public-set',0x854a8,0x854f0),
             ('sys-get-dispatch',0x6678,0x6a3c),('sys-set-dispatch',0x7d70,0x8238),
             ('view-get',0x6448,0x6678),('view-set',0x8238,0x8484),
             ('ordinary-map',0x6a3c,0x6de4),('timer-get',0x5c44,0x5d70),('timer-set',0x5d70,0x5eb0),
             ('get-other-bank-first',0x5eb0,0x6370),('get-other-bank-second',0x6370,0x6448),
             ('set-other-bank-first',0x8484,0x886c),('set-other-bank-second',0x886c,0x9054),
             ('last-physical-map',0x6e2c,0x7b68)]
    for name,begin,end in windows:
        argv,text,rows=reader.disassemble(Path(modern_image['path']),modern_image['imageBase'],begin,end)
        b=reader.raw(modern_data,modern_image,begin,end)
        modern_frames[name]=dict(beginRVA=begin,endRVA=end,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),instructions=rows,argv=argv,LCFunctionStartsPresent=False)
        (frames/('modern27-'+name+'.asm')).write_text(text)
    calls=new['vmm27FullSaveFunction']['calls'];assert len(calls)==132 and len({c['typedID'] for c in calls})==132
    caller_rows=[]
    view={int(r['typedID'],16) for r in new['modernVIEWPreemptedGetters']}
    ordinary={int(r['typedID'],16):r for r in new['allSDKOrdinaryMapperResults'] if r['new27OrdinaryMapperOnly']['valid']}
    timer={0xdf11:dict(getLeaf=0x73674,setLeaf=0x73774),0xdf12:dict(getLeaf=0x738ec,setLeaf=0x7396c)}
    for call in calls:
        typed=int(call['typedID'],16)
        classification='timer-VIEW-special' if typed in timer else 'VIEW-special' if typed in view else 'ordinary-USER' if typed in ordinary else 'other-modern-family-not-classified-here'
        caller_rows.append(dict(**call,oldPublicGet=coverage['get'][typed],oldPublicSet=coverage['set'][typed],modernFamily=classification))
    missing=[r for r in caller_rows if r['oldPublicGet']['kind']=='unsupported'];assert len(missing)==32
    selected={int(c['typedID'],16):c for c in calls if int(c['typedID'],16) in {0xdf11,0xdf12,0xde87,0xc687}}
    header=['#include <stdint.h>','typedef struct {uint32_t identifier,callRVA,saveOffset;} Original27SaveCall;']
    blocks=[]
    for name,ids in [('Original27PhysicalTimerSave',[0xdf11,0xdf12]),('Original27SCXTNUMSave',[0xde87,0xc687])]:
        entries=[]
        for typed in ids:
            c=selected[typed];call=int(c['callRVA'],16)
            argv,text,rows=reader.disassemble(Path(vmm_image['path']),vmm_image['imageBase'],call-16,call+16)
            by={r['rva']:r['instruction'].split(';')[0].split('<')[0].strip() for r in rows}
            assert re.match(r'str\s+xzr, \[sp, #0x50\]',by[call-12])
            assert 'hv_vcpu_get_sys_reg' in rows[4]['instruction'] or by[call].startswith('bl')
            assert re.match(r'cbnz\s+w0,',by[call+4]);assert re.match(r'ldr\s+x8, \[sp, #0x50\]',by[call+8])
            stored=re.fullmatch(r'str\s+x8, \[x19, #0x([0-9a-f]+)\]',by[call+12]);assert stored
            save_offset=int(stored[1],16);entries.append((typed,call,save_offset))
            b=reader.raw(vmm_data,vmm_image,call-16,call+16)
            blocks.append(dict(identifier=typed,callRVA=call,saveObjectOffset=save_offset,startRVA=call-16,endRVA=call+16,machineSHA256=hashlib.sha256(b).hexdigest(),instructions=rows))
            (frames/(hex(typed)+'-original27-save-block.asm')).write_text(text)
        header.append('static const Original27SaveCall '+name+'[2]={'+','.join('{%s,%s,%s}'%tuple(hex(v) for v in e) for e in entries)+'};')
    (source/'original27-sys-save-blocks.h').write_text('\n'.join(header)+'\n')
    model=R/'VirtualMac/scripts/tests/test-original27-sys-save-route-errors-v1.c'
    (source/model.name).write_bytes(model.read_bytes());model_inputs=[model]+[R/'VirtualMac/vz/host'/name for name in ['modern_cpu_kernel_system_v2.c','modern_cpu_kernel_system.h','modern_cpu_kernel_system_private.h','modern_cpu_kernel_profile_v2.h','modern_cpu_kernel_system_fields.inc','modern_cpu_kernel_initialization_private.h','modern_cpu_kernel_initialization.h','modern_cpu_kernel_lifecycle.h']]
    for p in model_inputs[1:]:(source/p.name).write_bytes(p.read_bytes())
    commands=[]
    def run(label,argv):
        r=subprocess.run(argv,capture_output=True,timeout=30);commands.append(dict(label=label,argv=list(map(str,argv)),exit=r.returncode))
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,(label,r.stderr.decode(errors='replace'));return r.stdout
    sdk=run('macos-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
    for sanitized in [False,True]:
        label='mock-sanitized' if sanitized else 'mock';exe=out/label
        argv=['xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-isysroot',sdk,'-I',str(source),str(source/model.name),str(source/'modern_cpu_kernel_system_v2.c'),'-o',str(exe)]
        if sanitized:argv+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        run(label+'-compile',argv);run(label+'-run',[str(exe)])
    result=dict(schema='pinned-original27-caller-SYS-route-coverage-v1',sourcePins=[pin(p) for p,_ in INPUT_PINS]+[pin(p) for p in model_inputs],oldPublicFullDispatch=complete_counts,immutablePublicJumpTables=jump_tables,
                modernPublicAndDispatchWindows=modern_frames,original27FullSaveCaller=pin(Path(new['sourcePins'][2]['path'])),callerCount=132,oldPublicSupportedCallerCount=100,oldPublicUnsupportedCallerCount=32,callerRows=caller_rows,
                mandatoryBlocks=blocks,modernPhysicalTimer=dict(routes=timer,getGate='USER+0x13a bit0',setGate='USER+0x13a exact byte1',gateRefusal=0xfae9400f,original13FullPublicGateRefusal=0xfae94003),
                conditionalCallerGates=dict(EL2='x26+0x78 == 1; else885f8 jumps88930',SME='(x26+0xeb)&0xf != 0; else88978 jumps88e9c'),mockCases=12,commands=commands,syntheticValuesOnly=True,originalCodeExecuted=False,nativeCalls=0,nativeWrites=0,deviceOperations=0,raw11MeaningInferred=False,full27Backend=False)
    (out/'coverage.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in sorted(out.rglob('*')) if p.is_file()]),indent=2)+'\n')
    print(json.dumps(dict(coverage=pin(out/'coverage.json'),freeze=pin(out/'freeze.json'),oldPublicGetAndSetSupported=165,callerMissing=32,mockCases=12,nativeCalls=0,deviceOperations=0)))


if __name__=='__main__':main()
