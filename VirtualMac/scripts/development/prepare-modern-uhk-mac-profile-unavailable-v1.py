#!/usr/bin/env python3
"""Finite own UIKit profile: cut only three unavailable original Mac entries.

Never loads original UHK, touches a device, signs, or changes a prior candidate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
HOST = ROOT / 'VirtualMac/vz/host'
READER = ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/compiler_image.py'
sys.path.insert(0, str(READER.parent))
from compiler_image import commands, segments, imports, chain_entries, export_trie
BASE = 0x100000000
ENTRY, EXTENT, SLOT = 0x2ad4, 68, 68240
PATH = '@loader_path/VM27MacInputUnavailableV1.dylib'
NAMES = {103: '_VM27MacDoubleUnavailableV1', 104: '_VM27MacIntegerUnavailableV1', 190: '_VM27MacInputUnavailableV1'}
OLD = {103: '_SLEventGetDoubleValueField', 104: '_SLEventGetIntegerValueField', 190: '_OBJC_CLASS_$_NSTouch'}

def pin(path):
    path = Path(path).resolve(); b = path.read_bytes()
    return dict(path=str(path), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')

def sx(value, width):
    return value - (1 << width) if value & (1 << (width-1)) else value

def adrp(pc, word):
    if word & 0x9f000000 != 0x90000000: return None
    return word & 31, (pc & ~4095) + (sx(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3), 21) << 12)

def target(pc, word):
    if word & 0x7c000000 == 0x14000000: return pc + (sx(word & 0x3ffffff, 26) << 2)
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
        return pc + (sx((word >> 5) & 0x7ffff, 19) << 2)
    if word & 0x7e000000 == 0x36000000: return pc + (sx((word >> 5) & 0x3fff, 14) << 2)
    return None

def proof(before):
    info = imports(before); selected = [r for r in info['imports'] if r['ordinal'] in (5, 23)]
    assert [(r['index'],r['name'],r['ordinal'],r['weak']) for r in selected] == [
        (103, OLD[103], 23, False), (104, OLD[104], 23, False), (190, OLD[190], 5, False)]
    segs = segments(before); text = next(s for g in segs for s in g['sections'] if s['name'] == '__text')
    assert not any(s['name'] == '__objc_classrefs' for g in segs for s in g['sections'])
    assert (text['fileoff'],text['size'],text['address']) == (5072,37864,BASE+5072)
    nodes = list(chain_entries(before)); node = next(r for r in nodes if r['symbol'] == OLD[190])
    assert node['fileoff'] == SLOT and node['bind'] and not node['auth'] and node['section'] is None
    direct, interior, slot_loads, slot_addresses, accessor_addresses = [], [], [], [], []
    lo, hi = BASE + ENTRY, BASE + ENTRY + EXTENT
    for at in range(text['fileoff'], text['fileoff']+text['size'], 4):
        pc = BASE + at; word = struct.unpack_from('<I',before,at)[0]; to = target(pc,word)
        if to is not None and lo <= to < hi and not lo <= pc < hi:
            (direct if to == lo else interior).append(dict(pc=pc,target=to))
        ad = adrp(pc, word)
        if ad and at+8 <= text['fileoff']+text['size']:
            reg,page = ad; nxt = struct.unpack_from('<I',before,at+4)[0]
            if nxt & 0xffc00000 == 0xf9400000 and (nxt >> 5) & 31 == reg:
                to = page + ((nxt >> 10) & 4095)*8
                if to == BASE+SLOT: slot_loads.append(dict(pc=pc,loadPC=pc+4,target=to))
            if nxt & 0xff000000 == 0x91000000 and (nxt >> 5) & 31 == reg:
                to = page + (((nxt >> 10)&4095) << (12 if nxt & (1<<22) else 0))
                if to == BASE+SLOT: slot_addresses.append(pc)
                if lo <= to < hi: accessor_addresses.append(dict(pc=pc,target=to))
        if word & 0x9f000000 == 0x10000000:
            to = pc + sx(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3),21)
            if to == BASE+SLOT: slot_addresses.append(pc)
            if lo <= to < hi: accessor_addresses.append(dict(pc=pc,target=to))
    assert [r['pc']-BASE for r in direct] == [0x2a9c,0x8014,0x808c]
    assert not interior and not accessor_addresses and not slot_addresses
    assert slot_loads == [dict(pc=BASE+0x2aec,loadPC=BASE+0x2af0,target=BASE+SLOT)]
    relative, absolute, rebases = [], [], []
    header_end = 32 + struct.unpack_from('<I',before,20)[0]; scanned = 0
    for g in segs:
        if g['name'] == '__LINKEDIT': continue
        for at in range(g['fileoff'],g['fileoff']+g['filesize']-3):
            va = g['address'] + at-g['fileoff']
            if text['address'] <= va < text['address']+text['size'] or BASE+SLOT <= va < BASE+SLOT+8: continue
            scanned += 1; word = struct.unpack_from('<i',before,at)[0]
            for to in (va+word,va+word-(word&1)):
                if at >= header_end and (to == BASE+SLOT or lo < to < hi): relative.append(dict(fileoff=at,target=to))
            if at+8 <= g['fileoff']+g['filesize']:
                to = struct.unpack_from('<Q',before,at)[0]
                if to == BASE+SLOT or lo < to < hi: absolute.append(dict(fileoff=at,target=to))
    for r in nodes:
        if r['bind']: continue
        to = BASE+(r['word']&0xffffffff) if r['auth'] else (r['word']&((1<<43)-1))|(((r['word']>>43)&255)<<56)
        if to == BASE+SLOT or lo < to < hi: rebases.append(r)
    assert not relative and not absolute and not rebases
    aliases = []
    for cmd, at, _ in commands(before):
        if cmd == 2:
            off,count,strings,size = struct.unpack_from('<4I',before,at+8)
            for i in range(count):
                string,kind,section,desc,value = struct.unpack_from('<IBBHQ',before,off+i*16)
                if lo <= value < hi:
                    name = before[strings+string:strings+size].split(b'\0')[0].decode()
                    aliases.append(dict(name=name,address=value)); assert value == lo
        if cmd == 0x80000033:
            off,size = struct.unpack_from('<II',before,at+8)
            for r in export_trie(before[off:off+size]):
                assert not r['flags'] & 8, 'No dylib-ordinal reexport may be silently renumbered'
                if not r['flags'] & 8 and lo <= BASE+r['address'] < hi:
                    aliases.append(r); assert BASE+r['address'] == lo
    return dict(selectedOriginalImports=selected,originalNSTouchSlot=node,externalDirectEntryCalls=direct,
        externalInteriorEntryBranches=interior,accessorAddressMaterializations=accessor_addresses,
        originalClassSlotLoads=slot_loads,classSlotAddressMaterializations=slot_addresses,
        nonTextRelative32EdgesToClassSlotOrAccessorInterior=relative,absolute64Edges=absolute,
        chainRebaseEdges=rebases,nonTextScannedBytes=scanned,symbolEntryAliases=aliases,
        objcClassrefsSectionAbsent=True,allThreeAreOnlyOrdinal5Or23Imports=True)

def body():
    delta = ((BASE+SLOT)&~4095)-((BASE+ENTRY)&~4095); pages = delta//4096
    adr = 0x90000010 | ((pages&3)<<29) | (((pages>>2)&0x7ffff)<<5)
    load = 0xf9400210 | (((SLOT&4095)//8)<<10)
    return struct.pack('<3I',adr,load,0xd61f0200) + struct.pack('<I',0xd503201f)*14

def transform(before):
    evidence = proof(before); data = bytearray(before); data[ENTRY:ENTRY+EXTENT] = body()
    ords = 0; remove = None
    for cmd, at, size in commands(before):
        if cmd not in (0xc,0x80000018,0x8000001f): continue
        ords += 1
        if ords == 5:
            offset = struct.unpack_from('<I',before,at+8)[0]
            name = PATH.encode()+b'\0'; assert len(name) <= size-offset
            data[at+offset:at+size] = name + bytes(size-offset-len(name))
        if ords == 23: remove = (at,size)
    assert remove == (4920,104) and ords == 24
    # The two function consumers now bind to the unique own ordinal 5.
    # Remove the emptied SkyLight dependency. Keep every segment/section at
    # its original file offset; the shortened command region leaves padding.
    at,size = remove; header_end = 32+struct.unpack_from('<I',before,20)[0]
    data[at:header_end-size] = data[at+size:header_end]
    data[header_end-size:header_end] = bytes(size)
    struct.pack_into('<II',data,16,struct.unpack_from('<I',before,16)[0]-1,
        struct.unpack_from('<I',before,20)[0]-size)
    info = imports(before); version,starts,imp,names,count,fmt,compressed = info['header']
    assert names == imp+count*4 and version == compressed == 0 and fmt == 1
    blob = bytearray(before[info['data']:info['data']+info['size']])
    for index,name in NAMES.items():
        pool_offset = len(blob)-names; old = struct.unpack_from('<I',blob,imp+index*4)[0]
        assert pool_offset < (1<<23)
        struct.pack_into('<I',blob,imp+index*4,(old&256)|5|(pool_offset<<9)); blob += name.encode()+b'\0'
    for r in info['imports']:
        if r['ordinal'] > 23:
            word=struct.unpack_from('<I',blob,imp+r['index']*4)[0]
            struct.pack_into('<I',blob,imp+r['index']*4,(word&~255)|(r['ordinal']-1))
    for cmd,at,size in commands(data):
        if cmd == 2:
            symoff,count,_,_=struct.unpack_from('<4I',data,at+8)
            for i in range(count):
                desc=struct.unpack_from('<H',data,symoff+i*16+6)[0]
                # This exact parent has no two-level ordinal >23 in nlist.
                # Retained unused NSEvent/NSTouch declarations are not binds.
                assert desc >> 8 <= 23
    offset = (len(data)+7)&~7; data += bytes(offset-len(data)); data += blob
    for cmd,at,size in commands(data):
        if cmd == 0x80000034: struct.pack_into('<II',data,at+8,offset,len(blob))
        elif cmd == 0x19 and data[at+8:at+24].split(b'\0')[0] == b'__LINKEDIT':
            first = struct.unpack_from('<Q',data,at+40)[0]
            struct.pack_into('<Q',data,at+32,(len(data)-first+16383)&~16383)
            struct.pack_into('<Q',data,at+48,len(data)-first)
    return bytes(data),evidence

def validate(before,after):
    expected,evidence = transform(before); assert expected == after
    old,new = imports(before),imports(after); assert len(old['imports']) == len(new['imports'])
    for a,b in zip(old['imports'],new['imports']):
        ordinal=5 if a['index'] in NAMES else a['ordinal']-(1 if a['ordinal']>23 else 0)
        assert (ordinal,a['weak'],a['index']) == (b['ordinal'],b['weak'],b['index'])
        assert b['name'] == NAMES.get(a['index'],a['name'])
    oldnodes,newnodes = list(chain_entries(before)),list(chain_entries(after))
    assert len(oldnodes) == len(newnodes)
    for a,b in zip(oldnodes,newnodes):
        assert (a['fileoff'],a['word'],a['auth'],a['bind']) == (b['fileoff'],b['word'],b['auth'],b['bind'])
        assert b['symbol'] == NAMES.get(a['import_index'],a['symbol'])
    for g in segments(before):
        for s in g['sections']:
            at,z = s['fileoff'],s['size']
            if not at or not z or s['flags']&255 in (1,12,18): continue
            expected = bytearray(before[at:at+z])
            if at <= ENTRY and ENTRY+EXTENT <= at+z: expected[ENTRY-at:ENTRY-at+EXTENT] = body()
            assert after[at:at+z] == bytes(expected),(s['name'],at,z)
    assert not any(r['name'] in OLD.values() for r in new['imports'])
    return dict(proof=evidence,originalImportCount=len(old['imports']),newImportCount=len(new['imports']),
        chainNodes=len(newnodes),allActualChainWordsPACKeysDiscriminatorsAndIndicesUnchanged=True,
        originalNSTouchClassBindBecameOwnFunctionBind=True,metadataAccessorNeverReturnsClassOrMetadata=True,
        originalSwiftMetadataAndObjCMetadataSectionsPreserved=True,onlyOriginalAccessor68TextBytesChanged=True,
        removedEmptySkyLightLoadCommand=True,unchangedCGeImportExactlyRenumbered24To23=True,
        retainedUnusedOriginalNlistDeclarationsHaveNoLiveChainBind=True,
        remainingThreeMacSpecificStrongImports=0,allThreeOwnSourceFunctionsStrong=True)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--output',required=True,type=Path); args = ap.parse_args()
    out = args.output.resolve(); assert out.is_relative_to(NODE) and not out.exists(); out.mkdir()
    parent = NODE/'uhk-own-uikit-keyboard-property-source-port-data-v3'
    manifest = parent/'candidate.json'; m = json.loads(manifest.read_bytes()); image = Path(m['providerCandidate']['path'])
    assert pin(image) == m['providerCandidate']; before = image.read_bytes(); after,_ = transform(before)
    verification = validate(before,after); source = HOST/'vm27_mac_input_unavailable_v1.m'
    header = HOST/'vm27_mac_input_unavailable_v1.h'; fixture = HOST/'test-vm27-mac-input-unavailable-v1.m'; runs=[]
    def run(label,argv):
        argv=list(map(str,argv)); result=subprocess.run(argv,capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout); (out/(label+'.stderr')).write_bytes(result.stderr)
        runs.append(dict(label=label,argv=argv,exit=result.returncode)); save(out/'commands.json',runs)
        assert result.returncode == 0,(label,result.stderr.decode()); return result.stdout
    try:
        mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
        ios=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
        own=[]
        for mode in ('normal','sanitized'):
            exe=out/('unavailable-'+mode); flags=['xcrun','clang','-target','arm64e-apple-macos13','-isysroot',mac,'-fobjc-arc','-O2','-Wall','-Wextra','-Werror']
            if mode == 'sanitized': flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            run('compile-'+mode,flags+[source,fixture,'-framework','Foundation','-o',exe])
            result=json.loads(run('run-'+mode,[exe])); assert result['calls']==result['caught']==3 and result['failures']==0
            own.append(dict(mode=mode,result=result,executable=pin(exe)))
        dylib=out/'VM27MacInputUnavailableV1.ios.inert.dylib'
        flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',ios,'-fobjc-arc','-O2','-Wall','-Wextra','-Werror']
        run('link-ios',flags+[source,'-dynamiclib','-framework','Foundation','-Wl,-no_adhoc_codesign','-Wl,-install_name,'+PATH,'-o',dylib])
        run('validate-ios',['xcrun','dyld_info','-validate_only',dylib])
        symbols=run('nm-ios',['xcrun','nm','-gU',dylib]).decode()
        assert all(' '+name+'\n' in symbols for name in NAMES.values())
        assert '_OBJC_CLASS_$_NSTouch' not in symbols and '_SLEventGet' not in symbols
        # Real assembler independently encodes this PC-relative page distance.
        oracle=out/'metadata-tail.s'; oracle.write_text('.text\n.globl _VM27MetadataTailOracleV1\n_VM27MetadataTailOracleV1:\n adrp x16, #0xe000\n ldr x16, [x16, #0xa90]\n br x16\n')
        obj=out/'metadata-tail.ios.o'; run('assemble-tail',['xcrun','clang','-target','arm64e-apple-ios16.1','-c',oracle,'-o',obj])
        ob=obj.read_bytes(); st=next(s for g in segments(ob) for s in g['sections'] if s['name']=='__text')
        assert ob[st['fileoff']:st['fileoff']+st['size']] == body()[:12]
        candidate=out/'UniversalHIDKit27.own-uikit-mac-unavailable.mac.inert.macho-data'; candidate.write_bytes(after)
        run('validate-uhk',['xcrun','dyld_info','-validate_only',candidate])
        negative=[]
        for label,at in [('tail-branch',ENTRY+8),('own-function-chain',SLOT),('unrelated-original-text',0x8014),('remaining-auth-chain',67344)]:
            damaged=bytearray(after); damaged[at]^=1
            try: validate(before,bytes(damaged))
            except (AssertionError,ValueError): negative.append(dict(label=label,rejected=True))
            else: raise AssertionError(label)
        cp=out/'typed-caller.cc'; cp.write_text('#include "vm27_mac_input_unavailable_v1.h"\nextern "C" void VM27TypedCallerV1(unsigned x,const void*p,int32_t f) { if(x==0) VM27MacInputUnavailableV1(); if(x==1) (void)VM27MacDoubleUnavailableV1(p,f); (void)VM27MacIntegerUnavailableV1(p,f); }\n')
        cobj=out/'typed-caller.ios.o'; run('compile-cxx',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',ios,'-I',HOST,'-O2','-c',cp,'-o',cobj])
        joined=out/'typed-caller.ios.inert.dylib'; run('link-cxx',['xcrun','clang++','-target','arm64e-apple-ios16.1','-isysroot',ios,'-dynamiclib',cobj,dylib,'-Wl,-no_adhoc_codesign','-o',joined])
        run('validate-cxx',['xcrun','dyld_info','-validate_only',joined])
        abi=run('nm-cxx',['xcrun','nm','-u',joined]).decode(); assert all(name in abi for name in NAMES.values())
        audit=NODE/'uhk-mac-input-four-original-readonly-v6/audit.json'; handoff=NODE/'own-uikit-genuine-ingress-handoff-v1/handoff.json'
        save(out/'candidate.json',dict(schema='Own UIKit/headless explicit unavailable Mac input three-entry source port inert v1',
            parentCandidate=pin(manifest),parentImage=pin(image),providerCandidate=pin(candidate),ownSourceProvider=pin(dylib),
            source=pin(source),header=pin(header),fixture=pin(fixture),realOriginalCallerEvidence=pin(audit),actualUIKitIngressHandoff=pin(handoff),
            verification=verification,ownExecutableFixtures=own,negativeControls=negative,actualAssemblerTailOracle=pin(obj),
            actualIOSCXXTypedSymbolsJoined=True,exceptionName='VM27UnsupportedMacInputProfile',
            MacViewEntryResult='Throws an actual unavailable NSException; no event-field, Class or Swift metadata is returned',
            MacEventMemoryRead=False,fakeNSTouchClassDefined=False,completeMacViewBehavior=False,
            headlessUIKitProfileOnly=True,actualOriginalUHKLoaded=False,actualOriginalAccessorExecuted=False,
            actualUIKitDisplayConnected=False,completeLoadGraphValidated=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0,
            codeSigned=False,readyWritten=False,full27Backend=False))
        pins=[pin(Path(__file__)),pin(READER),pin(source),pin(header),pin(fixture),pin(audit),pin(handoff)]
        for row in json.loads((parent/'freeze.json').read_bytes())['files']:
            assert pin(row['path']) == row; pins.append(row)
        pins.append(pin(parent/'freeze.json')); pins += [pin(p) for p in out.iterdir() if p.is_file()]
        prior=NODE/'uhk-own-uikit-mac-unavailable-source-port-v1-attempt1'
        if prior.exists(): pins += [pin(p) for p in prior.rglob('*') if p.is_file()]
        save(out/'freeze.json',dict(files=list({p['path']:p for p in pins}.values()),deviceOperations=0,originalUHKExecuted=False))
        print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),provider=pin(candidate),sourceProvider=pin(dylib),remaining3=0)))
    except Exception as error:
        failed=out/'failed-sources'; failed.mkdir(exist_ok=True)
        for p in (Path(__file__),source,header,fixture): (failed/p.name).write_bytes(p.read_bytes())
        save(out/'failure.json',dict(error=repr(error),deviceOperations=0)); raise
if __name__ == '__main__': main()
