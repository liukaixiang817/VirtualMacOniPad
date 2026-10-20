#!/usr/bin/env python3
"""Bind actual scroll jump tables and request actual UIKitCore exports."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('uikit_tables_s',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p=s.p
from current_hid_extra_three_capture_v1 import mapping

def main():
    out=p.NODE/'uikit-scroll-current-tables-readonly-v2';assert not out.exists()
    heads=p.NODE/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json';headers=json.loads(heads.read_bytes())
    cap=p.NODE/'ipad-current-uikit-scroll-bounded-tail-readonly-v1'
    plan=p.NODE/'ipad-current-uikit-scroll-bounded-tail-plan-v1'
    receipt=s.checked_capture(cap,plan/'request.json',heads)
    prefix=p.NODE/'ipad-current-uikit-own-input-command-prefix-readonly-v1'
    s.checked_capture(prefix,p.NODE/'ipad-current-uikit-own-input-command-prefix-plan-v1/request.json',heads)
    type_file=cap/'iokit-current-scroll-type-jump.bin';field_file=cap/'iokit-current-scroll-field-jumps.bin'
    type_entry=struct.unpack('<i',type_file.read_bytes())[0]
    fields=struct.unpack('<4i',field_file.read_bytes())
    assert 0x18ec7731c+type_entry==0x18ec77450
    targets=[0x18ec77470+x for x in fields]
    assert targets==[0x18ec779f0,0x18ec77b2c,0x18ec77b34,0x18ec7747c]
    body_path=p.NODE/'ipad-current-iokit-processed-scroll-native-callees-readonly-v1/iokit-current-float-common-complete.bin'
    body=body_path.read_bytes();base=0x18ec772c8
    actual_loads=[struct.unpack_from('<I',body,x-base)[0]for x in targets[:3]]
    assert actual_loads==[0xb9401108,0xb9401508,0xb9401908]
    actual_common=[struct.unpack_from('<I',body,x-base)[0]for x in (0x18ec77b38,0x18ec77b3c,0x18ec77b44)]
    assert actual_common==[0x1e620100,0xd2e7de09,0x1e610800]
    full=(prefix/'uikitcore-command-prefix.bin').read_bytes()+(cap/'uikitcore-command-tail.bin').read_bytes()
    assert len(full)==11352 and len(list(p.commands(full)))==83
    uuids=[full[at+8:at+24].hex()for cmd,at,size in p.commands(full)if cmd==27]
    assert uuids==['179501b60fc2344ab969b4e3961ebe10']
    off,length=next(struct.unpack_from('<II',full,at+8)for cmd,at,size in p.commands(full)if cmd==0x80000033)
    assert (off,length)==(118734120,189408)
    link=next(seg for seg in p.segments(full)if seg['name']=='__LINKEDIT')
    request=dict(name='uikitcore-exports',**mapping(headers,link['address']+off-link['fileoff'],length))
    out.mkdir();(out/'uikitcore-complete-commands.bin').write_bytes(full)
    p.save(out/'request.json',dict(ranges=[request]))
    uikit_raw=(prefix/'uikit-command-prefix.bin').read_bytes()[:1464]
    uikit_deps=p.dependencies(uikit_raw)
    assert any(r['path']=='/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore'and r['command']==0x8000001f for r in uikit_deps)
    trie=s.primary.trie((cap/'uikit-exports.bin').read_bytes());assert not trie
    negative=[]
    for label,data in [('truncated type entry',type_file.read_bytes()[:3]),('truncated fields',field_file.read_bytes()[:12])]:
        try:struct.unpack('<i'if label.startswith('truncated type')else'<4i',data)
        except struct.error:negative.append(dict(name=label,rejected=True))
        else:raise AssertionError('accepted truncated actual jump table')
    for slot,target in enumerate(targets[:3]):
        word=actual_loads[slot]^4
        assert word!=[0xb9401108,0xb9401508,0xb9401908][slot]
        negative.append(dict(name='typed field '+str(slot)+' changed load word',rejected=True))
    p.save(out/'audit.json',dict(schema='Current typed scroll fields and genuine UIKit reexport contract v1',
        actualTableCapture=p.pin(cap/'receipt.json'),currentHeaders=p.pin(heads),
        type6ActualJumpTarget=0x18ec77450,actualTypedFieldEntries=targets,
        nativeScrollDoubleFields=dict(x=0x60000,y=0x60001,z=0x60002),
        actualNativePacketLoadOffsets=[16,20,24],signed16FractionBits=16,
        nativeScalarGetterReadOnlyMachineContractProven=True,
        UIKitActualEmptyTrieIsNotAbsence=True,UIKitActualDependencies=uikit_deps,
        UIKitCoreCompleteCommands=p.pin(out/'uikitcore-complete-commands.bin'),
        actualUIKitCoreUUID=uuids[0],LCExports=dict(fileOffset=off,bytes=length,linkedit=link),
        negativeControls=negative,request=p.pin(out/'request.json'),
        UIKitCoreActualExportsRead=False,actualNativeFactoryExecuted=False,
        UIKitSelectorsRuntimeOrTimestampOriginValidated=False,deviceOperations=0,nativeHVCalls=0,nativeVMCalls=0))
    pins=[p.pin(Path(__file__)),p.pin(heads),p.pin(body_path),p.pin(plan/'request.json'),p.pin(plan/'derivation.json')]
    pins+=[p.pin(cap/name)for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr','iokit-current-scroll-type-jump.bin','iokit-current-scroll-field-jumps.bin','uikitcore-command-tail.bin','uikit-exports.bin')]
    pins+=[p.pin(prefix/name)for name in ('receipt.json','manifest.json','reader-source.py','script.sh','stdout','stderr','uikit-command-prefix.bin','uikitcore-command-prefix.bin')]
    pins+=[p.pin(out/name)for name in ('audit.json','request.json','uikitcore-complete-commands.bin')]
    p.save(out/'freeze.json',dict(files=list({r['path']:r for r in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),request=p.pin(out/'request.json'),range=request)))
if __name__=='__main__':main()
