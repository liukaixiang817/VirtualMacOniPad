#!/usr/bin/env python3
"""Audit the complete actual current native Metal default-device entry bytes."""
import importlib.util,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('metal_actual_stock',HERE/'audit-modern-current-stock-extra-exports-v2.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);p=s.p
spec=importlib.util.spec_from_file_location('metal_words',p.NODE/'universalhid-array-reexport-abi-readonly-v1/audit.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
from current_hid_extra_three_capture_v1 import commands,mapping

def main():
    n=p.NODE;out=n/'metal-current-default-entry-readonly-v1';assert not out.exists()
    pd=n/'ipad-current-trace-exports-metal-default-body-plan-v2'
    for pin in json.loads((pd/'freeze.json').read_bytes())['files']:assert p.pin(Path(pin['path']))==pin
    derivation=json.loads((pd/'derivation.json').read_bytes());hp=Path(derivation['currentHeaders']['path'])
    assert p.pin(hp)==derivation['currentHeaders'];headers=json.loads(hp.read_bytes())
    cap=n/'ipad-current-trace-tail-metal-default-body-readonly-v1'
    receipt=s.checked_capture(cap,pd/'request.json',hp)
    captured=next(x for x in receipt['ranges']if x['name']=='metal-native-default-device-complete')
    path=Path(captured['path']);raw=path.read_bytes();bounds=derivation['nativeMetalDefaultBodyBounds']
    assert len(raw)==bounds['bytes']==248 and bounds['start']==6470882192 and bounds['end']==6470882440
    assert bounds['exactNamedEntry'] and bounds['LC26Index']==418
    assert {k:captured[k]for k in ('cache','offset','length')}==mapping(headers,bounds['start'],len(raw))
    native=derivation['nativeMetalDefaultDefinition'];assert native==dict(symbol='_MTLCreateSystemDefaultDevice',flags=0,offsetOrAbsoluteAddress=144272)
    assert derivation['actualNativeMetalUUID']=='8f062125748839efafda57db8cd80033'
    decoded=h.decode_body(raw,bounds['start']);assert len(decoded)==62
    words=struct.unpack('<62I',raw)
    assert words[0]==0xd503237f and words[55]==0xd65f0fff
    assert words[51]==0xaa1303e0 # x0 <- x19, pointer return before balanced epilogue
    known_pac={0xd503237f:'PACIBSP',0xdac10130:'PACIA x16,x9',0xdac10a30:'PACDA x16,x17',0xd65f0fff:'RETAB'}
    authenticated=[dict(address=bounds['start']+4*i,word=hex(w),instruction=known_pac[w])for i,w in enumerate(words)if w in known_pac]
    assert len(authenticated)==6
    direct=[]
    for i,w in enumerate(words):
        if w&0xfc000000==0x94000000:
            delta=(w&0x3ffffff)<<2
            if delta&0x8000000:delta-=0x10000000
            direct.append(dict(address=bounds['start']+4*i,target=bounds['start']+4*i+delta))
    assert direct==[dict(address=0x181b1d444,target=0x181c14c30),dict(address=0x181b1d458,target=0x186cbd270),dict(address=0x181b1d480,target=0x181c14b30)]
    import subprocess
    sdk=Path(subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip())
    header=sdk/'System/Library/Frameworks/Metal.framework/Headers/MTLDevice.h';text=header.read_text()
    assert 'MTLCreateSystemDefaultDevice(void) API_AVAILABLE(macos(10.11), ios(8.0)) NS_RETURNS_RETAINED' in text
    for selector in ('isLowPower','isRemovable'):
        lines=[line.strip()for line in text.splitlines()if 'getter='+selector+')'in line and'@property'in line]
        assert len(lines)==1 and 'API_UNAVAILABLE(ios)'in lines[0],(selector,lines)
    out.mkdir(mode=0o700)
    report=dict(schema='Actual current native Metal zero-argument entry bytes v1',
        actualReceipt=p.pin(cap/'receipt.json'),actualCurrentHeaders=p.pin(hp),actualCurrentNativeDefinition=native,
        actualNativeMetalUUID=derivation['actualNativeMetalUUID'],
        exactBodyBounds=bounds,actualCompleteBody=p.pin(path),instructions=decoded,
        exactPACInstructionWords=authenticated,directCallTargets=direct,
        actualCZeroArgumentDeclarationAndPlusOneContract=p.pin(header),returnPointerInX0Observed=True,
        internalBlockAndCalleeRetainImplementationComplete=False,directCalleePACBindingsProven=False,
        nativeConsumerSelectorsUnavailableInIOSSDK=True,actualIPadConsumerSelectorsCallable=False,
        ordinaryMacDeviceAndOwnedArrayEvidenceSeparate=True,originalVZCallerExecuted=False,
        nativeIPadDeviceFactoryExecuted=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False)
    p.save(out/'audit.json',report)
    paths=[Path(__file__),Path(h.__file__),header,hp,pd/'request.json',pd/'derivation.json',pd/'freeze.json',path,out/'audit.json']
    paths += [cap/name for name in ('receipt.json','manifest.json','script.sh','stdout','stderr','reader-source.py')]
    pins=[p.pin(x)for x in paths]+json.loads((pd/'freeze.json').read_bytes())['files']
    p.save(out/'freeze.json',dict(files=list({x['path']:x for x in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),actualBodyBytes=248,PACWords=6)))

if __name__=='__main__':main()
