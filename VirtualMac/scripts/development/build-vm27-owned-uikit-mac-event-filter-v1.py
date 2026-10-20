#!/usr/bin/env python3
"""HOST-only named UIKit filter provider and one exact VZ classref port."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'
BASE=N/'independent27-owned-platform-launch-stage-v13-attempt1/candidate.json'
READER=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
KEY='VM27OwnedUIKitMacEventFilter.dylib'
CLASS='VM27OwnedUIKitMacEventFilterV1'

def need(value,why):
    if not value:raise ValueError(why)
def pin(p):
    p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def exact(r):
    need(pin(r['path'])==r,'changed pinned input');return Path(r['path']).read_bytes()
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def run(o,label,argv):
    r=subprocess.run([str(x) for x in argv],capture_output=True,timeout=60)
    (o/(label+'.stdout')).write_bytes(r.stdout);(o/(label+'.stderr')).write_bytes(r.stderr)
    result=dict(argv=[str(x) for x in argv],exit=r.returncode,stdout=pin(o/(label+'.stdout')),stderr=pin(o/(label+'.stderr')))
    need(r.returncode==0,'actual tool failed '+label+': '+r.stderr.decode(errors='replace')[-3000:]);return result
def load_reader():
    sp=importlib.util.spec_from_file_location('own_filter_reader_v1',READER);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def patch_vz(o,m,base):
    row=next(r for r in base['stagedImages'] if r['key']=='VZ27.dylib');raw=exact(row['staged']);z=m.MachO(raw)
    need(z.uuid=='418efc4809d93606918eb6f95baeffdc','exact original VZ UUID')
    slot=z.file(z.base+0x318d68);oldword=struct.unpack_from('<Q',raw,slot)[0]
    need(oldword==0x000800000034e258,'single actual original classref rebase word')
    cls=z.file(z.base+0x34e258);word=struct.unpack_from('<Q',raw,cls+32)[0]
    need(not ((word>>62)&1),'actual class ro rebase')
    ro=((word&0xffffffff) if word>>63 else (word&((1<<43)-1)))&~7
    word=struct.unpack_from('<Q',raw,z.file(z.base+ro)+24)[0]
    need(not ((word>>62)&1),'actual ro name rebase')
    name=(word&0xffffffff) if word>>63 else (word&((1<<43)-1))
    f=z.file(z.base+name);need(raw[f:raw.index(0,f)]==b'_VZHIDEventFilter','actual original class descriptor')
    fix=next(c for c in z.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',raw,fix['at']+8);old=raw[fo:fo+fs]
    version,starts,imports,symbols,count,form,sform=struct.unpack_from('<7I',old)
    need(version==0 and form==2 and sform==0 and imports+count*8==symbols and count<65536,'actual import table ABI')
    ordinal=len(z.loads)+1;symbol='_OBJC_CLASS_$_'+CLASS;newentry=struct.pack('<Ii',ordinal|((len(old)-symbols)<<9),0)
    payload=bytearray(old[:symbols]+newentry+old[symbols:]+symbol.encode()+b'\0')
    struct.pack_into('<I',payload,12,symbols+8);struct.pack_into('<I',payload,16,count+1)
    header_end=32+z.sizeofcmds;first=min(s['fileoff'] for s in z.sections if s['fileoff'] and s['size'])
    dep=('@loader_path/'+KEY).encode()+b'\0';cmdsize=(24+len(dep)+7)&~7
    need(header_end+cmdsize<=first and raw[header_end:header_end+cmdsize]==bytes(cmdsize),'true unused zero header capacity')
    cmd=struct.pack('<6I',12,cmdsize,24,2,0x10000,0x10000)+dep;cmd+=bytes(cmdsize-len(cmd))
    b=bytearray(raw);b[header_end:header_end+cmdsize]=cmd
    struct.pack_into('<II',b,16,z.ncmds+1,z.sizeofcmds+cmdsize)
    newword=(oldword&(((1<<11)-1)<<51))|(1<<62)|count
    struct.pack_into('<Q',b,slot,newword)
    while len(b)%8:b.append(0)
    newfo=len(b);b.extend(payload);struct.pack_into('<II',b,fix['at']+8,newfo,len(payload))
    link=next(c for c in z.commands if c['cmd']==25 and raw[c['at']+8:c['at']+24].rstrip(b'\0')==b'__LINKEDIT')
    linkoff=struct.unpack_from('<Q',b,link['at']+40)[0];newsize=len(b)-linkoff
    struct.pack_into('<Q',b,link['at']+48,newsize)
    oldvm=struct.unpack_from('<Q',raw,link['at']+32)[0]
    struct.pack_into('<Q',b,link['at']+32,max(oldvm,(newsize+16383)&~16383))
    after=m.MachO(bytes(b));norm=lambda rows:[{k:v for k,v in r.items() if k!='at'} for r in rows]
    need(after.uuid==z.uuid and after.exports==z.exports and norm(after.imports[:-1])==norm(z.imports),'old UUID/exports/import records preserved')
    need([r for r in after.binds if r['fileoff']!=slot]==z.binds and
         len([r for r in after.binds if r['fileoff']==slot])==1,'all other actual chained binds preserved')
    for section in z.sections:
        if not section['fileoff'] or not section['size']:continue
        start,end=section['fileoff'],section['fileoff']+section['size']
        prior=raw[start:end];actual=bytearray(b[start:end])
        if start<=slot<end:actual[slot-start:slot-start+8]=raw[slot:slot+8]
        need(bytes(actual)==prior,'all original backed section bytes except one classref unchanged')
    return b,z,after,row['staged'],dict(classrefRVA=0x318d68,classrefFileOffset=slot,oldRebase=oldword,newBindraw=newword,newRequiredOrdinal=ordinal,newActualImportIndex=count,newSymbol=symbol,newRequiredLoad='@loader_path/'+KEY,headerCapacity=first-header_end,newLoadCommandBytes=cmdsize,fixupPayloadBefore=dict(fileOffset=fo,bytes=fs,sha256=hashlib.sha256(old).hexdigest()),fixupPayloadAfter=dict(fileOffset=newfo,bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest()))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh own output');o.mkdir(mode=0o700)
    try:
        source=S/'vm27_owned_uikit_mac_event_filter_v1.m';header=S/'vm27_owned_uikit_mac_event_filter_v1.h';test=S/'test-vm27-owned-uikit-mac-event-filter-v1.m'
        sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
        common=['xcrun','clang','-O2','-fobjc-arc','-fblocks','-Wall','-Wextra','-Werror','-fvisibility=hidden','-I',str(S)]
        tools=[]
        for kind,extra in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
            binary=o/('test-'+kind)
            tools.append(run(o,'compile-'+kind,common+['-DVM27_MAC_EVENT_FILTER_FIXTURE_V1=1']+extra+[source,test,'-framework','Foundation','-framework','CoreGraphics','-o',binary]))
            tools.append(run(o,'run-'+kind,[binary]))
        dso=o/KEY
        tools.append(run(o,'compile-ios',common+['-target','arm64e-apple-ios16.1','-isysroot',sdk,'-dynamiclib','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-install_name','@rpath/'+KEY,source,'-framework','Foundation','-framework','CoreGraphics','-o',dso]))
        tools.append(run(o,'validate-ios',['xcrun','dyld_info','-validate_only',dso]))
        tools.append(run(o,'nm-ios',['xcrun','nm','-g',dso]))
        m=load_reader();provider=m.MachO(dso.read_bytes());need('_OBJC_CLASS_$_'+CLASS in provider.exports and '_OBJC_METACLASS_$_'+CLASS in provider.exports,'actual own named class definitions')
        base=json.loads(BASE.read_bytes());b,z,after,vzpin,recipe=patch_vz(o,m,base)
        (o/'VZ27.dylib').write_bytes(b)
        save(o/'patch-recipe.json',recipe)
        contract=dict(providerKey=KEY,ownClass=CLASS,classSymbol='_OBJC_CLASS_$_'+CLASS,VZUUID=z.uuid,sourcePin=pin(source),headerPin=pin(header),patchedVZ=pin(o/'VZ27.dylib'),originalVZ=vzpin,**recipe,isEnabled=False,hasEventTranslators=False,macMethodsReturnFakeReports=False,unexpectedMacCalls='typed NSException VM27OwnedUIKitMacEventFilterUnavailable',realOwnerPIDAndVZImageEpochRequired=True,originalMonitorAndVMConstructorPreserved=True,ordinaryUIKitKeyboardRVA=0x58aa8,ordinaryUIKitCoordinateRVA=0x6460c,unsupportedAlsoIncludes=['rawHIDmonitor','mediaKeyFallback','digitizerFilteredReports','processedScrollFiltering','MacNSEventTranslation','MacViewCoordinateTransforms'],parentBundleIdentifier='com.mac.virtual.independent27',ownerUID=501,childClassDefinitionLoadPermittedWithoutConstruction=True)
        c=dict(schema='Actual named owned UIKit Mac-event filter source provider and single classref source port v1',builder=pin(__file__),reader=pin(READER),baseStage=pin(BASE),providerKey=KEY,provider=pin(dso),source=pin(source),header=pin(header),tests=pin(test),patchedVZ=pin(o/'VZ27.dylib'),originalVZ=vzpin,ownMacEventFilterContract=contract,recipe=pin(o/'patch-recipe.json'),actualExports=provider.exports,actualNativeImports=provider.imports,tools=tools,codeSignatureStaleUntilFinalSigning=True,deviceOperations=0,trustCacheOperations=0,guestBoot=False,ordinaryKeyPointerExecuted=False,fakeNSEventClass=False,fakeSwiftMetadata=False,fullUIKitInputSupport=False)
        save(o/'candidate.json',c)
        pins=[pin(__file__),pin(READER),pin(BASE),vzpin,pin(source),pin(header),pin(test),pin(dso),pin(o/'VZ27.dylib'),pin(o/'patch-recipe.json'),pin(o/'candidate.json')]
        for t in tools:pins.extend([t['stdout'],t['stderr']])
        save(o/'freeze.json',dict(files=pins,deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
    except Exception as e:
        save(o/'failure.json',dict(error=str(e),deviceOperations=0));raise
if __name__=='__main__':main()
