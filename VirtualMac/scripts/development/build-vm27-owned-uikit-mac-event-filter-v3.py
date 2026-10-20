#!/usr/bin/env python3
"""Reuse frozen real V2 source/provider; make an unsigned, signable VZ layout.

Only obsolete signature bytes/command are removed. New fixups use their true
place before the future terminal signature. Two private temporary copies are
actually signed and parsed; no iOS image, device or trust cache is executed.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, shutil, struct, sys, tempfile
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P=N/'owned-uikit-mac-event-filter-source-port-v2-attempt1'
B=Path(__file__).with_name('build-vm27-owned-uikit-mac-event-filter-v2.py')
SIG=Path(__file__).with_name('build-independent27-signed-runtime-product-v8.py')
def module(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=module(B,'frozen_filter_build_v2');need,pin,exact,save,run=base.need,base.pin,base.exact,base.save,base.run
def norm(rows):return [{k:v for k,v in r.items() if k!='at'} for r in rows]
def unsigned_layout(v2,original,m):
    z=m.MachO(v2);old=m.MachO(original)
    cs=[c for c in z.commands if c['cmd']==29];need(len(cs)==1,'one real stale signature command')
    start,size=struct.unpack_from('<II',v2,cs[0]['at']+8)
    oldcs=next(c for c in old.commands if c['cmd']==29)
    need(struct.unpack_from('<II',original,oldcs['at']+8)==(start,size) and start+size==len(original),'exact original terminal signature')
    fix=next(c for c in z.commands if c['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',v2,fix['at']+8)
    need(fo>=start+size and fo+fs==len(v2) and start%8==0,'actual appended payload to relocate')
    payload=v2[fo:fo+fs]
    b=bytearray(v2[:start]+payload)
    commands=[]
    for c in z.commands:
        if c['cmd']==29:continue
        raw=bytearray(c['raw'])
        if c['cmd']==0x80000034:struct.pack_into('<II',raw,8,start,fs)
        if c['cmd']==25 and raw[8:24].rstrip(b'\0')==b'__LINKEDIT':
            linkoff=struct.unpack_from('<Q',raw,40)[0];extent=len(b)-linkoff
            struct.pack_into('<Q',raw,48,extent);struct.pack_into('<Q',raw,32,(extent+16383)&~16383)
        commands.append(raw)
    new_commands=b''.join(commands);need(len(new_commands)==z.sizeofcmds-16,'only obsolete signature command removed')
    b[32:32+z.sizeofcmds]=new_commands+bytes(16)
    struct.pack_into('<II',b,16,z.ncmds-1,z.sizeofcmds-16)
    after=m.MachO(bytes(b));need(not any(c['cmd']==29 for c in after.commands),'honest unsigned input, no fake signature')
    need(after.uuid==z.uuid and after.exports==z.exports and after.binds==z.binds and norm(after.imports)==norm(z.imports),'actual same UUID/export/bind/import contracts')
    for s in z.sections:
        if not s['fileoff'] or not s['size']:continue
        a,e=s['fileoff'],s['fileoff']+s['size'];need(bytes(b[a:e])==v2[a:e],'every V2 backed section unchanged')
    link=next(s for s in z.segments if s['name']=='__LINKEDIT')
    need(bytes(b[link['fileoff']:start])==v2[link['fileoff']:start],'all original non-signature LINKEDIT bytes retained')
    return bytes(b),dict(oldSignatureFileOffset=start,oldSignatureBytes=size,
        oldStaleSignatureRemoved=True,oldSignatureCommandRemoved=True,
        actualUnsignedSignatureCommandCount=0,actualFixupsFileOffset=start,actualFixupsBytes=fs,
        payloadSHA256=hashlib.sha256(payload).hexdigest(),
        oldNonSignatureLINKEDITWholeBytesUnchanged=True,allV2BackedSectionBytesUnchanged=True,
        allV2ImportSemanticsAndChainedWordsUnchanged=True,
        actualUnsignedFileBytes=len(b),headerCommandsCompactedExactly16Bytes=True)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh own output');o.mkdir(mode=0o700)
    try:
        p=json.loads((P/'candidate.json').read_bytes());f=json.loads((P/'freeze.json').read_bytes())
        for row in f['files']:exact(row)
        m=base.load_reader();original=exact(p['originalVZ']);v2=exact(p['patchedVZ']);data,layout=unsigned_layout(v2,original,m)
        (o/'VZ27.dylib').write_bytes(data);shutil.copyfile(exact_path:=Path(p['provider']['path']),o/p['providerKey'])
        need(pin(exact_path)==p['provider'],'frozen provider bytes');before=m.MachO(data)
        checker=module(SIG,'frozen_actual_signature_checker_v8');tools=[];signed=[]
        with tempfile.TemporaryDirectory(prefix='vm27-filter-v3-sign-',dir='/private/tmp') as td:
            for role in ('parent','child'):
                directory=Path(td)/role;directory.mkdir(mode=0o700);path=directory/'VZ27.dylib';path.write_bytes(data);path.chmod(0o700)
                tools.append(run(o,'sign-'+role,['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','org.lkx.VirtualMacIndependent27.'+role+'.VZ27.dylib',path]))
                tools.append(run(o,'verify-'+role,['codesign','--verify','--strict',path]))
                sb=path.read_bytes();after=m.MachO(sb);cs=next(c for c in after.commands if c['cmd']==29);so,ss=struct.unpack_from('<II',sb,cs['at']+8)
                need(so+ss==len(sb),'actual newly signed terminal signature')
                need(after.uuid==before.uuid and after.exports==before.exports and after.binds==before.binds and norm(after.imports)==norm(before.imports),'signed import/export/chained pointer bytes preserved')
                for s in before.sections:
                    if s['fileoff'] and s['size']:
                        start,end=s['fileoff'],s['fileoff']+s['size'];need(sb[start:end]==data[start:end],'signed actual code/data section bytes unchanged')
                sig=checker.signature(sb,before.uuid)
                dest=o/('signed-'+role);dest.mkdir(mode=0o700);target=dest/'VZ27.dylib';target.write_bytes(sb)
                signed.append(dict(role=role,binary=pin(target),signature=sig,signatureTerminal=True,actualImportsAndChainedWordsPreserved=True))
        recipe=json.loads(exact(p['recipe']));recipe['signaturePreparation']=layout
        save(o/'patch-recipe.json',recipe)
        contract=dict(p['ownMacEventFilterContract']);contract['patchedVZ']=pin(o/'VZ27.dylib');contract['fixupPayloadAfter']=dict(fileOffset=layout['actualFixupsFileOffset'],bytes=layout['actualFixupsBytes'],sha256=layout['payloadSHA256']);contract['signaturePreparation']=layout
        c=dict(p);c.update(schema='Actual named UIKit Mac-event filter source port v3 signable unsigned layout',builder=pin(__file__),priorSourceProviderCandidate=pin(P/'candidate.json'),priorSourceProviderFreeze=pin(P/'freeze.json'),provider=pin(o/p['providerKey']),patchedVZ=pin(o/'VZ27.dylib'),recipe=pin(o/'patch-recipe.json'),ownMacEventFilterContract=contract,actualUnsignedVZ=True,codeSignatureStaleUntilFinalSigning=False,finalRuntimeSigningRequired=True,signaturePreparation=layout,twoRoleActualLocalSigning=signed,actualSigningTools=tools,unchanged19HostModelsInherited=True,hostModelReruns=0,deviceOperations=0,trustCacheOperations=0)
        save(o/'candidate.json',c)
        pins=f['files']+[pin(__file__),pin(SIG),pin(P/'candidate.json'),pin(P/'freeze.json'),pin(o/p['providerKey']),pin(o/'VZ27.dylib'),pin(o/'patch-recipe.json'),pin(o/'candidate.json')]
        for t in tools:pins.extend([t['stdout'],t['stderr']])
        pins.extend([r['binary'] for r in signed]);unique={r['path']:r for r in pins}
        save(o/'freeze.json',dict(files=list(unique.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
    except Exception as e:save(o/'failure.json',dict(error=str(e),deviceOperations=0));raise
if __name__=='__main__':main()
