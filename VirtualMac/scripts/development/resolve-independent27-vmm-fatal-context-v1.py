#!/usr/bin/env python3
"""HOST-only exact runtime UUID/symbol mapping for an owned VMM fatal record."""
import argparse,bisect,importlib.util,json,pathlib,re,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
sp=importlib.util.spec_from_file_location('actual_macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--runtime-candidate',required=True,type=pathlib.Path);ap.add_argument('--sample',required=True,type=pathlib.Path);ap.add_argument('--log',required=True,type=pathlib.Path);a=ap.parse_args();rt=json.loads(a.runtime_candidate.read_bytes());manifest=json.loads((a.runtime_candidate.parent/'manifest.json').read_bytes());root=pathlib.Path(rt['runtimeRoot']);files={r['uuid']:r for r in manifest['files']if r['kind']=='mach-o'}
 text=a.log.read_text(errors='replace');records=re.findall(r'^\[VM27OwnedVMMFatalContextV1\] signal=SIGSEGV.*$',text,re.M)
 if not records:raise SystemExit('No actual fatal record')
 fields={k:int(v,16)for k,v in re.findall(r'(\w+)=(0x[0-9a-f]+)',records[-1])};modules=[]
 for line in a.sample.read_text(errors='replace').splitlines():
  dyld=re.search(r'^VM27_DYLD_IMAGE load=(0x[0-9a-f]+) textSize=0x[0-9a-f]+ uuid=([0-9a-f]{32})$',line)
  match=dyld or re.search(r'^\s*(0x[0-9a-f]+)\s+-\s+(?:0x[0-9a-f]+|\?\?\?).*?<([A-Fa-f0-9-]{36})>',line)
  if not match:continue
  address=int(match[1],16);uuid=match[2].replace('-','').lower()
  if uuid not in files:continue
  row=files[uuid];path=root/row['path'];im=m.MachO(path.read_bytes());assert im.uuid==uuid;modules.append((address,row,path,im))
 # The handler itself supplies the actual main-image base even if absent in a sample.
 childid=manifest['childEntryContract']['childID'];row=next(r for r in manifest['files']if r['id']==childid)
 if not any(r['id']==childid for _,r,_,_ in modules):
  path=root/row['path'];modules.append((fields['base'],row,path,m.MachO(path.read_bytes())))
 print(records[-1]);print('Mapping uses only actual runtime UUIDs and same-run image table or sample; masked values are data analysis only.')
 for key in ('pc','lr'):
  raw=fields.get(key,0);pointer=raw&0x0000ffffffffffff;found=False
  for base,row,path,im in modules:
   va=im.base+pointer-base;section=next((s for s in im.sections if s['va']<=va<s['va']+s['size']and s['fileoff']and s['flags']&255 not in(1,12,18)),None)
   if section is None:continue
   found=True;symbols=[]
   for c in im.commands:
    if c['cmd']!=2:continue
    so,n,st,ss=struct.unpack_from('<4I',c['raw'],8)
    for i in range(n):
     ni,typ,sec,desc,value=struct.unpack_from('<IBBHQ',im.data,so+i*16)
     if ni>=ss or typ&0xe0 or typ&0xe!=0xe or value>va or not section['va']<=value<section['va']+section['size']:continue
     end=im.data.find(b'\0',st+ni,st+ss);name=im.data[st+ni:end].decode(errors='replace');symbols.append((value,name))
   nearest=max(symbols,default=(section['va'],'<stripped>'));print(json.dumps(dict(register=key,raw=hex(raw),maskedForDataAnalysis=hex(pointer),image=str(path),uuid=im.uuid,loadBase=hex(base),rva=hex(va-im.base),section=section['name'],symbol=nearest[1],offset=hex(va-nearest[0]))))
   low=max(section['va'],va-64);high=min(section['va']+section['size'],va+68);run=subprocess.run(['xcrun','llvm-objdump','--disassemble','--start-address='+str(low),'--stop-address='+str(high),str(path)],capture_output=True);print('DISASSEMBLY starts RVA '+hex(low-im.base));print(run.stdout.decode());print(run.stderr.decode()if run.returncode else '',end='')
  if not found:print(key+' unresolved in sampled owned images; raw='+hex(raw))
if __name__=='__main__':main()
