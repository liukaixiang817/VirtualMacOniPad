"""Read exactly two current native cache headers; execute no provider code."""
from pathlib import Path
import argparse,base64,datetime,hashlib,importlib.util,json,re,struct,subprocess,sys
from DyldExtractor.dyld.dyld_structs import dyld_cache_header,dyld_cache_mapping_info,dyld_subcache_entry2
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE='/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e'
def need(v,why):
 if not v:raise ValueError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):
 p=Path(p);need(p.is_absolute() and p.is_file() and not p.is_symlink(),'absolute regular input');b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=sha(b))
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();out=a.output.resolve();need(out.is_relative_to(N) and not out.exists(),'new diagnostic output required')
 oldp=N/'ipad-current-cache-pod-leaf-headers-v3/headers.json';old=json.loads(oldp.read_bytes());prefix=(N.parent/'2026-10-02-macos27-backend/ipad-cache-headers.bin').read_bytes()[:4096];tail=N/'ipad-current-cache-hid-extra-commands-readonly-v1/main-image-table-tail.bin';recp=tail.parent/'receipt.json';receipt=json.loads(recp.read_bytes());need(receipt['transportExit']==0 and receipt['allHeaderPinsMatchBeforeAndAfter'] and receipt['headersSHA256']==pin(oldp)['sha256'],'bound actual current main tail')
 need(any(x['path']==str(tail) and x['sha256']==pin(tail)['sha256'] for x in receipt['ranges']),'current main tail pin');mainrow=next(x for x in old['headers'] if x['name']=='main');need(sha(prefix)==mainrow['sha256'],'archive prefix exact current guarded bytes');b=prefix+tail.read_bytes();h=dyld_cache_header.from_buffer_copy(b);need(bytes(h.uuid).hex()==old['mainUUID']=='1995ea169d0a33a0b78962cf99891168','actual main UUID');need(h.mappingOffset>dyld_cache_header.cacheSubType.offset,'actual suffix-bearing subcache schema')
 selected={}
 for i in range(h.subCacheArrayCount):
  at=h.subCacheArrayOffset+i*dyld_subcache_entry2.SIZE;need(at+dyld_subcache_entry2.SIZE<=len(b),'actual subcache bounds');x=dyld_subcache_entry2.from_buffer_copy(b[at:at+dyld_subcache_entry2.SIZE]);suffix=bytes(x.fileExtension).split(b'\0')[0].decode()
  if suffix in ('.13','.17'):selected[suffix[1:]]=dict(UUID=bytes(x.uuid).hex(),suffix=suffix,index=i,entryOffset=at,cacheVMOffset=x.cacheVMOffset)
 need(set(selected)=={'13','17'},'two actual native suffix entries')
 remote_path=R/'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py';need(pin(remote_path)['sha256']=='29a8d0241704440152fb734cf78cf0b0536c30524ab121da483941777b215424','fixed root transport')
 script="set -eu\nexport PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin\n[ \"$(id -u)\" = 0 ]\n[ \"$(sysctl -n hw.machine)\" = iPad14,6 ]\n[ \"$(sysctl -n kern.osversion)\" = 20B101 ]\n"
 guard=f"[ -f '{BASE}' ]\n[ ! -L '{BASE}' ]\n[ \"$(dd if='{BASE}' bs=4096 count=1 status=none | sha256sum | cut -d ' ' -f1)\" = '{mainrow['sha256']}' ]\n"
 script+=guard
 for name in sorted(selected):
  path=BASE+selected[name]['suffix'];script+=f"[ -f '{path}' ]\n[ ! -L '{path}' ]\n[ \"$(stat -c '%s' '{path}')\" -ge 4096 ]\nprintf 'BEGIN_BASE64 {name}\\n'\ndd if='{path}' bs=4096 count=1 status=none | base64\nprintf '\\nEND_BASE64 {name}\\n'\n"
 script+=guard+"printf 'FINAL_MAIN_HEADER_MATCH\\n'\n";subprocess.run(['/bin/sh','-n'],input=script.encode(),capture_output=True,check=True);out.mkdir(mode=0o700,exist_ok=False);(out/'script.sh').write_text(script);(out/'source.py').write_bytes(Path(__file__).read_bytes());(out/'plan.json').write_text(json.dumps(dict(selected=selected,currentHeaders=pin(oldp),currentMainReceipt=pin(recp),mainTail=pin(tail),deviceWrites=0,nativeCPUCalls=0,newFrameworksLoaded=0),indent=2)+'\n')
 spec=importlib.util.spec_from_file_location('readonly_swift_headers_remote',remote_path);remote=importlib.util.module_from_spec(spec);spec.loader.exec_module(remote);started=datetime.datetime.now(datetime.timezone.utc).isoformat();result=remote.run(script,device='ipad',root=True,timeout=45);(out/'stdout').write_bytes(result.stdout);(out/'stderr').write_bytes(result.stderr)
 proof=dict(schema='Two actual native Swift cache headers bounded read receipt v1',startedUTC=started,recordedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),transportExit=result.returncode,requestedBytes=8192,deviceWrites=0,nativeCPUCalls=0,newFrameworksLoaded=0,stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),source=pin(out/'source.py'),plan=pin(out/'plan.json'),script=pin(out/'script.sh'))
 (out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n');need(result.returncode==0 and result.stdout.endswith(b'FINAL_MAIN_HEADER_MATCH\n'),'actual read completed')
 parts=re.findall(rb'BEGIN_BASE64 (13|17)\n(.*?)\nEND_BASE64 \1\n',result.stdout,re.S);need(len(parts)==2,'two exact header frames');newrows=[]
 for key,encoded in parts:
  name=key.decode();raw=base64.b64decode(encoded,validate=False);need(len(raw)==4096,'one header page');ch=dyld_cache_header.from_buffer_copy(raw);need(bytes(ch.uuid).hex()==selected[name]['UUID'],'actual suffix header UUID');need(0<ch.mappingCount<=8 and ch.mappingOffset+ch.mappingCount*dyld_cache_mapping_info.SIZE<=4096,'actual mapping bounds');maps=[]
  for i in range(ch.mappingCount):
   at=ch.mappingOffset+i*dyld_cache_mapping_info.SIZE;mh=dyld_cache_mapping_info.from_buffer_copy(raw[at:at+dyld_cache_mapping_info.SIZE]);maps.append(dict(address=mh.address,size=mh.size,fileOffset=mh.fileOffset,maxProt=mh.maxProt,initProt=mh.initProt))
  need(maps[0]['address']-6442450944==selected[name]['cacheVMOffset'],'actual main subcache VM offset');(out/(name+'-header.bin')).write_bytes(raw);newrows.append(dict(name=name,sha256=sha(raw),UUID=selected[name]['UUID'],maps=maps))
 merged=dict(old);merged['headers']=old['headers']+newrows;merged['native13And17ActualReceiptPath']=str(out/'receipt.json');merged['mainSuffixTableDerivedFromActualCurrentTail']=True;need(len(merged['headers'])==12 and len({x['name'] for x in merged['headers']})==12,'exact twelve header set');(out/'headers.json').write_text(json.dumps(merged,indent=2)+'\n');proof['headers']=pin(out/'headers.json');proof['mainHeaderMatchesBeforeAndAfter']=True;proof['actualSuffixUUIDAndVMOffsetVerified']=True;(out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(dict(receipt=pin(out/'receipt.json'),headers=pin(out/'headers.json'),newNativeHeaders=newrows),indent=2))
if __name__=='__main__':main()
