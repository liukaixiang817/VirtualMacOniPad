"""Resolve the sole added native pthread import against existing device captures."""
import pathlib,struct
INDEX_SHA='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
CACHE_UUID='1995ea169d0a33a0b78962cf99891168'
LIBSYSTEM='/usr/lib/libSystem.B.dylib'
PTHREAD='/usr/lib/system/libsystem_pthread.dylib'
SYMBOL='_pthread_cond_wait'
def verify(base,provider):
 import json
 need=base.need;pin=base.pin
 root=pathlib.Path(__file__).resolve().parents[3]
 index_path=root/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/current-native-header-export-index-v3/index.json'
 need(pin(index_path)['sha256']==INDEX_SHA,'exact existing captured native index')
 index=json.loads(base.regular_bytes(index_path));need(index['currentCacheUUID']==CACHE_UUID,'same captured current iPad cache')
 files=[pin(__file__),pin(index_path)]
 def exact(row):
  need(pin(row['path'])==row,'exact native command/export capture');files.append(row);return base.regular_bytes(row['path'])
 def image(path):
  row=index['images'][path];raw=exact(row['actualCompleteCommands']);export_raw=exact(row['actualCompleteExportSource']['rangePin'])
  need(len(raw)>=32 and struct.unpack_from('<I',raw)[0]==0xfeedfacf,'actual native Mach-O64 header')
  ncmds,size=struct.unpack_from('<II',raw,16);need(32+size<=len(raw),'complete actual native load commands')
  at=32;loads=[];uuid=None;extent=None
  for _ in range(ncmds):
   cmd,z=struct.unpack_from('<II',raw,at);need(z>=8 and at+z<=32+size,'bounded actual native command')
   if cmd==0x1b:need(z>=24,'actual UUID command');uuid=raw[at+8:at+24].hex()
   if cmd in (0xc,0x80000018,0x8000001f,0x80000023,0x20):
    off=struct.unpack_from('<I',raw,at+8)[0];need(8<=off<z,'actual native dependency path offset');end=raw.find(b'\0',at+off,at+z);need(end>=0,'actual native dependency path termination')
    loads.append(dict(ordinal=len(loads)+1,command=cmd,path=raw[at+off:end].decode()))
   found=None
   if cmd==0x80000033:need(z>=16,'actual exports trie command');found=list(struct.unpack_from('<II',raw,at+8))
   if cmd in (0x22,0x80000022):need(z>=48,'actual dyld info command');found=list(struct.unpack_from('<II',raw,at+40))
   if found and found[1]:need(extent is None or extent==found,'same actual native export extent');extent=found
   at+=z
  need(at==32+size and uuid==row['UUID'] and loads==row['dependencies'] and extent==row['exportExtent'] and len(export_raw)==extent[1],'actual native UUID/dependency/export extent joins captured index')
  definitions,_=base.m.trie(export_raw)
  return row,loads,definitions
 lib,loads,libdefs=image(LIBSYSTEM);pthread,_,definitions=image(PTHREAD)
 route=next(row for row in loads if row['ordinal']==28)
 need(route==dict(ordinal=28,command=0x8000001f,path=PTHREAD),'real libSystem LC_REEXPORT_DYLIB to pthread')
 actual=definitions[SYMBOL];need(actual==dict(flags=0,address=12680) and pthread['definitions'][SYMBOL]==dict(flags=0,offset=12680),'actual direct strong pthread_cond_wait export')
 need(SYMBOL not in libdefs,'resolution is actual umbrella reexport')
 importer_load=next(row for row in provider.loads if row['ordinal']==4)
 need(importer_load['path']==LIBSYSTEM and importer_load['cmd']==0xc,'actual added import selects strong native libSystem load4')
 return dict(resolved=True,symbol=SYMBOL,actualImport=dict(ordinal=4,weak=0,name=SYMBOL,addend=0),actualImporterLoad=importer_load,actualNativeCacheUUID=CACHE_UUID,nativeIndex=pin(index_path),route=[dict(image=LIBSYSTEM,uuid=lib['UUID'],actualReexport=route),dict(image=PTHREAD,uuid=pthread['UUID'],actualExport=actual)],actualCapturedCommandAndExportPins=list({row['path']:row for row in files}.values())),list({row['path']:row for row in files}.values())
