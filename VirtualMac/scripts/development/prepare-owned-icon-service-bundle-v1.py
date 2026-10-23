"""Make a non-executable, ad-hoc diagnostic bundle from the captured same-guest agent.

Only its Objective-C implementation will be loaded by an owned probe. Original
main/sandbox/cache setup is never called. Apple system files are not modified.
"""
from pathlib import Path
import subprocess,struct,hashlib,json
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';O=N/'owned-icon-service-bundle-v1';O.mkdir(mode=0o700)
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
original=N/'normal177-actual-iconservicesagent';thin=O/'agent.arm64e'
subprocess.run(['xcrun','lipo','-thin','arm64e',str(original),'-output',str(thin)],check=True)
b=thin.read_bytes();magic,cpu,subtype,kind,count,size,flags,reserved=struct.unpack_from('<8I',b)
assert magic==0xfeedfacf and cpu==0x100000c and subtype&0xffffff==2 and kind==2
at=32;commands=[];removed=[];sections=[];uuid=None
for _ in range(count):
 cmd,z=struct.unpack_from('<II',b,at);data=b[at:at+z];assert z>=8 and at+z<=32+size
 if cmd==0x1b:uuid=data[8:24].hex()
 if cmd==0x19:
  n=struct.unpack_from('<I',data,64)[0]
  for i in range(n):
   off=72+80*i;name=data[off:off+16].rstrip(b'\0').decode();addr,length,fileoff=struct.unpack_from('<QQI',data,off+32)
   if fileoff and length:sections.append((name,fileoff,length))
 if cmd in [0xe,0x80000028,0x1d]:removed.append(cmd)
 else:commands.append(data)
 at+=z
assert at==32+size and 0x80000028 in removed and 0xe in removed
# Drop only executable startup and stale signature commands. Every section byte
# remains in place; image fixups/Objective-C code and native dependencies stay.
header=b''.join(commands);out=bytearray(b);out[32:32+size]=header+b'\0'*(size-len(header))
struct.pack_into('<I',out,12,8) # MH_BUNDLE
struct.pack_into('<III',out,16,len(commands),len(header),flags&~0x200000) # no MH_PIE
for name,offset,length in sections:assert out[offset:offset+length]==b[offset:offset+length],name
bundle=O/'VM27OwnedIconService.bundle';bundle.write_bytes(out)
subprocess.run(['codesign','--force','--sign','-','--timestamp=none','--identifier','org.lkx.vm27.owned-icon-service',str(bundle)],check=True,capture_output=True)
subprocess.run(['codesign','--verify','--strict',str(bundle)],check=True,capture_output=True)
subprocess.run(['xcrun','dyld_info','-validate_only',str(bundle)],check=True,capture_output=True)
record=dict(schema='Owned diagnostic bundle of same-guest Objective-C icon agent; no original main execution',original=pin(original),thin=pin(thin),bundle=pin(bundle),originalUUID=uuid,removedCommands=removed,originalSectionsUnchangedBeforeSigning=True,mainNeverExecuted=True,AppleSystemFilesModified=False,deviceOperations=0)
(O/'scope.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
