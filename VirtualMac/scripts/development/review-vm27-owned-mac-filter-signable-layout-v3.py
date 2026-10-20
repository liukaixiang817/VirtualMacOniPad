#!/usr/bin/env python3
"""Independent finite exact-layout and actual two-role signed payload review."""
import argparse,hashlib,importlib.util,json,pathlib,struct,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(r):
 need(pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},'actual pin '+r['path']);return pathlib.Path(r['path'])
def load(p):
 sp=importlib.util.spec_from_file_location('signable_filter_independent',p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def sem(rows):return [{k:v for k,v in r.items()if k!='at'}for r in rows]
def signature(blob,parser):
 cs=[c for c in parser.commands if c['cmd']==29];need(len(cs)==1,'one true signed CS command');fo,fs=struct.unpack_from('<II',blob,cs[0]['at']+8);need(fo+fs==len(blob),'true newly terminal signature');b=blob[fo:fo+fs];magic,length,count=struct.unpack_from('>III',b);need(magic==0xfade0cc0 and length<=fs and b[length:]==bytes(fs-length) and 0<count<16,'bounded actual superblob');slots={}
 for i in range(count):
  key,at=struct.unpack_from('>II',b,12+i*8);ml,l=struct.unpack_from('>II',b,at);need(at>=12+8*count and l>=8 and at+l<=length and key not in slots,'bounded actual embedded slots');slots[key]=b[at:at+l]
 cd=slots[0];magic,length,version,flags,ho,ident,ns,nc,limit=struct.unpack_from('>9I',cd);size,ht,platform,shift=struct.unpack_from('>4B',cd,36);need(magic==0xfade0c02 and length==len(cd)and ht==2 and size==32 and shift==14 and limit==fo and nc==(limit+16383)//16384 and ho>=ns*32 and ho+nc*32<=len(cd),'actual primary CodeDirectory geometry')
 for i in range(nc):need(hashlib.sha256(blob[i*16384:min(limit,(i+1)*16384)]).digest()==cd[ho+i*32:ho+(i+1)*32],'actual primary code page '+str(i))
 for i in range(1,ns+1):
  h=cd[ho-i*32:ho-(i-1)*32];need(h==(hashlib.sha256(slots[i]).digest()if i in slots else bytes(32)),'actual embedded or absent special slot '+str(i))
 need(5 not in slots and 7 not in slots,'dylib actual no entitlements');return dict(codeLimit=limit,pages=nc,specialSlots=ns,CDHash=hashlib.sha256(cd).hexdigest()[:40],signatureTerminal=True,allPrimaryPagesAndEmbeddedSpecialSlotsVerified=True)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh peer');c=json.loads(a.candidate.read_bytes());f=a.candidate.parent/'freeze.json'
 for r in json.loads(f.read_bytes())['files']:actual(r)
 prior=N/'owned-uikit-mac-event-filter-source-port-v2-attempt1/candidate.json';p=json.loads(prior.read_bytes());m=load(actual(c['reader']));v2=actual(p['patchedVZ']).read_bytes();b=actual(c['patchedVZ']).read_bytes();z=m.MachO(v2);after=m.MachO(b);need(c['source']==p['source']and c['header']==p['header']and c['tests']==p['tests']and c['provider']['sha256']==p['provider']['sha256'],'V2 owner/source/header/tests/provider retained exact, no model rerun')
 oldcs=next(x for x in z.commands if x['cmd']==29);start,size=struct.unpack_from('<II',v2,oldcs['at']+8);fix=next(x for x in z.commands if x['cmd']==0x80000034);fo,fs=struct.unpack_from('<II',v2,fix['at']+8);need((start,size,fo,fs)==(4203600,8480,4212080,41719),'actual known obsolete signature and relocated payload');expected=bytearray(v2[:start]+v2[fo:fo+fs]);cmds=[]
 for lc in z.commands:
  if lc['cmd']==29:continue
  q=bytearray(lc['raw'])
  if lc['cmd']==0x80000034:struct.pack_into('<II',q,8,start,fs)
  if lc['cmd']==25 and q[8:24].rstrip(b'\0')==b'__LINKEDIT':
   link=struct.unpack_from('<Q',q,40)[0];extent=len(expected)-link;struct.pack_into('<Q',q,48,extent);struct.pack_into('<Q',q,32,(extent+16383)&~16383)
  cmds.append(q)
 expected[32:32+z.sizeofcmds]=b''.join(cmds)+bytes(16);struct.pack_into('<II',expected,16,z.ncmds-1,z.sizeofcmds-16);need(bytes(expected)==b,'whole unsigned V3 independently reconstructed from V2 without producer code')
 need(not any(x['cmd']==29 for x in after.commands)and after.uuid==z.uuid and after.exports==z.exports and sem(after.loads)==sem(z.loads) and after.binds==z.binds and sem(after.imports)==sem(z.imports),'unsigned signature honestly absent; code contracts unchanged')
 for s in z.sections:
  if s['fileoff']and s['size']:need(b[s['fileoff']:s['fileoff']+s['size']]==v2[s['fileoff']:s['fileoff']+s['size']],'V2 backed section bytes exact')
 recipe=json.loads(actual(c['recipe']).read_bytes());need(recipe['fixupPayloadAfter']['fileOffset']==start and recipe['fixupPayloadAfter']['bytes']==fs and recipe['fixupPayloadAfter']['sha256']==hashlib.sha256(b[start:]).hexdigest(),'final recipe actual new offset, no stale append offset')
 signatures=[]
 for row in c['twoRoleActualLocalSigning']:
  sb=actual(row['binary']).read_bytes();s=m.MachO(sb);sig=signature(sb,s);need(sig['CDHash']==row['signature']['cdhash']and s.uuid==after.uuid and s.exports==after.exports and s.binds==after.binds and sem(s.imports)==sem(after.imports),'true signed role identity/primary/allslots/import contracts')
  for sec in after.sections:
   if sec['fileoff']and sec['size']:need(sb[sec['fileoff']:sec['fileoff']+sec['size']]==b[sec['fileoff']:sec['fileoff']+sec['size']],'signed role backed sections exactly same')
  signatures.append(dict(role=row['role'],binary=row['binary'],actualSignature=sig))
 need({x['role']for x in signatures}=={'parent','child'}and all(x['exit']==0 for x in c['actualSigningTools']),'two actual codesign/strictverify tool executions passed')
 o.mkdir(mode=0o700);report=dict(schema='Named Mac filter V3 actual signable-layout finite independent peer',candidate=pin(a.candidate),candidateFreeze=pin(f),sourceProviderInheritedV2=True,priorStaticPeer=pin(N/'owned-uikit-mac-event-filter-stage14-independent-peer-v2-attempt1/review.json'),obsoleteSignatureOnlyRemoved=True,oldSignatureBytes=size,exactHeaderCommandCompactionBytes=16,actualFixupsFileOffset=start,wholeUnsignedOutputIndependentlyReconstructed=True,allV2BackedSectionsChainedWordsImportsUUIDExportsPreserved=True,actualTwoRoleSigning=signatures,oldV2SigningInternalErrorResolvedByActualV3TwoRoleSigning=True,modelReruns=0,readyForNewStageAndFinalRuntimeSigning=True,finalRuntimeSignedProductsNotYetReviewed=True,originalVZExecuted=False,guestInputExecuted=False,actualGuestBoot=False,deviceOperations=0,trustCacheOperations=0,findings=[],finiteLocalScopePassed=True)
 (o/'review.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),pin(a.candidate),pin(f),pin(prior),c['reader'],c['source'],c['header'],c['provider'],c['patchedVZ'],p['patchedVZ'],c['recipe'],report['priorStaticPeer']]+[r['binary']for r in c['twoRoleActualLocalSigning']]+[pin(o/'review.json')];(o/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),findings=[])))
if __name__=='__main__':main()
