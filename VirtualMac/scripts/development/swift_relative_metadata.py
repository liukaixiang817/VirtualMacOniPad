#!/usr/bin/env python3
"""Audit/repair bounded Swift metadata relative pointers after cache relocation.

Schema: Swift ABI Metadata.h / MetadataValues.h at pinned commit
5ea0a2a5d8e126628da27747739e8d017c1d4882. No binary loading or device work.
Unresolved external targets are reported and block apply; no weak/nil fallback.
"""
import argparse,hashlib,json,pathlib,struct,sys

def verified_external_auth(target,labels,symbol,contract):
 """Validate a pinned, original-cache per-slot authentication oracle.

 ProtocolRequirement and MethodDescriptor are distinct concrete ABI types
 (ABI/Metadata.h at the commit above, aliases at 659 and 669). Their mangled
 Tq names alone do not identify the pointer-auth discriminator. The original
 cache and a compiler-produced CaseIterable/RawRepresentable IR oracle prove
 DA/address diversity/0x7d4c for this protocol-requirement scope, versus 0xae86
 for ContextDescriptor/ProtocolDescriptor. Class MethodDescriptor 0x675a is
 deliberately not accepted here. No unauthenticated external pointer fallback.
 """
 labels=set(labels)
 assert labels and labels<={'protocol','resilientRequirement','mangledSymbolicContextIndirect'}
 assert contract['originalSlotVA']==target and contract['symbol']==symbol and set(contract['labels'])==labels
 assert contract['chainMembershipVerified'] and contract['slideInfoVersion']==5
 assert contract['auth']==1 and contract['key']==2 and contract['addressDiversity']==1
 # Mixing these pointee kinds in one GOT entry is an ABI error, even when two
 # symbols happen to resolve to the same address in one source cache.
 requirement='resilientRequirement'in labels
 assert not requirement or labels=={'resilientRequirement'}
 discriminator=int(contract['diversity'],16)
 assert discriminator==(0x7d4c if requirement else 0xae86)
 return {'auth':True,'key':2,'addressDiversity':True,'discriminator':discriminator,
         'pointeeKind':'ProtocolRequirement'if requirement else 'ContextDescriptor',
         'evidence':'pinned original slide-info-v5 chain member; not mangled suffix inference'}

class RelativeMetadata:
 def __init__(self,raw,rebuilt):
  from compiler_image import segments
  self.raw=raw;self.rebuilt=rebuilt;self.old=segments(raw);self.new=segments(rebuilt);self.rows=[];self.schemas=[];self.unresolved=[]
 def section(self,address,original=True):
  for g in self.old if original else self.new:
   for s in g['sections']:
    if s['address']<=address<s['address']+s['size']:return g,s
  raise ValueError(f'address not in a declared section: {address:#x}')
 def mapped(self,address):
  g,s=self.section(address);targets=[(a,b)for a in self.new for b in a['sections']if a['name']==g['name']and b['name']==s['name']];assert len(targets)==1
  a,b=targets[0];delta=address-s['address'];assert delta<b['size'];return b['address']+delta
 def offset(self,address,original=True):
  g,s=self.section(address,original);assert s['fileoff'] and (s['flags']&0xff)not in(1,12),('relative field in zero-fill',hex(address))
  return s['fileoff']+address-s['address']
 def read(self,address,fmt):return struct.unpack_from(fmt,self.raw,self.offset(address))
 def relative(self,slot,label,indirect=False,nullable=False,external=None):
  word=self.read(slot,'<i')[0]
  if word==0 and nullable:return
  low=word&1 if indirect else 0;target=slot+(word-low);newSlot=self.mapped(slot);newOff=self.offset(newSlot,False)
  try:newTarget=self.mapped(target);policy='original source section plus intra-section offset'
  except ValueError:
   if external is None or target not in external:self.unresolved.append({'slot':slot,'label':label,'target':target,'indirect':bool(low)});return
   newTarget=external[target];policy='explicit independently proven external indirection slot'
  relative=newTarget-newSlot+low;assert -(1<<31)<=relative<(1<<31);assert not indirect or (relative&1)==low
  before=struct.unpack_from('<i',self.rebuilt,newOff)[0];assert before in(word,relative),('unexpected prior mutation',hex(slot),word,before,relative)
  self.rows.append({'slot':slot,'label':label,'originalTarget':target,'newSlot':newSlot,'newTarget':newTarget,'fileoff':newOff,'originalRelative32':word,'beforeRelative32':before,'newRelative32':relative,'indirect':bool(low),'policy':policy})
 def entries(self,name):
  sections=[s for g in self.old for s in g['sections']if s['name']==name]
  if not sections:return []
  assert len(sections)==1 and sections[0]['size']%4==0;s=sections[0];result=[]
  for i in range(s['size']//4):
   at=s['address']+i*4;word=self.read(at,'<i')[0];assert word&3==0,('non-direct record unsupported',name,hex(at));self.relative(at,name+' record');result.append(at+word)
  return result
 def singletons(self):
  for descriptor in self.entries('__swift5_types'):
   flags=self.read(descriptor,'<I')[0];kind=flags&31;specific=flags>>16
   namePointer=descriptor+8+self.read(descriptor+8,'<i')[0];nameoff=self.offset(namePointer);end=self.raw.index(0,nameoff,min(nameoff+128,len(self.raw)));name=self.raw[nameoff:end].decode()
   schema={'descriptor':descriptor,'name':name,'flags':flags,'kind':kind,'generic':bool(flags&0x80),'singleton':specific&3==1};self.schemas.append(schema)
   if not schema['singleton']:continue
   if schema['generic'] or kind not in(16,17,18) or kind==16 and specific&0x2000:self.unresolved.append({'descriptor':descriptor,'label':'unsupported generic/resilient superclass singleton schema'});continue
   tail=44 if kind==16 else 28;schema['singletonTailBytes']=tail
   for off,label in [(0,'initializationCache'),(4,'incompleteMetadata'),(8,'completionFunction')]:self.relative(descriptor+tail+off,label,nullable=off==8)
 def conformances(self,external=None):
  for descriptor in self.entries('__swift5_proto'):
   flags=self.read(descriptor+12,'<I')[0];kind=(flags>>3)&7
   schema={'descriptor':descriptor,'flags':flags,'typeReferenceKind':kind,'kind':'conformance'};self.schemas.append(schema)
   # Explicitly reject conditional/generic-pack/actor trailing layouts until
   # their official field schemas are implemented. Existing DIKit uses 0/30000.
   if flags&~0x30038 or kind not in(0,1,2,3):self.unresolved.append({'descriptor':descriptor,'label':'unsupported conformance trailing schema','flags':flags});continue
   self.relative(descriptor,'protocol',True,external=external);self.relative(descriptor+4,'typeReference',external=external);self.relative(descriptor+8,'witnessPattern',nullable=True,external=external);at=descriptor+16
   if flags&0x10000:
    count=self.read(at,'<I')[0];assert count<1024;schema['resilientWitnessCount']=count;at+=4
    for i in range(count):self.relative(at,'resilientRequirement',True,external=external);self.relative(at+4,'resilientWitnessImpl',nullable=True,external=external);at+=8
   if flags&0x20000:self.relative(at+4,'genericWitnessInstantiator',nullable=True,external=external);self.relative(at+8,'genericWitnessPrivateData',nullable=True,external=external)
 def reflection(self,external=None):
  # RemoteInspection/Records.h: 16-byte FieldDescriptor followed by
  # NumFields 12-byte FieldRecords. Parse the declared record size instead of
  # interpreting arbitrary __const words as relative pointers.
  for g in self.old:
   for s in g['sections']:
    if s['name']=='__swift5_fieldmd':
     at=s['address'];end=at+s['size']
     while at<end:
      assert at+16<=end;kind,recordSize,count=self.read(at+8,'<HHI');assert kind<=8 and recordSize==12 and count<1024 and at+16+count*recordSize<=end
      self.schemas.append({'descriptor':at,'kind':'fieldDescriptor','fieldKind':kind,'recordBytes':recordSize,'numFields':count})
      self.relative(at,'fieldMangledType',nullable=True,external=external);self.relative(at+4,'fieldSuperclass',nullable=True,external=external)
      for i in range(count):
       record=at+16+i*recordSize;flags=self.read(record,'<I')[0];assert flags&~7==0
       self.relative(record+4,'fieldRecordMangledType',nullable=True,external=external);self.relative(record+8,'fieldRecordName',nullable=True,external=external)
      at+=16+count*recordSize
    if s['name']=='__swift5_typeref':
     # Demangler.cpp: 01/02 context,09 accessor,0a/0b existential,
     # 0c ObjC protocol; payload is signed relative32 beginning after kind.
     # Indirection is encoded in kind, NOT in the low pointer bit.
     at=s['address'];end=at+s['size']
     while at<end:
      kind=self.read(at,'<B')[0]
      if 1<=kind<=12:
       if kind not in(1,2,9,10,11,12):
        # The pinned public demangler reserves 03..08. Some original Apple
        # manglings use 07. Do not invent its semantics: only preserve it when
        # its four-byte payload and mapped local relative distance are exact.
        assert at+5<=end;word=self.read(at+1,'<i')[0]
        try:stable=self.mapped(at+1+word)-self.mapped(at+1)==word and self.read(at+1,'<i')[0]==struct.unpack_from('<i',self.rebuilt,self.offset(self.mapped(at+1),False))[0]
        except ValueError:stable=False
        self.schemas.append({'slot':at,'kind':'opaqueReservedSymbolicReference','rawKind':kind,'unchangedLocalDistance':stable})
        if not stable:self.unresolved.append({'slot':at,'label':'reserved symbolic reference relocation unsupported','kind':kind})
        at+=5;continue
       assert at+5<=end;self.relative(at+1,'mangledSymbolicContextIndirect'if kind==2 else 'mangledSymbolicReference'+str(kind),external=external);at+=5
      else:at+=1
 def apply(self):
  if self.unresolved:raise ValueError('unresolved metadata edges forbid apply: '+str(len(self.unresolved)))
  b=bytearray(self.rebuilt)
  for row in self.rows:struct.pack_into('<i',b,row['fileoff'],row['newRelative32'])
  return bytes(b)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--raw',type=pathlib.Path,required=True);p.add_argument('--rebuilt',type=pathlib.Path,required=True);p.add_argument('--expected-raw-sha256',required=True);p.add_argument('--expected-rebuilt-sha256',required=True);p.add_argument('--compiler-reader',type=pathlib.Path,required=True);p.add_argument('--scopes',choices=['singletons','conformances','reflection','both','all'],default='singletons');p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--apply',action='store_true');args=p.parse_args();sys.path.insert(0,str(args.compiler_reader));raw=args.raw.read_bytes();rebuilt=args.rebuilt.read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest();assert sha(raw)==args.expected_raw_sha256;assert sha(rebuilt)==args.expected_rebuilt_sha256;args.output.mkdir(parents=True,exist_ok=False);a=RelativeMetadata(raw,rebuilt)
 if args.scopes in['singletons','both','all']:a.singletons()
 if args.scopes in['conformances','both','all']:a.conformances()
 if args.scopes in['reflection','all']:a.reflection()
 report={'rawSHA256':sha(raw),'rebuiltSHA256':sha(rebuilt),'scopes':args.scopes,'schemas':a.schemas,'relativePointers':a.rows,'unresolved':a.unresolved,'applyRequested':args.apply};(args.output/'audit.json').write_text(json.dumps(report,indent=2)+'\n')
 if args.apply:result=a.apply();(args.output/'image.relative-fixed').write_bytes(result)
 print(json.dumps({'schemas':len(a.schemas),'fields':len(a.rows),'unresolved':len(a.unresolved),'applied':args.apply and not a.unresolved}))
if __name__=='__main__':main()
