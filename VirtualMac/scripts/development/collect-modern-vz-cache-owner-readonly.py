#!/usr/bin/env python3
"""Generate/build/run a bounded stock-Mac-only VZ cache owner collector.

dlopen performs stock framework initialization only; no original function or
VM/GPU API is called. Original VMM and all relocated candidates remain unloaded.
Only original slots, instructions and exact exported target addresses are read.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def write(path, value):
    path.write_text(json.dumps(value,indent=2)+'\n')


def pin(path):
    b=path.read_bytes();return dict(path=str(path),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


SOURCE = r'''
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "requirements.h"

static void quote(const char *s) {
  putchar('"');
  if (s) {
    for(;*s;s++) { unsigned char c=*s;
      if(c=='"'||c=='\\') {putchar('\\');putchar(c);}
      else if(c>=32&&c<127) putchar(c); else printf("\\u%04x",c);
    }
  }
  putchar('"');
}
static int identity(const char *path, const char *uuid, uint64_t base, intptr_t *slide) {
  for(uint32_t i=0;i<_dyld_image_count();i++) {
    const char *p=_dyld_get_image_name(i); if(!p||strcmp(p,path))continue;
    const struct mach_header_64 *h=(const void *)_dyld_get_image_header(i);
    if(h->magic!=MH_MAGIC_64 || h->sizeofcmds>0x100000 || h->ncmds>4096)return 0;
    const uint8_t *at=(const void *)(h+1),*end=at+h->sizeofcmds; int uuidOK=0,textOK=0;
    for(uint32_t k=0;k<h->ncmds;k++) {
      if(at+8>end)return 0; const struct load_command *lc=(const void *)at;
      if(lc->cmdsize<8||at+lc->cmdsize>end)return 0;
      if(lc->cmd==LC_UUID) {
        if(lc->cmdsize!=sizeof(struct uuid_command))return 0;
        const struct uuid_command *u=(const void *)at; char hex[33];
        for(int j=0;j<16;j++)snprintf(hex+j*2,3,"%02x",u->uuid[j]);uuidOK=!strcmp(hex,uuid);
      }
      if(lc->cmd==LC_SEGMENT_64) {
        if(lc->cmdsize<sizeof(struct segment_command_64))return 0;
        const struct segment_command_64 *s=(const void *)at;
        if(!strcmp(s->segname,"__TEXT"))textOK=s->vmaddr==base;
      }
      at+=lc->cmdsize;
    }
    if(at!=end||!uuidOK||!textOK)return 0;
    *slide=_dyld_get_image_vmaddr_slide(i);
    return (uintptr_t)h==base+(uintptr_t)*slide;
  }
  return 0;
}
static uintptr_t strip(uintptr_t raw,int auth,int key) {
  if(!auth)return raw & UINT64_C(0x00ffffffffffffff);
  switch(key) {
    case 0:return (uintptr_t)ptrauth_strip((void*)raw,ptrauth_key_asia);
    case 1:return (uintptr_t)ptrauth_strip((void*)raw,ptrauth_key_asib);
    case 2:return (uintptr_t)ptrauth_strip((void*)raw,ptrauth_key_asda);
    case 3:return (uintptr_t)ptrauth_strip((void*)raw,ptrauth_key_asdb);
  } return 0;
}
int main(void) {
  alarm(15); setbuf(stdout,NULL);
  void *vz=dlopen(VZ_PATH,RTLD_NOW|RTLD_LOCAL); if(!vz) {
    printf("{\"type\":\"loadError\",\"pid\":%d,\"message\":",getpid());quote(dlerror());puts("}");return 78;
  }
  intptr_t slide=0;
  if(!identity(VZ_PATH,VZ_UUID,VZ_BASE,&slide)) {puts("{\"type\":\"identityMismatch\"}");return 79;}
  printf("{\"type\":\"identity\",\"pid\":%d,\"uuid\":\"%s\",\"slide\":%lld,\"loadedStockVZ\":true,\"VZAPICalls\":0,\"originalVMMExecuted\":false}\n",getpid(),VZ_UUID,(long long)slide);
  unsigned verified=0,exact=0,exported=0;
  for(size_t i=0;i<sizeof(requirements)/sizeof(requirements[0]);i++) {
    const struct Requirement *r=&requirements[i]; int proofOK=1; size_t readSlots=0,readWords=0;
    for(size_t j=r->checkBegin;j<r->checkEnd;j++) {
      const struct Check *c=&checks[j]; uintptr_t address=c->address+(uintptr_t)slide;
      if(c->kind==1) {
        uintptr_t raw=0;memcpy(&raw,(const void*)address,8);readSlots++;
        if(strip(raw,c->auth,c->key)!=c->expected+(uintptr_t)slide)proofOK=0;
      } else {
        uint32_t word=0;memcpy(&word,(const void*)address,4);readWords++;
        if(word!=(uint32_t)c->expected)proofOK=0;
      }
    }
    intptr_t ownerSlide=0;int ownerOK=identity(r->ownerPath,r->ownerUUID,r->ownerBase,&ownerSlide)&&ownerSlide==slide;
    uintptr_t target=r->target+(uintptr_t)slide;Dl_info d={0};int lookup=ownerOK?dladdr((const void*)target,&d):0;
    int exactTarget=lookup&&d.dli_saddr==(const void*)target;
    int exactOwner=lookup&&d.dli_fname&&!strcmp(d.dli_fname,r->ownerPath)&&d.dli_fbase==(const void*)(r->ownerBase+(uintptr_t)slide);
    void *ownerHandle=ownerOK?dlopen(r->ownerPath,RTLD_NOLOAD|RTLD_LAZY):NULL;
    void *symbol=ownerHandle?dlsym(ownerHandle,r->symbol+1):NULL;
    int exactExport=strip((uintptr_t)symbol,1,0)==target;
    if(ownerHandle)dlclose(ownerHandle);
    int accepted=proofOK&&ownerOK&&exactTarget&&exactOwner&&exactExport&&r->offlineExactExport;
    verified+=proofOK;exact+=exactTarget;exported+=accepted;
    printf("{\"type\":\"target\",\"importIndex\":%u,\"target\":\"0x%llx\",\"sourceProofVerified\":%s,\"slotReads\":%zu,\"instructionReads\":%zu,\"ownerUUIDVerified\":%s,\"dladdrExactTarget\":%s,\"dladdrExactOwner\":%s,\"dlsymExactTarget\":%s,\"offlineDirectExactExport\":%s,\"accepted\":%s,\"symbol\":",r->index,(unsigned long long)r->target,proofOK?"true":"false",readSlots,readWords,ownerOK?"true":"false",exactTarget?"true":"false",exactOwner?"true":"false",exactExport?"true":"false",r->offlineExactExport?"true":"false",accepted?"true":"false");quote(r->symbol);printf(",\"dladdrName\":");quote(d.dli_sname);printf(",\"dladdrPath\":");quote(d.dli_fname);puts("}");
  }
  printf("{\"type\":\"summary\",\"pid\":%d,\"requirements\":%zu,\"sourceProofVerified\":%u,\"dladdrExactTargets\":%u,\"acceptedExactExports\":%u,\"actualVZCalls\":0,\"originalVMMExecuted\":false,\"guestInstructions\":0,\"completeStrongVZClosure\":false}\n",getpid(),sizeof(requirements)/sizeof(requirements[0]),verified,exact,exported);
  dlclose(vz);alarm(0);return verified==sizeof(requirements)/sizeof(requirements[0])?0:80;
}
'''


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--oracle',required=True,type=pathlib.Path)
    ap.add_argument('--expected-sha256',required=True)
    ap.add_argument('--output',required=True,type=pathlib.Path)
    ap.add_argument('--run',action='store_true',help='Run only UUID-pinned stock framework on this Mac; no VM/GPU APIs')
    args=ap.parse_args(); oracle=args.oracle.resolve();record=pin(oracle)
    assert record['sha256']==args.expected_sha256
    v=json.loads(oracle.read_text());assert v['originalVZUUID']=='418efc4809d93606918eb6f95baeffdc'
    assert len(v['imports'])==171 and v['exactOriginalProofRows']==171
    out=args.output.resolve();assert out.is_relative_to(N) and not out.exists();out.mkdir(parents=True)
    checks=[];requirements=[];skipped=[]
    for row in v['imports']:
        for ci,c in enumerate(row['candidates']):
            owner=c['physicalOwner']
            if not owner:skipped.append(dict(importIndex=row['index'],candidate=ci,reason='no exact physical owner'));continue
            begin=len(checks)
            for proof in c['proofs']:
                if 'slot' in proof:checks.append((proof['slot'],proof['target'],1,int(proof['auth']),proof['key']))
                elif proof['kind']=='originalVZExternalBranchInstruction':checks.append((proof['originalInstructionPC'],int(proof['rawInstructionWord'],16),2,0,0))
                else:raise AssertionError('unknown original proof kind')
            for step in c['exactStubChain']:
                for k,w in enumerate(step['instructionWords']):checks.append((step['stubVA']+k*4,int(w,16),2,0,0))
                sc=step['slotContract']
                if sc:checks.append((sc['slot'],sc['target'],1,int(sc['auth']),sc['key']))
            end=len(checks);assert end>begin
            requirements.append((row['index'],row['symbol'],c['target'],owner,begin,end,c['directExactExport'] is not None))
    vz=next(im for im in v['images'] if im['path']==v['originalVZPath'])
    h=['#define VZ_PATH '+json.dumps(v['originalVZPath']),'#define VZ_UUID '+json.dumps(v['originalVZUUID']),f'#define VZ_BASE UINT64_C({vz["base"]})','struct Check {uint64_t address,expected;int kind,auth,key;};','static const struct Check checks[]={']
    h += [f'{{UINT64_C({a}),UINT64_C({x}),{kind},{auth},{key}}},' for a,x,kind,auth,key in checks]
    h += ['};','struct Requirement {unsigned index;const char *symbol;uint64_t target;const char *ownerPath,*ownerUUID;uint64_t ownerBase;size_t checkBegin,checkEnd;int offlineExactExport;};','static const struct Requirement requirements[]={']
    for index,name,target,owner,begin,end,ex in requirements:
        h.append('{'+f'{index},{json.dumps(name)},UINT64_C({target}),{json.dumps(owner["path"])},{json.dumps(owner["uuid"])},UINT64_C({owner["base"]}),{begin},{end},{int(ex)}'+'},')
    h += ['};'];(out/'requirements.h').write_text('\n'.join(h)+'\n');(out/'collector.c').write_text(SOURCE)
    write(out/'plan.json',dict(oracle=record,requirements=len(requirements),checks=len(checks),skipped=skipped,runStockMacOnly=True,deviceOperations=0,originalVMMExecuted=False,actualVZCalls=0,completeStrongVZClosure=False,originalWeakBitsRecovered=False))
    processes=[]
    def run(name,command,timeout):
        with (out/(name+'.stdout')).open('wb') as so,(out/(name+'.stderr')).open('wb') as se:
            p=subprocess.Popen(command,stdout=so,stderr=se);rc=p.wait(timeout=timeout)
        processes.append(dict(name=name,pid=p.pid,wait=rc,command=command));write(out/'processes.json',processes)
        assert rc==0,(name,rc)
    run('identity',['xcrun','dyld_info','-uuid',v['originalVZPath']],15)
    assert v['originalVZUUID'].upper() in (out/'identity.stdout').read_text().replace('-','')
    for cp in v['cacheInputs']:
        p=pathlib.Path(cp['path']);st=p.stat();assert st.st_size==cp['bytes'] and st.st_mtime_ns==cp['mtime_ns']
        with p.open('rb') as f:f.seek(88);current=f.read(16).hex()
        assert current==cp['uuid']
    run('compile',['xcrun','clang','-arch','arm64e','-std=c11','-Wall','-Wextra','-Werror','-O2',str(out/'collector.c'),'-o',str(out/'collector')],45)
    if args.run:run('native',[str(out/'collector')],20)
    write(out/'inputs.json',[record,pin(pathlib.Path(__file__).resolve())])
    print(json.dumps(dict(requirements=len(requirements),checks=len(checks),executed=args.run,output=str(out))))


if __name__=='__main__':main()
