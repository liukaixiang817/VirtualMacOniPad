#!/usr/bin/env python3
"""HOST-only one scoped Child import and genuine typed MG compatibility library."""
import argparse,hashlib,importlib.util,json,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
BASE=N/'independent27-signed-runtime-cache-context-product-v11-attempt1/candidate.json';READER=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';NATIVE=N/'current-native-header-export-index-v3/index.json';CODE=N/'ipad-native-mobilegestalt-sint32-code-readonly-v1-attempt1/mobilegestalt-sint32-abort-code.bin';RECEIPT=CODE.parent/'receipt.json'
KEY='VM27OwnedChildGestaltCompat.dylib';SYMBOL='_VM27OwnedChildMGGetSInt32AnswerV1'
def need(x,s):
 if not x:raise ValueError(s)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def align(x,n=8):return (x+n-1)&~(n-1)
def module(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def native_routes(index,path,name,seen=()):
 need((path,name)not in seen,'native alias cycle')
 if path not in index['images']:return []
 image=index['images'][path];d=image['definitions'].get(name)
 if d:
  if d['flags']&8:
   target=next(x['path']for x in image['dependencies']if x['ordinal']==d['ordinal']);return native_routes(index,target,d.get('alias')or d.get('importedName')or name,seen+((path,name),))
  return [dict(path=path,UUID=image['UUID'],symbol=name,definition=d)]
 return [r for dep in image['dependencies']if dep['command']==0x8000001f for r in native_routes(index,dep['path'],name,seen+((path,name),))]

def patch(data,reader):
 old=reader.MachO(data);need(len(old.loads)==56 and len(old.imports)==1203,'actual baseline Child56/1203');need(old.imports[944]['name']=='_MGGetSInt32Answer'and old.imports[944]['ordinal']==39,'actual944 nativeMG');commands=[bytearray(c['raw'])for c in old.commands if c['cmd']!=0x1d];cs=next(c for c in old.commands if c['cmd']==0x1d);start,size=struct.unpack_from('<II',cs['raw'],8);need(start+size==len(data),'terminal actual signature');work=bytearray(data[:start]);chain=next(c for c in old.commands if c['cmd']==0x80000034);at,length=struct.unpack_from('<II',chain['raw'],8);raw=bytearray(data[at:at+length]);v,starts,imports,symbols,count,form,sform=struct.unpack_from('<7I',raw);need(count==1203 and form==2 and sform==0,'true chained imports2');symboloff=len(raw)-symbols;raw+=SYMBOL.encode()+b'\0';before,addend=struct.unpack_from('<Ii',raw,imports+944*8);need(addend==0,'true zero addend');struct.pack_into('<Ii',raw,imports+944*8,57|(symboloff<<9),0);newchain=len(work);work+=raw
 sym=next(c for c in old.commands if c['cmd']==2);so,nsyms,stro,strsize=struct.unpack_from('<4I',sym['raw'],8);nlist=bytearray(data[so:so+nsyms*16]);strings=bytearray(data[stro:stro+strsize]);hits=[]
 for i in range(nsyms):
  no,typ,sec,desc,value=struct.unpack_from('<IBBHQ',nlist,i*16);name=strings[no:strings.find(b'\0',no)].decode()
  if name=='_MGGetSInt32Answer'and (typ&0xe)==0:
   need(desc>>8==39,'native nlist ordinal39');hits.append(i);no=len(strings);strings+=SYMBOL.encode()+b'\0';struct.pack_into('<IBBHQ',nlist,i*16,no,typ,sec,(57<<8)|(desc&255),value)
 need(len(hits)==1,'one selected nlist');work+=b'\0'*(align(len(work))-len(work));newso=len(work);work+=nlist;newstr=len(work);work+=strings
 path=('@loader_path/'+KEY).encode()+b'\0';length=align(24+len(path));load=bytearray(struct.pack('<6I',12,length,24,0,0x10000,0x10000)+path);load+=b'\0'*(length-len(load));commands.append(load)
 for cmd in commands:
  kind=struct.unpack_from('<I',cmd)[0]
  if kind==0x80000034:struct.pack_into('<II',cmd,8,newchain,len(raw))
  elif kind==2:struct.pack_into('<4I',cmd,8,newso,nsyms,newstr,len(strings))
  elif kind==0x19 and cmd[8:24].rstrip(b'\0')==b'__LINKEDIT':
   off=struct.unpack_from('<Q',cmd,40)[0];extent=len(work)-off;struct.pack_into('<Q',cmd,32,align(extent,16384));struct.pack_into('<Q',cmd,48,extent)
 header=b''.join(commands);first=min(x['fileoff']for x in old.sections if x['fileoff']>0);need(32+len(header)<=first and not any(data[32+old.sizeofcmds:first]),'true zero header capacity');work[32:first]=header+b'\0'*(first-32-len(header));struct.pack_into('<II',work,16,len(commands),len(header));need(bytes(work[first:start])==data[first:start],'all original postheader code/PAC/oldlinkedit byte exact');return bytes(work),old,dict(oldSignatureOffset=start,oldSignatureBytes=size,newFixupsOffset=newchain,newFixupsBytes=len(raw),newNlistOffset=newso,newStringsOffset=newstr,headerRemainingBytes=first-32-len(header))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh exclusive output');out.mkdir(mode=0o700);reader=module(READER,'child_gestalt_reader');base=json.loads(BASE.read_bytes());manifest=json.loads('{}')
 import plistlib
 manifest=plistlib.loads(pathlib.Path(base['manifest']['path']).read_bytes());childrow=next(x for x in manifest['files']if x['id']==manifest['parentBootstrapContract']['childID']);original=pathlib.Path(base['runtimeRoot'])/childrow['path'];need(pin(original)['sha256']==childrow['sha256'],'true signed baseline child');index=json.loads(NATIVE.read_bytes());mg=index['images']['/usr/lib/libMobileGestalt.dylib'];need(mg['UUID']=='74e2f22337043f21aeb0f681c003e5fb','true nativeMG UUID');receipt=json.loads(RECEIPT.read_bytes());need(receipt['transportExit']==0 and len(CODE.read_bytes())==2304 and hashlib.sha256(CODE.read_bytes()).hexdigest()==receipt['ranges'][0]['sha256'],'actual native-code capture');tbd=out/'libMobileGestalt.tbd';tbd.write_text('--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64e-ios ]\ninstall-name: /usr/lib/libMobileGestalt.dylib\ncurrent-version: 1.0\ncompatibility-version: 1.0\nexports:\n  - targets: [ arm64e-ios ]\n    symbols: [ _MGCopyAnswer, _MGGetSInt32Answer ]\n...\n')
 commands=[]
 def run(label,argv):
  z=subprocess.run(argv,capture_output=True);(out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr);commands.append(dict(label=label,argv=argv,exit=z.returncode));dump(out/'commands.json',commands);need(z.returncode==0,label+': '+z.stderr.decode(errors='replace'))
 sdk=subprocess.run(['xcrun','--sdk','iphoneos','--show-sdk-path'],check=True,capture_output=True).stdout.decode().strip();source=S/'vm27_owned_child_gestalt_v1.c';header=S/'vm27_owned_child_gestalt_v1.h';obj=out/'child-gestalt.ios.o';target=['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1','-arch','arm64e','-isysroot',sdk,'-Wall','-Wextra','-Werror'];run('compile',target+['-fvisibility=hidden','-c',str(source),'-o',str(obj)]);provider=out/KEY;run('link',target+['-dynamiclib','-Wl,-no_adhoc_codesign','-Wl,-install_name,@loader_path/'+KEY,str(obj),'-framework','CoreFoundation',str(tbd),'-o',str(provider)]);helper=reader.MachO(provider.read_bytes());need(set(helper.exports)=={SYMBOL}and helper.exports[SYMBOL]['flags']==0,'one true own export');routes=[]
 for imp in helper.imports:
  need(imp['ordinal']>0 and not imp['weak'],'true strong two-level helper import');load=helper.loads[imp['ordinal']-1];found=native_routes(index,load['path'],imp['name']);unique={json.dumps(x,sort_keys=True):x for x in found};need(len(unique)==1,'true native route '+imp['name']);routes.append(dict(actualImport=imp,requiredLoad=load,resolvedDefinition=next(iter(unique.values()))))
 changed,old,layout=patch(original.read_bytes(),reader);child=out/'ChildMain.unsigned';child.write_bytes(changed);new=reader.MachO(changed);need(new.uuid==old.uuid and new.exports==old.exports and new.binds==[{**x,'name':SYMBOL}if x['index']==944 else x for x in old.binds],'all old raw PAC/binds exact; only import name mapped');
 def sem(x):return {k:x[k]for k in ('index','ordinal','weak','name','addend')}
 for i,(x,y)in enumerate(zip(old.imports,new.imports)):
  want=sem(x)
  if i==944:want.update(name=SYMBOL,ordinal=57)
  need(sem(y)==want,'all old imports except944 exact')
 for targetpath in (provider,child):run('validate-'+targetpath.name,['xcrun','dyld_info','-validate_only',str(targetpath)])
 contract=dict(symbol=SYMBOL,selectedActualImportIndex=944,newRequiredOrdinal=57,newRequiredLoad='@loader_path/'+KEY,providerKey=KEY,question='SoCSKU',actualQuestionCFStringRVA=0x4c5fb8,actualQuestionCStringRVA=0x44efc7,exactCallerReturnRVA=0x307d14,childUUID=new.uuid,nativeMGUUID=mg['UUID'],nativeMGCopyAnswerRVA=0x2584,nativeMGGetSInt32AnswerRVA=0x2ba4,callerDefault=-1,onlyExactOwnedChildAndKey=True,otherNativeQueriesAndCallersUnchanged=True,genuineUntypedAnswerAndCFNumberValueOnly=True,unknownOrMismatchReturnsCallerDefault=True,numericSKUInvented=False,VMOrCPUSuccessClaimed=False,sourcePin=pin(source),headerPin=pin(header),nativeAbortCodeReceipt=pin(RECEIPT))
 graph=out/'graph.json';dump(graph,dict(childOnly=True,baselineRuntimeCandidate=pin(BASE),originalChildSignedPin=pin(original),actualSelectedChildImport=new.imports[944],actualSelectedChildRequiredLoad=new.loads[56],parentWholeUnchanged=True,allOtherChildImagesWholeUnchanged=True,newProviderStrongImportsClosed=True,actualProviderNativeRows=routes,newProvider=pin(provider),allOriginalChildCodeAndRawPACWholeUnchanged=True,actualNativeMGDefinitions={k:mg['definitions'][k]for k in ('_MGCopyAnswer','_MGGetSInt32Answer')},sourcePins=[pin(source),pin(header)],layout=layout,deviceOperations=0));recipe=out/'recipe.json';dump(recipe,dict(selectedBefore=old.imports[944],selectedAfter=new.imports[944],newRequiredLoad=new.loads[56],layout=layout,allOriginalNonheaderPrefixWholeUnchanged=True));cp=out/'candidate.json';dump(cp,dict(schema='Actual owned Child SoCSKU safe numeric query source port v1',baselineRuntimeCandidate=pin(BASE),providerKey=KEY,originalChildMain=pin(original),patchedChildMain=pin(child),newProvider=pin(provider),adapterContract=contract,recipe=pin(recipe),graph=pin(graph),verification=pin(graph),actualSelectedChildImport=new.imports[944],actualSelectedChildRequiredLoad=new.loads[56],actualIOSObject=pin(obj),actualProviderStrongImports=len(routes),childOnly=True,codeSignatureRemovedForActualSigning=True,deviceOperations=0,trustCacheOperations=0,localCodeSigned=False));freeze=out/'freeze.json';files=[pathlib.Path(__file__),BASE,READER,NATIVE,RECEIPT,CODE,source,header,original]+sorted(p for p in out.iterdir()if p.is_file());dump(freeze,dict(files=[pin(p)for p in files],deviceOperations=0));print(json.dumps(dict(candidate=pin(cp),freeze=pin(freeze),provider=pin(provider),child=pin(child),actualProviderStrongImports=len(routes))))
if __name__=='__main__':main()
