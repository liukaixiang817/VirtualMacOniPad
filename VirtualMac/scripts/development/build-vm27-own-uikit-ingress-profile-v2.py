#!/usr/bin/env python3
"""HOST-only real class metadata/runtime alignment and production iOS compile."""
import argparse,difflib,hashlib,importlib.util,json,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(r):
 need(pin(r['path'])=={k:r[k]for k in ('path','bytes','sha256')},'actual pin '+r['path']);return pathlib.Path(r['path'])
def save(p,j):p.write_text(json.dumps(j,indent=2)+'\n')
def module(p):
 spec=importlib.util.spec_from_file_location('original_input_layout_reader',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args();o=a.output.resolve();need(o.parent==N and not o.exists(),'fresh diagnostic output');o.mkdir(mode=0o700)
 old=N/'own-uikit-genuine-input-ingress-source-build-v1';fc=N/'owned-uikit-mac-event-filter-source-port-v2-attempt1/candidate.json';c=json.loads(fc.read_bytes());m=module(actual(c['reader']));raw=actual(c['originalVZ']).read_bytes();z=m.MachO(raw)
 source=S/'vm27_own_uikit_ingress_profile_v2.m';prior=S/'vm27_own_uikit_ingress_profile_v1.m';test=S/'test-vm27-own-uikit-ingress-runtime-layout-v2.m';header=S/'vm27_own_uikit_ingress_profile_v1.h';oldfreeze=json.loads((old/'freeze.json').read_bytes());fp={r['path']:r for r in oldfreeze['files']}
 actual(fp[str(prior)]);actual(fp[str(header)])
 before=prior.read_text();after=source.read_text();expected=before.replace('class_shape("_VZScreenCoordinatePointingDevice", 36, &screenPointing)','class_shape("_VZScreenCoordinatePointingDevice", 40, &screenPointing)');start=expected.index('        if (packet->source == VM27InputPan) {');end=expected.index('        return VM27InputUnsupported;',start)
 expected=expected[:start]+'''        if (packet->source == VM27InputPan) {
            /* This explicit basic-input profile does not admit processed scroll.
             * Keep the real copied-packet error: no original sender, state or
             * sequence commit can be claimed for this deferred capability.
             * QueueV3 closes its actual admission on this unavailable result. */
            return VM27InputUnavailable;
        }
'''+expected[end:];need(after==expected,'only actual alignment correction and explicit Pan unavailable delta')
 (o/'source.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile=prior.name,tofile=source.name)))
 def pointer(va):
  w=struct.unpack_from('<Q',raw,z.file(va))[0]
  if w>>62&1:return dict(importName=z.imports[w&0xffff]['name'],rawWord=hex(w))
  return z.base+((w&0xffffffff)if w>>63 else w&((1<<43)-1))
 def string(va):
  f=z.file(va);return raw[f:raw.index(0,f)].decode()
 names=['_VZKeyEvent','_VZScreenCoordinatePointerEvent','_VZKeyboard','_VZUSBKeyboard','_VZScreenCoordinatePointingDevice','_VZPointingDevice','_VZScrollWheelEvent'];sizes=[24,32,40,48,40,32,56];layouts=[]
 for name,size in zip(names,sizes):
  cl=z.base+z.exports['_OBJC_CLASS_$_'+name]['address'];ro=pointer(cl+32)&~7;flags,start,end=struct.unpack_from('<III',raw,z.file(ro));iv=pointer(ro+48);ivars=[]
  if iv!=z.base:
   es,count=struct.unpack_from('<II',raw,z.file(iv));need(es==32 and count<=8,'true bounded ivar list')
   for i in range(count):
    loc=iv+8+i*es;off=struct.unpack_from('<I',raw,z.file(pointer(loc)))[0];al,sz=struct.unpack_from('<II',raw,z.file(loc)+24);ivars.append(dict(name=string(pointer(loc+8)),encoding=string(pointer(loc+16)),offset=off,alignmentLog2=al,bytes=sz))
  need((end+7)&~7==size and all(r['offset']+r['bytes']<=end for r in ivars),'actual raw field end and pointer alignment '+name)
  super0=pointer(cl+8);supername=super0['importName']if isinstance(super0,dict)else next(k.replace('_OBJC_CLASS_$_','')for k,v in z.exports.items()if k.startswith('_OBJC_CLASS_$_')and z.base+v['address']==super0)
  layouts.append(dict(name=name,classRVA=cl-z.base,classRORVA=ro-z.base,rawInstanceStart=start,rawInstanceSize=end,alignedLP64InstanceSize=size,superclass=supername,ivars=ivars,classBytes=raw[z.file(cl):z.file(cl)+40].hex(),classROBytes=raw[z.file(ro):z.file(ro)+72].hex()))
 need(layouts[4]['rawInstanceSize']==36 and layouts[4]['superclass']=='_VZPointingDevice'and layouts[3]['superclass']=='_VZKeyboard','true original superclass and raw36 boundary')
 save(o/'actual-original-class-layouts.json',dict(originalVZ=c['originalVZ'],UUID=z.uuid,classes=layouts,actualIOSRuntimeNotExecuted=True,primarySources=[dict(url='https://raw.githubusercontent.com/apple-oss-distributions/objc4/main/runtime/objc-class.mm',lines=[756,760],fact='class_getInstanceSize realizes class and returns alignedInstanceSize'),dict(url='https://raw.githubusercontent.com/apple-oss-distributions/objc4/main/runtime/objc-runtime-new.h',lines=[2884,2903],fact='RO instanceSize is unaligned; alignedInstanceSize rounds to pointer boundary')]))
 commands=[]
 def run(label,args):
  args=list(map(str,args));p=subprocess.run(args,capture_output=True,timeout=60);(o/(label+'.stdout')).write_bytes(p.stdout);(o/(label+'.stderr')).write_bytes(p.stderr);commands.append(dict(label=label,argv=args,exit=p.returncode));save(o/'commands.json',commands);need(p.returncode==0,label+': '+p.stderr.decode(errors='replace'));return p
 mac=run('sdk-mac',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip();ios=run('sdk-ios',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip();flags=['xcrun','clang','-Wall','-Wextra','-Werror','-O2','-fblocks','-fobjc-arc'];results=[]
 for mode in ['normal','sanitized']:
  exe=o/('runtime-layout-'+mode);opts=flags+['-target','arm64-apple-macos13.0','-isysroot',mac]
  if mode=='sanitized':opts+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
  run('compile-'+mode,opts+[test,'-framework','Foundation','-framework','CoreGraphics','-o',exe]);r=json.loads(run('run-'+mode,[exe]).stdout);need(r['checks']==31 and r['screenPointingRuntimeSize']==40 and r['originalVZExecuted']is False,'real runtime LP64 bounded model');results.append(r)
 target=flags+['-target','arm64e-apple-ios16.1','-isysroot',ios,'-I',S];obj=o/'own-profile-v2.o';run('compile-ios-profile',target+['-c',source,'-o',obj]);ir=o/'own-profile-v2.ll';run('ir-ios-profile',target+['-S','-emit-llvm',source,'-o',ir]);text=ir.read_text();need('i64 noundef 40'not in text or '@class_getInstanceSize'in text,'real runtime class size call kept')
 reused=[old/(n+'.o')for n in ['values','normalization','native-scroll','scroll-sink','genuine-scroll-receiver','own-endpoint']]
 for p in reused:actual(fp[str(p)])
 provider=o/'VM27OwnUIKitGenuineIngressV2.ios.unsigned.inert.dylib';run('link-ios-provider',target+['-dynamiclib',obj]+reused+['-framework','Foundation','-framework','CoreFoundation','-framework','CoreGraphics','-framework','IOKit','-lobjc','-Wl,-install_name,@loader_path/VM27OwnUIKitGenuineIngress.dylib','-Wl,-no_adhoc_codesign','-o',provider]);run('validate-ios-provider',['xcrun','dyld_info','-validate_only',provider]);p=m.MachO(provider.read_bytes());oldp=m.MachO((old/'VM27OwnUIKitGenuineIngress.ios.unsigned.inert.dylib').read_bytes());sem=lambda rows:sorted([(x['name'],x['ordinal'],x['weak'],x['addend'])for x in rows]);need(sem(p.imports)==sem(oldp.imports)and p.loads==oldp.loads and set(p.exports)==set(oldp.exports),'same actual strong import/dependency/export namespace; no new runtime provider requirement')
 app=N/'independent27-app-uikit-basic-input-source-v11-attempt1/candidate.json';aj=json.loads(app.read_bytes());actual(aj['source']);apptext=pathlib.Path(aj['source']['path']).read_text();need('VZIndependent27SourceRouteSelected() ||'in apptext,'actual independent source USB selection');need('VZUSBKeyboardConfiguration' in apptext and 'VZUSBScreenCoordinatePointingDeviceConfiguration'in apptext,'true original public USB configuration names')
 record=dict(schema='Own UIKit basic input profile V2 actual alignment source',builder=pin(__file__),source=pin(source),header=pin(header),priorSource=pin(prior),priorFreeze=pin(old/'freeze.json'),sourceDiff=pin(o/'source.diff'),originalClassLayouts=pin(o/'actual-original-class-layouts.json'),tests=pin(test),hostRuntimeLayoutResults=results,actualIOSObject=pin(obj),actualIOSIR=pin(ir),actualAggregate=pin(provider),reusedFrozenObjects=[pin(p)for p in reused],actualStrongImports=p.imports,actualStrongImportNamespaceUnchanged=True,actualExports=p.exports,app11SourceCandidate=pin(app),app11Source=aj['source'],publicClassAndHeaderABIUnchanged=True,onlyProductionDelta=['ScreenPointing true runtime size36-to40','Pan exact copied packet returns Unavailable without sender/state/sequence commit'],processedScrollDeferred=True,PanUnavailableClosesQueueV3Admission=True,basicKeyPointerLifecycleAndVersionGatesUnchanged=True,originalVZClassLayoutActuallyParsed=True,originalVZExecuted=False,actualIOSClassRuntimeValidated=False,actualBasicGuestInputValidated=False,deviceOperations=0,trustCacheOperations=0,codeSigned=False,findings=[])
 save(o/'candidate.json',record);rows=[pin(__file__),pin(source),pin(prior),pin(header),pin(test),pin(fc),c['reader'],c['originalVZ'],pin(old/'freeze.json'),pin(old/'VM27OwnUIKitGenuineIngress.ios.unsigned.inert.dylib'),pin(app),aj['source']]+record['reusedFrozenObjects']+[pin(f)for f in o.iterdir()if f.is_file()];save(o/'freeze.json',dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0));print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'))))
if __name__=='__main__':main()
