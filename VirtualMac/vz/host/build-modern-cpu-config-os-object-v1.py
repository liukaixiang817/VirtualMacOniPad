#!/usr/bin/env python3
"""Ordinary own OS_object CF lifetime and unsigned iOS compilation only."""
from pathlib import Path
import hashlib,json,subprocess,sys
R=Path(__file__).resolve().parents[3]
D=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-config-os-object-local-v1'
S=Path(__file__).resolve().parent
def pin(p):
    p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(label,args,env=None):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    (D/(label+'.stdout')).write_bytes(p.stdout);(D/(label+'.stderr')).write_bytes(p.stderr)
    row=dict(label=label,args=args,exit=p.returncode,stdout=pin(D/(label+'.stdout')),stderr=pin(D/(label+'.stderr')))
    steps.append(row)
    if p.returncode:raise RuntimeError(label+' failed '+str(p.returncode))
    return p.stdout
def main():
    global steps
    steps=[];D.mkdir(exist_ok=True)
    if (D/'candidate.json').exists():raise ValueError('never overwrite a candidate')
    source=S/'modern_cpu_config_os_object_v1.m';test=S/'test-modern-cpu-config-os-object-v1.m'
    flags=['-fno-objc-arc','-Wall','-Wextra','-Werror','-I',str(S)]
    normal=D/'normal-final-fixture';san=D/'sanitized-final-fixture'
    for label,output,extra in [('normal',normal,[]),('sanitized',san,['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        run(label+'-final-compile',['xcrun','--sdk','macosx','clang',*flags,'-DVM27_CPU_CONFIG_TESTING=1',*extra,str(source),str(test),'-framework','CoreFoundation','-lobjc','-o',str(output)])
        import os
        env=dict(os.environ);env['ASAN_OPTIONS']='detect_leaks=0'
        out=run(label+'-final-run',[str(output)],env)
        value=json.loads(out.splitlines()[-1])
        if value['created']!=129 or value['destroyed']!=129 or value['checks']!=3739:raise ValueError('actual lifecycle result')
    exports=D/'ios-exported-symbols.txt';exports.write_text(''.join('_'+x+'\n' for x in ['VM27CPUConfigCreateV1','VM27CPUConfigCopyV1','VM27CPUConfigSetVMKeyV1','VM27CPUConfigSetFGTV1','VM27CPUConfigSetTLBIV1']))
    obj=D/'config-final-ios.o';provider=D/'VM27CPUConfig.dylib'
    ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.0',*flags]
    run('ios-final-compile',[*ios,'-c',str(source),'-o',str(obj)])
    run('ios-final-link',[*ios,'-dynamiclib',str(obj),'-framework','CoreFoundation','-lobjc','-Wl,-no_adhoc_codesign','-Wl,-exported_symbols_list,'+str(exports),'-Wl,-install_name,@rpath/VM27CPUConfig.dylib','-o',str(provider)])
    run('ios-final-exports',['xcrun','nm','-gU',str(provider)])
    run('ios-final-imports',['xcrun','nm','-u',str(provider)])
    run('ios-final-dyld',['xcrun','dyld_info','-validate_only',str(provider)])
    importText=(D/'ios-final-imports.stdout').read_text();exportText=(D/'ios-final-exports.stdout').read_text()
    if any(x in importText for x in ['_hv_','Virtualization','VMM','Hypervisor']):raise ValueError('forbidden native imports')
    if sum(x in exportText for x in exports.read_text().splitlines())!=5:raise ValueError('five own APIs')
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    inputs=[Path(__file__),source,S/'modern_cpu_config_os_object_v1.h',test,exports,
        sdk/'usr/include/os/object.h',sdk/'usr/include/objc/NSObject.h',sdk/'usr/include/objc/runtime.h']
    result=dict(schema='Own OS_object config real CF lifecycle and unsigned iOS source v1',finiteLocalScopePassed=True,findings=[],steps=steps,provider=pin(provider),sourceInputs=[pin(x) for x in inputs],actualCreated=129,actualDestroyed=129,actualNormalAndSanitizedChecks=3739,allocator='_os_object_alloc(ownClass,48)',ownClass='OS_VM27CPUConfigV1',genuineAppleObjectIdentity=False,ownZeroInitializationIsNativeDefault=False,currentTLBISupportKnown=False,nonNULLNativeCPUConfigApplicationImplemented=False,V5SourceChanged=False,nativeCalls=0,deviceOperations=0,signed=False,loadedOnIPad=False,nativeRunImplemented=False,full27Backend=False)
    (D/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(D/'candidate.json'),normalAndASanChecks=3739,created=129,destroyed=129,iOSUnsigned=True)))
if __name__=='__main__':main()
