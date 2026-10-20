#!/usr/bin/env python3
"""HOST-only Main25 plus Runtime69 anchor App build; Root alone executes.

Compile only Main25 with the real inherited Main21 compiler arguments. Link
App82 with object0 and the already compiled Runtime69 anchor replaced; never sign or run.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD=N/'independent27-actual-app-pl011-uart-bootargs-v82-attempt1/candidate.json'
OLD_SHA='3845ce72124d0eedecfea7018f837ec7a885e3bdbd8dcb0bdc518ca03fda262c'
RUNTIME_SHA='b9f9376cb1f9d7fb4facee0c481eb516a2c4ed555dd42c6749da2b708f3e39eb'
PLAN_SHA='e6d4bb4013f3c86fab36213cadb131fd397940d95747a6d6c1b7e174fdbfeee1'


def need(value, reason):
    if not value: raise ValueError(reason)


def pin(path):
    path=pathlib.Path(path).resolve()
    sdk_settings=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/SDKSettings.json').resolve()
    need((path.is_relative_to(R) or path==sdk_settings) and path.is_file() and not path.is_symlink(), 'owned input/output or exact inherited readonly Apple SDK settings')
    data=path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def exact(row):
    need(pin(row['path'])==row,'exact whole input changed: '+row['path'])
    return pathlib.Path(row['path'])


def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-plan',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path,required=True)
    args=ap.parse_args();out=args.output.resolve();plan_path=args.source_plan.resolve()
    need(out.parent==N and not out.exists(),'fresh local Main25 and Runtime69 anchor App output')
    need(pin(OLD)['sha256']==OLD_SHA and pin(plan_path)['sha256']==PLAN_SHA,'actual frozen App82 unsigned baseline and reviewed Main25 source plan')
    plan_pin=pin(plan_path);old=json.loads(OLD.read_bytes());plan=json.loads(plan_path.read_bytes())
    need(len(old['objects'])==len(old['sourceFiles'])==35 and
         plan['actualChangedAppObjectIndices']==[0] and len(plan['sourceFiles'])==1,
         'one reviewed Main source replaces only object0 of actual35')
    contract_key=plan['contractKey']
    need(isinstance(contract_key,str) and re.fullmatch('[A-Za-z][A-Za-z0-9]*Contract',contract_key),
         'one named actual Main source contract')
    contract=plan[contract_key] if contract_key in plan else plan['contract']
    need(isinstance(contract,dict),'actual source-owner Main contract')
    source=plan['sourceFiles'][0]
    need(source['path'].endswith('.m'),'actual complete Objective-C Main source')
    for row in [*old['sourceFiles'],*old['actualIncludeClosure'],*old['objects'],
                *old.get('externalPrecompiledObjects',[]),*old['appFiles'],source,plan['sourceDiff']]: exact(row)
    baseline=plan['baselineMain21Source']
    need(plan['baselineMain23Source']==old['sourceFiles'][0] and plan['baselineMain23SourcePlan']==old['mainSourcePlan'],'Main25 starts from actual whole App82 Main23 source and diagnostic plan')
    exact(baseline)
    runtime_pin=pin(args.runtime_candidate);runtime=json.loads(exact(runtime_pin).read_bytes())
    need(runtime_pin['sha256']==RUNTIME_SHA and runtime['localCodeSigned'] is True and
         runtime['actualProductPreflightPassed'] is True and
         runtime['baselineRuntimeCandidate']==old['actualRuntimeCandidate'] and
         runtime['canonicalDeviceRoot']==old['runtimeRoot'] and runtime['cpu28OtherObjectsWholeRuntime68'] is True,
         'actual signed Runtime69 snapshot product derives from installed Runtime68')
    for key in ('anchorSource','anchorIOSObject','manifest'):exact(runtime[key])
    main21_pin=old['inheritedMainCompilerCandidate'];main21=json.loads(exact(main21_pin).read_bytes())
    need(main21['source']==baseline and main21['actualCompileExit']==0,
         'actual inherited successful Main21 compiler provenance matches reviewed source baseline')
    compile_pin=main21['actualCompile'];compiler=json.loads(exact(compile_pin).read_bytes())
    need(compiler['exit']==0,'actual successful Main21 compiler template')
    links=[row for row in old['commands'] if row['label']=='link-app']
    need(len(links)==1 and links[0]['exit']==0,'actual successful App82 link template')
    out.mkdir(mode=0o700);(out/'objects').mkdir(mode=0o700)
    original_root=pathlib.Path(old['binary']['path']).parent;app=out/'VirtualMacIndependent27.app'
    need(not any(p.is_symlink() for p in original_root.rglob('*')),'ordinary inherited complete App resources')
    shutil.copytree(original_root,app);binary=app/'VirtualMacIndependent27'
    commands=[]

    def run(label,argv):
        result=subprocess.run(argv,capture_output=True,timeout=90)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=argv,exit=result.returncode));save(out/'commands.json',commands)
        need(result.returncode==0,label+': '+result.stderr.decode(errors='replace'))

    target=out/'objects'/('0-'+pathlib.Path(source['path']).stem+'.o');dep=out/'main.d'
    argv=list(compiler['argv']);old_source=main21['source']['path'];old_object=main21['object']['path']
    need(argv.count(old_source)==argv.count(old_object)==1,'one actual Main21 compiler source and object')
    argv[argv.index(old_source)]=source['path'];argv[argv.index(old_object)]=str(target)
    need('-MMD' not in argv and '-MF' not in argv,'original compiler has no dependency output to overwrite')
    argv+=['-MMD','-MF',str(dep)];run('compile-0',argv)
    sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects'])
    sources[0]=source;objects[0]=pin(target)
    sources[34]=runtime['anchorSource'];objects[34]=runtime['anchorIOSObject']
    argv=list(links[0]['argv']);old_main=old['objects'][0]['path'];old_anchor=old['objects'][34]['path']
    need(argv.count(old_main)==argv.count(old_anchor)==argv.count(old['binary']['path'])==1,
         'one actual App82 Main23 object, Runtime68 anchor and output in linker')
    argv[argv.index(old_main)]=str(target);argv[argv.index(old_anchor)]=runtime['anchorIOSObject']['path']
    argv[argv.index(old['binary']['path'])]=str(binary)
    run('link-app',argv);need(binary.stat().st_size<=2097152,'same parent self-inspector bound')
    run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
    for before,after in zip(old['objects'][1:34],objects[1:34],strict=True):
        exact(after);need(before==after,'all33 other actual App82 objects whole')
    app_files=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()]
    for row in app_files:
        relative=pathlib.Path(row['path']).relative_to(app)
        if relative!=pathlib.Path('VirtualMacIndependent27'):
            before=pin(original_root/relative)
            need((row['bytes'],row['sha256'])==(before['bytes'],before['sha256']),'all inherited App resources whole')
    closure={row['path']:row for row in old['actualIncludeClosure'] if row['path'] not in (old['sourceFiles'][0]['path'],old['sourceFiles'][34]['path'])}
    closure[runtime['anchorSource']['path']]=runtime['anchorSource']
    for name in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split():
        path=pathlib.Path(name)
        if path.is_relative_to(R) and path.is_file(): closure[str(path)]=pin(path)
    record=copy.deepcopy(old)
    historical_keys=('actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor',
                     'actualOnlyMainObjectChanged','actualOther34ObjectsWholeApp81','actualRuntime68AndAnchorWholeUnchanged',
                     'actualMainSourceChanged','actualChangedAppObjectIndices','mainSourcePlan','mainSourceContractKey')
    record['historicalApp82Main23Compilation']={key:record.pop(key)for key in historical_keys if key in record}
    record.update(schema='Actual Main25 and Runtime69 anchor App build with33 whole App82 objects',
        builder=pin(__file__),sourceCandidate=plan_pin,mainSourcePlan=plan_pin,
        mainSourceContractKey=contract_key,sourceFiles=sources,objects=objects,commands=commands,
        binary=pin(binary),appFiles=app_files,actualIncludeClosure=list(closure.values()),
        inheritedCompiledAppCandidate=pin(OLD),inheritedMainCompilerCandidate=main21_pin,
        inheritedCompilationCommands=compile_pin,actualRuntimeCandidate=runtime_pin,
        actualChangedAppObjectIndices=[0,34],actualUnchangedCompiledObjects=33,
        actualNewAppCompilations=1,actualOnlyMainObjectChanged=False,actualOnlyRelinkedRuntimeAnchor=False,
        actualMain25AndNewRuntimeAnchorChanged=True,actualUARTAndBootArgsMaintenanceOrderFixed=True,
        actualOther33ObjectsWholeApp82=True,actualObserver2AndBitmap5ObjectsWholeUnchanged=True,
        allOriginalAppResourcesWholeUnchanged=True,actualMainSourceChanged=True,codeSigned=False,
        deviceOperations=0,trustCacheOperations=0,codeSigningOperations=0,applicationBinaryLinked=True,
        applicationPackaged=True,actualGuestBoot=False,actualSSHVerified=False)
    record['pl011UARTBootArgumentsV23ContractAppliesToHistoricalApp82DeltaOnly']=True
    record[contract_key]=contract
    save(out/'candidate.json',record)
    files=[pin(p)for p in sorted(out.rglob('*'))if p.is_file()]
    files += [pin(__file__),pin(OLD),plan_pin,main21_pin,compile_pin,runtime_pin,old['actualRuntimeCandidate'],runtime['manifest'],
              *sources,*objects,*old.get('externalPrecompiledObjects',[]),*closure.values(),plan['sourceDiff'],baseline]
    save(out/'freeze.json',dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),changedObjects=2,
                         wholeObjects=33,appCompilations=1,mainSourcePlan=plan_pin)))


if __name__=='__main__':main()
