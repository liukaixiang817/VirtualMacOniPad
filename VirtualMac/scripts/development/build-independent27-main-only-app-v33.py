#!/usr/bin/env python3
"""HOST-only one-Main App build from actual App81/R68; Root alone executes.

Accept the reviewed Main22 or Main23 source plan. Reuse the real Main21 compiler
arguments and App81 linker arguments, replacing only object0; never sign or run.
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
OLD=N/'independent27-actual-app-reset-origin-anchor-v81-attempt1/candidate.json'
OLD_SHA='4f3890655d8f08dde929cd03169aa7eb443d06f02e37dca50189fa6ec9592402'
RUNTIME_SHA='fa6253ff902a99bca85dc5110ab8e6d38e131f818be4b1ecfbfdd4012b74769e'


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
    ap.add_argument('--output',type=pathlib.Path,required=True)
    args=ap.parse_args();out=args.output.resolve();plan_path=args.source_plan.resolve()
    need(out.parent==N and not out.exists(),'fresh local one-Main App output')
    need(pin(OLD)['sha256']==OLD_SHA,'actual frozen App81 unsigned baseline')
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
    need(baseline==old['sourceFiles'][0],'new Main starts from actual whole Main21 source')
    exact(baseline)
    runtime=json.loads(exact(old['actualRuntimeCandidate']).read_bytes())
    need(old['actualRuntimeCandidate']['sha256']==RUNTIME_SHA and
         runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         old['sourceFiles'][34]==runtime['anchorSource'] and old['objects'][34]==runtime['anchorIOSObject'],
         'actual R68 runtime and compiled manifest anchor remain whole')
    main21_pin=old['main21ObjectCandidate'];main21=json.loads(exact(main21_pin).read_bytes())
    need(main21['source']==baseline and main21['object']==old['objects'][0] and main21['actualCompileExit']==0,
         'actual Main21 compiler provenance joins current object0')
    compile_pin=main21['actualCompile'];compiler=json.loads(exact(compile_pin).read_bytes())
    need(compiler['exit']==0,'actual successful Main21 compiler template')
    links=[row for row in old['commands'] if row['label']=='link-app']
    need(len(links)==1 and links[0]['exit']==0,'actual successful App81 link template')
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
    argv=list(compiler['argv']);old_source=old['sourceFiles'][0]['path'];old_object=old['objects'][0]['path']
    need(argv.count(old_source)==argv.count(old_object)==1,'one actual Main21 compiler source and object')
    argv[argv.index(old_source)]=source['path'];argv[argv.index(old_object)]=str(target)
    need('-MMD' not in argv and '-MF' not in argv,'original compiler has no dependency output to overwrite')
    argv+=['-MMD','-MF',str(dep)];run('compile-0',argv)
    sources=copy.deepcopy(old['sourceFiles']);objects=copy.deepcopy(old['objects'])
    sources[0]=source;objects[0]=pin(target)
    argv=list(links[0]['argv'])
    need(argv.count(old_object)==argv.count(old['binary']['path'])==1,'one actual object0 and App81 output in linker')
    argv[argv.index(old_object)]=str(target);argv[argv.index(old['binary']['path'])]=str(binary)
    run('link-app',argv);need(binary.stat().st_size<=2097152,'same parent self-inspector bound')
    run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
    for before,after in zip(old['objects'][1:],objects[1:],strict=True):
        exact(after);need(before==after,'all34 other actual App81 objects whole')
    app_files=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()]
    for row in app_files:
        relative=pathlib.Path(row['path']).relative_to(app)
        if relative!=pathlib.Path('VirtualMacIndependent27'):
            before=pin(original_root/relative)
            need((row['bytes'],row['sha256'])==(before['bytes'],before['sha256']),'all inherited App resources whole')
    closure={row['path']:row for row in old['actualIncludeClosure'] if row['path']!=old_source}
    for name in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split():
        path=pathlib.Path(name)
        if path.is_relative_to(R) and path.is_file(): closure[str(path)]=pin(path)
    record=copy.deepcopy(old)
    historical_keys=('actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor',
                     'actualMain21AndOther33CompiledObjectsWholeUnchanged','actualMain21ObjectReused','main21ObjectCandidate',
                     'actualChangedAppObjectIndices')
    record['historicalApp81Main21AndAnchorOnlyStatements']={k:record.pop(k)for k in historical_keys if k in record}
    record.update(schema='Actual one-Main UART App build with34 whole App81 objects and whole Runtime68',
        builder=pin(__file__),sourceCandidate=plan_pin,mainSourcePlan=plan_pin,
        mainSourceContractKey=contract_key,sourceFiles=sources,objects=objects,commands=commands,
        binary=pin(binary),appFiles=app_files,actualIncludeClosure=list(closure.values()),
        inheritedCompiledAppCandidate=pin(OLD),inheritedMainCompilerCandidate=main21_pin,
        inheritedCompilationCommands=compile_pin,actualChangedAppObjectIndices=[0],actualUnchangedCompiledObjects=34,
        actualNewAppCompilations=1,actualOnlyMainObjectChanged=True,actualOnlyRelinkedRuntimeAnchor=False,
        actualOther34ObjectsWholeApp81=True,actualRuntime68AndAnchorWholeUnchanged=True,
        actualObserver2AndBitmap5ObjectsWholeUnchanged=True,allOriginalAppResourcesWholeUnchanged=True,
        actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0,
        codeSigningOperations=0,applicationBinaryLinked=True,applicationPackaged=True,actualGuestBoot=False,
        actualSSHVerified=False)
    record[contract_key]=contract
    save(out/'candidate.json',record)
    files=[pin(p)for p in sorted(out.rglob('*'))if p.is_file()]
    files += [pin(__file__),pin(OLD),plan_pin,main21_pin,compile_pin,old['actualRuntimeCandidate'],
              *sources,*objects,*old.get('externalPrecompiledObjects',[]),*closure.values(),plan['sourceDiff'],baseline]
    save(out/'freeze.json',dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),changedObjects=1,
                         wholeObjects=34,runtimeWhole=True,mainSourcePlan=plan_pin)))


if __name__=='__main__':main()
