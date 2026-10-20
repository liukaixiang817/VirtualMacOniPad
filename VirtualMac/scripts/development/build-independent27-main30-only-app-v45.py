#!/usr/bin/env python3
"""HOST-only one-Main App build from actual App90/R74; Root alone executes.

Accept the reviewed Main30 exact-original boot-args restoration retaining VideoToolbox deferral source plan. Reuse the real Main21 compiler
arguments and App90 linker arguments, replacing only object0; never sign or run.
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
OLD=N/'independent27-actual-app-serialized-gic-pg-anchor-v90-attempt1/candidate.json'
OLD_SHA='eb8780e51c987ae0ce1177da28737e18962086728d53419ea3fca00c76da1f64'
RUNTIME_SHA='ca6e15db641596a4a66ba1b62fc6d3586cc4f1a27b59cfbfcb7737e4c2d46ad9'
PLAN_SHA='9c66aebe70efaf544ffea356b3eaf9dbae906d314c234d3327947c7cad0b4d01'


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
    need(pin(OLD)['sha256']==OLD_SHA and pin(plan_path)['sha256']==PLAN_SHA,'actual frozen App90 baseline and reviewed Main30 source plan')
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
    need(plan['baselineApp90Candidate']==pin(OLD) and plan['actualRuntime74Candidate']==old['actualRuntimeCandidate'],
         'actual App90 and signed Runtime74 source-plan bindings')
    need(source['sha256']==plan['reviewedMain29Source']['sha256'] and
         exact(source).read_bytes()==exact(plan['reviewedMain29Source']).read_bytes(),
         'reviewed Main29 source reused byte for byte without new restoration logic')
    baseline=plan['baselineMain21Source']
    need(plan['baselineMain27Source']==old['sourceFiles'][0],'Main30 starts from the actual whole App90 Main27 source')
    exact(baseline)
    runtime=json.loads(exact(old['actualRuntimeCandidate']).read_bytes())
    need(old['actualRuntimeCandidate']['sha256']==RUNTIME_SHA and
         runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         old['sourceFiles'][34]==runtime['anchorSource'] and old['objects'][34]==runtime['anchorIOSObject'],
         'actual R74 runtime and compiled manifest anchor remain whole')
    main21_pin=old['inheritedMainCompilerCandidate'];main21=json.loads(exact(main21_pin).read_bytes())
    need(main21['source']==baseline and main21['actualCompileExit']==0,
         'actual inherited successful Main21 compiler provenance matches the source plan')
    compile_pin=main21['actualCompile'];compiler=json.loads(exact(compile_pin).read_bytes())
    need(compiler['exit']==0,'actual successful Main21 compiler template')
    links=[row for row in old['commands'] if row['label']=='link-app']
    need(len(links)==1 and links[0]['exit']==0,'actual successful App90 link template')
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
    argv=list(links[0]['argv']);old_main=old['objects'][0]['path']
    need(argv.count(old_main)==argv.count(old['binary']['path'])==1,'one actual App90 Main27 object and output in linker')
    argv[argv.index(old_main)]=str(target);argv[argv.index(old['binary']['path'])]=str(binary)
    run('link-app',argv);need(binary.stat().st_size<=2097152,'same parent self-inspector bound')
    run('validate-app',['xcrun','dyld_info','-validate_only',str(binary)])
    for before,after in zip(old['objects'][1:],objects[1:],strict=True):
        exact(after);need(before==after,'all34 other actual App90 objects including Runtime74 anchor whole')
    app_files=[pin(p)for p in sorted(app.rglob('*'))if p.is_file()]
    for row in app_files:
        relative=pathlib.Path(row['path']).relative_to(app)
        if relative!=pathlib.Path('VirtualMacIndependent27'):
            before=pin(original_root/relative)
            need((row['bytes'],row['sha256'])==(before['bytes'],before['sha256']),'all inherited App resources whole')
    closure={row['path']:row for row in old['actualIncludeClosure'] if row['path']!=old['sourceFiles'][0]['path']}
    for name in dep.read_text().replace(chr(92)+chr(10),' ').split(':',1)[1].split():
        path=pathlib.Path(name)
        if path.is_relative_to(R) and path.is_file(): closure[str(path)]=pin(path)
    record=copy.deepcopy(old)
    historical_keys=('actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor',
                     'actualChangedAppObjectIndices','actualOther34ObjectsWholeApp85',
                     'actualUARTAndBootArgsObjectsWholeApp84','actualUARTAndBootArgsObjectsWholeApp86',
                     'actualUARTAndBootArgsObjectsWholeApp87','actualUARTAndBootArgsObjectsWholeApp89',
                     'actualMain27AndOther33CompiledObjectsWholeUnchanged',
                     'mainSourcePlan','mainSourceContractKey')
    record['historicalApp90Main27AnchorOnlyBuild']={k:record.pop(k)for k in historical_keys if k in record}
    prior_contract_key=old['mainSourceContractKey']
    if prior_contract_key in record:
        record['historicalApp90MainSourceContract']={prior_contract_key:record.pop(prior_contract_key)}
    record.update(schema='Actual Main30 original boot-args restoration retaining VideoToolbox deferral App build with34 whole App90 objects and whole Runtime74',
        builder=pin(__file__),sourceCandidate=plan_pin,mainSourcePlan=plan_pin,
        mainSourceContractKey=contract_key,sourceFiles=sources,objects=objects,commands=commands,
        binary=pin(binary),appFiles=app_files,actualIncludeClosure=list(closure.values()),
        inheritedCompiledAppCandidate=pin(OLD),inheritedMainCompilerCandidate=main21_pin,
        inheritedCompilationCommands=compile_pin,actualChangedAppObjectIndices=[0],actualUnchangedCompiledObjects=34,
        actualNewAppCompilations=1,actualOnlyMainObjectChanged=True,actualOnlyRelinkedRuntimeAnchor=False,
        actualOther34ObjectsWholeApp90=True,actualRuntime74AndAnchorWholeUnchanged=True,
        actualObserver2AndBitmap5ObjectsWholeUnchanged=True,allOriginalAppResourcesWholeUnchanged=True,
        actualMainSourceChanged=True,codeSigned=False,deviceOperations=0,trustCacheOperations=0,
        codeSigningOperations=0,applicationBinaryLinked=True,applicationPackaged=True,actualGuestBoot=False,
        actualSSHVerified=False,readyForDeviceExecution=False,
        executionDeferredUntilRootConfirmsActualGuestFrame=True,
        actualReviewedMain29SourceCopiedByteForByte=True)
    record[contract_key]=contract
    save(out/'candidate.json',record)
    files=[pin(p)for p in sorted(out.rglob('*'))if p.is_file()]
    files += [pin(__file__),pin(OLD),plan_pin,main21_pin,compile_pin,old['actualRuntimeCandidate'],
              *sources,*objects,*old.get('externalPrecompiledObjects',[]),*closure.values(),plan['sourceDiff'],baseline]
    save(out/'freeze.json',dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0,codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),changedObjects=1,
                         wholeObjects=34,runtimeWhole=True,mainSourcePlan=plan_pin)))


if __name__=='__main__':main()
