#!/usr/bin/env python3
"""Root-only HOST compile/link of software keyboard and QGA optional diagnostic units.

No signing, runtime build, network or device operations. Reuse the exact App105
Main32, Runtime86 anchor, other31 objects, external object and all resources.
Only source-plan units8/17 are compiled. Frozen old inputs must remain whole.
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

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N/'independent27-actual-app-display-rgb-guest-boot-v105-attempt1/candidate.json'
OLD_SHA = 'f04556d18479f58818d01857d5baf7de16035664aef72219d6385b930af6e68d'
RUNTIME_SHA = 'aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
COMPILE = N/'independent27-actual-app-display-rgb-guest-boot-v105-attempt1/commands.json'
SURFACE_COMPILE = N/'independent27-actual-app-future-persistent-ssh-v30-attempt1/commands.json'
SURFACE_COMPILE_SHA = 'e7369ecf7e30c19f45ef76174c72a35ecdddb46bfc749fb49f0648188439e817'
COMPILE_SHA = 'e8e76b3abc5ff4e50136d7c74e7dfa80acbdbdbb99d7a3621bdb1b743cdc9432'
CONTRACT = 'softwareKeyboardAndOptionalQGADiagnosticV1Contract'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(path):
    path = pathlib.Path(path).resolve()
    need(path.is_file() and not path.is_symlink(), 'actual regular input '+str(path))
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def exact(row):
    need(pin(row['path']) == row, 'exact reviewed input '+row['path'])
    return pathlib.Path(row['path'])


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-plan', type=pathlib.Path, required=True)
    ap.add_argument('--source-plan-sha256', required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    out, plan_path = args.output.resolve(), args.source_plan.resolve()
    need(out.parent == N and not out.exists(), 'fresh HOST output')
    need(pin(OLD)['sha256'] == OLD_SHA and pin(COMPILE)['sha256'] == COMPILE_SHA and pin(SURFACE_COMPILE)['sha256'] == SURFACE_COMPILE_SHA,
         'exact App105 object provenance and actual successful compile templates')
    need(re.fullmatch('[0-9a-f]{64}', args.source_plan_sha256) and
         pin(plan_path)['sha256'] == args.source_plan_sha256, 'exact Root-reviewed source plan')
    old, plan = json.loads(OLD.read_bytes()), json.loads(plan_path.read_bytes())
    need(plan['baselineCompiledAppCandidate'] == pin(OLD) and
         plan['actualRuntimeCandidate'] == old['actualRuntimeCandidate'] and
         plan['contractKey'] == CONTRACT and isinstance(plan['contract'], dict),
         'two-unit source plan joins actual App105 and unchanged Runtime86')
    runtime_path = exact(old['actualRuntimeCandidate'])
    need(old['actualRuntimeCandidate']['sha256'] == RUNTIME_SHA, 'actual installed Runtime86')
    runtime = json.loads(runtime_path.read_bytes())
    need(runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True and
         runtime['canonicalDeviceRoot'] == old['runtimeRoot'] and
         old['sourceFiles'][34] == runtime['anchorSource'] and
         old['objects'][34] == runtime['anchorIOSObject'], 'same signed runtime and compiled anchor')
    need(len(old['sourceFiles']) == len(old['objects']) == 35 and
         old['sourceFiles'][0]['sha256'] == '3b3f6d3797edb88536c0609e01ec813177d64387e921e90a060b2bfdd0c6a440' and
         old['objects'][0]['sha256'] == 'cb3487165f9bb83cdd0c6d32de44caf8afaf8794b20f5e68bac725ad3822cc01',
         'actual Main32 and original35 units')
    units = plan['compileUnits']
    need([row['index'] for row in units] == [8,17] and
         [pathlib.Path(row['source']['path']).name for row in units] ==
         ['VZGuestTools_owned_active_ssh_v9.m','modern_uikit_input_surface_v4_keyboard.m'],
         'only the exact GuestTools9 and software-keyboard surface4 units are compiled')
    reviewed = {row['path']:row for row in plan['sourceFiles']}
    need(all(row['source'] == reviewed.get(row['source']['path']) for row in units),
         'both compile sources are directly pinned in the reviewed include/source plan')
    for key in ('independent27SoftwareKeyboardV3Contract', 'optionalQGADiagnosticContract'):
        need(isinstance(plan['contract'].get(key), dict), 'actual current aggregate sub-contract '+key)
    inherited = [*old['sourceFiles'],*old['actualIncludeClosure'],*old['objects'],
                 *old.get('externalPrecompiledObjects',[]),*old['appFiles']]
    for row in [*inherited,*plan['sourceFiles'],*plan['componentSourcePlans'],
                *plan['originalInputs'],old['mainSourcePlan']]:
        exact(row)
    need(all(unit['source']['path'] != old['sourceFiles'][unit['index']]['path'] for unit in units),
         'fresh source files; never overwrite frozen display inputs')
    templates = json.loads(COMPILE.read_bytes())
    surface_templates = json.loads(SURFACE_COMPILE.read_bytes())
    out.mkdir(mode=0o700); (out/'objects').mkdir(mode=0o700)
    app = out/'VirtualMacIndependent27.app'
    shutil.copytree(pathlib.Path(old['binary']['path']).parent, app)
    need(not any(p.is_symlink() for p in app.rglob('*')), 'regular inherited App resource tree')
    binary, commands = app/'VirtualMacIndependent27', []
    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=argv,exit=result.returncode))
        save(out/'commands.json',commands)
        need(result.returncode == 0,label+': '+result.stderr.decode(errors='replace'))
    sources, objects = copy.deepcopy(old['sourceFiles']), copy.deepcopy(old['objects'])
    for unit in units:
        index = unit['index']
        template = [c for c in (surface_templates if index == 17 else templates) if c['label'] == 'compile-'+str(index) and c['exit'] == 0]
        need(len(template) == 1, 'one actual successful compile template')
        argv = list(template[0]['argv'])
        need(('-fobjc-arc' not in argv) if index == 8 else ('-fobjc-arc' in argv),
             'preserve actual GuestTools MRC and input surface ARC compile modes')
        need(argv.count(old['sourceFiles'][index]['path']) == argv.count(old['objects'][index]['path']) == 1,
             'actual template source and output match the current display object')
        obj = out/'objects'/(str(index)+'-'+pathlib.Path(unit['source']['path']).stem+'.o')
        argv[argv.index(old['sourceFiles'][index]['path'])] = unit['source']['path']
        argv[argv.index(old['objects'][index]['path'])] = str(obj)
        run('compile-'+str(index),argv)
        sources[index], objects[index] = unit['source'],pin(obj)
    links = [c for c in old['commands'] if c['label'] == 'link-app' and c['exit'] == 0]
    need(len(links) == 1, 'one actual successful App105 linker command')
    argv = list(links[0]['argv'])
    need(argv.count(old['binary']['path']) == 1 and
         [v for v in argv if v.endswith('.o')] ==
         [row['path'] for row in old['objects']+old.get('externalPrecompiledObjects',[])],
         'current complete35 objects and external object in exact linker order')
    for unit in units:
        index = unit['index']
        argv[argv.index(old['objects'][index]['path'])] = objects[index]['path']
    argv[argv.index(old['binary']['path'])] = str(binary)
    run('link-app',argv)
    need(binary.stat().st_size <= 2097152, 'original App self-inspector size bound')
    for label,flag in [('validate-app','-validate_only'),('imports-app','-imports'),('exports-app','-exports')]:
        run(label,['xcrun','dyld_info',flag,str(binary)])
    for i in range(35):
        if i not in (8,17):
            need(sources[i] == old['sourceFiles'][i] and objects[i] == old['objects'][i],
                 'all other33 complete sources/objects whole, including Main32 and runtime anchor')
    for row in [*inherited,*plan['sourceFiles'],*objects]:
        exact(row)
    original_root = pathlib.Path(old['binary']['path']).parent
    app_files = [pin(p) for p in sorted(app.rglob('*')) if p.is_file()]
    for row in app_files:
        relative = pathlib.Path(row['path']).relative_to(app)
        if relative != pathlib.Path('VirtualMacIndependent27'):
            prior = pin(original_root/relative)
            need((row['bytes'],row['sha256']) == (prior['bytes'],prior['sha256']),
                 'all103 ordinary App resources whole unchanged')
    closure = {row['path']:row for row in old['actualIncludeClosure']}
    closure.update({row['path']:row for row in plan['sourceFiles']})
    record = copy.deepcopy(old)
    historical_keys = [k for k in record if k.startswith('actualDisplayObserverAndBitmapObjectsWholeApp')]
    historical_keys += ['actualObserver2AndBitmap5ObjectsWholeUnchanged','actualOther33CompiledObjectsWholeApp103',
        'actualMain32AndOther33CompiledObjectsWholeUnchanged','actualOther33CompiledObjectsWholeApp104',
        'actualChangedAppObjectIndices',
        'actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor']
    record['historicalApp105DisplayAndAnchorObjectVerification'] = {
        k:record.pop(k) for k in historical_keys if k in record}
    record.update(schema='Actual two-unit software keyboard and optional QGA diagnostic build from App105',
        builder=pin(__file__),sourceFiles=sources,objects=objects,actualIncludeClosure=list(closure.values()),
        commands=commands,binary=pin(binary),appFiles=app_files,inheritedCompiledAppCandidate=pin(OLD),
        inheritedCompilationCommands=pin(OLD.parent/'commands.json'),
        inheritedDisplayCompilationCommands=pin(COMPILE),inheritedInputSurfaceCompilationCommands=pin(SURFACE_COMPILE),softwareKeyboardAndOptionalQGADiagnosticSourcePlan=pin(plan_path),
        softwareKeyboardAndOptionalQGADiagnosticContractKey=CONTRACT,
        actualChangedAppObjectIndices=[8,17],actualUnchangedCompiledObjects=33,actualNewAppCompilations=2,
        actualOnlyRelinkedRuntimeAnchor=False,actualMain32SourceAndObjectWholeApp105=True,
        actualOther33CompiledObjectsWholeApp105=True,actualRuntime86AndAnchorWholeUnchanged=True,
        actualObserver3AndBitmap7WholeApp105=True,
        actualUARTAndBootArgsObjectsWholeApp105=True,allOriginalAppResourcesWholeUnchanged=True,
        actualOnlyMainObjectChanged=False,actualMainSourceChanged=False,codeSigned=False,
        deviceOperations=0,applicationBinaryLinked=True,applicationPackaged=True,
        actualGuestBoot=False,actualSSHVerified=False)
    record[CONTRACT] = plan['contract']
    save(out/'candidate.json',record)
    files = [pin(p) for p in sorted(out.rglob('*')) if p.is_file()]
    files += [pin(__file__),pin(OLD),pin(COMPILE),pin(SURFACE_COMPILE),pin(plan_path),old['actualRuntimeCandidate'],
              old['mainSourcePlan'],*inherited,*plan['sourceFiles'],*plan['componentSourcePlans'],*plan['originalInputs']]
    save(out/'freeze.json',dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),binary=pin(binary),
                          unchangedAppObjects=33,appCompilations=2,runtimeAndAnchorWhole=True)))


if __name__ == '__main__':
    main()
