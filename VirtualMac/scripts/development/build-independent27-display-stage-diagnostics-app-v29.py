#!/usr/bin/env python3
"""Root-only HOST build: two bounded display diagnostic units, no runtime change.

The actual App78 compile/link commands are reused, with only the two source
and object paths and final binary path changed. This builder never signs or
accesses a device. Root reviews its source before executing it.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OLD = N / 'independent27-actual-app-range-transaction-anchor-v78-attempt1/candidate.json'
OLD_SHA = '133a6c53754e5fb824c564e1e6d33ac4d60c4ebf44773f5c8f7b1ee66cb535b9'
PLAN = N / 'independent27-display-stage-diagnostics-source-v1-attempt1/candidate.json'
PLAN_SHA = 'e8be4afc0e4852e7ee907a0ec2fc3577754ff131f38d163c67ea755d31788f52'
COMPILES = N / 'independent27-actual-app-future-persistent-ssh-v30-attempt1/commands.json'
COMPILES_SHA = 'e7369ecf7e30c19f45ef76174c72a35ecdddb46bfc749fb49f0648188439e817'


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def exact(row):
    need(pin(row['path']) == row, 'actual whole input changed: ' + row['path'])
    return pathlib.Path(row['path'])


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh local App79 output')
    need(pin(OLD)['sha256'] == OLD_SHA and pin(PLAN)['sha256'] == PLAN_SHA and
         pin(COMPILES)['sha256'] == COMPILES_SHA, 'fixed actual App78, diagnostic plan, and actual original compile commands')
    old, plan = json.loads(OLD.read_bytes()), json.loads(PLAN.read_bytes())
    need(len(old['objects']) == len(old['sourceFiles']) == 35 and
         plan['actualChangedAppObjectIndices'] == [15, 16] and len(plan['sourceFiles']) == 2,
         'exact two intended display units of actual35')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'],
                *old.get('externalPrecompiledObjects', []), *old['appFiles'],
                *plan['sourceFiles'], *plan['baselineSources'], plan['sourceDiff']]:
        exact(row)
    need(old['sourceFiles'][15:17] == plan['baselineSources'], 'exact App78 observer V1 and bitmap V4 source provenance')
    need(old['objects'][0]['sha256'] == '4eee5fff26ce0cb171bb10891e149bb3cb61506870431d03d28a1da65d194d68' and
         old['actualMain21ObjectReused'] is True, 'actual Main21 object retained')
    need(old['actualMain20UIAndSSHDeferralPreserved'] is True and
         old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True,
         'same actual UI and deferred guest SSH')
    runtime = json.loads(exact(old['actualRuntimeCandidate']).read_bytes())
    need(old['actualRuntimeCandidate']['sha256'] == 'badb8d9bdb49551c7980bf6bf03fbe500144af7b2934c24e34cbbb27720ca34a' and
         runtime['localCodeSigned'] is True and runtime['actualProductPreflightPassed'] is True,
         'actual whole Runtime66 remains selected')
    need(old['sourceFiles'][34] == runtime['anchorSource'] and old['objects'][34] == runtime['anchorIOSObject'],
         'actual Runtime66 manifest anchor source and object stay whole')
    original_compiles = json.loads(COMPILES.read_bytes())
    original_links = [c for c in old['commands'] if c['label'] == 'link-app']
    need(len(original_links) == 1 and original_links[0]['exit'] == 0, 'actual successful App78 link command')
    out.mkdir(mode=0o700)
    objects_dir = out / 'objects'
    objects_dir.mkdir(mode=0o700)
    app = out / 'VirtualMacIndependent27.app'
    original_root = pathlib.Path(old['binary']['path']).parent
    shutil.copytree(original_root, app)
    need(not any(p.is_symlink() for p in app.rglob('*')), 'ordinary inherited App resources')
    binary = app / 'VirtualMacIndependent27'
    commands, sources, objects = [], copy.deepcopy(old['sourceFiles']), copy.deepcopy(old['objects'])

    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        save(out / 'commands.json', commands)
        need(result.returncode == 0, label + ': ' + result.stderr.decode(errors='replace'))

    replacements = {}
    for index, source in zip((15, 16), plan['sourceFiles'], strict=True):
        rows = [c for c in original_compiles if c['label'] == 'compile-' + str(index)]
        need(len(rows) == 1 and rows[0]['exit'] == 0, 'one actual original successful display compilation')
        argv = copy.deepcopy(rows[0]['argv'])
        old_source, old_object = old['sourceFiles'][index]['path'], old['objects'][index]['path']
        need(argv.count(old_source) == argv.count(old_object) == 1,
             'exact actual source and output in original display compile command')
        target = objects_dir / (str(index) + '-' + pathlib.Path(source['path']).stem + '.o')
        argv[argv.index(old_source)] = source['path']
        argv[argv.index(old_object)] = str(target)
        run('compile-' + str(index), argv)
        sources[index], objects[index] = source, pin(target)
        replacements[old_object] = str(target)
    argv = copy.deepcopy(original_links[0]['argv'])
    for before, after in replacements.items():
        need(argv.count(before) == 1, 'one actual display object in App78 link')
        argv[argv.index(before)] = after
    need(argv.count(old['binary']['path']) == 1, 'one actual App78 binary output')
    argv[argv.index(old['binary']['path'])] = str(binary)
    run('link-app', argv)
    need(binary.stat().st_size <= 2097152, 'same parent self-inspector bound')
    run('validate-app', ['xcrun', 'dyld_info', '-validate_only', str(binary)])
    whole = []
    for index, (before, after) in enumerate(zip(old['objects'], objects, strict=True)):
        exact(after)
        if index not in (15, 16):
            need(after == before, 'one of33 unchanged actual App78 objects')
            whole.append(after)
    app_files = [pin(p) for p in sorted(app.rglob('*')) if p.is_file()]
    for row in app_files:
        relative = pathlib.Path(row['path']).relative_to(app)
        if relative != pathlib.Path('VirtualMacIndependent27'):
            before = pin(original_root / relative)
            need((row['bytes'], row['sha256']) == (before['bytes'], before['sha256']), 'whole actual App78 resource')
    record = copy.deepcopy(old)
    history_keys = ('actualUnchangedCompiledObjects', 'actualNewAppCompilations',
                    'actualOnlyRelinkedRuntimeAnchor', 'actualMain21AndOther33CompiledObjectsWholeUnchanged')
    record['historicalApp78RuntimeAnchorOnlyRelink'] = {k: record.pop(k) for k in history_keys if k in record}
    record.update(schema='Actual App79 bounded display-stage diagnostics with33 whole App78 objects',
                  builder=pin(__file__), sourceFiles=sources, objects=objects, commands=commands,
                  binary=pin(binary), appFiles=app_files, inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(COMPILES), actualUnchangedCompiledObjects=33,
                  actualNewAppCompilations=2, actualOnlyRelinkedRuntimeAnchor=False,
                  actualMain21AndOther32CompiledObjectsWholeUnchanged=True,
                  actualRuntime66AndAnchorWholeUnchanged=True, actualChangedAppObjectIndices=[15, 16],
                  displayStageDiagnosticsSourceCandidate=pin(PLAN), displayStageDiagnosticsContract=plan['contract'],
                  codeSigned=False, deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0,
                  applicationBinaryLinked=True, applicationPackaged=True, actualGuestBoot=False,
                  actualSSHVerified=False)
    save(out / 'candidate.json', record)
    files = [pin(p) for p in sorted(out.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), pin(PLAN), pin(COMPILES), old['actualRuntimeCandidate'],
              *sources, *objects, *old.get('externalPrecompiledObjects', []), *old['actualIncludeClosure'],
              plan['sourceDiff'], *plan['baselineSources']]
    save(out / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0, codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'),
                          changedObjects=2, wholeObjects=len(whole), runtimeWhole=True)))


if __name__ == '__main__':
    main()
