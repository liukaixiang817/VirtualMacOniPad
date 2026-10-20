#!/usr/bin/env python3
"""Relink precompiled Main20 and 33 actual App52 objects with a new genuine runtime anchor.

Only Root executes this HOST builder. Exact existing component objects and resources are
reused by exact content pins; no guest or device code is executed here.
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
OLD = N / 'independent27-actual-app-scratch-gpr-trace-anchor-v52-attempt1/candidate.json'
OLD_SHA = '3b360905121b3c532082eb15bdd6267b457ba3cd1e0b1deee7290a1dfb6d9a29'


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runtime-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--main-object-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    args = ap.parse_args()
    output = args.output.resolve()
    need(output.parent == N and not output.exists(), 'fresh HOST output')
    need(pin(OLD)['sha256'] == OLD_SHA, 'original actual App52 object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    main_object = json.loads(args.main_object_candidate.read_bytes())
    need(pin(args.main_object_candidate)['sha256']=='213a5e76ce44b458e7cc2c937004237a4470942e45e8cbab095e1d1c8423b5bd', 'actual Main20 precompiled candidate')
    main_source_pin=main_object['sourceCandidate'];main_source=json.loads(pathlib.Path(main_source_pin['path']).read_bytes())
    need(pin(main_source_pin['path'])==main_source_pin and main_object['actualCompileExit']==0 and main_object['actualIOSMainCompiled'] is True, 'actual Main20 source and successful iOS compile')
    need(main_source['baselineMain19']==old['sourceCandidate'] and main_source['baselineMain19Source']==old['sourceFiles'][0], 'actual Main20 derives from installed Main19 source')
    need(main_source['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and main_source['genuineSSHRegistrationRouteEnabled'] is False, 'guest SSH truly deferred for first basic boot')
    need(all(v is True for k,v in main_source['urlDisplayPresentationContract'].items() if k!='actualGuestFrameOrBootClaimed') and main_source['urlDisplayPresentationContract']['actualGuestFrameOrBootClaimed'] is False,'exact validated URL display-presentation source contract')
    for row in (main_object['source'],main_object['object'],main_object['actualCompile'],main_source['sourceDiff']):
        need(pin(row['path'])==row,'exact precompiled Main20 source/object proof')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited App30 input')
    need(len(old['objects']) == 35 and len(old['sourceFiles']) == 35, 'original 35 compile units')
    need(old['objects'][0]==main_object['baselineMain19Object'],'exact inherited Main19 object is replaced by precompiled Main20')
    need(pathlib.Path(old['sourceFiles'][34]['path']).name == 'vm27_independent_runtime_product_anchor_v1.c',
         'only actual last anchor unit replaced')
    for key in ('anchorSource', 'anchorIOSObject', 'manifest'):
        need(pin(runtime[key]['path']) == runtime[key], 'actual new runtime ' + key)
    output.mkdir(mode=0o700)
    app = output / 'VirtualMacIndependent27.app'
    shutil.copytree(pathlib.Path(old['binary']['path']).parent, app)
    need(not any(p.is_symlink() for p in app.rglob('*')), 'regular inherited resources')
    binary = app / 'VirtualMacIndependent27'
    commands = []

    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        save(output / 'commands.json', commands)
        need(result.returncode == 0, label + ': ' + result.stderr.decode(errors='replace'))

    original_links = [c for c in old['commands'] if c['label'] == 'link-app']
    need(len(original_links) == 1 and original_links[0]['exit'] == 0, 'original successful linker arguments')
    argv = copy.deepcopy(original_links[0]['argv'])
    old_anchor = old['objects'][34]['path']
    need(argv.count(old_anchor) == 1 and argv.count(old['binary']['path']) == 1, 'one true anchor and output')
    argv[argv.index(old_anchor)] = runtime['anchorIOSObject']['path']
    need(argv.count(old['objects'][0]['path'])==1,'one original Main19 object in actual linker command')
    argv[argv.index(old['objects'][0]['path'])]=main_object['object']['path']
    argv[argv.index(old['binary']['path'])] = str(binary)
    run('link-app', argv)
    need(binary.stat().st_size <= 2097152, 'original parent self-inspector limit')
    run('validate-app', ['xcrun', 'dyld_info', '-validate_only', str(binary)])
    run('imports-app', ['xcrun', 'dyld_info', '-imports', str(binary)])
    run('exports-app', ['xcrun', 'dyld_info', '-exports', str(binary)])
    # Main20 was compiled once by its pinned HOST object builder; all other
    # 33 component objects stay whole, and the actual runtime supplies its anchor.
    source_files = [main_object['source']] + old['sourceFiles'][1:34] + [runtime['anchorSource']]
    objects = [main_object['object']] + old['objects'][1:34] + [runtime['anchorIOSObject']]
    for row in [*source_files, *objects, *old.get('externalPrecompiledObjects', [])]:
        need(pin(row['path']) == row, 'inputs stable through actual relink')
    original_root = pathlib.Path(old['binary']['path']).parent
    app_files = [pin(p) for p in sorted(app.rglob('*')) if p.is_file()]
    for row in app_files:
        rel = pathlib.Path(row['path']).relative_to(app)
        if rel != pathlib.Path('VirtualMacIndependent27'):
            need((row['bytes'], row['sha256']) == (pin(original_root / rel)['bytes'], pin(original_root / rel)['sha256']),
                 'every existing App resource whole unchanged')
    record = copy.deepcopy(old)
    record.update(schema='Actual Main20 URL display and SSH-deferred App with 33 inherited App52 objects',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects,
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  sourceCandidate=main_source_pin,main20ObjectCandidate=pin(args.main_object_candidate),
                  sourceDiff=main_source['sourceDiff'],urlDisplayPresentationContract=main_source['urlDisplayPresentationContract'],
                  sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,genuineSSHRegistrationRouteEnabled=False,
                  genuineSSHBridgeDormantForFirstBoot=True,trueSSHRegistrationAfterRuntimeBindBeforeStart=False,
                  persistentSSHServiceImplementationRetainedButInvocationDeferred=True,guestSSHRemainsFutureWork=True,
                  ownedSSHService=copy.deepcopy(main_source['ownedSSHService']),
                  priorMain19AppCandidate=pin(OLD),
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=33, actualNewAppCompilations=0,
                  actualPrecompiledMain20ObjectReused=True,actualPriorMain20Compilations=1,
                  actualOnlyRelinkedRuntimeAnchor=False, codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    if 'finalNetworkAndSSHStillRequired' in record:
        record['historicalPriorGuestSSHAcceptanceRequirement']=record.pop('finalNetworkAndSSHStillRequired')
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *old['actualIncludeClosure'],pin(args.main_object_candidate),pin(args.main_object_candidate.parent/'freeze.json'),main_source_pin,pin(pathlib.Path(main_source_pin['path']).parent/'freeze.json'),main_source['sourceDiff'],main_object['actualCompile']]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=33, appCompilations=0, precompiledMain20Reused=True)))


if __name__ == '__main__':
    main()
