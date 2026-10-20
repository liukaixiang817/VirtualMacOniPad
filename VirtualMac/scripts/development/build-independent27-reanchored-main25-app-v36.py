#!/usr/bin/env python3
"""Relink actual App83 Main25 and other33 whole objects with a new runtime anchor.

Only Root executes this HOST builder. All34 Main25 App83 code objects and resources are
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
OLD = N / 'independent27-actual-app-reset-snapshot-maintenance-v83-attempt1/candidate.json'
OLD_SHA = '1b821e5a8d2ee316f7247a85bfc4810b32ae3a32f1e9000cc94d452b8b4a2dbf'


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
    ap.add_argument('--output', required=True, type=pathlib.Path)
    args = ap.parse_args()
    output = args.output.resolve()
    need(output.parent == N and not output.exists(), 'fresh HOST output')
    need(pin(OLD)['sha256'] == OLD_SHA, 'original actual App83 Main25 object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    need(old['mainSourcePlan']['sha256']=='e6d4bb4013f3c86fab36213cadb131fd397940d95747a6d6c1b7e174fdbfeee1' and old['sourceFiles'][0]['sha256']=='e2635789fae84fb86fb99d96de92a3bb8ccdf36388506c8b9aaa76df44a17dd8' and old['objects'][0]['sha256']=='804db4f22cc2f1d1abb9983f71f2ce62ff3621049685d1f5f6460a8e5d5a86a0' and old['mainSourceContractKey']=='pl011UARTBootArgumentsMaintenanceV25Contract','actual Main25 source/object and UART maintenance plan whole')
    need(old['rawDiskThreadPoolAttachmentContract']['parentOriginalDescriptorBackendType']==1 and old['rawDiskThreadPoolAttachmentContract']['actualChildEncodedBackend']==3 and old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and old['actualMain20UIAndSSHDeferralPreserved'] is True,'preserve original raw FD route, selected VM view exposure and guest SSH deferral')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['baselineRuntimeCandidate']==old['actualRuntimeCandidate'] and runtime['cpu28OtherObjectsWholeRuntime69'] is True and runtime['cpuResetPanicPrefixV1Contract']['onlyLife58ObjectChanged'] is True,'actual new Runtime70 panic prefix product derives from the installed Runtime69')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited App83 Main25 input')
    need(len(old['objects']) == 35 and len(old['sourceFiles']) == 35, 'original 35 compile units')
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
    argv[argv.index(old['binary']['path'])] = str(binary)
    run('link-app', argv)
    need(binary.stat().st_size <= 2097152, 'original parent self-inspector limit')
    run('validate-app', ['xcrun', 'dyld_info', '-validate_only', str(binary)])
    run('imports-app', ['xcrun', 'dyld_info', '-imports', str(binary)])
    run('exports-app', ['xcrun', 'dyld_info', '-exports', str(binary)])
    # Resource and code provenance is inherited truthfully; only the anchor
    # was compiled by the new runtime builder, then linked here.
    source_files = old['sourceFiles'][:34] + [runtime['anchorSource']]
    objects = old['objects'][:34] + [runtime['anchorIOSObject']]
    for row in [*source_files, *objects, *old.get('externalPrecompiledObjects', [])]:
        need(pin(row['path']) == row, 'inputs stable through actual relink')
    original_root = pathlib.Path(old['binary']['path']).parent
    app_files = [pin(p) for p in sorted(app.rglob('*')) if p.is_file()]
    for row in app_files:
        rel = pathlib.Path(row['path']).relative_to(app)
        if rel != pathlib.Path('VirtualMacIndependent27'):
            need((row['bytes'], row['sha256']) == (pin(original_root / rel)['bytes'], pin(original_root / rel)['sha256']),
                 'every existing App resource whole unchanged')
    closure={row['path']:row for row in old['actualIncludeClosure'] if row['path']!=old['sourceFiles'][34]['path']}
    closure[runtime['anchorSource']['path']]=runtime['anchorSource']
    record = copy.deepcopy(old)
    record.update(schema='Actual App84 pure runtime anchor relink with34 whole App83 Main25 objects',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects, actualIncludeClosure=list(closure.values()),
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
                  actualOnlyRelinkedRuntimeAnchor=True,actualMain25AndOther33CompiledObjectsWholeUnchanged=True,
                  codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    # App83 compiled Main25 and replaced its anchor; only the new anchor changes now.
    historical_keys=('actualUnchangedCompiledObjects','actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor',
                     'actualOnlyMainObjectChanged','actualMain25AndNewRuntimeAnchorChanged',
                     'actualUARTAndBootArgsMaintenanceOrderFixed','actualOther33ObjectsWholeApp82',
                     'actualMainSourceChanged','actualChangedAppObjectIndices')
    record['historicalApp83Main25AndAnchorCompilation']={key:old[key]for key in historical_keys if key in old}
    for key in ('actualOnlyMainObjectChanged','actualMain25AndNewRuntimeAnchorChanged',
                'actualUARTAndBootArgsMaintenanceOrderFixed','actualOther33ObjectsWholeApp82','actualMainSourceChanged'):
        record.pop(key,None)
    record['actualChangedAppObjectIndices']=[34]
    record['actualDisplayObserverAndBitmapObjectsWholeApp83']=True
    record['pl011UARTBootArgumentsMaintenanceV25ContractAppliesToHistoricalApp83DeltaOnly']=True
    record['actualUARTAndBootArgsObjectsWholeApp83']=True
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *closure.values()]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=34, appCompilations=0)))


if __name__ == '__main__':
    main()
