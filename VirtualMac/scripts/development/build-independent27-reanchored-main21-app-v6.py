#!/usr/bin/env python3
"""Relink actual App55 Main21 and other33 whole objects with a new runtime anchor.

Only Root executes this HOST builder. All34 Main21 App55 code objects and resources are
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
OLD = N / 'independent27-actual-app-raw-disk-main21-v55-attempt1/candidate.json'
OLD_SHA = '45ada277352c42ada8be51e5baa60d3c74992d809d871cf4b5b4f70f75fa2ad0'


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
    need(pin(OLD)['sha256'] == OLD_SHA, 'original actual App55 Main21 object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    need(old['sourceCandidate']['sha256']=='30e4b48aefa97c98eceb9bd3c4a5d8981e88bbedcebafa5d6af7ae0a4e95b3fb' and old['objects'][0]['sha256']=='4eee5fff26ce0cb171bb10891e149bb3cb61506870431d03d28a1da65d194d68','actual Main21 source/object whole; no Main20 or Main19 fallback')
    need(old['rawDiskThreadPoolAttachmentContract']['parentOriginalDescriptorBackendType']==1 and old['rawDiskThreadPoolAttachmentContract']['actualChildEncodedBackend']==3 and old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and old['actualMain20UIAndSSHDeferralPreserved'] is True,'preserve original raw FD route, selected VM view exposure and guest SSH deferral')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited App55 Main21 input')
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
    record = copy.deepcopy(old)
    record.update(schema='Actual App56 pure runtime anchor relink with34 whole App55 Main21 objects',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects,
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
                  actualOnlyRelinkedRuntimeAnchor=True,actualMain21AndOther33CompiledObjectsWholeUnchanged=True,
                  codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    if 'actualRuntime43AndAnchorWholeUnchanged' in record:
        record['historicalApp55Runtime43AndAnchorWholeUnchanged']=record.pop('actualRuntime43AndAnchorWholeUnchanged')
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *old['actualIncludeClosure']]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=34, appCompilations=0)))


if __name__ == '__main__':
    main()
