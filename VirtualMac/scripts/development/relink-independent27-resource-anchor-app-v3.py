#!/usr/bin/env python3
"""Relink the actual App using unchanged objects and one true new runtime anchor.

Only the anchor changes when adding a sealed runtime data resource. The other
30 objects and every copied App resource are verified against frozen inputs.
No device action, signing, guest start, or synthetic runtime result is performed.
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
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def exact(row):
    assert pin(row['path']) == row, row['path']
    return pathlib.Path(row['path'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--old-app-candidate',required=True,type=pathlib.Path)
    parser.add_argument('--runtime-candidate',required=True,type=pathlib.Path)
    parser.add_argument('--output',required=True,type=pathlib.Path)
    args = parser.parse_args()
    old_path,runtime_path,out = args.old_app_candidate.resolve(),args.runtime_candidate.resolve(),args.output.resolve()
    assert out.parent == N and not out.exists()
    old,runtime = json.loads(old_path.read_bytes()),json.loads(runtime_path.read_bytes())
    old_signed_freeze = N/'independent27-signed-app-owned-bundle-product-v6-attempt1/freeze.json'
    frozen_old = json.loads(old_signed_freeze.read_bytes())['files']
    assert pin(old_path) in frozen_old, 'old actual compilation candidate is bound by the installed signed App freeze'
    for row in frozen_old:
        exact(row)
    for row in json.loads((runtime_path.parent/'freeze.json').read_bytes())['files']:
        exact(row)
    assert old['applicationBinaryLinked'] and old['applicationPackaged'] and not old['codeSigned']
    assert runtime['actualProductPreflightPassed']
    assert len(old['objects']) == len(old['sourceFiles']) == 31
    assert old['runtimeRoot'] == runtime['canonicalDeviceRoot']
    assert not old['runtimeProviderLibraries']
    for row in old['sourceFiles']+old['actualIncludeClosure']+old['objects']+old['appFiles']:
        exact(row)
    anchor = runtime['anchorSource']
    anchor_object = runtime['anchorIOSObject']
    exact(anchor);exact(anchor_object)
    assert pathlib.Path(old['sourceFiles'][30]['path']).name == pathlib.Path(anchor['path']).name
    old_anchor_path = old['sourceFiles'][30]['path']
    out.mkdir(mode=0o700)
    app = out/'VirtualMacIndependent27.app'
    shutil.copytree(pathlib.Path(old['binary']['path']).parent,app)
    assert not any(path.is_symlink() for path in app.rglob('*'))
    binary = app/'VirtualMacIndependent27'
    link = next(row for row in old['commands'] if row['label'] == 'link-app')
    assert link['exit'] == 0
    argv = list(link['argv'])
    assert argv.count(old['objects'][30]['path']) == argv.count(old['binary']['path']) == 1
    argv[argv.index(old['objects'][30]['path'])] = anchor_object['path']
    argv[argv.index(old['binary']['path'])] = str(binary)
    assert all(argv.count(row['path']) == 1 for row in old['objects'][:30])
    commands = []

    def run(label,argv):
        result = subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=result.returncode))
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        assert result.returncode == 0,(label,result.stderr.decode(errors='replace'))

    run('link-app',argv)
    assert binary.stat().st_size <= 2097152
    assert bytes.fromhex(runtime['manifest']['sha256']) in binary.read_bytes()
    for label,mode in [('validate-app','-validate_only'),('imports-app','-imports'),('exports-app','-exports')]:
        run(label,['xcrun','dyld_info',mode,binary])
    for row in old['objects'][:30]+old['sourceFiles'][:30]:
        exact(row)
    app_files = [pin(path) for path in sorted(app.rglob('*')) if path.is_file()]
    old_files = {str(pathlib.Path(row['path']).relative_to(pathlib.Path(old['binary']['path']).parent)):row for row in old['appFiles']}
    for row in app_files:
        name = str(pathlib.Path(row['path']).relative_to(app))
        if name != 'VirtualMacIndependent27':
            assert row['sha256'] == old_files[name]['sha256'] and row['bytes'] == old_files[name]['bytes']
    record = copy.deepcopy(old)
    record.update(schema='Actual independent27 reused App objects and new resource manifest anchor v1',
        builder=pin(__file__),inheritedActualObjectCompilationEvidence=pin(old_path),
        actualNewAnchorObjectEvidence=pin(runtime_path),sourceFiles=old['sourceFiles'][:30]+[anchor],
        objects=old['objects'][:30]+[anchor_object],commands=commands,
        actualIncludeClosure=[anchor if row['path'] == old_anchor_path else row for row in old['actualIncludeClosure']],
        binary=pin(binary),appFiles=app_files,actualRuntimeCandidate=pin(runtime_path),
        reusedWholeUnchangedAppObjects=30,actualOnlyAnchorObjectChanged=True,
        actualOnlyMainAppFileChanged=True,deviceOperations=0,readyForDeviceExecution=False)
    (out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n')
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += [pin(__file__),pin(old_path),pin(runtime_path),pin(old_signed_freeze),pin(runtime_path.parent/'freeze.json')]
    files += record['sourceFiles']+record['actualIncludeClosure']+record['objects']
    (out/'freeze.json').write_text(json.dumps(dict(files=list({row['path']:row for row in files}.values())),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),binary=pin(binary))))


if __name__ == '__main__':
    main()
