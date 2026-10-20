#!/usr/bin/env python3
"""Relink actual App96 Main32 and other33 whole objects with a new runtime anchor.

Only Root executes this HOST builder. All34 Main32 App96 code objects and resources are
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
OLD = N / 'independent27-actual-app-guest-process-v96-attempt1/candidate.json'
OLD_SHA = '511f8ca4c27a1bfe389e67bb07b9c69869c1072e2c27b871da74519201f8f5ba'


def pin(path):
    path = pathlib.Path(path).resolve()
    need(path.is_file() and not path.is_symlink(), 'actual regular file: ' + str(path))
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
    need(pin(OLD)['sha256'] == OLD_SHA, 'original actual App96 Main32 object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    need(old['mainSourcePlan']['sha256']=='935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866' and old['sourceFiles'][0]['sha256']=='3b3f6d3797edb88536c0609e01ec813177d64387e921e90a060b2bfdd0c6a440' and old['objects'][0]['sha256']=='cb3487165f9bb83cdd0c6d32de44caf8afaf8794b20f5e68bac725ad3822cc01' and old['mainSourceContractKey']=='normalBootOriginalArgsV32Contract','actual Main32 source/object and normal original boot arguments restoration plan whole')
    plan = json.loads(pathlib.Path(old['mainSourcePlan']['path']).read_bytes())
    need(pin(old['mainSourcePlan']['path']) == old['mainSourcePlan'] and
         plan['contractKey'] == old['mainSourceContractKey'] and
         plan['sourceFiles'] == [old['sourceFiles'][0]] and
         old[old['mainSourceContractKey']] == plan['contract'],
         'actual Main32 complete source and named original boot arguments contract whole')
    need(old['rawDiskThreadPoolAttachmentContract']['parentOriginalDescriptorBackendType']==1 and old['rawDiskThreadPoolAttachmentContract']['actualChildEncodedBackend']==3 and old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and old['actualMain20UIAndSSHDeferralPreserved'] is True,'preserve original raw FD route, selected VM view exposure and guest SSH deferral')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['baselineRuntimeCandidate']==old['actualRuntimeCandidate'] and runtime['cpuGuestMsgbufReadV1Candidate']==runtime['cpu29SourceProof'] and len(runtime['actualChangedCPUObjects'])==1 and len(runtime['actualWholeCPUObjects'])==28 and runtime['allMDPGVTAndOtherProvidersWholeRuntime79'] is True,'actual Runtime80 derives from installed Runtime79 with one Life64 CPU object and all other providers whole')
    prior_runtime = json.loads(pathlib.Path(old['actualRuntimeCandidate']['path']).read_bytes())
    need(pin(old['actualRuntimeCandidate']['path']) == old['actualRuntimeCandidate'] and
         old['sourceFiles'][34] == prior_runtime['anchorSource'] and
         old['objects'][34] == prior_runtime['anchorIOSObject'],
         'actual App96 Runtime79 source and compiled anchor binding')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited App96 Main32 input')
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
    need(source_files[:34] == old['sourceFiles'][:34] and objects[:34] == old['objects'][:34],
         'actual Main32 and other33 full sources and compiled objects reused whole')
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
    record.update(schema='Actual App97 pure runtime anchor relink with34 whole App96 Main32 objects',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects, actualIncludeClosure=list(closure.values()),
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
                  actualOnlyRelinkedRuntimeAnchor=True,actualMain32AndOther33CompiledObjectsWholeUnchanged=True,
                  actualOriginalBootArgsRestorationCodePresent=True,
                  allOriginalAppResourcesWholeUnchanged=True,
                  codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    # All Main32 code is inherited; the current delta only replaces the Runtime79 anchor.
    historical_keys=('actualChangedAppObjectIndices','actualUnchangedCompiledObjects',
        'actualNewAppCompilations','actualOnlyRelinkedRuntimeAnchor','actualOnlyMainObjectChanged',
        'actualOther34ObjectsWholeApp85','actualRuntime71AndAnchorWholeUnchanged','actualMainSourceChanged',
        'actualOther34ObjectsWholeApp94','actualRuntime79AndAnchorWholeUnchanged')
    record['historicalApp96Main32Build']={key:old[key]for key in historical_keys if key in old}
    for key in ('actualOther34ObjectsWholeApp85','actualRuntime71AndAnchorWholeUnchanged',
                'actualOther34ObjectsWholeApp94','actualRuntime79AndAnchorWholeUnchanged'):
        record.pop(key,None)
    record['actualOnlyMainObjectChanged']=False
    record['actualMainSourceChanged']=False
    record['actualChangedAppObjectIndices']=[34]
    record['actualDisplayObserverAndBitmapObjectsWholeApp96']=True
    record['actualUARTAndBootArgsObjectsWholeApp96']=True
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), old['mainSourcePlan'], old['actualRuntimeCandidate'], pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *closure.values()]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=34, appCompilations=0)))


if __name__ == '__main__':
    main()
