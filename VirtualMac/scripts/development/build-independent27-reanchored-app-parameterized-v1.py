#!/usr/bin/env python3
"""Root-only pure runtime-anchor relink from an explicitly pinned App baseline.

Preserve the complete current Main source plan and named contract, all 34
non-anchor objects and App resources. Only object34 is replaced by the new
runtime manifest anchor; this builder never compiles a Main or signs an App.
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
    ap.add_argument('--baseline-app-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--baseline-app-sha256', required=True)
    ap.add_argument('--runtime-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    args = ap.parse_args()
    output = args.output.resolve()
    need(output.parent == N and not output.exists(), 'fresh HOST output')
    OLD = args.baseline_app_candidate.resolve()
    need(len(args.baseline_app_sha256) == 64 and all(c in '0123456789abcdef' for c in args.baseline_app_sha256),
         'explicit lowercase baseline App SHA256')
    need(pin(OLD)['sha256'] == args.baseline_app_sha256, 'actual pinned baseline App object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    plan = json.loads(pathlib.Path(old['mainSourcePlan']['path']).read_bytes())
    contract_key = old['mainSourceContractKey']
    need(isinstance(contract_key, str) and contract_key in old, 'actual named Main source contract')
    contract = plan[contract_key] if contract_key in plan else plan.get('contract')
    need(pin(old['mainSourcePlan']['path']) == old['mainSourcePlan'] and
         plan['contractKey'] == contract_key and
         plan['sourceFiles'] == [old['sourceFiles'][0]] and
         old[contract_key] == contract,
         'complete current Main source plan and named contract match the unchanged Main0 source')
    need(old['rawDiskThreadPoolAttachmentContract']['parentOriginalDescriptorBackendType']==1 and old['rawDiskThreadPoolAttachmentContract']['actualChildEncodedBackend']==3 and old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and old['actualMain20UIAndSSHDeferralPreserved'] is True,'preserve original raw FD route, selected VM view exposure and guest SSH deferral')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['baselineRuntimeCandidate']['sha256']=='aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b' and runtime['nativeGPUTaskNoContainerEntitlementActuallyPresent'] is True and runtime['nativeGPUTaskCanExecuteCDHashEntitlementActuallyPresent'] is True and runtime['nativeGPUTaskExtendedVirtualAddressingEntitlementActuallyPresent'] is True and runtime['all29CPUObjectsWholeRuntime86'] is True and runtime['bothSignedCPUProvidersWholeRuntime86'] is True and runtime['ownedPGRemoteTaskParentTransportV1Contract']['originalNonzeroTaskStillPGRemoteTask'] is True and runtime['ownedPGRemoteTaskParentTransportV1Contract']['noGPUCommandsOrRepliesEmulated'] is True and runtime['nativeGPUTaskImagesPreviouslySignedAndWholeInherited']==2,'actual native GPU runtime on historical R86 baseline; all34 non-anchor App objects remain whole')
    prior_runtime = json.loads(pathlib.Path(old['actualRuntimeCandidate']['path']).read_bytes())
    need(pin(old['actualRuntimeCandidate']['path']) == old['actualRuntimeCandidate'] and prior_runtime['baselineRuntimeCandidate']==runtime['baselineRuntimeCandidate'] and
         old['sourceFiles'][34] == prior_runtime['anchorSource'] and
         old['objects'][34] == prior_runtime['anchorIOSObject'],
         'actual baseline runtime source and compiled anchor binding')
    need(len(runtime['nativeGPUTaskActualEntitlements']) == 9 and
         runtime['nativeGPUTaskActualEntitlements'] == prior_runtime['nativeGPUTaskActualEntitlements'],
         'same actual nine Task entitlements as the baseline runtime')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited current App input')
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
         'current Main and other33 full sources and compiled objects reused whole')
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
    record.update(schema='Actual pure runtime anchor relink with34 whole baseline App objects and whole Main source contract',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects, actualIncludeClosure=list(closure.values()),
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
                  actualOnlyRelinkedRuntimeAnchor=True,actualMainAndOther33CompiledObjectsWholeUnchanged=True,
                  allOriginalAppResourcesWholeUnchanged=True,
                  codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    # Prior build-delta claims remain historical; the Main source metadata,
    # source plan and named contract remain the exact inherited values.
    historical_keys = {
        'actualChangedAppObjectIndices', 'actualUnchangedCompiledObjects',
        'actualNewAppCompilations', 'actualOnlyRelinkedRuntimeAnchor',
        'actualOnlyMainObjectChanged', 'actualMainSourceChanged',
        'actualMain32AndOther33CompiledObjectsWholeUnchanged',
        'actualMainAndOther33CompiledObjectsWholeUnchanged'
    }
    for key in old:
        if (key.startswith(('actualOther34ObjectsWholeApp', 'all34OtherAppObjectsWholeApp')) or
            (key.startswith('actualRuntime') and key.endswith('AndAnchorWholeUnchanged'))):
            historical_keys.add(key)
            record.pop(key, None)
    record['historicalBaselineAppBuild'] = {key:old[key] for key in historical_keys if key in old}
    record.pop('actualMain32AndOther33CompiledObjectsWholeUnchanged', None)
    record['actualOnlyMainObjectChanged'] = False
    record['actualMainSourceChanged'] = False
    record['actualChangedAppObjectIndices'] = [34]
    record['actualMainAndOther33CompiledObjectsWholeUnchanged'] = True
    record['actualMainSourcePlanAndContractWholeUnchanged'] = True
    record['actualNativeRuntimeGPUServiceIntegrationOnlyNewAnchor'] = True
    need(record['mainSourcePlan'] == old['mainSourcePlan'] and
         record['mainSourceContractKey'] == contract_key and record[contract_key] == old[contract_key],
         'current Main source plan and contract preserved verbatim through anchor-only relink')
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), old['mainSourcePlan'], old['actualRuntimeCandidate'], pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *closure.values()]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=34, appCompilations=0)))


if __name__ == '__main__':
    main()
