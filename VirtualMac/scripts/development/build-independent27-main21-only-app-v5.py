#!/usr/bin/env python3
"""Relink only precompiled Main21 into actual App54; all34 other objects and Runtime43 stay whole.

Only Root executes this HOST builder. The34 unchanged App54 code objects and all existing resources are
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
OLD = N / 'independent27-actual-app-run-tail-trace-anchor-v54-attempt1/candidate.json'
OLD_SHA = '45bf476aebb68af3497eaa824ebb4edfd6c4e622d155b7f0e3a7bd7708834038'


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
    need(pin(OLD)['sha256'] == OLD_SHA, 'original actual App54 Main20 object provenance')
    old = json.loads(OLD.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    need(pin(args.runtime_candidate)==old['actualRuntimeCandidate'],'actual same Runtime43 and its anchor; no runtime recompile or reanchor')
    main_object=json.loads(args.main_object_candidate.read_bytes())
    need(pin(args.main_object_candidate)['sha256']=='30e4b48aefa97c98eceb9bd3c4a5d8981e88bbedcebafa5d6af7ae0a4e95b3fb','exact actual compiled Main21 raw disk source candidate')
    main_source_pin=pin(args.main_object_candidate);main_source=main_object
    need(main_source['sourceCandidate']==old['sourceCandidate'] and main_source['baselineCompiledAppCandidate']==pin(OLD),'Main21 derives from actual current Main20 and App54')
    need(main_source['actualRuntimeCandidate']==old['actualRuntimeCandidate'] and main_source['actualInheritedWholeAppObjects']==34 and main_source['runtime43AnchorWholeUnchanged'] is True,'Main21 retains exact34 App54 objects and Runtime43 anchor')
    raw_contract=main_source['rawDiskThreadPoolAttachmentContract']
    need(raw_contract['parentOriginalDescriptorBackendType']==1 and raw_contract['actualChildEncodedBackend']==3 and all(raw_contract[k] is True for k in ('onlyIndependent27OrdinaryRawDiskImgChanged','otherBackendPublicInitializationWholeUnchanged','cachingAutomatic0AndFullSynchronization1Preserved','rootStorageRole1Preserved','originalRawDiskImageFormatAndOwnedFDThreadPoolIOSelected','noDI2SuccessFabricated','noMacOS13Fallback','missingClassesOrMethodsOrActualInitializationErrorsRefuse','allThreeClassesMustBelongToActualVZ27Image','descriptorAndDiskReleasedOnEveryPath','originalFactoryStronglyOwnsDisk','autoreleasedFactoryResultRetainedToOriginalPlusOne','allOtherMain20CodeWholeUnchanged','main20URLDisplayAndSSHDeferralWholeUnchanged','noRuntimeOrChildMachineCodeChanged','actualGuestIOOrBootNotYetExecuted')),'actual private original RawDisk format/FD/ThreadPool route, truthful refusal and unchanged ownership/UI/SSH')
    need(pin(main_source['originalParentAndChildBasis']['path'])==main_source['originalParentAndChildBasis'],'exact original Parent and Child descriptor basis')
    need(pin(main_source_pin['path'])==main_source_pin and main_object['actualCompileExit']==0,'actual Main21 source and successful sole-Main compile')
    for row in (main_object['source'],main_object['object'],main_object['actualCompile'],main_source['sourceDiff']):
        need(pin(row['path'])==row,'exact Main21 compile/source proof')
    need(old['sourceCandidate']['sha256']=='176fbe12cbed9466e9da0a85b7e3935de4df0338b2e571f0f40366b1da0a9752' and old['sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot'] is True and old['genuineSSHRegistrationRouteEnabled'] is False,'preserve actual Main20 URL display fix and guest SSH deferral')
    need(old['objects'][0]['sha256']=='2388c905797069751dc21bcd8e8e6e02d1ad7f0ec2d37dcf88201a27b4f2697c','actual Main20 object whole; no Main19 fallback')
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'], 'actual runtime product')
    need(runtime['canonicalDeviceRoot'] == old['runtimeRoot'], 'same configured device runtime')
    for row in [*old['sourceFiles'], *old['actualIncludeClosure'], *old['objects'], *old.get('externalPrecompiledObjects', []), *old['appFiles']]:
        need(pin(row['path']) == row, 'exact inherited App54 input')
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
    need(runtime['anchorIOSObject']==old['objects'][34] and runtime['anchorSource']==old['sourceFiles'][34],'whole Runtime43 anchor already linked in App54')
    need(argv.count(old['objects'][0]['path'])==1,'one actual previous Main20 object')
    argv[argv.index(old['objects'][0]['path'])]=main_object['object']['path']
    argv[argv.index(old['binary']['path'])] = str(binary)
    run('link-app', argv)
    need(binary.stat().st_size <= 2097152, 'original parent self-inspector limit')
    run('validate-app', ['xcrun', 'dyld_info', '-validate_only', str(binary)])
    run('imports-app', ['xcrun', 'dyld_info', '-imports', str(binary)])
    run('exports-app', ['xcrun', 'dyld_info', '-exports', str(binary)])
    # Main21 was compiled once in its pinned HOST candidate. The other34
    # App54 objects, including the actual Runtime43 anchor, stay whole.
    source_files = [main_object['source']] + old['sourceFiles'][1:]
    objects = [main_object['object']] + old['objects'][1:]
    need(source_files==main_source['sourceFiles'] and objects==main_source['objects'],'exact producer34 whole objects and sole Main21 replacement join')
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
    record.update(schema='Actual App55 sole Main21 relink with34 whole App54 objects and unchanged Runtime43 anchor',
                  builder=pin(__file__), sourceFiles=source_files, objects=objects,
                  commands=commands, binary=pin(binary), appFiles=app_files,
                  inheritedCompiledAppCandidate=pin(OLD),
                  inheritedCompilationCommands=pin(OLD.parent / 'commands.json'),
                  sourceCandidate=main_source_pin,main21ObjectCandidate=pin(args.main_object_candidate),
                  sourceDiff=main_source['sourceDiff'],priorMain20AppCandidate=pin(OLD),
                  rawDiskThreadPoolAttachmentContract=main_source['rawDiskThreadPoolAttachmentContract'],
                  originalParentAndChildBasis=main_source['originalParentAndChildBasis'],
                  actualRuntimeCandidate=pin(args.runtime_candidate),
                  actualUnchangedCompiledObjects=34, actualNewAppCompilations=0,
                  actualOnlyRelinkedRuntimeAnchor=False,actualRuntime43AndAnchorWholeUnchanged=True,
                  actualMain21ObjectReused=True,codeSigned=False,
                  deviceOperations=0, applicationBinaryLinked=True, applicationPackaged=True,
                  actualGuestBoot=False, actualSSHVerified=False)
    record['historicalMain20PresentationSourceContract']=record['urlDisplayPresentationContract']
    record['urlDisplayPresentationContract']={key:value for key,value in record['urlDisplayPresentationContract'].items() if key not in ('onlyValidatedIndependentStartVMURLBranchChanged','allOtherMain19SourceWholeUnchangedExceptSSHDeferralConstant')}
    record['actualMain20UIAndSSHDeferralPreserved']=True
    for field in ('actualPrecompiledMain20ObjectReused','actualMainAndOther33CompiledObjectsWholeUnchanged','main20ObjectCandidate'):
        if field in record:record.setdefault('historicalMain20AppProvenance',{})[field]=record.pop(field)
    save(output / 'candidate.json', record)
    files = [pin(p) for p in sorted(output.rglob('*')) if p.is_file()]
    files += [pin(__file__), pin(OLD), pin(args.runtime_candidate), *source_files, *objects, *old.get('externalPrecompiledObjects', []), *old['actualIncludeClosure'],pin(args.main_object_candidate),pin(args.main_object_candidate.parent/'freeze.json'),main_source_pin,pin(pathlib.Path(main_source_pin['path']).parent/'freeze.json'),main_source['sourceDiff'],main_object['actualCompile']]
    save(output / 'freeze.json', dict(files=list({p['path']: p for p in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), binary=pin(binary),
                          unchangedAppObjects=34, appCompilations=0, main21PrecompiledReused=True)))


if __name__ == '__main__':
    main()
