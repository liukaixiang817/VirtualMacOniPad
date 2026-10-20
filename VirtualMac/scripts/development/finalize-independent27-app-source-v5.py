#!/usr/bin/env python3
"""Freeze actual App5 NIC0/audio0 source and compiled components; no anchor."""
import argparse
import hashlib
import json
import pathlib
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    out.mkdir()
    source = N / 'independent27-app-first-display-source-v5-attempt1/candidate.json'
    components = N / 'independent27-app-components-v5-attempt1/candidate.json'
    sj = json.loads(source.read_bytes())
    cj = json.loads(components.read_bytes())
    for key in ('source', 'backendSource', 'builder', 'runtimeInterface', 'sourceDiff'):
        assert pin(pathlib.Path(sj[key]['path'])) == sj[key]
    assert cj['sourceCandidate'] == pin(source)
    assert pin(pathlib.Path(cj['builder']['path'])) == cj['builder']
    for row in cj['sourceFiles'] + cj['actualIncludeClosure'] + cj['objects']:
        assert pin(pathlib.Path(row['path'])) == row
    assert len(cj['objects']) == 29 and all(cmd['exit'] == 0 for cmd in cj['commands'])
    for key in ('firstVisibleBootExperiment', 'actualNetworkDevicesClearedAndCountChecked',
                'actualAudioDevicesClearedAndCountChecked',
                'userNATOrBridgeSettingsCannotChangeExperimentNIC0',
                'finalNetworkAndSSHStillRequired'):
        assert sj[key] is True
    assert sj['networkingAvailable'] is False and sj['guestSSHAvailable'] is False
    assert sj['soundAvailable'] is False
    app_text = pathlib.Path(sj['source']['path']).read_text()
    for name in ('Audio', 'Network'):
        assert f'set{name}Devices:' in app_text
        assert f'first-display experiment actual {name.lower()}Devices=0' in app_text
    runtime = [row for row in cj['sourceFiles']
               if pathlib.Path(row['path']).name.startswith('vm27_independent_app_runtime_')]
    assert len(runtime) == 1
    assert pathlib.Path(runtime[0]['path']).name == 'vm27_independent_app_runtime_v3.m'
    parents = [N / 'independent27-app-source-finalization-v4/freeze.json',
               N / 'independent27-runtime-source-local-v3-attempt1/freeze.json',
               N / 'uikit-genuine-display-source-finalization-v1/freeze.json',
               N / 'actual-vm-main-input-queue-source-v3-attempt1/freeze.json',
               N / 'independent27-runtime-v3-independent-source-review-v1/freeze.json']
    seen = set()
    verified = []

    def verify(path):
        path = path.resolve()
        if path in seen:
            return
        seen.add(path)
        data = json.loads(path.read_bytes())
        verified.append(pin(path))
        for row in data['files']:
            assert pin(pathlib.Path(row['path'])) == row, (row['path'], 'parent drift')
        for row in data['files']:
            child = pathlib.Path(row['path'])
            if child.name == 'freeze.json':
                verify(child)

    for parent in parents:
        verify(parent)
    files = {}

    def add(path):
        files[str(path.resolve())] = pin(path)

    for directory in (source.parent, components.parent):
        for path in directory.rglob('*'):
            if path.is_file():
                add(path)
    for row in cj['sourceFiles'] + cj['actualIncludeClosure']:
        add(pathlib.Path(row['path']))
    for path in (pathlib.Path(sj['builder']['path']), pathlib.Path(cj['builder']['path']),
                 pathlib.Path(__file__), *parents):
        add(path)
    final = dict(
        schema='Copied App5 first-display NIC0/audio0 source and Runtime3 components finalization',
        sourceCandidate=pin(source), components=pin(components),
        parentFreezes=[pin(path) for path in parents],
        recursivelyVerifiedParentFreezes=verified, actualCompiledUnits=29,
        soleActualRuntimeSource=runtime[0],
        actualIndependentBackendRootCanonicalized=True,
        actualOriginalVMQueueBindBeforeInputDisplayAndStart=True,
        actualGuestStartedRequiresChildFactoryAndVZRunning=True,
        actualUIInputAndIOSurfaceDisplaySources=True,
        actualNetworkDevicesClearedAndGetterCountChecked=True,
        actualAudioDevicesClearedAndGetterCountChecked=True,
        firstVisibleBootExperiment=True, configuredNICCount=0, configuredAudioCount=0,
        userNATOrBridgeSettingsCannotChangeExperimentNIC0=True,
        networkingAvailable=False, guestSSHAvailable=False, soundAvailable=False,
        finalNetworkAndSSHStillRequired=True,
        oldVenturaCPUVZFallbackExcludedFromSelected27Route=True,
        sourceAndComponentCompilationPassed=True, productAnchorGenerated=False,
        fixtureAnchorUsed=False, actualProductMainBinaryLinked=False,
        actualApplicationPackaged=False, actualSignedAppMainBytes=None,
        actualParentSelfInspectorMaxBytes=2097152,
        finalSignedMainSizeVerificationRequired=True,
        nativeCPUCalls=0, deviceOperations=0, actualVZRuntimeExecuted=False, guestBoot=False,
        boundary='Actual source and 29-unit iOS component compile only. Final main link/package '
                 'requires the genuine signed runtime manifest anchor. NIC0/audio0 is a finite '
                 'first-display experiment; actual guest display and eventual network/SSH remain required.')
    save(out / 'finalization.json', final)
    add(out / 'finalization.json')
    save(out / 'freeze.json', dict(schema='Copied App5 actual source and components freeze v1',
                                  files=list(files.values()),
                                  parentFreezes=[pin(path) for path in parents]))
    print(json.dumps(dict(finalization=pin(out / 'finalization.json'),
                          freeze=pin(out / 'freeze.json'), pins=len(files))))


if __name__ == '__main__':
    main()
