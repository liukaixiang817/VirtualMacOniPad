#!/usr/bin/env python3
"""HOST-only copied App main: explicitly defer optional SSH for basic boot."""
import argparse
import copy
import difflib
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
BASE = N / 'independent27-app-uikit-basic-input-source-v11-attempt1/candidate.json'
APP12 = N / 'independent27-actual-app-vm-class-binding-v12-attempt1/candidate.json'

def pin(path):
    path = pathlib.Path(path).resolve(); data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args(); out = args.output.resolve()
    assert out.parent == N and not out.exists()
    assert pin(BASE)['sha256'] == 'ef56f86d2fbbdfaf1a10316e485117ec012d1e924a2ee57a628d706035d3779c'
    base = json.loads(BASE.read_bytes()); source_path = pathlib.Path(base['source']['path'])
    assert pin(source_path) == base['source']
    linked = json.loads(APP12.read_bytes())
    assert linked['sourceFiles'][0] == base['source']
    original = source_path.read_text(); text = original
    edits = [
        ('static struct vm27_host_ssh_snapshot_v1 gIndependent27SSHLastSnapshot;\n',
         'static struct vm27_host_ssh_snapshot_v1 gIndependent27SSHLastSnapshot;\n'
         '// This copied product explicitly limits its first independent27 boot to\n'
         '// CPU, actual guest display and basic input. SSH remains unavailable.\n'
         'static const BOOL kIndependent27FirstDisplaySSHDeferredV13 = YES;\n'),
        ('static void VZIndependent27PollActualSSHBridge(void) {\n'
         '    NSCAssert(pthread_main_np(),@"SSH snapshots use actual main VM.queue.");\n',
         'static void VZIndependent27PollActualSSHBridge(void) {\n'
         '    NSCAssert(pthread_main_np(),@"SSH snapshots use actual main VM.queue.");\n'
         '    if (VZIndependent27SourceRouteSelected() &&\n'
         '        kIndependent27FirstDisplaySSHDeferredV13) return;\n'),
        ('    if (VZIndependent27SourceRouteSelected()) {\n'
         '        if (gIndependent27SSHBridge) {\n',
         '    if (VZIndependent27SourceRouteSelected() &&\n'
         '        kIndependent27FirstDisplaySSHDeferredV13) {\n'
         '        printf("[Independent27SSH] SSH bridge deferred for first basic guest boot; unavailable\\n");\n'
         '    }\n'
         '    if (VZIndependent27SourceRouteSelected() &&\n'
         '        !kIndependent27FirstDisplaySSHDeferredV13) {\n'
         '        if (gIndependent27SSHBridge) {\n'),
        ('            gIndependent27SSHStarted=YES;\n'
         '            VZIndependent27PollActualSSHBridge();\n',
         '            if (!kIndependent27FirstDisplaySSHDeferredV13) {\n'
         '                gIndependent27SSHStarted=YES;\n'
         '                VZIndependent27PollActualSSHBridge();\n'
         '            }\n'),
    ]
    for before, after in edits:
        assert text.count(before) == 1
        text = text.replace(before, after, 1)
    restored = text
    for before, after in reversed(edits): restored = restored.replace(after, before, 1)
    assert restored == original
    # Actual VM readiness is still required even though optional SSH is deferred.
    assert text.count('if (!VM27IndependentAppRuntimeGuestStartedV1(&startedError)) {') == 1
    assert text.count('SSH bridge deferred for first basic guest boot; unavailable') == 1
    out.mkdir(mode=0o700)
    source = out / 'VirtualMacApp.independent27.first-basic-boot-source-v13.m'
    source.write_text(text)
    diff = out / 'app-v11-main-to-v13.diff'
    diff.write_text(''.join(difflib.unified_diff(original.splitlines(True), text.splitlines(True),
        fromfile=str(source_path), tofile=str(source))))
    result = copy.deepcopy(base)
    result.update(schema='Copied App13 explicit independent27 first basic guest boot with optional SSH deferred',
        source=pin(source), priorSourceCandidate=pin(BASE), priorActualApp12Candidate=pin(APP12),
        sourceDiff=pin(diff), preparer=pin(__file__),
        firstVisibleBootExperiment=True, selectedIndependent27FirstDisplaySSHDeferred=True,
        primaryGuestBootScope='CPU/VMM execution, genuine UIKit display, basic keyboard/single pointer',
        independent27FirstDisplayPolicyConstant='kIndependent27FirstDisplaySSHDeferredV13=YES',
        trueSSHRegistrationAfterRuntimeBindBeforeStart=False,
        sshRegistrationExplicitlyDeferredForFirstBasicGuestBoot=True,
        sshStartedAndRuntimePollingExplicitlyDeferred=True,
        sshStartedOnlyAfterActualGuestStarted=False,
        sshSnapshotActivelyPolledForFirstBoot=False,
        runtimeGuestStartedActualStateAdmissionPreserved=True,
        actualRuntimeBindQueueAndFactoryCallsWholeUnchanged=True,
        actualCPUDisplayInputAndGuestConfigurationWholeUnchanged=True,
        existingSocketDeviceAndGuestToolsListenersPreserved=True,
        existingSSHOwnerDrainAndFailureRetentionWholeUnchanged=True,
        deferredSSHDoesNotBypassExistingOwnerCleanup=True,
        oneExplicitSSHUnavailableLogBeforeGuestStart=True,
        fakeProtocolOrClassAdded=False, fakeHELLOOrSSHReadyAdded=False,
        inheritedUSBSelectionSourceOnlyTwoExpressions=True,
        sourceChangesOnlyTwoActualDeviceSelectionExpressions=False,
        sourceChangesOnlySSHPolicyConstantRegistrationStartedAndPollGuards=True,
        futureSSHBuildUnits=base['newSSHBuildUnits'],
        futureSSHRegistrationAndActualGuestHelperAuthenticationStillRequired=True,
        genuineSSHBridgeIncludedAsDormantFutureCode=True,
        qgaFutureSourceIntegrated=False,
        actualSSHVerified=False, guestSSHAvailable=False, networkingAvailable=False,
        finalNetworkAndSSHStillRequired=True, actualVZRuntimeExecuted=False,
        applicationBinaryLinked=False, applicationPackaged=False, codeSigned=False,
        actualGuestDisplayObserved=False, actualInputDelivered=False,
        deviceOperations=0, trustCacheOperations=0, guestBoot=False)
    (out / 'candidate.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    rows = [pin(__file__), pin(BASE), pin(APP12), base['source'], base['backendSource'],
        pin(source), pin(diff), pin(out / 'candidate.json')] + base['newSSHBuildUnits']
    (out / 'freeze.json').write_text(json.dumps(dict(files=rows, deviceOperations=0,
        codeSigningOperations=0, trustCacheOperations=0), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), freeze=pin(out / 'freeze.json'), source=pin(source))))

if __name__ == '__main__':
    main()
