#!/usr/bin/env python3
"""Derive an unsigned App10 source; never edit App9 or run a device."""
import argparse, difflib, hashlib, json, pathlib, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
def pin(p):
    b = p.read_bytes()
    return dict(path=str(p.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, value):
    p.write_text(json.dumps(value, indent=2) + '\n')
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=pathlib.Path, required=True)
    a = ap.parse_args()
    o = a.output.resolve()
    assert o.is_relative_to(N) and not o.exists()
    prior = N / 'independent27-app-unbuffered-log-source-v9-attempt1/candidate.json'
    plan = N / 'genuine-vz-ssh-bridge-app-integration-plan-v1-attempt1/report.json'
    m = json.loads(prior.read_bytes())
    source = pathlib.Path(m['source']['path'])
    assert pin(source) == m['source']
    p = json.loads(plan.read_bytes())
    assert pin(source) == p['exactAppSource']
    bridgeCandidate = pathlib.Path(p['sourceCandidate']['path'])
    bridgeFreeze = pathlib.Path(p['sourceFreeze']['path'])
    assert pin(bridgeCandidate) == p['sourceCandidate'] and pin(bridgeFreeze) == p['sourceFreeze']
    old = source.read_text()
    text = old
    def replace(before, after):
        nonlocal text
        assert text.count(before) == 1, before[:100]
        text = text.replace(before, after, 1)
    replace('#import "vm27_independent_app_runtime_v1.h"',
            '#import "vm27_independent_app_runtime_v1.h"\n#import "vm27_genuine_vz_ssh_bridge_v1.h"')
    replace('static VM27UIKitGuestDisplayV1 *gIndependent27GuestDisplay;', '''static VM27UIKitGuestDisplayV1 *gIndependent27GuestDisplay;
// MRC App owns this ARC adapter until its actual queue drain completes.
static VM27GenuineVZSSHBridgeV1 *gIndependent27SSHBridge;
static BOOL gIndependent27SSHStarted;
static BOOL gIndependent27SSHLastSnapshotValid;
static struct vm27_host_ssh_snapshot_v1 gIndependent27SSHLastSnapshot;
static void VZIndependent27PollActualSSHBridge(void);''')
    replace('    dispatch_source_set_event_handler(timer, ^{\n        NSInteger state = gVirtualMachine',
            '    dispatch_source_set_event_handler(timer, ^{\n        VZIndependent27PollActualSSHBridge();\n        NSInteger state = gVirtualMachine')
    replace('    if (gIndependent27OwnerClosePending) return;\n    if (gIndependent27InputQueueV3 || gIndependent27GuestDisplay) {', '''    if (gIndependent27OwnerClosePending) return;
    gIndependent27SSHStarted=NO;
    if (gIndependent27SSHBridge) {
        gIndependent27OwnerClosePending=YES;
        id retainedOwner=[self retain];
        NSError *retainedError=[(error ?: gIndependent27DisplayFailure) retain];
        VM27GenuineVZSSHBridgeV1 *retainedBridge=[gIndependent27SSHBridge retain];
        [retainedBridge closeWithCompletion:^(NSError *closeError) {
            NSCAssert(pthread_main_np(),@"SSH drain completes on actual main VM.queue.");
            gIndependent27OwnerClosePending=NO;
            if (!closeError && gIndependent27SSHBridge!=retainedBridge)
                closeError=[NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:EIO
                    userInfo:@{NSLocalizedDescriptionKey:@"The retained SSH owner changed during drain. The VM remains retained."}];
            if (closeError) {
                VZPresentFailureReport(retainedOwner,VZL(@"Virtual Mac Stopped"),
                    closeError.localizedDescription,closeError.debugDescription,
                    VZFailureSupportOptionSuggestDebugLogging);
            } else {
                printf("[Independent27SSH] actual queue drain completed; VM release may proceed\\n");
                [gIndependent27SSHBridge release];gIndependent27SSHBridge=nil;
                gIndependent27SSHLastSnapshotValid=NO;
                [retainedOwner finishVMAndShowLibraryWithError:retainedError];
            }
            [retainedBridge release];[retainedError release];[retainedOwner release];
        }];
        return;
    }
    if (gIndependent27InputQueueV3 || gIndependent27GuestDisplay) {''')
    replace('    return configuration;\n}\n\nstatic BOOL prepareFramebuffer(UIView *container) {', '''    if (VZIndependent27SourceRouteSelected()) {
        // SSH uses its own port22223 listener on the existing genuine device.
        // Keep GuestTools505050 and Pencil listeners on that same device.
        NSArray *socketConfigurations=m0(configuration,"socketDevices");
        if (socketConfigurations.count==0) {
            id socketConfiguration=NEW("VZVirtioSocketDeviceConfiguration");
            if (socketConfiguration)
                setObj(configuration,"setSocketDevices:",@[socketConfiguration]);
            socketConfigurations=m0(configuration,"socketDevices");
        }
        if (socketConfigurations.count!=1) {
            if (error) *error=[NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:ENODEV
                userInfo:@{NSLocalizedDescriptionKey:@"Independent SSH requires exactly one genuine VZ socket device configuration."}];
            return nil;
        }
    }
    return configuration;
}

static BOOL prepareFramebuffer(UIView *container) {''')
    replace('static void activateFramebuffer(void) {', '''static void VZIndependent27PollActualSSHBridge(void) {
    NSCAssert(pthread_main_np(),@"SSH snapshots use actual main VM.queue.");
    if (!gIndependent27SSHStarted || !gIndependent27SSHBridge ||
        gIndependent27OwnerClosePending) return;
    struct vm27_host_ssh_snapshot_v1 snapshot={0};
    int status=[gIndependent27SSHBridge copySnapshot:&snapshot];
    if (status || snapshot.stopped || snapshot.error) {
        gIndependent27SSHStarted=NO;
        NSError *failure=[NSError errorWithDomain:@"VirtualMac.Independent27SSH"
            code:status ?: snapshot.error ?: ECONNABORTED
            userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:
                @"The actual SSH byte bridge stopped (snapshot=%d, stopped=%d, error=%d).",status,snapshot.stopped,snapshot.error]}];
        VZIndependent27FailActualDisplay(failure);
        return;
    }
    if (!gIndependent27SSHLastSnapshotValid ||
        snapshot.ready!=gIndependent27SSHLastSnapshot.ready ||
        snapshot.streams_started!=gIndependent27SSHLastSnapshot.streams_started ||
        snapshot.streams_completed!=gIndependent27SSHLastSnapshot.streams_completed ||
        snapshot.bytes_tcp_to_guest!=gIndependent27SSHLastSnapshot.bytes_tcp_to_guest ||
        snapshot.bytes_guest_to_tcp!=gIndependent27SSHLastSnapshot.bytes_guest_to_tcp) {
        printf("[Independent27SSH] controlHELLO=%d tcpPort=%u pending=%u active=%u "
               "started=%llu completed=%llu tx=%llu rx=%llu; guest SSH unverified\\n",
            snapshot.ready,(unsigned)snapshot.tcp_port,snapshot.pending,snapshot.active,
            (unsigned long long)snapshot.streams_started,(unsigned long long)snapshot.streams_completed,
            (unsigned long long)snapshot.bytes_tcp_to_guest,(unsigned long long)snapshot.bytes_guest_to_tcp);
    }
    gIndependent27SSHLastSnapshot=snapshot;gIndependent27SSHLastSnapshotValid=YES;
}

static void activateFramebuffer(void) {''')
    replace('    if (guestToolsEnabled ||\n        [options[VZGuestToolsRemovalPendingKey] boolValue])\n        VZGuestToolsAttachToVirtualMachine(gVirtualMachine);', '''    if (VZIndependent27SourceRouteSelected()) {
        if (gIndependent27SSHBridge) {
            finishVMThreadSafe(delegate,[NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:EALREADY
                userInfo:@{NSLocalizedDescriptionKey:@"A retained SSH owner already exists; it must drain before another start."}]);return;
        }
        NSString *actualVZPath=[VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"];
        NSError *sshError=nil;
        VM27GenuineVZSSHBridgeV1 *actualOwner=nil;
        BOOL registered=VM27CreateGenuineVZSSHBridgeV1(gVirtualMachine,actualVZPath,
            300000,&actualOwner,&sshError);
        // Failure may still publish real resources. Keep that owner for close.
        gIndependent27SSHBridge=[actualOwner retain];
        gIndependent27SSHStarted=NO;gIndependent27SSHLastSnapshotValid=NO;
        if (!registered || !gIndependent27SSHBridge) {
            finishVMThreadSafe(delegate,sshError ?: [NSError errorWithDomain:@"VirtualMac.Independent27SSH" code:EIO
                userInfo:@{NSLocalizedDescriptionKey:@"The genuine SSH listener could not register before VM start."}]);return;
        }
        printf("[Independent27SSH] actual listener22223 registered; loopbackTCP22222; guest SSH unverified\\n");
    }
    if (guestToolsEnabled ||
        [options[VZGuestToolsRemovalPendingKey] boolValue])
        VZGuestToolsAttachToVirtualMachine(gVirtualMachine);''')
    replace('            if (!VM27IndependentAppRuntimeGuestStartedV1(&startedError)) {\n                VZIndependent27FailActualDisplay(startedError);return;\n            }', '''            if (!VM27IndependentAppRuntimeGuestStartedV1(&startedError)) {
                VZIndependent27FailActualDisplay(startedError);return;
            }
            gIndependent27SSHStarted=YES;
            VZIndependent27PollActualSSHBridge();''')
    assert source.read_text() == old and text != old
    o.mkdir()
    new = o/'VirtualMacApp.independent27.genuine-ssh-source-v10.m'
    new.write_text(text)
    diff = o/'app-v9-to-v10.diff'
    diff.write_text(''.join(difflib.unified_diff(old.splitlines(True),text.splitlines(True),fromfile='frozen-App9',tofile='new-App10')))
    units = [pathlib.Path(f) for f in p['newAppBuildUnits']]
    m.update(schema='Copied App10 genuine VZ SSH source integration; HOST only',
        source=pin(new), priorSourceCandidate=pin(prior), sourceDiff=pin(diff),
        preparer=pin(pathlib.Path(__file__)), sshIntegrationPlan=pin(plan),
        sshBridgeSourceCandidate=pin(bridgeCandidate), sshBridgeSourceFreeze=pin(bridgeFreeze),
        newSSHBuildUnits=[pin(f) for f in units],
        trueSSHRegistrationAfterRuntimeBindBeforeStart=True,
        trueSocketDeviceRequiredWithoutGuestTools=True,
        existingSocketDeviceAndGuestToolsListenersPreserved=True,
        sshFactoryFailureOwnerRetained=True, sshStartedOnlyAfterActualGuestStarted=True,
        sshSnapshotOnActualMainVMQueue=True, sshHELLOIsGuestSSHSuccess=False,
        sshCleanupJoinsBeforeExistingInputDisplayAndVMRelease=True,
        sshCleanupFailureRetainsVMAndBridge=True, sshAutomaticReconnect=False,
        relayIdleMilliseconds=300000, socketListenerPort=22223, loopbackTCPPort=22222,
        actualVMRuntimeBoundBeforeStart=True, actualSSHVerified=False,
        actualVZCallbackExecuted=False, actualGuestHelperInstalled=False,
        applicationBinaryLinked=False,applicationPackaged=False,codeSigned=False,
        deviceOperations=0,trustCacheOperations=0,guestSSHAvailable=False)
    save(o/'candidate.json',m)
    files=[pathlib.Path(__file__),prior,source,plan,bridgeCandidate,bridgeFreeze,new,diff,
        pathlib.Path(m['backendSource']['path'])]+units+[o/'candidate.json']
    save(o/'freeze.json',dict(schema='Immutable App10 source pins',files=[pin(f) for f in files]))
    print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),source=pin(new))))
if __name__=='__main__': main()
