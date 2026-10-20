#!/usr/bin/env python3
"""Finite HOST-only elapsed clock/cleanup delta peer; no concrete dispatch."""
import ast
import hashlib
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = R / 'VirtualMac/scripts/development'

def pin(path):
    path = pathlib.Path(path).resolve(); raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def exact(row):
    assert pin(row['path']) == {key: row[key] for key in ('path', 'bytes', 'sha256')}
    return pathlib.Path(row['path'])

def functions(text):
    return {node.name: ast.get_source_segment(text, node) for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}

def main():
    cp = N / 'independent27-normal-lifecycle-elapsed-source-v4-attempt1/candidate.json'
    c = json.loads(cp.read_bytes()); fp = cp.parent / 'freeze.json'
    for row in json.loads(fp.read_bytes())['files']: exact(row)
    builder_path = exact(c['builder']); runner_path = exact(c['runner'])
    builder, runner = builder_path.read_text(), runner_path.read_text()
    old_builder_path = B / 'prepare-independent27-normal-guest-lifecycle-v3.py'
    old_runner_path = B / 'independent27_normal_guest_lifecycle_v1.py'
    old_builder, old_runner = old_builder_path.read_text(), old_runner_path.read_text()
    bfn, old_bfn, rfn, old_rfn = functions(builder), functions(old_builder), functions(runner), functions(old_runner)
    assert {name for name in old_bfn if bfn[name] != old_bfn[name]} == {'render_start', 'render_owned', 'prepare'}
    assert {name for name in old_rfn if rfn[name] != old_rfn[name]} == {'stream_start', 'dispatch'}
    assert set(rfn) - set(old_rfn) == {'offer_clock_valid_v4'}
    assert rfn['gate'] == old_rfn['gate'] and rfn['lease_data'] == old_rfn['lease_data']
    # Real ledger persistence and ACK ownership code remains the old suffix.
    marker = "                    common.need(not offer_seen, 'one actual handoff offer')"
    suffix_end = '\ndef lease_data('
    assert runner[runner.index(marker):runner.index(suffix_end)] == old_runner[old_runner.index(marker):old_runner.index(suffix_end)]
    assert 'actual_monotonic_now - observation_started >= 90 and late_progress' in rfn['offer_clock_valid_v4']
    stream = rfn['stream_start']
    assert stream.index('observation_started = time.monotonic()') < stream.index("common.need(offer_clock_valid_v4(")
    assert 'time.monotonic() - observation_started >= 45' in stream
    assert "last_frame > late_baseline and match.group(3) == '1'" in stream
    assert stream.index('common.dump(output / \'handoff-ledger.json\'') < stream.index("child.stdin.write(('ACK '")
    assert 'own_wall_now' in builder and 'own_wall_now-own_wall_start' in builder
    assert '[ "$own_wall_now" -ge "$own_wall_last" ] || return 82' in builder
    assert '[ "$((own_wall_now-own_wall_last))" -le 20 ] || return 82' in builder
    assert '[ "$own_elapsed" -lt 91 ] || break' in bfn['render_start']
    assert 'own_second=0' not in bfn['render_start'] and 'own_second=$((own_second+1))' not in bfn['render_start']
    for token in ('[ "$own_started" = 1 ]', '[ "$own_frames" -ge 2 ]', '[ "$own_last" -gt "$own_first" ]',
                  '[ "$own_late_progress" = 1 ]', '[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ]'):
        assert token in bfn['render_start']
    assert '--signal=TERM --kill-after=20 112' in bfn['bounded_run_v4']
    assert '--signal=TERM --kill-after=1 19' in builder
    assert 'vm27-owned-cleanup-v4 "$own_app_pid" "$own_app_start" "$own_child_pid" "$own_child_start"' in builder
    assert 'own_app_pid=$1;own_app_start=$2;own_child_pid=$3;own_child_start=$4' in bfn['cleanup_body_v4']
    assert 'cleanup_own || exit 78' in bfn['cleanup_body_v4'] and 'scan_own || exit 78' in bfn['cleanup_body_v4']
    assert 'INDEPENDENT27_OWN_TERMINAL_CLEANUP_VERIFIED_OFF_V4' in bfn['cleanup_body_v4']
    assert '--signal=TERM --kill-after=1 5' in bfn['render_start']
    dispatch = rfn['dispatch']
    assert "row['transportExit'] != 0" in dispatch and "not (packet / 'device-receipts/start/handoff-ack.json').exists()" in dispatch
    assert "'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text" not in dispatch
    assert 'failedStartPostCleanupFromInitialPrefixClaimed=False' in dispatch
    assert 'actual init' not in c.get('status', '').lower() and not c['concretePacketGenerated']
    observed = json.loads(exact(c['actualDateReadOnlyReceipt']).read_bytes())
    assert observed['transportExit'] == 0
    observed_stdout = exact(observed['stdout']).read_text()
    assert '/var/jb/usr/bin/date' in observed_stdout and 'OWN_ACTUAL_DATE_EPOCH 1791878976' in observed_stdout
    for fixture in c['elapsedClockFixtures']:
        assert fixture['exit'] == fixture['expected']; exact(fixture['fixture']); exact(fixture['stdout']); exact(fixture['stderr'])
    assert len(c['elapsedClockFixtures']) == len(c['shellSyntax']) == 4
    for syntax in c['shellSyntax']: assert syntax['exit'] == 0; exact(syntax['template'])
    spec = importlib.util.spec_from_file_location('normal_elapsed_peer_only', runner_path)
    control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
    # Four new pure HOST clock-gate checks have no transport or file mutation.
    actual_host_checks = [not control.offer_clock_valid_v4(None, True, 100),
        not control.offer_clock_valid_v4(10, True, 99.999),
        not control.offer_clock_valid_v4(10, False, 100), control.offer_clock_valid_v4(10, True, 100)]
    assert all(actual_host_checks)
    out = N / 'independent27-normal-elapsed-v4-source-independent-peer-v1-attempt1'
    out.mkdir(mode=0o700)
    report = dict(schema='Finite HOST normal elapsed/cleanup source V4 independent peer',
        sourceCandidate=pin(cp), sourceFreeze=pin(fp), builder=c['builder'], runner=c['runner'],
        originalGateLeaseDurableLedgerACKAndOwnershipSuffixWholePreserved=True,
        elapsedUsesGuardedNativeWallSecondsNotIterationCount=True, wallClockIsNotMonotonic=True,
        wallBackwardAndOver20SecondJumpReject=True, integerWallThreshold=91,
        actualNativeDateAvailabilityReceipt=c['actualDateReadOnlyReceipt'],
        actualHostMonotonic90AndAfter45State1AdvancingFrameBeforeACK=True, actualPureHostClockGateChecks=4,
        recordedFourWallFixturesAndFourShellSyntaxReceiptsVerifiedNotRerun=True,
        exactPIDUIDPathPPIDStartHashInheritedCleanupPreserved=True,
        nestedExactCleanupTERM19KILL1Seconds=20, outerTERM112KILL20HardSeconds=132,
        ACKReadTERM5KILL1Seconds=6, transportMaximumSeconds=145,
        failedStartPostRequiresRealFailureNoACKAndFreshIndependentReadonlyOFFFirst=True,
        initialOFFPrefixNeverUsedAsTerminalCleanupProof=True,
        noConcreteFutureInitializerOrGuestReceiptsSynthesized=True,
        concretePacketStillRequiresActualApp12InitPostReadonlyAndIndependentPeer=True,
        sourceOnly=True, deviceOperations=0, guestStarted=False, actualVisibleGuest=False,
        actualSSHAuthenticated=False, findings=[], finiteLocalScopePassed=True)
    (out / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(__file__), pin(cp), pin(fp), c['builder'], c['runner'], pin(old_builder_path), pin(old_runner_path),
        c['actualDateReadOnlyReceipt'], observed['stdout'], pin(out / 'review.json')]
    (out / 'freeze.json').write_text(json.dumps(dict(files=rows, deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'), findings=[])))

if __name__ == '__main__':
    main()
