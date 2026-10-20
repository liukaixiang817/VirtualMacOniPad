#!/usr/bin/env python3
"""Finite explicit HOST mocks for the actual premature-result regression.

No genuine App/child, process scan, device, QGA or guest is executed. Actual
awk/grep/shell run against temporary logs; time/ps/metadata are explicit mocks.
"""
import importlib.util
import json
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
P = N / 'independent27-owned-platform-init-only-v1-attempt1'
O = N / 'independent27-init-only-readiness-host-model-v1-attempt1'
SOURCE = pathlib.Path(__file__).with_name('prepare-independent27-owned-platform-init-only-v1.py')
spec = importlib.util.spec_from_file_location('readiness_frozen_source', SOURCE)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
pin, need, dump = source.pin, source.need, source.dump


def main():
    need(not O.exists(), 'fresh HOST model directory')
    for row in json.loads((P / 'freeze.json').read_bytes())['files']:
        source.base.exact(row)
    O.mkdir(mode=0o700)
    loop = (P / 'readiness-loop.sh').read_text()
    _, old_body = source.unwrap((source.OLD / 'launch.sh').read_text())
    at = old_body.index('own_wait=0\nown_result=none\n')
    old_loop = old_body[at:old_body.index('own_accept_count=', at)]
    prefix = r'''set -eu
mode=$1
OWN_LOG=$2
own_log_inode=1:2
own_app_pid=100
own_app_start=appstart
own_child_pid=0
own_child_start=none
iteration=0
stat() {
 case "$2" in %d:%i) printf '1:2\n';; %u:%g:%a:%h) printf '501:501:600:1\n';; %s) printf '1000\n';; *) exit 91;; esac
}
ps() { printf 'S\n'; }
sleep() { :; }
scan_own() {
 iteration=$((iteration+1))
 app_rows='100 1 501 /fixed/app'
 child_rows=''
 own_child_pid=0
 own_child_start=none
 result=1
 [ "$mode" != resultzero ] || result=0
 printf '[Independent27] runtime-startup result=%s errorDomain= errorCode=0 error=\n' "$result" >"$OWN_LOG"
 ready=0
 if [ "$iteration" -ge 3 ]; then ready=1;fi
 if [ "$mode" = childlost ] && [ "$iteration" = 4 ]; then ready=0;fi
 if [ "$ready" = 1 ]; then
  own_child_pid=101
  own_child_start=childstart
  child_rows='101 100 501 /fixed/child'
  printf '[Independent27] parent-hello install-factory status=0 nativeDetailsAvailable=0\n' >>"$OWN_LOG"
  printf '[Independent27] child-prepare status=0 pid=101 ppid=100 uid=501 euid=501 acquiredOwnerReturned=1 helloReturned=1\n' >>"$OWN_LOG"
  if [ "$mode" != neverprepared ]; then
   printf '%s\n' 'VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 policyDeferred=1 trustedGuestOwnedProcess=1' >>"$OWN_LOG"
  fi
  if [ "$mode" = duplicateprepared ]; then
   printf '%s\n' 'VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 policyDeferred=1 trustedGuestOwnedProcess=1' >>"$OWN_LOG"
  fi
 fi
}
'''
    tail = "printf 'HOST_MOCK_READINESS_PASSED iterations=%s stable=%s\\n' \"$iteration\" \"${own_stable_seconds:-none}\"\n"
    paths = {}
    for label, selected in [('new', loop), ('old', old_loop)]:
        path = O / (label + '-explicit-mock.sh')
        path.write_text(prefix + selected + tail)
        syntax = subprocess.run(['/bin/sh', '-n', path], capture_output=True)
        need(syntax.returncode == 0, 'actual mock shell syntax')
        paths[label] = path
    cases = [
        ('old', 'delayed', 1, None),
        ('new', 'delayed', 0, 'iterations=5 stable=2'),
        ('new', 'childlost', 0, 'iterations=7 stable=2'),
        ('new', 'neverprepared', 1, None),
        ('new', 'resultzero', 1, None),
        ('new', 'duplicateprepared', 1, None),
    ]
    results = []
    for label, mode, expected, marker in cases:
        name = label + '-' + mode
        argv = ['/bin/sh', str(paths[label]), mode, str(O / (name + '.mock-log'))]
        result = subprocess.run(argv, capture_output=True, timeout=5)
        (O / (name + '.stdout')).write_bytes(result.stdout)
        (O / (name + '.stderr')).write_bytes(result.stderr)
        need(result.returncode == expected and
             (marker is None or marker.encode() in result.stdout), 'actual finite race assertion: ' + name)
        results.append(dict(case=name, argv=argv, actualExit=result.returncode,
             expectedExit=expected, expectedSuccessfulSampleMarker=marker,
             stdout=pin(O / (name + '.stdout')), stderr=pin(O / (name + '.stderr'))))
    report = dict(schema='Explicit HOST-only initializer readiness race regression v1',
         packetCandidate=pin(P / 'candidate.json'), packetFreeze=pin(P / 'freeze.json'),
         readinessLoop=pin(P / 'readiness-loop.sh'), preparer=pin(SOURCE),
         oldPrematureResultFailureReproducedInExplicitMocks=True,
         delayedActualPreparationGateFixedInExplicitMocks=True, cases=results,
         actualShellAndAwkGrepExecuted=True, timeAndPSAndMetadataExplicitlyMocked=True,
         realAppOrChildExecuted=False, deviceOperations=0, guestOperations=0,
         realInitializerReadinessProven=False, realProcessCleanupProven=False)
    dump(O / 'report.json', report)
    files = [pin(p) for p in O.iterdir() if p.is_file()]
    files += [pin(__file__), report['packetCandidate'], report['packetFreeze'], report['readinessLoop'], report['preparer']]
    dump(O / 'freeze.json', dict(files=files, deviceOperations=0, guestOperations=0))
    print(json.dumps(dict(report=pin(O / 'report.json'), freeze=pin(O / 'freeze.json'), cases=len(results))))


if __name__ == '__main__':
    main()
