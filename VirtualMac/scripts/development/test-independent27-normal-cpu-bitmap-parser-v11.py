#!/usr/bin/env python3
"""HOST-only finite tests of the actual new CPU bitmap log parser.

Inputs below are explicit log fixtures, never device execution receipts. Old
ownership, clock, ACK and cleanup tests are not repeated by this delta test.
"""
import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    sp = importlib.util.spec_from_file_location('normal11_actual_parser', args.source.resolve())
    module = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(module)
    match = re.search(r"own_summary=\$\(awk '([\s\S]*?)' \"\$OWN_LOG\"\)", module.LOG_FUNCTIONS)
    if not match:
        raise ValueError('actual single awk program required')
    program = match.group(1)
    accepted = '[Independent27] start-vm accepted path=/private/var/mobile/Media/VirtualMac/Tahoe3.bundle; entering actual VM startup\n'
    started = '[VirtualMac] VM STARTED state=1\n'
    def frame(n, width=1920, height=1080, backend='cpu-bitmap'):
        return '[Independent27Display] completed actual IOSurface bitmap frame=' + str(n) + ' size=' + str(width) + 'x' + str(height) + ' backend=' + backend + '\n'
    normal = accepted + started + frame(1) + frame(5) + frame(10)
    # Each expected output is a full actual awk summary. A zero started count
    # is deliberately not treated as a running VM or authorized handoff.
    cases = [
        ('partial-empty', '', [0,0,0,0,0,0,0,0]),
        ('actual-cpu-bitmap-sequence', normal, [1,1,3,1,10,1920,1080,0]),
        ('source-bounded-resize', accepted+started+frame(2,2048,1536)+frame(8,8192,1), [1,1,2,2,8,8192,1,0]),
        ('seed-change-drop-not-completion', normal+'[Independent27DisplayV4] dropped=seed-changed frame=11\n', [1,1,3,1,10,1920,1080,0]),
        ('missing-running-state', accepted+frame(1)+frame(2), [1,0,2,1,2,1920,1080,0]),
        ('state-zero-does-not-run', accepted+'[VirtualMac] VM STARTED state=0\n'+frame(1), [1,0,1,1,1,1920,1080,0]),
        ('wrong-backend', frame(1,backend='metal'), [0,0,0,0,0,0,0,1]),
        ('legacy-metal-marker', '[Independent27Display] completed actual IOSurface frame=1 size=1920x1080\n', [0,0,0,0,0,0,0,1]),
        ('missing-backend', '[Independent27Display] completed actual IOSurface bitmap frame=1 size=1920x1080\n', [0,0,0,0,0,0,0,1]),
        ('extra-tail', frame(1).rstrip('\n')+' extra=1\n', [0,0,0,0,0,0,0,1]),
        ('malformed-dimensions', '[Independent27Display] completed actual IOSurface bitmap frame=1 size=1920x1080x4 backend=cpu-bitmap\n', [0,0,0,0,0,0,0,1]),
        ('zero-frame', frame(0), [0,0,1,0,0,1920,1080,1]),
        ('duplicate-frame', frame(5)+frame(5), [0,0,2,5,5,1920,1080,1]),
        ('regressed-frame', frame(5)+frame(4), [0,0,2,5,4,1920,1080,1]),
        ('negative-frame', frame(-1), [0,0,0,0,0,0,0,1]),
        ('zero-dimension', frame(1,width=0), [0,0,1,1,1,0,1080,1]),
        ('outside-actual-source-width', frame(1,width=8193), [0,0,1,1,1,8193,1080,1]),
        ('outside-actual-source-height', frame(1,height=8193), [0,0,1,1,1,1920,8193,1]),
        ('historical-prefix-not-current-frame', 'historical: '+frame(1), [0,0,0,0,0,0,0,0]),
    ]
    rows = []
    for label, text, expected in cases:
        run = subprocess.run(['/usr/bin/awk', program], input=text.encode(), capture_output=True)
        actual = [int(x) for x in run.stdout.decode().strip().split()]
        if run.returncode != 0 or actual != expected:
            raise ValueError((label, run.returncode, actual, expected, run.stderr.decode()))
        rows.append(dict(label=label, fixtureOnly=True, expectedSummary=expected,
                         actualSummary=actual, actualAwkExit=run.returncode))
    failures = [
        ('ctor-nil', '[Independent27DisplayV4] failed=init-super pid=42\n', 0),
        ('copy-unlock-unresolved', '[Independent27DisplayV4] failed=surface-unlock reason=Actual failure.\n', 0),
        ('publish-failure', '[Independent27DisplayV4] failed=image-publish reason=Actual exception.\n', 0),
        ('nonfatal-seed-drop', '[Independent27DisplayV4] dropped=seed-changed frame=2\n', 1),
        ('valid-completion-not-fatal', normal, 1),
        ('embedded-failure-not-current', 'historical: [Independent27DisplayV4] failed=init-super\n', 1),
        ('old-real-stop-still-fatal', '[VirtualMac] VM delegate didStopWithError=Actual failure.\n', 0),
    ]
    for label, text, expected in failures:
        run = subprocess.run(['/usr/bin/grep', '-E', module.FAILURE], input=text.encode(), capture_output=True)
        if run.returncode != expected:
            raise ValueError((label, run.returncode, expected, run.stderr.decode()))
        rows.append(dict(label=label, fixtureOnly=True, expectedGrepExit=expected, actualGrepExit=run.returncode))
    args.output.resolve().write_text(json.dumps(dict(actualHostFixtureChecks=rows,
        allFiniteParserChecksPassed=True, checkCount=len(rows), deviceOperations=0,
        noActualGuestExecutionReceipt=True), indent=2)+'\n')
    print(json.dumps(dict(checkCount=len(rows), actualHostPassed=True, deviceOperations=0)))


if __name__ == '__main__':
    main()
