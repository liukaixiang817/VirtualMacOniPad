#!/usr/bin/env python3
"""Read-only v32 outcome check: 0 instruction test passed, 1 failed, 2 invalid.

This never launches a probe. Host cleanup and a valid transcript do not prove
guest execution. It classifies the saved v32 artifact format only; it cannot
certify a complete macOS27 backend. The original transcript verifier's reported
result is an input; this checker does not replace that verifier or authenticate
the original capture.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import sys

LIMIT = 1024 * 1024

class InvalidEvidence(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)

def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 <= before.st_size <= LIMIT, 'bounded single-link regular file required')
        parts = []
        remaining = before.st_size
        while remaining:
            part = os.read(fd, min(65536, remaining))
            require(bool(part), 'file truncated while reading')
            parts.append(part)
            remaining -= len(part)
        require(os.read(fd, 1) == b'', 'file grew while reading')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink',
                  'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, f) == getattr(after, f) for f in fields),
                'file identity changed while reading')
        return b''.join(parts)
    finally:
        os.close(fd)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def reject_constant(value):
    raise InvalidEvidence('nonfinite JSON constant: ' + value)

def decode(data):
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)

def typed(obj, key, kind):
    require(type(obj) is dict and key in obj and type(obj[key]) is kind,
            'missing or mistyped field: ' + key)
    return obj[key]

def classify(folder):
    result = decode(read_regular(folder / 'result.json'))
    require('validationError' not in result, 'original transcript validation failed')
    native = typed(result, 'native', dict)
    require(typed(result, 'transcriptValid', bool), 'transcript is not verified')
    stdout, stderr = (read_regular(folder / name) for name in ('native.stdout', 'native.stderr'))
    for name, data in (('nativeStdoutSHA256', stdout), ('nativeStderrSHA256', stderr)):
        digest = typed(result, name, str)
        require(re.fullmatch('[0-9a-f]{64}', digest) is not None and
                hashlib.sha256(data).hexdigest() == digest, 'saved log hash mismatch')
    parent = typed(result, 'directParentPID', int)
    child = typed(native, 'runChildPID', int)
    wait = typed(result, 'observedWaitExit', int)
    require(parent > 1 and child > 1 and parent != child and 0 <= wait <= 255,
            'invalid saved process identity or exit')
    require(typed(result, 'transportExit', int) == wait ==
            typed(native, 'observedWaitExit', int), 'inconsistent parent exits')
    require(typed(native, 'directParentPID', int) == parent, 'inconsistent parent identity')
    require(read_regular(folder / 'native.exit') == (str(wait) + '\n').encode(),
            'saved native exit mismatch')
    require(re.findall(rb'^NATIVE_STARTED pid=(\d+)$', stderr, re.M) == [str(parent).encode()] and
            re.findall(rb'^NATIVE_WAIT pid=(\d+) exit=(\d+)$', stderr, re.M) ==
            [(str(parent).encode(), str(wait).encode())], 'saved direct wait mismatch')
    rows = [decode(line) for line in stdout.splitlines()]
    summaries = [row for row in rows if row.get('kind') == 'summary']
    parents = [row for row in rows if row.get('kind') == 'parent']
    require(len(summaries) == len(parents) == 1, 'unique native summary and parent required')
    summary, reaped = summaries[0], parents[0]
    require(typed(reaped, 'childPID', int) == child and
            typed(reaped, 'exitStatus', int) == typed(native, 'observedNestedChildExit', int),
            'saved nested wait mismatch')
    require(typed(reaped, 'childReaped', bool) and not typed(reaped, 'wallTimeout', bool) and
            typed(reaped, 'signal', int) == 0, 'nested run did not finish normally')
    require(typed(native, 'cleanupVerified', bool) and
            typed(result, 'deviceAndProductionHealthy', bool) and
            typed(result, 'exactParentAndChildAbsent', bool), 'historical cleanup proof incomplete')
    require(read_regular(folder / 'post.exit') == b'0\n' and
            read_regular(folder / 'post.stdout').endswith(b'V32_DEVICE_OFF_FILES_PRESERVED\n') and
            read_regular(folder / 'exact-child-absence.exit') == b'0\n' and
            read_regular(folder / 'exact-child-absence.stdout') == b'V32_EXACT_PARENT_AND_CHILD_ABSENT\n',
            'historical cleanup receipt mismatch')
    flags = [typed(result, 'guestInstructionOracleVerified', bool),
             typed(native, 'guestInstructionOracleVerified', bool), typed(native, 'passed', bool),
             typed(summary, 'nativeBRKPASS', bool), typed(reaped, 'strictPASS', bool)]
    require(all(flag == flags[0] for flag in flags), 'contradictory guest execution evidence')
    passed = flags[0]
    require((wait, reaped['exitStatus']) == ((0, 0) if passed else (73, 69)),
            'v32 execution verdict and exit pair disagree')
    require(typed(result, 'full27Backend', bool) is False and
            typed(native, 'complete27CPU', bool) is False and
            typed(summary, 'complete27CPU', bool) is False,
            'v32 instruction diagnostic cannot certify complete backend')
    return {
        'classification': 'instruction_test_passed' if passed else 'instruction_test_failed',
        'exitCode': 0 if passed else 1,
        'guestInstructionOracleVerified': passed,
        'transcriptValidationReported': True,
        'savedLogHashesMatchResult': True,
        'historicalCleanupVerified': True,
        'currentDeviceHealthChecked': False,
        'observedParentExit': wait,
        'observedChildExit': reaped['exitStatus'],
        'rawReason': typed(native, 'rawReason', int),
        'rawReasonInterpretedAsErrno': False,
        'full27Backend': False,
        'nativeExecutedByChecker': False,
    }

def main():
    try:
        require(len(sys.argv) == 2, 'usage: check-saved-cpu-v32-result.py SAVED_DIRECTORY')
        outcome = classify(Path(sys.argv[1]))
    except (InvalidEvidence, OSError, ValueError, KeyError, AttributeError, TypeError, RecursionError) as error:
        outcome = {'classification': 'invalid_evidence', 'exitCode': 2, 'error': str(error),
                   'nativeExecutedByChecker': False, 'full27Backend': False}
    print(json.dumps(outcome, indent=2))
    return outcome['exitCode']

if __name__ == '__main__':
    sys.exit(main())
