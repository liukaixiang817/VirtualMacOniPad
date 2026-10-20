#!/usr/bin/env python3
"""Corrupt real Mac receipts; never run a service or manufacture native proof."""
from pathlib import Path
import copy
import importlib.util
import json
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('LargeInstance',
    ROOT / 'scripts/tests/validate-modern-large-original-xpc-instance-transport.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def main(build):
    candidate = json.loads((build / 'candidate.json').read_text())
    results = []
    for variant in validator.VARIANTS:
        process = next(row for row in candidate['processes']
                       if row['label'] == 'macos-' + variant + '-native')
        pid, wait = process['directChildPID'], process['observedWaitExit']
        path = build / ('macos-' + variant + '-native.stdout')
        original_sha = validator.sha(path.read_bytes())
        original = [json.loads(line) for line in path.read_text().splitlines()]
        validator.native_transcript(build, path, 'macos', variant, pid, wait)
        mutations = []
        for record, fields in [
            ('largeInertRoute', ['originalDataBytes', 'originalDataUUID', 'originalDataSHA256',
                'ownTemporaryPath', 'ownTemporaryRemoved', 'plansCreatedDestroyed',
                'unstartedConsumersCreatedDestroyed', 'transportLargeParentInspections',
                'originalVMMExecutions', 'originalDataSpawns', 'messages', 'originalPluginLoaderExecutions']),
            ('largeTransportRoute', ['parentFileInspections', 'largeParentFileInspections',
                'registryCapacityBytes', 'plistCapacityBytes', 'originalVMMExecutions',
                'originalPluginLoaderExecutions']),
            ('timeoutRequestOwnership', ['retained', 'released', 'realParentCloseEvents', 'pending']),
            ('instanceSetterDeadline', ['elapsedNanoseconds', 'deadlineNanoseconds'])]:
            for field in fields:
                rows = copy.deepcopy(original)
                selected = next(row for row in rows if row['record'] == record)
                value = selected[field]
                selected[field] = not value if isinstance(value, bool) else value + 1 if isinstance(value, int) else 'wrong'
                mutations.append((record + '.' + field, rows))
        for label in ['unknownRecord', 'duplicateInertRecord', 'missingLargeParentProvider',
                      'wrongLargeParentUUID', 'missingChildSummary', 'missingActualChildWait']:
            rows = copy.deepcopy(original)
            if label == 'unknownRecord': rows.append({'record': 'unreviewed'})
            elif label == 'duplicateInertRecord':
                rows.append(copy.deepcopy(next(row for row in rows if row['record'] == 'largeInertRoute')))
            elif label == 'missingLargeParentProvider':
                rows.remove(next(row for row in rows if row['record'] == 'provider'
                                 and row['symbol'] == 'VM27LargeOriginalParentCheckFile'))
            elif label == 'wrongLargeParentUUID':
                next(row for row in rows if row['record'] == 'provider'
                     and row['symbol'] == 'VM27LargeOriginalParentCheckFile')['UUID'] = '0' * 32
            elif label == 'missingChildSummary':
                rows.remove(next(row for row in rows if row['record'] == 'childSummary'))
            else:
                next(row for row in rows if row['record'] == 'summary')['observedChildWaitExit'] = 133
            mutations.append((label, rows))
        with tempfile.NamedTemporaryFile(prefix='VM27-Large-Actual-Receipt-', suffix='.jsonl', mode='w+') as stream:
            for label, rows in mutations:
                stream.seek(0); stream.truncate()
                stream.write(''.join(json.dumps(row) + '\n' for row in rows)); stream.flush()
                try:
                    validator.native_transcript(build, stream.name, 'macos', variant, pid, wait)
                except (AssertionError, KeyError, ValueError):
                    results.append({'variant': variant, 'mutation': label, 'rejected': True})
                else:
                    raise AssertionError('corrupt real receipt accepted: ' + variant + '.' + label)
        for wrong_pid, wrong_wait in [(pid + 1, wait), (pid, 133), (pid, 124)]:
            try:
                validator.native_transcript(build, path, 'macos', variant, wrong_pid, wrong_wait)
            except AssertionError:
                results.append({'variant': variant, 'mutation': 'PID/wait=' + str((wrong_pid, wrong_wait)),
                                'rejected': True})
            else:
                raise AssertionError('corrupt actual process proof accepted')
        assert validator.sha(path.read_bytes()) == original_sha
    return {'passed': True, 'cases': results, 'realReceiptsModified': False,
            'deviceOperations': False, 'originalVMMExecuted': False}


if __name__ == '__main__':
    assert len(sys.argv) == 2
    print(json.dumps(main(Path(sys.argv[1]).resolve()), indent=2))
