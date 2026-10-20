#!/usr/bin/env python3
"""Typed saved Foundation receipt gate layered over the frozen ABI validator."""
import hashlib
import importlib.util
import json
from pathlib import Path

VALIDATOR = Path(__file__).with_name('validate-modern-foundation-stringdata.py')
EXPECTED = '088c6c01f2566e80da7dc0d4f85c5cd7a5810affe1745e4fd423aa7f201406d2'


def native_transcript(path, pid, wait, role='ios'):
    assert hashlib.sha256(VALIDATOR.read_bytes()).hexdigest() == EXPECTED
    assert type(pid) is int and pid > 1 and type(wait) is int and wait == 0
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    assert len(rows) == 8
    for index, row in enumerate(rows):
        assert type(row) is dict
        for key, value in row.items():
            if key in ('naturalAliasSameAddress', 'originalSDKDeclarations', 'NSStringAndLegacyGenericCompared', 'passed'):
                assert type(value) is bool and value is True
            elif key in ('PID', 'conversionCallsSoFar', 'size', 'stride', 'alignment', 'checks', 'originalSDKCalls',
                         'iterations', 'strings', 'encodings', 'lossyCalls', 'nilResults', 'copyOnWriteChecks',
                         'privateAliasIdentities', 'diskVMGPUCalls'):
                assert type(value) is int
            else:
                assert type(value) is str
    spec = importlib.util.spec_from_file_location('vm27_foundation_frozen_validator', VALIDATOR)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.native_transcript(path, pid, wait, role)
