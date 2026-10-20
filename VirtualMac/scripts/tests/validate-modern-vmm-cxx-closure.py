#!/usr/bin/env python3
"""Validate an actual bounded13-API probe log; no device access or execution.

The parent supplies its separately observed direct-child PID/wait status.
Static validation never becomes native success, and missing records fail.
"""
from pathlib import Path
import hashlib
import json
import sys


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate(stdout_path, build_path, role, expected_pid, wait_exit):
    source = Path(stdout_path).read_bytes()
    assert 0 < len(source) < 1024 * 1024
    rows = [json.loads(line, object_pairs_hook=unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
            for line in source.decode().splitlines()]
    assert all(isinstance(row, dict) for row in rows)
    assert set(row["record"] for row in rows) == {"start", "file", "binding", "census", "check", "summary"}
    starts = [row for row in rows if row["record"] == "start"]
    summaries = [row for row in rows if row["record"] == "summary"]
    assert len(starts) == len(summaries) == 1 and rows[0] == starts[0] and rows[-1] == summaries[0]
    assert type(expected_pid) is int and expected_pid > 1 and starts[0]["pid"] == expected_pid
    assert type(wait_exit) is int and wait_exit == 0
    start, summary = starts[0], summaries[0]
    assert start["cpuLimitSeconds"] == 5 and start["wallLimitSeconds"] == 10
    assert start["VMCalls"] == start["GPUCalls"] == 0
    assert role in ("ios", "macos")
    if role == "ios":
        assert start["uid"] == 0, "This candidate is scoped to the parent's private Root staging path"
    builds = json.loads(Path(build_path).read_bytes())
    selected = [row for row in builds["libraries"] if row["role"] == role]
    assert len(selected) == 1
    provider = selected[0]["provider"]
    exports = builds["exports"]
    assert len(exports) == 13 and len(set(exports)) == 13
    files = [row for row in rows if row["record"] == "file"]
    assert len(files) == 2 and {row["phase"] for row in files} == {"before", "after"}
    assert all(row["exact"] is True and row["sha256"] == provider["sha256"] and
               row["bytes"] == provider["bytes"] for row in files)
    bindings = [row for row in rows if row["record"] == "binding"]
    assert len(bindings) == 26
    assert {(row["phase"], row["index"]) for row in bindings} == {
        (phase, index) for phase in ("before", "after") for index in range(13)}
    for row in bindings:
        assert type(row["index"]) is int and 0 <= row["index"] < 13
        assert row["exact"] is True and row["UUID"] == provider["UUID"]
        assert row["rva"] == provider["RVAs"][exports[row["index"]]]
    censuses = [row for row in rows if row["record"] == "census"]
    assert len(censuses) == 2 and {row["phase"] for row in censuses} == {"before", "after"}
    assert all(row["exact"] is True and row["privateProviderCount"] == 1 and
               row["forbidden"] == 0 and 0 < row["imageCount"] <= 4096 for row in censuses)
    checks = [row for row in rows if row["record"] == "check"]
    assert len(checks) == summary["checks"] == 180
    assert [row["id"] for row in checks] == list(range(1, 181))
    assert all(row["passed"] is True for row in checks)
    assert summary["passed"] is True and summary["failures"] == 0
    assert summary["created"] == summary["released"] == 8
    assert summary["calls"] == [9, 7, 4, 9, 7, 4, 9, 7, 4, 6, 6, 6, 6]
    required_cases = {"identity", "plain-roundtrip", "general-roundtrip", "exhausted-buffer",
                      "precision-exact-text", "special-values", "typed-new-pattern-free",
                      "typed-delete-null", "typed-new-zero", "typed-new-overflow-throws", "lifecycle"}
    assert {row["case"] for row in checks} == required_cases
    assert not builds["deviceOperations"] and not builds["originalVMMExecuted"] and not builds["completeVMMClosure"]
    return {"passed": True, "role": role, "observedDirectChildPID": expected_pid,
            "observedWaitExit": wait_exit, "checks": 180, "exactStrongAPIs": 13,
            "allocationsReleased": 8, "stdoutSHA256": hashlib.sha256(source).hexdigest(),
            "originalVMMExecuted": False, "completeVMMClosure": False}


if __name__ == "__main__":
    if len(sys.argv) != 6:
        raise SystemExit("Usage: validate-modern-vmm-cxx-closure.py STDOUT BUILD_RESULT ios|macos DIRECT_CHILD_PID WAIT_EXIT")
    print(json.dumps(validate(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])), indent=2))
