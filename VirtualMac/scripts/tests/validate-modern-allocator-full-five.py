#!/usr/bin/env python3
"""Validate bounded actual five-API allocation records; no executable or remote import."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

NAMES = ["malloc_type_malloc", "malloc_type_calloc", "malloc_type_realloc",
         "malloc_type_posix_memalign", "malloc_type_zone_malloc_with_options"]
REQUIRED = {
    NAMES[0]: {"nonzero-pattern": {"allocated", "writePattern", "patternReadback", "realAllocationOwner"},
               "overflow-failure": {"oversizedNull", "oversizedENOMEM"},
               "zero-size-observation": {"zeroResultHasOwnerIfNonNull"}},
    NAMES[1]: {"clear-and-pattern": {"allocated", "allRequestedBytesZero", "writePattern", "patternReadback"},
               "multiplication-overflow": {"overflowNull", "overflowENOMEM"},
               "zero-count-observation": {"zeroResultHasOwnerIfNonNull"}},
    NAMES[2]: {"null-input": {"allocated", "writePattern"},
               "grow-preserves-prefix": {"growSucceeded", "oldPrefixPreserved", "writeGrownPattern"},
               "shrink-preserves-prefix": {"shrinkSucceeded", "shrinkPrefixPreserved"},
               "failure-preserves-input": {"oversizedNull", "oversizedENOMEM", "failureOriginalDataPreserved"}},
    NAMES[3]: {"legal-nonmultiple-size": {"allocated", "exactAlignment", "writePattern", "patternReadback"},
               "invalid-alignment": {"invalidReturnsEINVAL", "failureOutputUnchanged"},
               "oversized-failure": {"oversizedReturnsENOMEM", "failureOutputUnchanged"}},
    NAMES[4]: {"owned-zone-lifetime": {"customZoneCreated", "allZoneAllocationsReleasedBeforeDestroy"},
               "default-explicit-alignment": {"allocated", "exactAlignment", "writePattern", "patternReadback"},
               "custom-explicit-alignment": {"allocated", "exactAlignment", "customZoneOwner"},
               "default-alignment-nonmultiple-size": {"allocated", "clearBeforeWrite"},
               "invalid-alignment": {"invalidAlignmentNull"}, "explicit-nonmultiple-size": {"invalidSizeNull"}}
}


def need(ok, text):
    if not ok:
        raise ValueError(text)


def pairs(entries):
    result = {}
    for key, value in entries:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    need(0 < len(raw) <= 131072, "native stdout size bound")
    need(raw.endswith(b"\n"), "complete final newline")
    lines = raw.decode("ascii", errors="strict").splitlines()
    need(0 < len(lines) <= 1000, "record count bound")
    def invalid(_):
        raise ValueError("nonfinite JSON")
    rows = [json.loads(line, object_pairs_hook=pairs, parse_constant=invalid) for line in lines]
    need(all(type(row) is dict for row in rows), "object records only")
    return rows


def validate(raw, native_exit, target, provider_sha, actual_pid=None, provider_identity=None):
    need(type(native_exit) is int and native_exit == 0, "actual native exit zero required")
    need(target in ("mac", "ios") and re.fullmatch("[a-f0-9]{64}", provider_sha), "literal source pins")
    rows = decode(raw)
    need(rows[0].get("record") == "start" and rows[-1].get("record") == "summary", "exact record envelope")
    allowed = {"start", "check", "file", "binding", "census", "summary"}
    need(all(row.get("record") in allowed for row in rows), "no unexpected telemetry")
    types = Counter(row["record"] for row in rows)
    need(types["start"] == types["summary"] == 1 and types["file"] == 2 and
         types["binding"] == 10 and types["census"] == 2, "complete unique identity records")
    start, summary = rows[0], rows[-1]
    need(type(start.get("pid")) is int and 0 < start["pid"] < (1 << 31) and
         start.get("pid") == summary.get("pid"), "exact native PID")
    if actual_pid is not None:
        need(actual_pid == start["pid"], "direct parent PID binding")
    need(start.get("target") == target and start.get("fiveStrongImports") is True and
         start.get("VMCalls") == start.get("GPUCalls") == 0, "exact bounded probe target")
    check_rows = [r for r in rows if r["record"] == "check"]
    need(200 <= len(check_rows) <= 400 and
         [r.get("id") for r in check_rows] == list(range(1, len(check_rows) + 1)), "unique continuous checks")
    need(all(r.get("passed") is True for r in check_rows), "every native check must pass")
    need(summary.get("checks") == len(check_rows) and summary.get("failures") == 0 and
         summary.get("allFiveSemanticsPassed") is True, "summary independently recomputed")
    observed = Counter((r.get("api"), r.get("case"), r.get("name")) for r in check_rows)
    for api, cases in REQUIRED.items():
        for case, names in cases.items():
            for name in names:
                # Explicit alignment has four options per each of two type IDs.
                wanted = 8 if case in ("default-explicit-alignment", "custom-explicit-alignment") else 2
                need(observed[(api, case, name)] == wanted, "missing exact semantic oracle " + api + "/" + case + "/" + name)
    for case in ("default-explicit-alignment", "custom-explicit-alignment"):
        need(observed[(NAMES[4], case, "clearBeforeWrite")] == 4 and
             observed[(NAMES[4], case, "realCanonicalUntaggedPointer")] == 4, "CLEAR/CANONICAL option coverage")
    need(summary.get("calls") == [6, 6, 8, 6, 22], "exact actual five API call counts")
    need(type(summary.get("created")) is int and 26 <= summary["created"] <= 30 and
         summary.get("created") == summary.get("released") and summary.get("live") == 0,
         "genuine own allocation lifetime accounting")
    need(summary.get("zonesCreated") == summary.get("zonesDestroyed") == 2 and
         summary.get("requestedBytes") == 10124, "two actual zone lifetimes and bounded requests")
    need(summary.get("unknownOptionsTrapTested") is False and
         summary.get("typedTelemetryImplemented") is False and summary.get("full27VMMProved") is False,
         "scope cannot claim untested allocator telemetry or VMM")
    for phase in ("before", "after"):
        files = [r for r in rows if r["record"] == "file" and r.get("phase") == phase]
        need(len(files) == 1 and files[0].get("exact") is True and
             files[0].get("sameOriginalInodeMetadata") is True and
             files[0].get("sha256") == provider_sha and type(files[0].get("bytes")) is int,
             "exact before/after provider file")
        bindings = [r for r in rows if r["record"] == "binding" and r.get("phase") == phase]
        need([r.get("symbol") for r in bindings] == NAMES and all(r.get("exact") is True and
             r.get("fileSHA256") == provider_sha and type(r.get("rva")) is int and r["rva"] > 0 and
             re.fullmatch("[a-f0-9]{32}", r.get("uuid", "")) for r in bindings), "all five loaded identities")
        need(len({r["uuid"] for r in bindings}) == 1, "one true provider UUID")
        if provider_identity is not None:
            need(files[0]["bytes"] == provider_identity["bytes"] and all(
                row["uuid"] == provider_identity["uuid"] and
                row["rva"] == provider_identity["exports"][row["symbol"]] for row in bindings),
                "exact frozen provider UUID/RVA/size")
        census = [r for r in rows if r["record"] == "census" and r.get("phase") == phase]
        need(len(census) == 1 and census[0].get("exact") is True and
             census[0].get("privateProviderImages") == 1 and census[0].get("forbiddenFrameworks") == 0,
             "no HV/GPU framework in actual image census")
    before = [(r["symbol"], r["uuid"], r["rva"]) for r in rows if r["record"] == "binding" and r["phase"] == "before"]
    after = [(r["symbol"], r["uuid"], r["rva"]) for r in rows if r["record"] == "binding" and r["phase"] == "after"]
    need(before == after, "before/after loaded identity stability")
    return dict(passed=True, actualPID=start["pid"], target=target, checks=len(check_rows),
                actualAPICalls=summary["calls"], allocationsReleased=summary["released"],
                providerSHA256=provider_sha, stdoutSHA256=hashlib.sha256(raw).hexdigest(),
                full27VMMProved=False)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stdout", type=Path, required=True)
    p.add_argument("--native-exit", type=int, required=True)
    p.add_argument("--target", choices=("mac", "ios"), required=True)
    p.add_argument("--provider-sha", required=True)
    p.add_argument("--actual-pid", type=int)
    a = p.parse_args()
    print(json.dumps(validate(a.stdout.read_bytes(), a.native_exit, a.target, a.provider_sha, a.actual_pid), indent=2))
