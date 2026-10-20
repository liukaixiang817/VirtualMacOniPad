#!/usr/bin/env python3
"""Negative collector controls from genuine local allocation output, without native execution."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("allocator_validator", HERE / "validate-modern-allocator-full-five.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
RAW = None
PROVIDER = None


def encode(rows):
    return ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode()


class Validation(unittest.TestCase):
    def rows(self):
        return copy.deepcopy(validator.decode(RAW))

    def check(self, rows, code=0):
        return validator.validate(encode(rows), code, "mac", PROVIDER["sha256"],
                                  provider_identity=PROVIDER)

    def reject(self, rows, code=0):
        with self.assertRaises(ValueError):
            self.check(rows, code)

    def test_actual_local_fixture(self):
        self.assertTrue(self.check(self.rows())["passed"])

    def test_actual_exit_failure(self):
        self.reject(self.rows(), 83)

    def test_missing_loaded_binding(self):
        rows = self.rows()
        rows.pop(next(i for i, row in enumerate(rows) if row["record"] == "binding"))
        self.reject(rows)

    def test_false_call_counts(self):
        rows = self.rows(); rows[-1]["calls"][0] = 0
        self.reject(rows)

    def test_changed_provider_UUID_both_phases(self):
        rows = self.rows()
        for row in rows:
            if row["record"] == "binding": row["uuid"] = "0" * 32
        self.reject(rows)

    def test_changed_provider_RVA(self):
        rows = self.rows()
        next(row for row in rows if row["record"] == "binding")["rva"] += 4
        self.reject(rows)

    def test_failure_cannot_hide_in_success_summary(self):
        rows = self.rows()
        next(row for row in rows if row["record"] == "check")["passed"] = False
        self.reject(rows)

    def test_missing_semantic_even_with_consistent_summary(self):
        rows = self.rows()
        rows.pop(next(i for i, row in enumerate(rows) if row.get("name") == "oldPrefixPreserved"))
        count = 0
        for row in rows:
            if row["record"] == "check": count += 1; row["id"] = count
        rows[-1]["checks"] = count
        self.reject(rows)

    def test_duplicate_JSON_key(self):
        raw = RAW.replace(b'"record":"start"', b'"record":"start","record":"start"', 1)
        with self.assertRaises(ValueError): validator.decode(raw)

    def test_leaked_buffer(self):
        rows = self.rows(); rows[-1]["live"] = 1
        self.reject(rows)

    def test_full_VMM_claim_rejected(self):
        rows = self.rows(); rows[-1]["full27VMMProved"] = True
        self.reject(rows)

    def test_out_of_order_check_identity(self):
        rows = self.rows()
        next(row for row in rows if row["record"] == "check")["id"] = 2
        self.reject(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    args = parser.parse_args()
    RAW = args.fixture.read_bytes()
    PROVIDER = json.loads(args.build_report.read_text())["files"]["mac"]["provider"]
    unittest.main(argv=["allocator-negative-controls"], verbosity=2)
