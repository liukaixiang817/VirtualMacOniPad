#!/usr/bin/env python3
"""Real instruction regressions for the genuine27 extraction collector."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cache_tests", HERE / "test-modern-dyld-cache.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
uncache = fixtures.uncache


class GOTDefinitionLifetimeTests(unittest.TestCase):
    def collect(self, words, reg=22):
        buf, text, _ = fixtures.fixture_image()
        # __text is eight instructions; use real ARM64 encodings assembled by
        # clang and the exact genuine UniversalHID LDP/ADD counter pair.
        size = len(words) * 4
        struct.pack_into("<Q", buf, 32 + 72 + 40, size)
        source = 0x280000000
        words = [uncache._set_adrp(0x90000000 | reg, text+0x200, source)] + words
        struct.pack_into("<Q", buf, 32 + 72 + 40, len(words)*4)
        struct.pack_into("<" + "I" * len(words), buf, 0x200, *words)
        calls = []
        def symbols(addresses):
            calls.append(set(addresses))
            return {a: ("_real_genuine_target", "/usr/lib/libSystem.B.dylib") for a in addresses}
        with patch.object(uncache, "a2s_batch", side_effect=symbols):
            result = uncache.collect_got_refs(buf, "not-opened")
        return result, calls, source

    def test_genuine_ldp_overwrites_old_callee_saved_definition(self):
        result, calls, _ = self.collect([0xA9412296, 0x910006D5])
        self.assertEqual(result, {})
        self.assertEqual(calls, [])

    def test_32_bit_write_invalidates_the_64_bit_alias(self):
        for word in (0x2A0003F6, 0x4A0002D6):  # MOV W22 / EOR W22
            with self.subTest(word=hex(word)):
                self.assertEqual(self.collect([word, 0x910006D5])[0], {})

    def test_load_destination_does_not_keep_its_previous_adrp(self):
        self.assertEqual(self.collect([0xF9400296, 0x910006D5])[0], {})

    def test_unknown_instruction_and_control_flow_reset_definitions(self):
        for word in (0, 0xB4000000, 0x36000000, 0x14000000, 0xD65F03C0):
            with self.subTest(word=hex(word)):
                self.assertEqual(self.collect([word, 0x910082D5])[0], {})

    def test_calls_keep_callee_saved_but_clear_caller_saved_definitions(self):
        result, _, source = self.collect([0x94000000, 0x910082D5])
        self.assertEqual(result, {source+32: ("_real_genuine_target", True)})
        # ADD X21,X0,#32: caller-saved X0 does not survive BL.
        self.assertEqual(self.collect([0x94000000, 0x91008015], reg=0)[0], {})

    def test_actual_immediate_and_load_consumers_keep_auth_semantics(self):
        for word, auth in ((0x910082D5, True), (0xF94012D5, False)):
            result, _, source = self.collect([word])
            self.assertEqual(result, {source+32: ("_real_genuine_target", auth)})

    def ivar_fixture(self, alignment=3, width=8, count=1, entry=32):
        buf, text, data = fixtures.fixture_image()
        # Turn the spare section into a bounded objc_const ivar list and use
        # file-backed __DATA for the runtime ivar-offset word.
        section = 32+72+80
        struct.pack_into("<16s16sQQIIIIIIII", buf, section,
                         b"__objc_const", b"__TEXT", text+0x300, 40, 0x300,
                         3, 0, 0, 0, 0, 0, 0)
        struct.pack_into("<IIQQQII", buf, 0x300, entry, count,
                         data, 0x1F549E080, 0x1F949C4BF, alignment, width)
        struct.pack_into("<Q", buf, 0x1000, 16)
        return buf, text

    def test_empty_encoding_scope_is_the_concrete_ivar_type_field(self):
        buf, text = self.ivar_fixture()
        self.assertEqual(uncache.collect_objc_ivar_type_slots(buf), {text+0x318})
        for overrides in (dict(alignment=7), dict(width=0x100001), dict(count=2), dict(entry=24)):
            with self.subTest(overrides=overrides):
                buf, _ = self.ivar_fixture(**overrides)
                self.assertEqual(uncache.collect_objc_ivar_type_slots(buf), set())

    def test_only_the_original_zero_extent_record_can_have_null_storage(self):
        buf, text = self.ivar_fixture(alignment=0, width=0)
        struct.pack_into("<Q", buf, 0x308, 0)
        self.assertEqual(uncache.collect_objc_ivar_type_slots(buf), {text+0x318})
        struct.pack_into("<I", buf, 0x324, 8)
        self.assertEqual(uncache.collect_objc_ivar_type_slots(buf), set())


if __name__ == "__main__":
    unittest.main()
