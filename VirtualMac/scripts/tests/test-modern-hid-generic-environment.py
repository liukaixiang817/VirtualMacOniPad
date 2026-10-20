#!/usr/bin/env python3
"""Meaningful structural checks for the bounded binary generic environment."""
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'development'))
from universalhid_generic_environment_v1 import parse_environment


class EnvironmentTests(unittest.TestCase):
    def valid(self):
        # Genuine record layout: flags, cumulative count, ordinary key type
        # parameter, zero alignment, then one Protocol requirement.
        return bytearray(struct.pack('<IHBBIii',0x1001,1,0x80,0,0x80,-28,838348793))

    def test_binary_header_not_mangled_reference(self):
        b=self.valid();r=parse_environment(b,0,len(b))
        self.assertEqual((r['flags'],r['levels'],r['counts'],r['parameters'],r['end']),
                         (0x1001,1,[1],[0x80],20))
        self.assertEqual(r['requirements'][0]['parameterOffset'],12)
        self.assertEqual(r['requirements'][0]['valueOffset'],16)

    def test_truncated_requirement_rejected(self):
        b=self.valid()
        for end in range(20):
            with self.assertRaises(AssertionError):parse_environment(b,0,end)

    def test_unknown_environment_flags_rejected(self):
        b=self.valid();struct.pack_into('<I',b,0,0x10001001)
        with self.assertRaises(AssertionError):parse_environment(b,0,len(b))

    def test_invalid_levels_and_parameter_counts_rejected(self):
        for flags,count in ((0x1000,1),(0x1101,1),(0x1001,0),(0x1001,1025)):
            b=self.valid();struct.pack_into('<IH',b,0,flags,count)
            with self.assertRaises(AssertionError):parse_environment(b,0,len(b))

    def test_non_cumulative_counts_rejected(self):
        b=struct.pack('<IHH',2,2,1)+b'\x80\x80'
        with self.assertRaises(AssertionError):parse_environment(b,0,len(b))

    def test_unsupported_parameter_and_padding_rejected(self):
        for offset,value in ((6,0x81),(7,0x80)):
            b=self.valid();b[offset]=value
            with self.assertRaises(AssertionError):parse_environment(b,0,len(b))

    def test_unsupported_requirement_or_null_targets_rejected(self):
        for offset,value in ((8,0x85),(8,0x10080),(12,0),(16,0)):
            b=self.valid();struct.pack_into('<I',b,offset,value)
            with self.assertRaises(AssertionError):parse_environment(b,0,len(b))

    def test_alignment_with_multiple_parameters(self):
        b=struct.pack('<IH',0x1001,3)+b'\x80\x80\0\0\0\0'+struct.pack('<Iii',0x80,-4,17)
        r=parse_environment(b,0,len(b));self.assertEqual(r['requirements'][0]['offset'],12)
        self.assertEqual(r['end'],24)


if __name__=='__main__':unittest.main()
