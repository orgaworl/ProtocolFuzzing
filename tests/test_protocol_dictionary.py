from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from can_fuzzing.common.protocol_dictionary import (
    COMMON_AFL_DICTIONARY_ENTRIES,
    COMMON_CAN_IDS,
    COMMON_DIAGNOSTIC_TEMPLATES,
    COMMON_OBD_PIDS,
    PRIVATE_OPCODES,
    render_afl_dictionary,
)


class ProtocolDictionaryTests(unittest.TestCase):
    def test_common_dictionary_contains_diagnostic_seed(self) -> None:
        self.assertIn(0x7DF, COMMON_CAN_IDS)
        self.assertIn(bytes([0x02, 0x10, 0x01]), COMMON_DIAGNOSTIC_TEMPLATES)

    def test_common_dictionary_contains_obd_and_private_tokens(self) -> None:
        self.assertIn(0x0C, COMMON_OBD_PIDS)
        self.assertIn(0xFF, PRIVATE_OPCODES)

    def test_render_afl_dictionary(self) -> None:
        rendered = render_afl_dictionary(COMMON_AFL_DICTIONARY_ENTRIES)
        self.assertIn('"\\x02\\x10\\x01"', rendered)
        self.assertIn('"\\xff"', rendered)


if __name__ == "__main__":
    unittest.main()
