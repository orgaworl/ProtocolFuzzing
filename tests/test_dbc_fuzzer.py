from __future__ import annotations

import random
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_fuzzing.protocol.dbc import load_dbc_database
from can_fuzzing.fuzzing.dbc_fuzz import build_request


class DBCFuzzerTests(unittest.TestCase):
    def test_dbc_parse_pack_and_decode_roundtrip(self) -> None:
        dbc_text = """
VERSION ""
BO_ 256 DemoMessage: 8 Vector__XXX
 SG_ Speed : 0|16@1+ (0.1,0) [0|250] "kmh" Vector__XXX
 SG_ Counter : 23|16@0+ (1,0) [0|65535] "" Vector__XXX
VAL_ 256 Counter 0 "Zero" 1 "One";
""".strip()

        with TemporaryDirectory() as tmpdir:
            dbc_path = Path(tmpdir) / "demo.dbc"
            dbc_path.write_text(dbc_text, encoding="utf-8", newline="\n")
            database = load_dbc_database(dbc_path)

        self.assertEqual(len(database.messages), 1)
        message = database.messages[0]
        payload = message.encode({"Speed": 123.4, "Counter": 0x1234})
        self.assertEqual(len(payload), 8)
        decoded = message.decode(payload)
        self.assertAlmostEqual(float(decoded["Speed"]), 123.4, places=1)
        self.assertEqual(decoded["Counter"], 0x1234)

    def test_build_request_uses_dbc_message_definition(self) -> None:
        dbc_text = """
VERSION ""
BO_ 512 TestMessage: 8 Vector__XXX
 SG_ Value : 0|8@1+ (1,0) [0|255] "" Vector__XXX
""".strip()

        with TemporaryDirectory() as tmpdir:
            dbc_path = Path(tmpdir) / "test.dbc"
            dbc_path.write_text(dbc_text, encoding="utf-8", newline="\n")
            database = load_dbc_database(dbc_path)

        rng = random.Random(7)
        request = build_request(rng, database)
        self.assertEqual(request.message_id, 512)
        self.assertEqual(len(request.payload), 8)
        self.assertIn("Value", request.signal_values)


if __name__ == "__main__":
    unittest.main()




