from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from can_fuzzing.models import CANFrame, FrameFormat, FrameType
from can_fuzzing.scanner import expected_response_ids, frame_signature, is_probable_scan_response


class ScannerFilterTests(unittest.TestCase):
    def test_expected_response_ids_follow_standard_diagnostics(self) -> None:
        self.assertEqual(expected_response_ids(0x7DF), set(range(0x7E8, 0x7F0)))
        self.assertEqual(expected_response_ids(0x7E0), {0x7E8})
        self.assertIsNone(expected_response_ids(0x600))

    def test_background_and_echo_frames_are_filtered(self) -> None:
        probe = CANFrame.from_ints(0x7E0, [0x02, 0x10, 0x01, 0, 0, 0, 0, 0], FrameFormat.STANDARD, FrameType.DATA)
        passive_msg = SimpleNamespace(arbitration_id=0x4, data=bytes.fromhex("01207f00"), is_fd=False)
        echo_msg = SimpleNamespace(arbitration_id=0x7E0, data=probe.data, is_fd=False)
        response_msg = SimpleNamespace(arbitration_id=0x7E8, data=bytes.fromhex("0250010000000000"), is_fd=False)

        self.assertFalse(is_probable_scan_response(probe, passive_msg, {frame_signature(passive_msg)}))
        self.assertFalse(is_probable_scan_response(probe, echo_msg, set()))
        self.assertTrue(is_probable_scan_response(probe, response_msg, set()))


if __name__ == "__main__":
    unittest.main()
