from __future__ import annotations

import unittest

from can_fuzzing.protocol.obd import OBDProtocol, summarize_responses


class OBDProtocolTests(unittest.TestCase):
    def test_encode_request_frames_uses_isotp_single_frame(self) -> None:
        protocol = OBDProtocol()
        frames = protocol.encode_request_frames(bytes([0x01, 0x0C]))
        self.assertEqual(frames, [bytes([0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00])])

    def test_decode_response(self) -> None:
        protocol = OBDProtocol()
        positive = protocol.decode_response(bytes([0x03, 0x41, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00]), 0x01)
        negative = protocol.decode_response(bytes([0x03, 0x7F, 0x01, 0x12, 0x00, 0x00, 0x00, 0x00]), 0x01)
        self.assertTrue(positive.positive)
        self.assertTrue(negative.negative)
        self.assertEqual(negative.frame_kind, "negative_response")

    def test_summarize_responses(self) -> None:
        summary = summarize_responses(["03410c0000000000", "037f011200000000"], 0x01)
        self.assertEqual(summary["positive"], 1)
        self.assertEqual(summary["negative"], 1)
        self.assertEqual(summary["kind"], "negative_response")


if __name__ == "__main__":
    unittest.main()
