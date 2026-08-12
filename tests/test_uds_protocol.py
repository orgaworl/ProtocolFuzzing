from __future__ import annotations

import unittest

from can_fuzzing.protocol.uds import UDSProtocol, summarize_responses


class UDSProtocolTests(unittest.TestCase):
    def test_encode_request_frames_uses_isotp_single_frame(self) -> None:
        protocol = UDSProtocol()
        frames = protocol.encode_request_frames(bytes([0x3E, 0x00]))
        self.assertEqual(frames, [bytes([0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])])

    def test_decode_positive_and_negative_response(self) -> None:
        protocol = UDSProtocol()
        positive = protocol.decode_response(bytes([0x03, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0x3E)
        negative = protocol.decode_response(bytes([0x03, 0x7F, 0x3E, 0x13, 0x00, 0x00, 0x00, 0x00]), 0x3E)
        self.assertTrue(positive.positive)
        self.assertEqual(positive.frame_kind, "positive_response")
        self.assertTrue(negative.negative)
        self.assertEqual(negative.nrc, 0x13)

    def test_summarize_responses_counts_frames(self) -> None:
        summary = summarize_responses(["037e000000000000", "037f3e1300000000"], 0x3E)
        self.assertEqual(summary["positive"], 1)
        self.assertEqual(summary["negative"], 1)
        self.assertEqual(summary["kind"], "negative_response")


if __name__ == "__main__":
    unittest.main()
