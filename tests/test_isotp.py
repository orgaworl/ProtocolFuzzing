from __future__ import annotations

import unittest

from can_fuzzing.protocol.isotp import IsoTp, decode_isotp_payload, encode_isotp_single_frame, segment_isotp_message


class IsoTpTests(unittest.TestCase):
    def test_encode_single_frame_keeps_classic_can_padding(self) -> None:
        self.assertEqual(encode_isotp_single_frame(b"\x3e\x00"), b"\x02\x3e\x00\x00\x00\x00\x00\x00")

    def test_decode_single_frame_payload(self) -> None:
        frame_type, payload = decode_isotp_payload(b"\x02\x3e\x00\x00\x00\x00\x00\x00")
        self.assertEqual(frame_type, "single_frame")
        self.assertEqual(payload, b"\x3e\x00")

    def test_segment_message_builds_first_and_consecutive_frames(self) -> None:
        frames = segment_isotp_message(bytes(range(10)))
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0][:2], b"\x10\x0a")
        self.assertEqual(frames[1][0] >> 4, 0x2)
        self.assertEqual(frames[1][0] & 0x0F, 0x1)

    def test_segment_message_without_padding_keeps_last_frame_short(self) -> None:
        frames = IsoTp(padding_value=None).segment_message(bytes(range(8)))
        self.assertEqual(len(frames), 2)
        self.assertLess(len(frames[1]), 8)


if __name__ == "__main__":
    unittest.main()
