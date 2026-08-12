from __future__ import annotations

import unittest

from can_fuzzing.fuzzing.uds_fuzz import decode_response, encode_request_frames, summarize_responses


class UDSFuzzProtocolHelperTests(unittest.TestCase):
    def test_encode_request_frames_uses_isotp_single_frame(self) -> None:
        frames = encode_request_frames(bytes([0x3E, 0x00]))
        self.assertEqual(frames, [bytes([0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])])

    def test_decode_positive_and_negative_response(self) -> None:
        positive = decode_response(bytes([0x03, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0x3E)
        negative = decode_response(bytes([0x03, 0x7F, 0x3E, 0x13, 0x00, 0x00, 0x00, 0x00]), 0x3E)
        self.assertTrue(positive.positive)
        self.assertEqual(positive.frame_kind, 'positive_response')
        self.assertIsNotNone(positive.positive_info)
        self.assertEqual(positive.positive_info.subfunction, 0x00)
        self.assertTrue(negative.negative)
        self.assertEqual(negative.nrc, 0x13)
        self.assertIsNotNone(negative.negative_info)
        self.assertEqual(negative.negative_info.nrc_name, 'incorrect_message_length_or_invalid_format')

    def test_decode_read_data_by_identifier_response(self) -> None:
        frame = decode_response(bytes([0x06, 0x62, 0xF1, 0x90, 0x12, 0x34, 0x00, 0x00]), 0x22)
        self.assertTrue(frame.positive)
        self.assertIsNotNone(frame.positive_info)
        self.assertEqual(frame.positive_info.data_identifier, 0xF190)
        self.assertEqual(frame.positive_info.data, bytes([0x12, 0x34, 0x00]))

    def test_summarize_responses_counts_frames(self) -> None:
        summary = summarize_responses(['037e000000000000', '037f3e1300000000'], 0x3E)
        self.assertEqual(summary['positive'], 1)
        self.assertEqual(summary['negative'], 1)
        self.assertEqual(summary['kind'], 'negative_response')


if __name__ == '__main__':
    unittest.main()
