from __future__ import annotations

import unittest

from can_fuzzing.protocol.xcp import XCPProtocol, summarize_responses


class XCPProtocolTests(unittest.TestCase):
    def test_build_request_frame(self) -> None:
        protocol = XCPProtocol()
        frame = protocol.build_request_frame(bytes([0xFF, 0x00]))
        self.assertEqual(frame, bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    def test_decode_response(self) -> None:
        protocol = XCPProtocol()
        positive = protocol.decode_response(bytes([0xFF, 0xFF, 0x01, 0x00]), 0xFF)
        negative = protocol.decode_response(bytes([0xFE, 0x22, 0x00]), 0xFF)
        self.assertTrue(positive.positive)
        self.assertTrue(negative.negative)
        self.assertEqual(negative.error_name, 'ERR_OUT_OF_RANGE')

    def test_summarize_responses(self) -> None:
        summary = summarize_responses(['ffff0100', 'fe220000'], 0xFF)
        self.assertEqual(summary['positive'], 1)
        self.assertEqual(summary['negative'], 1)
        self.assertEqual(summary['kind'], 'negative_response')


if __name__ == '__main__':
    unittest.main()
