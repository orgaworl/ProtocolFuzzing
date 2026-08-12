from __future__ import annotations

import unittest

from can_fuzzing.protocol.xcp import XCPProtocol, summarize_responses


class XCPProtocolTests(unittest.TestCase):
    def test_build_request_frame(self) -> None:
        protocol = XCPProtocol()
        frame = protocol.build_request_frame(bytes([0xFF, 0x00]))
        self.assertEqual(frame, bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    def test_decode_connect_response(self) -> None:
        protocol = XCPProtocol()
        frame = protocol.decode_response(bytes([0xFF, 0x03, 0x06, 0x08, 0x34, 0x12, 0x01, 0x02]), 0xFF)
        self.assertTrue(frame.positive)
        self.assertIsNotNone(frame.connect_info)
        self.assertEqual(frame.connect_info.max_cto, 0x08)
        self.assertEqual(frame.connect_info.max_dto, 0x1234)

    def test_decode_status_and_comm_mode_and_id_responses(self) -> None:
        protocol = XCPProtocol()
        status = protocol.decode_response(bytes([0xFF, 0xA5, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00]), 0xFD)
        comm = protocol.decode_response(bytes([0xFF, 0x00, 0x03, 0x00, 0x10, 0x05, 0x02, 0x11]), 0xFB)
        ident = protocol.decode_response(bytes([0xFF, 0x00, 0x01, 0x11, 0x22, 0x33]), 0xFA)
        self.assertIsNotNone(status.status_info)
        self.assertIsNotNone(comm.comm_mode_info)
        self.assertIsNotNone(ident.id_info)
        self.assertEqual(ident.id_info.identifier, bytes([0x11, 0x22, 0x33]))

    def test_decode_negative_response(self) -> None:
        protocol = XCPProtocol()
        frame = protocol.decode_response(bytes([0xFE, 0x22, 0x00]), 0xFF)
        self.assertTrue(frame.negative)
        self.assertEqual(frame.error_name, 'ERR_OUT_OF_RANGE')

    def test_summarize_responses(self) -> None:
        summary = summarize_responses(['ff03060834120102', 'fe220000'], 0xFF)
        self.assertEqual(summary['positive'], 1)
        self.assertEqual(summary['negative'], 1)
        self.assertEqual(summary['kind'], 'negative_response')


if __name__ == '__main__':
    unittest.main()
