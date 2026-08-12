from __future__ import annotations

import unittest
from pathlib import Path

from can_fuzzing.runtime.models import CANHardwareConfig, FrameFormat
from can_fuzzing.scanning.xcp_scan import (
    XCPNode,
    XCPScanConfig,
    build_connect_frame,
    build_summary,
    classify_xcp_response,
    is_xcp_like_response,
)


class XCPScanTests(unittest.TestCase):
    def test_build_connect_frame_uses_scapy_payload(self) -> None:
        frame = build_connect_frame(0x700, False)
        self.assertEqual(frame.identifier, 0x700)
        self.assertEqual(frame.frame_format, FrameFormat.STANDARD)
        self.assertTrue(frame.data.startswith(bytes([0xFF])))

    def test_classify_positive_and_negative_response(self) -> None:
        positive = classify_xcp_response(0x700, 0x708, bytes.fromhex("ff15c00808001010"))
        negative = classify_xcp_response(0x700, 0x708, bytes.fromhex("fe22"))
        self.assertIsNotNone(positive)
        self.assertEqual(positive.response_kind, "positive_connect")
        self.assertEqual(positive.max_cto, 8)
        self.assertIsNotNone(negative)
        self.assertEqual(negative.response_kind, "negative_response")
        self.assertEqual(negative.error_name, "ERR_OUT_OF_RANGE")

    def test_is_xcp_like_response(self) -> None:
        self.assertTrue(is_xcp_like_response(bytes.fromhex("ff15c00808001010")))
        self.assertTrue(is_xcp_like_response(bytes.fromhex("fe22")))
        self.assertFalse(is_xcp_like_response(bytes.fromhex("000102")))

    def test_build_summary_counts_nodes(self) -> None:
        config = XCPScanConfig(
            hardware=CANHardwareConfig(interface="pcan", channel="PCAN_USBBUS1", bitrate=500000, receive_timeout=0.05, fd=False, data_bitrate=None, auto_bitrate=False, bitrate_candidates=(), data_bitrate_candidates=(), bitrate_probe_timeout=0.0, fd_timing_preset=None, fd_clock=0, nominal_sample_point=0.0, data_sample_point=0.0, check_message=False, drop_echo=True),
            output_dir=Path("result"),
            campaign="can_scan_xcp",
            request_id_start=0x700,
            request_id_end=0x701,
            response_timeout=0.1,
            inter_probe_delay_ms=1.0,
            extended_can_id=False,
        )
        nodes = [XCPNode(0x700, 0x708, "negative_response", "fe22", 0x22, "ERR_OUT_OF_RANGE", None, None, None, None, None, None)]
        summary = build_summary(config, nodes, Path("xcp_nodes.csv"), False)
        self.assertEqual(summary["node_count"], 1)
        self.assertEqual(summary["negative_nodes"], 1)
        self.assertEqual(summary["nodes"][0]["response_id"], "0x708")


if __name__ == "__main__":
    unittest.main()
