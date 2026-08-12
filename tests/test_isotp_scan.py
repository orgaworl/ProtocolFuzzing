from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from scapy.contrib.isotp.isotp_scanner import get_isotp_packet

from can_fuzzing.scanning.isotp_scan import (
    IsoTpNode,
    IsoTpScanConfig,
    build_summary,
    can_message_to_scapy_packet,
    scapy_packet_to_can_frame,
)
from can_fuzzing.runtime.models import CANHardwareConfig, FrameFormat


class IsoTpScanTests(unittest.TestCase):
    def test_scapy_probe_converts_to_can_frame(self) -> None:
        packet = get_isotp_packet(0x7E0)
        frame = scapy_packet_to_can_frame(packet)
        self.assertEqual(frame.identifier, 0x7E0)
        self.assertEqual(frame.frame_format, FrameFormat.STANDARD)
        self.assertEqual(frame.data.hex(), "1064000000000000")

    def test_can_message_converts_to_scapy_packet(self) -> None:
        msg = SimpleNamespace(arbitration_id=0x7E8, data=bytes.fromhex("3000000000000000"), is_fd=False, is_extended_id=False)
        packet = can_message_to_scapy_packet(msg)
        self.assertEqual(packet.identifier, 0x7E8)
        self.assertEqual(bytes(packet.data).hex(), "3000000000000000")

    def test_build_summary_serializes_nodes(self) -> None:
        config = IsoTpScanConfig(
            hardware=CANHardwareConfig(interface="pcan", channel="PCAN_USBBUS1", bitrate=500000, receive_timeout=0.05, fd=False, data_bitrate=None, auto_bitrate=False, bitrate_candidates=(), data_bitrate_candidates=(), bitrate_probe_timeout=0.0, fd_timing_preset=None, fd_clock=0, nominal_sample_point=0.0, data_sample_point=0.0, check_message=False, drop_echo=True),
            output_dir=Path("result"),
            campaign="can_scan_isotp",
            request_id_start=0x7E0,
            request_id_end=0x7E7,
            sniff_time=0.1,
            verify_results=True,
            extended_can_id=False,
        )
        summary = build_summary(config, [IsoTpNode(0x7E0, 0x7E8, "3000000000000000", "standard", "normal")], Path("nodes.csv"), False)
        self.assertEqual(summary["node_count"], 1)
        self.assertEqual(summary["nodes"][0]["request_id"], "0x7e0")
        self.assertEqual(summary["nodes"][0]["response_id"], "0x7e8")


if __name__ == "__main__":
    unittest.main()
