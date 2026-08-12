from __future__ import annotations

import unittest
from pathlib import Path

from can_fuzzing.fuzzing.xcp_fuzz import build_request, decode_response, summarize_responses, XCPFuzzConfig
from can_fuzzing.runtime.keepalive import KeepaliveConfig
from can_fuzzing.runtime.models import CANHardwareConfig
from scapy.contrib.automotive.xcp.xcp import XCPOnCAN, CTOResponse
from scapy.contrib.automotive.xcp.cto_commands_slave import ConnectPositiveResponse, GenericResponse, NegativeResponse


class XCPFuzzerTests(unittest.TestCase):
    def test_build_request_uses_known_command_code(self) -> None:
        config = XCPFuzzConfig(
            hardware=CANHardwareConfig(interface="pcan", channel="PCAN_USBBUS1", bitrate=500000, receive_timeout=0.05, fd=False, data_bitrate=None, auto_bitrate=False, bitrate_candidates=(), data_bitrate_candidates=(), bitrate_probe_timeout=0.0, fd_timing_preset=None, fd_clock=0, nominal_sample_point=0.0, data_sample_point=0.0, check_message=False, drop_echo=True),
            cases=1,
            seed=1,
            campaign="xcp_baseline",
            output_dir=Path("result"),
            inter_request_delay_ms=0.0,
            target_ids=(0x700,),
            request_ids=(0x700,),
            request_modes=("physical",),
            request_mix=0.5,
            malformed_rate=0.0,
            progress_interval=1,
            progress_seconds=1.0,
            keepalive=KeepaliveConfig(enabled=False, arbitration_id=0, payload=b"", interval_ms=0.0, extended=False, fd=False, listen=False, listen_timeout=0.0, check_message=False),
        )
        request = build_request(__import__("random").Random(1), config)
        self.assertIn(request.command_code, {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF2, 0xF1})
        self.assertTrue(request.payload)

    def test_decode_and_summarize_responses(self) -> None:
        pkt1 = bytes(XCPOnCAN(identifier=0x700) / CTOResponse() / ConnectPositiveResponse(b"\x15\xc0\x08\x08\x00\x10\x10"))
        pkt2 = bytes(XCPOnCAN(identifier=0x700) / CTOResponse() / NegativeResponse(error_code=0x22))
        pkt3 = bytes(XCPOnCAN(identifier=0x700) / CTOResponse() / GenericResponse(b"\x00\x01"))
        self.assertTrue(decode_response(pkt1, 0xFF).positive)
        self.assertTrue(decode_response(pkt2, 0xFF).negative)
        summary = summarize_responses([pkt1.hex(), pkt2.hex(), pkt3.hex()], 0xFF)
        self.assertEqual(summary["positive"], 2)
        self.assertEqual(summary["negative"], 1)
        self.assertIn(summary["kind"], {"connect_positive_response", "negative_response", "raw"})


if __name__ == "__main__":
    unittest.main()
