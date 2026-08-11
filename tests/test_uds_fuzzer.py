from __future__ import annotations

import random
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_fuzzing.fuzzing.uds_fuzz import UDSFuzzConfig, build_request
from can_fuzzing.runtime.keepalive import KeepaliveConfig
from can_fuzzing.runtime.models import CANHardwareConfig


class UDSFuzzerTests(unittest.TestCase):
    def test_malformed_service_choice_accepts_tuple_dictionary(self) -> None:
        config = UDSFuzzConfig(
            hardware=CANHardwareConfig(
                interface="pcan",
                channel="PCAN_USBBUS1",
                bitrate=500000,
                receive_timeout=0.05,
                fd=False,
                data_bitrate=None,
                auto_bitrate=False,
                bitrate_candidates=(500000,),
                data_bitrate_candidates=(2000000,),
                bitrate_probe_timeout=0.2,
                fd_timing_preset=None,
                fd_clock=80000000,
                nominal_sample_point=87.5,
                data_sample_point=80.0,
                check_message=True,
                drop_echo=True,
            ),
            cases=1,
            seed=2024,
            campaign="uds_baseline",
            output_dir=Path("result"),
            inter_request_delay_ms=10.0,
            request_mode="mixed",
            functional_id=0x7DF,
            physical_start=0x7E0,
            physical_end=0x7E7,
            service_bias=0.85,
            malformed_rate=1.0,
            progress_interval=1,
            progress_seconds=1.0,
            keepalive=KeepaliveConfig(
                enabled=False,
                arbitration_id=0x7DF,
                payload=b"\x02\x3E\x00",
                interval_ms=500.0,
                extended=False,
                fd=False,
                listen=True,
                listen_timeout=0.05,
                check_message=True,
            ),
        )
        rng = random.Random(7)
        request = build_request(rng, config)
        self.assertTrue(request.is_malformed)
        self.assertGreaterEqual(request.service_id, 0)
        self.assertLessEqual(request.service_id, 0xFF)


if __name__ == "__main__":
    unittest.main()
