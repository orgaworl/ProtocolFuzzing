from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from click.testing import CliRunner
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from can_fuzzing import cli


class FuzzCliTests(unittest.TestCase):
    def test_config_precedence_uses_cli_over_config_and_section_over_root(self) -> None:
        captured: list[SimpleNamespace] = []
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                """[hardware]
bitrate = 500000
receive_timeout = 0.05
fd = false
data_bitrate = 2000000
auto_bitrate = false
bitrate_candidates = [500000, 250000, 125000, 1000000, 800000, 100000, 50000]
data_bitrate_candidates = [2000000, 5000000, 4000000, 1000000]
bitrate_probe_timeout = 0.2
fd_clock = 80000000
nominal_sample_point = 87.5
data_sample_point = 80.0
check_message = true
drop_echo = true

[fuzz]
protocol = "private"
interface = "pcan"
channel = "PCAN_USBBUS1"
cases = 12
seed = 101
campaign = "private_control_baseline"
output_dir = "result"
inter_request_delay_ms = 10.0
target_ids = [0x100, 0x101, 0x200, 0x201, 0x300, 0x301]
opcodes = [0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21, 0x7f, 0x80, 0xfe, 0xff]
structured_rate = 0.7
malformed_rate = 0.15
min_payload_len = 1
max_payload_len = 8
extended = false
progress_interval = 1
progress_seconds = 1.0

[privatefuzz]
cases = 33
seed = 202
""",
                encoding="utf-8",
                newline="\n",
            )
            runner = CliRunner()
            with patch.object(cli, "run_fuzz_from_args", lambda args: captured.append(args)):
                result = runner.invoke(cli._fuzz_click, ["-c", str(config_path), "--protocol", "private", "--cases", "9"], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(captured[0].protocol, "private")
        self.assertEqual(captured[0].cases, 9)
        self.assertEqual(captured[0].seed, 202)
        self.assertFalse(hasattr(captured[0], "interface"))
        self.assertFalse(hasattr(captured[0], "channel"))


if __name__ == "__main__":
    unittest.main()
