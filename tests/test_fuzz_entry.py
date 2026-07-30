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
                '[fuzz]\nprotocol = "private"\ninterface = "pcan"\nchannel = "PCAN_USBBUS1"\ncases = 12\nseed = 101\n\n[privatefuzz]\ncases = 33\nseed = 202',
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
        self.assertEqual(captured[0].interface, "pcan")
        self.assertEqual(captured[0].channel, "PCAN_USBBUS1")


if __name__ == "__main__":
    unittest.main()
