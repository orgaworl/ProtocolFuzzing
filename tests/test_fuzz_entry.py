from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tempfile import TemporaryDirectory
import unittest

from can_fuzzing import cli


class FuzzCliTests(unittest.TestCase):
    def test_config_precedence_uses_cli_over_config_and_section_over_root(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text('[fuzz]\nprotocol = "private"\ninterface = "pcan"\nchannel = "PCAN_USBBUS1"\ncases = 12\nseed = 101\n\n[privatefuzz]\ncases = 33\nseed = 202', encoding="utf-8", newline="\n")
            parser = cli.make_parser("fuzz")
            cli.add_fuzz_arguments(parser)
            args = cli.parse_fuzz_args_with_config(
                parser,
                ["-c", str(config_path), "--protocol", "private", "--cases", "9"],
            )
        self.assertEqual(args.protocol, "private")
        self.assertEqual(args.cases, 9)
        self.assertEqual(args.seed, 202)
        self.assertEqual(args.interface, "pcan")
        self.assertEqual(args.channel, "PCAN_USBBUS1")


if __name__ == "__main__":
    unittest.main()