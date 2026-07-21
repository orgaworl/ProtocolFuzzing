from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from argparse import Namespace
import unittest
from unittest.mock import patch

from can_fuzzing import cli


class CliTests(unittest.TestCase):
    def test_list_parser_allows_missing_interface_and_channel(self) -> None:
        parser = cli.make_parser("list")
        cli.add_list_arguments(parser)
        args = cli.parse_args_with_config(parser, "list", [])
        self.assertEqual(args.interfaces, ",".join(cli.DEFAULT_DISCOVERY_INTERFACES))
        self.assertFalse(args.include_virtual)

    def test_udsfuzz_requires_interface_and_channel(self) -> None:
        parser = cli.make_parser("udsfuzz")
        cli.add_udsfuzz_arguments(parser)
        with patch.object(cli.argparse.ArgumentParser, "error", side_effect=SystemExit(2)):
            with self.assertRaises(SystemExit):
                cli.parse_args_with_config(parser, "udsfuzz", [])

    def test_resolve_interface_auto_selects_single_detection(self) -> None:
        args = Namespace(interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [{"interface": "pcan", "channel": "PCAN_USBBUS1"}]
        with patch.object(cli, "list_can_interfaces", return_value=configs), patch.object(cli, "print_interface_table", lambda _: None), patch.object(cli.console, "warning", lambda *a, **k: None), patch.object(cli.console, "info", lambda *a, **k: None):
            interface, channel = cli.resolve_interface_and_channel(args, "fuzz")
        self.assertEqual((interface, channel), ("pcan", "PCAN_USBBUS1"))

    def test_resolve_interface_uses_discovery_when_channel_missing(self) -> None:
        args = Namespace(interface="pcan", channel=None, interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [{"interface": "pcan", "channel": "PCAN_USBBUS1"}]
        with patch.object(cli, "list_can_interfaces", return_value=configs), patch.object(cli, "print_interface_table", lambda _: None), patch.object(cli.console, "warning", lambda *a, **k: None), patch.object(cli.console, "info", lambda *a, **k: None):
            interface, channel = cli.resolve_interface_and_channel(args, "fuzz")
        self.assertEqual((interface, channel), ("pcan", "PCAN_USBBUS1"))

    def test_resolve_interface_prompts_for_multiple_detections(self) -> None:
        args = Namespace(interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [
            {"interface": "pcan", "channel": "PCAN_USBBUS1"},
            {"interface": "vector", "channel": "vcan0"},
        ]
        with patch.object(cli, "list_can_interfaces", return_value=configs), patch.object(cli, "print_interface_table", lambda _: None), patch.object(cli.console, "warning", lambda *a, **k: None), patch.object(cli.console, "info", lambda *a, **k: None), patch("builtins.input", return_value="2"):
            interface, channel = cli.resolve_interface_and_channel(args, "scan")
        self.assertEqual((interface, channel), ("vector", "vcan0"))


if __name__ == "__main__":
    unittest.main()
