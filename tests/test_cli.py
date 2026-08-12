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
from can_fuzzing import config as cli_config, commands, log

BASE_HW = {
    "bitrate": 500000,
    "receive_timeout": 0.05,
    "fd": False,
    "data_bitrate": 2000000,
    "auto_bitrate": False,
    "bitrate_candidates": "500000,250000,125000,1000000,800000,100000,50000",
    "data_bitrate_candidates": "2000000,5000000,4000000,1000000",
    "bitrate_probe_timeout": 0.2,
    "fd_timing_preset": "sae-j2284",
    "fd_clock": 80000000,
    "nominal_sample_point": 87.5,
    "data_sample_point": 80.0,
    "check_message": True,
    "drop_echo": True,
}

BASE_KEEPALIVE = {
    "preset": "tester-present",
    "arbitration_id": 0x7DF,
    "payload": "02 3E 00",
    "interval_ms": 500.0,
    "format": "standard",
    "listen": True,
    "listen_timeout": 0.05,
    "check_message": True,
}


class CliTests(unittest.TestCase):
    def test_list_click_defaults_allow_missing_interface_and_channel(self) -> None:
        captured: list[SimpleNamespace] = []
        runner = CliRunner()
        with patch.object(cli, "run_list_from_args", lambda args: captured.append(args)):
            result = runner.invoke(cli._list_click, ["-c", str(Path(__file__).resolve().parents[1] / "config.toml")], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(captured[0].interfaces, ",".join(cli_config.DEFAULT_DISCOVERY_INTERFACES))
        self.assertFalse(captured[0].include_virtual)

    def test_fuzz_click_only_exposes_common_run_options(self) -> None:
        names = {param.name for param in cli._fuzz_click.params}
        self.assertEqual(names, {"config", "protocol", "interface", "channel", "cases", "seed", "keepalive"})



    def test_bitrate_auto_token_enables_auto_detection(self) -> None:
        args = cli_config.build_hardware_config(BASE_HW | {"bitrate": "auto", "bitrate_candidates": "125000,500000"})
        self.assertIsNone(args.bitrate)
        self.assertTrue(args.auto_bitrate)
        self.assertEqual(args.bitrate_candidates, (125000, 500000))

    def test_fd_timing_preset_sets_j2284_5_values(self) -> None:
        args = cli_config.build_hardware_config(BASE_HW | {"data_bitrate": None, "fd": True, "fd_timing_preset": "sae-j2284-5"})
        self.assertEqual(args.fd_timing_preset, "sae-j2284-5")
        self.assertEqual(args.bitrate, 500000)
        self.assertEqual(args.data_bitrate, 5000000)
        self.assertEqual(args.fd_clock, 80000000)
        self.assertEqual(args.nominal_sample_point, 87.5)
        self.assertEqual(args.data_sample_point, 80.0)

    def test_fd_timing_preset_keeps_cli_bitrate_override(self) -> None:
        args = cli_config.build_hardware_config(BASE_HW | {"fd": True, "fd_timing_preset": "sae-j2284-5", "data_bitrate": "2000000"})
        self.assertEqual(args.fd_timing_preset, "sae-j2284-5")
        self.assertEqual(args.bitrate, 500000)
        self.assertEqual(args.data_bitrate, 2000000)

    def test_fd_timing_preset_aliases_are_normalized(self) -> None:
        args = cli_config.build_hardware_config(BASE_HW | {"data_bitrate": None, "fd": True, "fd_timing_preset": "500k/5m"})
        self.assertEqual(args.fd_timing_preset, "sae-j2284-5")
        self.assertEqual(args.bitrate, 500000)
        self.assertEqual(args.data_bitrate, 5000000)

    def test_fuzz_keepalive_config_uses_preset_and_overrides(self) -> None:
        args = SimpleNamespace(
            keepalive=True,
            keepalive_preset="ff-classic-response",
            keepalive_id=None,
            keepalive_payload="AA BB",
            keepalive_interval_ms=250.0,
            keepalive_format=None,
            keepalive_fd=None,
            keepalive_listen=None,
            keepalive_listen_timeout=None,
            keepalive_check_message=None,
        )
        config = cli_config.build_fuzz_keepalive_config(args)
        self.assertTrue(config.enabled)
        self.assertEqual(config.arbitration_id, 0xFFFFFFFF)
        self.assertEqual(config.payload, b"\xAA\xBB")
        self.assertEqual(config.interval_ms, 250.0)
        self.assertTrue(config.extended)
        self.assertFalse(config.fd)
        self.assertTrue(config.listen)
        self.assertFalse(config.check_message)

    def test_keepalive_section_maps_to_fuzz_keepalive_defaults(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                '[fuzz]\nprotocol = "can"\nkeepalive = true\noutput_dir = "result"\ncases = 1\nseed = 1\ncampaign = "can_baseline"\ninter_frame_delay_ms = 5.0\nid_min = 0x000\nid_max = 0x7ff\ndiagnostic_bias = 0.6\nextended_probability = 0.0\ninclude_remote = false\ninclude_error = false\nprogress_interval = 1\nprogress_seconds = 1.0\n\n[keepalive]\npreset = "ff-classic-response"\narbitration_id = 0xFFFFFFFF\npayload = "FF FF FF FF FF FF FF FF"\ninterval_ms = 250.0\nformat = "extended"\nlisten = true\nlisten_timeout = 0.05\ncheck_message = false\n',
                encoding="utf-8",
                newline="\n",
            )
            args = cli_config.build_args("fuzz", cli_config.FUZZ_KEYS, {"config": str(config_path)})
        config = cli_config.build_fuzz_keepalive_config(args)
        self.assertTrue(config.enabled)
        self.assertEqual(args.keepalive_preset, "ff-classic-response")
        self.assertEqual(config.arbitration_id, 0xFFFFFFFF)
        self.assertEqual(config.interval_ms, 250.0)

    def test_keepalive_click_defaults_allow_missing_interface_and_channel(self) -> None:
        args = cli_config.build_keepalive_args(BASE_KEEPALIVE)
        self.assertEqual(args.arbitration_id, 0x7DF)
        self.assertEqual(args.payload, "02 3E 00")
        hardware = cli_config.build_hardware_config(BASE_HW)
        self.assertEqual(hardware.bitrate, 500000)

    def test_keepalive_config_ignores_unrelated_root_output_dir(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                'bitrate = 500000\nreceive_timeout = 0.05\nfd = false\ndata_bitrate = 2000000\nauto_bitrate = false\nbitrate_candidates = [500000, 250000, 125000, 1000000, 800000, 100000, 50000]\ndata_bitrate_candidates = [2000000, 5000000, 4000000, 1000000]\nbitrate_probe_timeout = 0.2\nfd_timing_preset = "sae-j2284"\nfd_clock = 80000000\nnominal_sample_point = 87.5\ndata_sample_point = 80.0\ncheck_message = true\ndrop_echo = true\n\n[keepalive]\npreset = "tester-present"\narbitration_id = 0x7DF\npayload = "02 3E 00"\ninterval_ms = 250.0\nformat = "extended"\nlisten = true\nlisten_timeout = 0.05\ncheck_message = true\n',
                encoding="utf-8",
                newline="\n",
            )
            args = cli_config.build_keepalive_args({"config": str(config_path)})
            hardware = cli_config.build_hardware_config({"config": str(config_path)})
            self.assertEqual(hardware.bitrate, 500000)
            self.assertEqual(args.interval_ms, 250.0)
            self.assertEqual(args.format, "extended")

    def test_payload_log_format_uses_fixed_eight_byte_width(self) -> None:
        self.assertEqual(log.format_hex_payload("02 3E 00"), "02 3E 00               ")
        self.assertEqual(log.format_hex_payload("00112233445566778899", fd=True), "00 11 22 33 44 55 66 77 ...")
        self.assertEqual(log.format_can_id(0x7DF), "0x000007DF")
        self.assertEqual(log.format_frame_block(0x7DF, 3, "02 3E 00"), "{ 0x000007DF [3] 02 3E 00                }")

    def test_no_response_exchange_does_not_log_rx_none(self) -> None:
        messages: list[str] = []
        snapshot = {
            "event": "can_exchange",
            "protocol": "can",
            "case_id": 0,
            "total_cases": 1,
            "tx_id": 0x7DF,
            "tx_payload": "02 3E 00",
            "tx_dlc": 3,
            "tx_format": "standard",
            "tx_type": "data",
            "fd": False,
            "sent": True,
            "fault": False,
            "state": "no_response",
            "reason": "no_response",
            "response_count": 0,
            "response_ids": [],
            "response_payloads": [],
            "latency_ms": 50.0,
            "error": "",
        }
        with patch.object(log, "log", lambda message, *_args, **_kwargs: messages.append(str(message))):
            log.log_can_event(snapshot)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0], ">> [CAN 1/1] { 0x000007DF [3] 02 3E 00                } -> no_response")
        self.assertNotIn("none", messages[0])
        self.assertNotIn("ms", messages[0])

    def test_click_main_keyboard_interrupt_prints_fuzz_summary(self) -> None:
        messages: list[str] = []
        log.start_run_summary("fuzz", "can", "can_baseline", 10)
        log.record_run_event(
            {
                "event": "can_exchange",
                "case_id": 2,
                "tx_id": 0x7DF,
                "tx_payload": "02 3E 00",
                "sent": True,
                "fault": False,
                "state": "response",
                "reason": "response_received",
                "response_count": 1,
                "error": "",
            }
        )
        with (
            patch.object(cli._fuzz_click, "main", side_effect=KeyboardInterrupt),
            patch.object(log, "warning", lambda message, **_kwargs: messages.append(str(message))),
            patch.object(log, "info", lambda message, **_kwargs: messages.append(str(message))),
            patch.object(log, "log", lambda message, *_args, **_kwargs: messages.append(str(message))),
        ):
            with self.assertRaises(SystemExit) as raised:
                cli.fuzz_main()
        self.assertEqual(raised.exception.code, 130)
        self.assertIn("interrupt { signal=Ctrl+C }", messages)
        self.assertIn("campaign { name=can_baseline }", messages)
        self.assertIn("status { value=interrupted }", messages)
        self.assertIn("summary { cases=3/10 sent=1 faults=0 responses=1 }", messages)

    def test_click_fuzz_uses_cli_over_config_and_protocol_section(self) -> None:
        captured: list[SimpleNamespace] = []
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                '[fuzz]\nprotocol = "dbc"\ninterface = "pcan"\nchannel = "PCAN_USBBUS1"\noutput_dir = "result"\ncases = 12\nseed = 1\ncampaign = "dbc_baseline"\ninter_frame_delay_ms = 5.0\nprogress_interval = 1\nprogress_seconds = 1.0\n\n[dbcfuzz]\ncases = 33\ndbc_file = "from_config.dbc"\n',
                encoding="utf-8",
                newline="\n",
            )
            runner = CliRunner()
            with patch.object(cli, "run_fuzz_from_args", lambda args: captured.append(args)):
                result = runner.invoke(cli._fuzz_click, ["-c", str(config_path), "--cases", "9"], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].protocol, "dbc")
        self.assertEqual(captured[0].cases, 9)
        self.assertEqual(captured[0].dbc_file, "from_config.dbc")
        self.assertFalse(hasattr(captured[0], "interface"))

    def test_resolve_interface_auto_selects_single_detection(self) -> None:
        args = SimpleNamespace(interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [{"interface": "pcan", "channel": "PCAN_USBBUS1"}]
        with patch.object(commands, "list_can_interfaces", return_value=configs), patch.object(commands, "print_interface_table", lambda _: None), patch.object(log, "warning", lambda *a, **k: None), patch.object(log, "info", lambda *a, **k: None):
            interface, channel = commands.resolve_interface_and_channel(args, "fuzz")
        self.assertEqual((interface, channel), ("pcan", "PCAN_USBBUS1"))

    def test_resolve_interface_uses_discovery_when_channel_missing(self) -> None:
        args = SimpleNamespace(interface="pcan", channel=None, interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [{"interface": "pcan", "channel": "PCAN_USBBUS1"}]
        with patch.object(commands, "list_can_interfaces", return_value=configs), patch.object(commands, "print_interface_table", lambda _: None), patch.object(log, "warning", lambda *a, **k: None), patch.object(log, "info", lambda *a, **k: None):
            interface, channel = commands.resolve_interface_and_channel(args, "fuzz")
        self.assertEqual((interface, channel), ("pcan", "PCAN_USBBUS1"))

    def test_resolve_interface_prompts_for_multiple_detections(self) -> None:
        args = SimpleNamespace(interfaces=None, include_virtual=False, verbose=False, json=False)
        configs = [
            {"interface": "pcan", "channel": "PCAN_USBBUS1"},
            {"interface": "vector", "channel": "vcan0"},
        ]
        with patch.object(commands, "list_can_interfaces", return_value=configs), patch.object(commands, "print_interface_table", lambda _: None), patch.object(log, "warning", lambda *a, **k: None), patch.object(log, "info", lambda *a, **k: None), patch("builtins.input", return_value="2"):
            interface, channel = commands.resolve_interface_and_channel(args, "scan")
        self.assertEqual((interface, channel), ("vector", "vcan0"))

    def test_click_fuzz_accepts_dbc_protocol_and_dbc_file(self) -> None:
        captured: list[SimpleNamespace] = []
        with TemporaryDirectory() as tmpdir:
            dbc_path = Path(tmpdir) / "demo.dbc"
            dbc_path.write_text('VERSION ""\nBO_ 256 Demo: 8 Vector__XXX\n SG_ Value : 0|8@1+ (1,0) [0|255] "" Vector__XXX\n', encoding="utf-8", newline="\n")
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                '[fuzz]\nprotocol = "dbc"\ndbc_file = "' + str(dbc_path).replace('\\', '\\\\') + '"\noutput_dir = "result"\ncases = 1\nseed = 1\ncampaign = "dbc_baseline"\ninter_frame_delay_ms = 5.0\nprogress_interval = 1\nprogress_seconds = 1.0\n\n[dbcfuzz]\ncases = 7\n',
                encoding="utf-8",
                newline="\n",
            )
            runner = CliRunner()
            with patch.object(cli, "run_fuzz_from_args", lambda args: captured.append(args)):
                result = runner.invoke(cli._fuzz_click, ["-c", str(config_path)], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(captured[0].protocol, "dbc")
        self.assertEqual(captured[0].dbc_file, str(dbc_path))
        self.assertEqual(captured[0].cases, 7)


if __name__ == "__main__":
    unittest.main()







