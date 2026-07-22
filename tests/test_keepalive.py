from __future__ import annotations

import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_fuzzing import cli
from can_fuzzing.common.keepalive import KeepaliveConfig, KeepaliveWorker


class DummyMessage:
    def __init__(self, arbitration_id: int, data: bytes, is_rx: bool = True) -> None:
        self.arbitration_id = arbitration_id
        self.data = data
        self.is_rx = is_rx


class DummyAdapter:
    def __init__(self) -> None:
        self.sent_frames: list[tuple[object, bool | None, bool | None]] = []
        self.responses = [DummyMessage(0x123, b"\x7f\x3e\x11")]

    def drain_pending(self) -> None:
        return None

    def send_frame(self, frame, is_fd=None, check_message=None) -> None:
        self.sent_frames.append((frame, is_fd, check_message))

    def receive_message(self, timeout: float):
        if self.responses:
            return self.responses.pop(0)
        time.sleep(min(timeout, 0.001))
        return None


class KeepaliveTests(unittest.TestCase):
    def test_keepalive_preset_from_cli(self) -> None:
        parser = cli.make_parser("keepalive")
        cli.add_keepalive_arguments(parser)
        args = cli.parse_keepalive_args_with_config(parser, ["--preset", "ff-classic-response"])
        self.assertEqual(args.arbitration_id, 0xFFFFFFFF)
        self.assertEqual(args.payload, "FF FF FF FF FF FF FF FF")
        self.assertEqual(args.format, "extended")
        self.assertFalse(args.fd)
        self.assertTrue(args.listen)
        self.assertFalse(args.check_message)

    def test_keepalive_preset_from_config(self) -> None:
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text(
                '[keepalive]\npreset = "ff-fd-no-response"\n',
                encoding="utf-8",
                newline="\n",
            )
            parser = cli.make_parser("keepalive")
            cli.add_keepalive_arguments(parser)
            args = cli.parse_keepalive_args_with_config(parser, ["-c", str(config_path)])
        self.assertEqual(args.arbitration_id, 0xFFFFFFFF)
        self.assertEqual(args.format, "extended")
        self.assertTrue(args.fd)
        self.assertFalse(args.listen)

    def test_keepalive_worker_sends_and_collects_responses(self) -> None:
        adapter = DummyAdapter()
        config = KeepaliveConfig(
            enabled=True,
            arbitration_id=0x7DF,
            payload=b"\x02\x3E\x00",
            interval_ms=1000.0,
            extended=False,
            fd=False,
            listen=True,
            listen_timeout=0.001,
            check_message=True,
        )
        worker = KeepaliveWorker(adapter, config)
        worker.start()
        time.sleep(0.05)
        stats = worker.stop()
        self.assertGreaterEqual(stats.sent, 1)
        self.assertEqual(stats.responses, 1)
        self.assertEqual(stats.response_ids, (0x123,))
        self.assertEqual(stats.response_payloads, ("7f3e11",))
        self.assertEqual(adapter.sent_frames[0][1], False)
        self.assertEqual(adapter.sent_frames[0][2], True)


if __name__ == "__main__":
    unittest.main()
