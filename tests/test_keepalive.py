from __future__ import annotations

import sys
import time
import contextlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_fuzzing import config as cli_config
from can_fuzzing.runtime.keepalive import KeepaliveConfig, KeepaliveSession, KeepaliveWorker


class DummyMessage:
    def __init__(self, arbitration_id: int, data: bytes, is_rx: bool = True) -> None:
        self.arbitration_id = arbitration_id
        self.data = data
        self.is_rx = is_rx
        self.is_fd = False
        self.timestamp = 123.456


class DummyAdapter:
    def __init__(self) -> None:
        self.sent_frames: list[tuple[object, bool | None, bool | None]] = []
        self.responses = [DummyMessage(0x123, b"\x7f\x3e\x11")]

    def drain_pending(self) -> None:
        return None

    def io_lock(self):
        return contextlib.nullcontext()

    def send_frame(self, frame, is_fd=None, check_message=None) -> None:
        self.sent_frames.append((frame, is_fd, check_message))

    def receive_message(self, timeout: float):
        if self.responses:
            return self.responses.pop(0)
        time.sleep(min(timeout, 0.001))
        return None


class KeepaliveTests(unittest.TestCase):
    def test_keepalive_preset_from_cli(self) -> None:
        args = cli_config.build_keepalive_args({"preset": "ff-classic-response"})
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
            args = cli_config.build_keepalive_args({"config": str(config_path)})
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

    def test_keepalive_session_writes_response_csv(self) -> None:
        events: list[dict] = []
        adapter = DummyAdapter()
        config = KeepaliveConfig(enabled=True, listen_timeout=0.001, interval_ms=1000.0)
        with TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "keepalive.csv"
            with KeepaliveSession(adapter, config, csv_path, events.append):
                time.sleep(0.05)
            content = csv_path.read_text(encoding="utf-8")
        self.assertIn("timestamp,arbitration_id,dlc,payload_hex,fd", content)
        self.assertIn("123.456000,0x123,3,7f3e11,0", content)
        self.assertTrue(any(event.get("event") == "can_rx" for event in events))
        self.assertTrue(any(event.get("event") == "keepalive_summary" for event in events))


if __name__ == "__main__":
    unittest.main()





