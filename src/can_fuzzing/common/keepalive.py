from __future__ import annotations

import threading
from dataclasses import dataclass

from ..adapters import CANHardwareAdapter
from ..models import CANFrame, FrameFormat, FrameType


@dataclass(frozen=True)
class KeepaliveConfig:
    enabled: bool = False
    arbitration_id: int = 0x7DF
    payload: bytes = b"\x02\x3E\x00"
    interval_ms: float = 500.0
    extended: bool = False
    fd: bool = False


@dataclass(frozen=True)
class KeepaliveStats:
    sent: int = 0
    errors: int = 0
    last_error: str = ""


class KeepaliveWorker:
    def __init__(
        self,
        adapter: CANHardwareAdapter,
        config: KeepaliveConfig,
    ) -> None:
        self._adapter = adapter
        self._config = config
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.errors = 0
        self.last_error = ""

    def start(self) -> None:
        if not self._config.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> KeepaliveStats:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        return KeepaliveStats(sent=self.sent, errors=self.errors, last_error=self.last_error)

    def _run(self) -> None:
        frame = CANFrame(
            identifier=self._config.arbitration_id,
            data=self._config.payload,
            frame_format=FrameFormat.EXTENDED if self._config.extended else FrameFormat.STANDARD,
            frame_type=FrameType.DATA,
        )
        delay_seconds = max(0.001, self._config.interval_ms / 1000.0)
        while not self._stop_event.is_set():
            try:
                self._adapter.send_frame(frame, is_fd=self._config.fd)
                self.sent += 1
            except Exception as exc:
                self.errors += 1
                self.last_error = str(exc)
                break
            if self._stop_event.wait(delay_seconds):
                break
