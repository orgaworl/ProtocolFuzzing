from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Any

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
    listen: bool = True
    listen_timeout: float = 0.05
    check_message: bool = True


@dataclass(frozen=True)
class KeepaliveStats:
    sent: int = 0
    errors: int = 0
    responses: int = 0
    response_ids: tuple[int, ...] = ()
    response_payloads: tuple[str, ...] = ()
    last_error: str = ""


class KeepaliveWorker:
    def __init__(
        self,
        adapter: CANHardwareAdapter,
        config: KeepaliveConfig,
        response_callback: Callable[[Any], None] | None = None,
    ) -> None:
        self._adapter = adapter
        self._config = config
        self._response_callback = response_callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.errors = 0
        self.responses = 0
        self.response_ids: list[int] = []
        self.response_payloads: list[str] = []
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
        return KeepaliveStats(
            sent=self.sent,
            errors=self.errors,
            responses=self.responses,
            response_ids=tuple(self.response_ids),
            response_payloads=tuple(self.response_payloads),
            last_error=self.last_error,
        )

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

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
                self._adapter.drain_pending()
                self._adapter.send_frame(frame, is_fd=self._config.fd, check_message=self._config.check_message)
                self.sent += 1
                if self._config.listen:
                    self._collect_responses()
            except Exception as exc:
                self.errors += 1
                self.last_error = str(exc)
                break
            if self._stop_event.wait(delay_seconds):
                break

    def _collect_responses(self) -> None:
        deadline = time.perf_counter() + max(0.0, self._config.listen_timeout)
        while not self._stop_event.is_set():
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return
            message = self._adapter.receive_message(timeout=remaining)
            if message is None:
                return
            if not getattr(message, "is_rx", True):
                continue
            self.responses += 1
            self.response_ids.append(int(message.arbitration_id))
            self.response_payloads.append(bytes(message.data).hex())
            if self._response_callback is not None:
                self._response_callback(message)
