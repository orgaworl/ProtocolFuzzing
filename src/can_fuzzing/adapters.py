from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .models import CANFrame, FrameType


@dataclass(frozen=True)
class HardwareObservation:
    sent: bool
    fault: bool
    state: str
    reason: str
    response_count: int
    response_ids: list[int]
    response_payloads: list[str]
    latency_ms: float
    error: str = ""


class CANHardwareAdapter:
    def __init__(
        self,
        interface: str,
        channel: str,
        bitrate: int | None = None,
        receive_timeout: float = 0.05,
        fd: bool = False,
        data_bitrate: int | None = None,
    ) -> None:
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self.receive_timeout = receive_timeout
        self.fd = fd
        self.data_bitrate = data_bitrate
        self._bus: Any = None

    def __enter__(self) -> "CANHardwareAdapter":
        try:
            import can
        except ImportError as exc:
            raise RuntimeError(
                "python-can is required for real CAN device testing. "
                "Install dependencies with pip install -e . or pip install python-can."
            ) from exc

        kwargs: dict[str, Any] = {
            "interface": self.interface,
            "channel": self.channel,
        }
        if self.bitrate is not None:
            kwargs["bitrate"] = self.bitrate
        if self.fd:
            kwargs["fd"] = True
        if self.data_bitrate is not None:
            kwargs["data_bitrate"] = self.data_bitrate

        self._bus = can.interface.Bus(**kwargs)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._bus is not None:
            self._bus.shutdown()
            self._bus = None

    def transact(self, frame: CANFrame) -> HardwareObservation:
        if self._bus is None:
            raise RuntimeError("CAN bus is not open")

        try:
            import can
        except ImportError as exc:
            raise RuntimeError("python-can is required for real CAN device testing") from exc

        self._drain_pending()
        message = can.Message(
            arbitration_id=frame.identifier,
            data=frame.data,
            is_extended_id=frame.frame_format.value == "extended",
            is_remote_frame=frame.frame_type == FrameType.REMOTE,
            is_error_frame=frame.frame_type == FrameType.ERROR,
            is_fd=self.fd,
            check=True,
        )

        start = time.perf_counter()
        try:
            self._bus.send(message)
        except can.CanError as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return HardwareObservation(
                sent=False,
                fault=True,
                state="send_error",
                reason="send_error",
                response_count=0,
                response_ids=[],
                response_payloads=[],
                latency_ms=latency,
                error=str(exc),
            )

        responses = []
        deadline = time.perf_counter() + self.receive_timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            try:
                response = self._bus.recv(timeout=remaining)
            except can.CanError as exc:
                latency = (time.perf_counter() - start) * 1000.0
                return HardwareObservation(
                    sent=True,
                    fault=True,
                    state="receive_error",
                    reason="receive_error",
                    response_count=len(responses),
                    response_ids=[msg.arbitration_id for msg in responses],
                    response_payloads=[bytes(msg.data).hex() for msg in responses],
                    latency_ms=latency,
                    error=str(exc),
                )
            if response is None:
                break
            if response.is_rx:
                responses.append(response)

        latency = (time.perf_counter() - start) * 1000.0
        response_ids = [msg.arbitration_id for msg in responses]
        response_payloads = [bytes(msg.data).hex() for msg in responses]
        if responses:
            return HardwareObservation(
                sent=True,
                fault=False,
                state="response",
                reason="response_received",
                response_count=len(responses),
                response_ids=response_ids,
                response_payloads=response_payloads,
                latency_ms=latency,
            )
        return HardwareObservation(
            sent=True,
            fault=False,
            state="no_response",
            reason="no_response",
            response_count=0,
            response_ids=[],
            response_payloads=[],
            latency_ms=latency,
        )

    def _drain_pending(self) -> None:
        if self._bus is None:
            return
        while True:
            msg = self._bus.recv(timeout=0.0)
            if msg is None:
                return
