from __future__ import annotations

import contextlib
import io
import logging
import time
from dataclasses import dataclass
from typing import Any

from .discovery import list_can_interfaces
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


class CANConnectionError(RuntimeError):
    pass


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
        previous_disable_level = logging.root.manager.disable
        try:
            logging.disable(logging.CRITICAL)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                import can
        except ImportError as exc:
            raise CANConnectionError(
                "python-can is required for real CAN device testing. "
                "Install dependencies with pip install -e . or pip install python-can."
            ) from exc
        finally:
            logging.disable(previous_disable_level)

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

        try:
            logging.disable(logging.CRITICAL)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self._bus = can.interface.Bus(**kwargs)
        except KeyError as exc:
            raise CANConnectionError(build_unknown_channel_message(self.interface, self.channel)) from exc
        except can.CanError as exc:
            raise CANConnectionError(build_can_error_message(self.interface, self.channel, exc)) from exc
        except OSError as exc:
            raise CANConnectionError(build_os_error_message(self.interface, self.channel, exc)) from exc
        finally:
            logging.disable(previous_disable_level)
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


def build_unknown_channel_message(interface: str, channel: str) -> str:
    lines = [
        f"Unknown CAN channel {channel!r} for interface {interface!r}.",
    ]
    if interface == "pcan" and channel.startswith("PCAN-"):
        lines.append("PCAN channel names use underscores, not hyphens. Did you mean PCAN_USBBUS1?")
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def build_can_error_message(interface: str, channel: str, exc: Exception) -> str:
    lines = [
        f"Could not open CAN interface {interface!r} channel {channel!r}.",
        f"Backend error: {exc}",
    ]
    if interface == "pcan":
        lines.append("For PCAN-USB, check that PCAN-View or another PCAN client is not using the channel.")
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def build_os_error_message(interface: str, channel: str, exc: OSError) -> str:
    lines = [
        f"Could not open CAN interface {interface!r} channel {channel!r}.",
        f"OS error: {exc}",
    ]
    if interface == "socketcan":
        lines.append("SocketCAN is normally available on Linux. On Windows, use a backend such as pcan, vector, or slcan.")
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def discovery_hint(interface: str) -> list[str]:
    lines = ["Run uv run list to see detected CAN interfaces."]
    try:
        configs = list_can_interfaces(interfaces=[interface], include_virtual=False, verbose=False)
    except RuntimeError:
        return lines
    if configs:
        channels = ", ".join(str(config.get("channel", "")) for config in configs)
        lines.append(f"Detected {interface} channel(s): {channels}")
    return lines




