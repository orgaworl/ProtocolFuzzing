from __future__ import annotations

import contextlib
import io
import logging
import threading
import time
from collections.abc import Iterable
from typing import Any

from .errors import (
    CANConnectionError,
    build_can_error_message,
    build_os_error_message,
    build_unknown_channel_message,
)
from .models import CANFrame, FrameType, HardwareObservation
from .timing import build_fd_timing

DEFAULT_CAN_BITRATE_CANDIDATES = (500000, 250000, 125000, 1000000, 800000, 100000, 50000)
DEFAULT_CAN_FD_DATA_BITRATE_CANDIDATES = (2000000, 5000000, 4000000, 1000000)


class CANHardwareAdapter:
    def __init__(
        self,
        interface: str,
        channel: str,
        bitrate: int | None = None,
        receive_timeout: float = 0.05,
        fd: bool = False,
        data_bitrate: int | None = None,
        fd_clock: int = 80000000,
        nominal_sample_point: float = 87.5,
        data_sample_point: float = 80.0,
        auto_bitrate: bool = False,
        bitrate_candidates: Iterable[int] | None = None,
        data_bitrate_candidates: Iterable[int] | None = None,
        bitrate_probe_timeout: float = 0.2,
        timing: Any | None = None,
        check_message: bool = True,
        drop_echo: bool = True,
    ) -> None:
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self.receive_timeout = receive_timeout
        self.fd = fd
        self.data_bitrate = data_bitrate
        self.fd_clock = fd_clock
        self.nominal_sample_point = nominal_sample_point
        self.data_sample_point = data_sample_point
        self.auto_bitrate = auto_bitrate
        self.bitrate_candidates = tuple(bitrate_candidates or DEFAULT_CAN_BITRATE_CANDIDATES)
        self.data_bitrate_candidates = tuple(data_bitrate_candidates or DEFAULT_CAN_FD_DATA_BITRATE_CANDIDATES)
        self.bitrate_probe_timeout = bitrate_probe_timeout
        self.detected_bitrate: int | None = None
        self.detected_data_bitrate: int | None = None
        self.auto_bitrate_status = "disabled"
        self.timing = timing
        self.check_message = check_message
        self.drop_echo = drop_echo
        self._bus: Any = None
        self._pending_messages: list[Any] = []
        self._io_lock = threading.RLock()

    def __enter__(self) -> "CANHardwareAdapter":
        previous_disable_level = logging.root.manager.disable
        try:
            logging.disable(logging.CRITICAL)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                import can
        except ImportError as exc:
            raise CANConnectionError(
                "python-can is required for real CAN device testing. Install dependencies with pip install -e . or pip install python-can."
            ) from exc
        finally:
            logging.disable(previous_disable_level)

        try:
            if self._should_auto_detect_bitrate():
                self._bus = self._open_with_auto_bitrate(can)
            else:
                self._bus = self._open_bus(can, self.bitrate, self.data_bitrate, self.timing)
                self.detected_bitrate = self.bitrate
                self.detected_data_bitrate = self.data_bitrate
        except KeyError as exc:
            raise CANConnectionError(build_unknown_channel_message(self.interface, self.channel)) from exc
        except can.CanError as exc:
            raise CANConnectionError(build_can_error_message(self.interface, self.channel, exc)) from exc
        except OSError as exc:
            raise CANConnectionError(build_os_error_message(self.interface, self.channel, exc)) from exc
        finally:
            logging.disable(previous_disable_level)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._bus is not None:
            quiet_shutdown(self._bus)
            self._bus = None

    def _should_auto_detect_bitrate(self) -> bool:
        if not self.auto_bitrate:
            return False
        if self.timing is not None:
            return False
        return self.bitrate is None or (self.fd and self.data_bitrate is None)

    def _open_bus(self, can_module: Any, bitrate: int | None, data_bitrate: int | None, timing: Any | None = None):
        kwargs: dict[str, Any] = {"interface": self.interface, "channel": self.channel}
        if bitrate is not None:
            kwargs["bitrate"] = bitrate
        if self.fd:
            kwargs["fd"] = True
            if timing is not None:
                kwargs["timing"] = timing
            if data_bitrate is not None:
                kwargs["data_bitrate"] = data_bitrate
        return quiet_call(can_module.interface.Bus, **kwargs)

    def _open_with_auto_bitrate(self, can_module: Any):
        attempts: list[tuple[int | None, int | None, Any | None]] = []
        if self.fd:
            nominal_candidates = self.bitrate_candidates if self.bitrate is None else (self.bitrate,)
            data_candidates = self.data_bitrate_candidates if self.data_bitrate is None else (self.data_bitrate,)
            for bitrate in nominal_candidates:
                for data_bitrate in data_candidates:
                    attempts.append(
                        (
                            bitrate,
                            data_bitrate,
                            build_fd_timing(
                                self.fd_clock,
                                bitrate,
                                data_bitrate,
                                self.nominal_sample_point,
                                self.data_sample_point,
                            ),
                        )
                    )
        else:
            candidates = self.bitrate_candidates if self.bitrate is None else (self.bitrate,)
            for bitrate in candidates:
                attempts.append((bitrate, None, None))

        last_error: Exception | None = None
        for bitrate, data_bitrate, timing in attempts:
            try:
                bus = self._open_bus(can_module, bitrate, data_bitrate, timing)
                observed = quiet_call(bus.recv, timeout=self.bitrate_probe_timeout)
            except (CANConnectionError, KeyError, OSError, can_module.CanError, ValueError) as exc:
                last_error = exc
                continue
            if observed is None:
                quiet_shutdown(bus)
                continue
            self._pending_messages.append(observed)
            self.detected_bitrate = bitrate
            self.detected_data_bitrate = data_bitrate
            self.auto_bitrate_status = "detected_from_bus_traffic"
            if bitrate is not None:
                self.bitrate = bitrate
            if data_bitrate is not None:
                self.data_bitrate = data_bitrate
            return bus

        detail = f"Last error: {last_error}" if last_error is not None else "No candidate bitrate was attempted."
        raise CANConnectionError(
            f"Could not auto-detect CAN hardware bitrate for interface {self.interface!r} channel {self.channel!r}. {detail}"
        )

    def transact(self, frame: CANFrame) -> HardwareObservation:
        if self._bus is None:
            raise RuntimeError("CAN bus is not open")
        start = time.perf_counter()
        message = self._build_message(frame)
        with self._io_lock:
            try:
                quiet_call(self._bus.send, message)
            except Exception as exc:
                latency = (time.perf_counter() - start) * 1000.0
                return HardwareObservation(False, True, "send_error", "send_error", 0, [], [], latency, str(exc))

            responses: list[Any] = []
            deadline = time.perf_counter() + max(0.0, self.receive_timeout)
            while time.perf_counter() < deadline:
                remaining = max(0.0, deadline - time.perf_counter())
                try:
                    response = self._take_pending_message()
                    if response is None:
                        response = quiet_call(self._bus.recv, timeout=remaining)
                except Exception as exc:
                    latency = (time.perf_counter() - start) * 1000.0
                    return HardwareObservation(
                        True,
                        True,
                        "receive_error",
                        "receive_error",
                        len(responses),
                        [msg.arbitration_id for msg in responses],
                        [bytes(msg.data).hex() for msg in responses],
                        latency,
                        str(exc),
                    )
                if response is None:
                    break
                if self.drop_echo and self._is_echo_message(message, response):
                    continue
                if getattr(response, "is_rx", True):
                    responses.append(response)

            latency = (time.perf_counter() - start) * 1000.0
            response_ids = [msg.arbitration_id for msg in responses]
            response_payloads = [bytes(msg.data).hex() for msg in responses]
            if responses:
                return HardwareObservation(True, False, "response", "response_received", len(responses), response_ids, response_payloads, latency)
            return HardwareObservation(True, False, "no_response", "no_response", 0, [], [], latency)

    def send_frame(self, frame: CANFrame, is_fd: bool | None = None, check_message: bool | None = None) -> None:
        if self._bus is None:
            raise RuntimeError("CAN bus is not open")
        try:
            import can
        except ImportError as exc:
            raise RuntimeError("python-can is required for real CAN device testing") from exc
        message = self._build_message(frame, is_fd=self.fd if is_fd is None else is_fd, check_message=check_message)
        with self._io_lock:
            quiet_call(self._bus.send, message)

    def receive_message(self, timeout: float):
        if self._bus is None:
            raise RuntimeError("CAN bus is not open")
        with self._io_lock:
            pending = self._take_pending_message()
            if pending is not None:
                return pending
            return quiet_call(self._bus.recv, timeout=timeout)

    def io_lock(self):
        return self._io_lock

    def drain_pending(self) -> None:
        if self._bus is None:
            return
        self._pending_messages.clear()
        while True:
            with self._io_lock:
                msg = quiet_call(self._bus.recv, timeout=0.0)
            if msg is None:
                return

    def _take_pending_message(self):
        if self._pending_messages:
            return self._pending_messages.pop(0)
        return None

    @staticmethod
    def _is_echo_message(sent_message: Any, received_message: Any) -> bool:
        return (
            getattr(received_message, "arbitration_id", None) == getattr(sent_message, "arbitration_id", None)
            and bytes(getattr(received_message, "data", b"")) == bytes(getattr(sent_message, "data", b""))
            and getattr(received_message, "is_extended_id", None) == getattr(sent_message, "is_extended_id", None)
            and getattr(received_message, "is_remote_frame", None) == getattr(sent_message, "is_remote_frame", None)
            and getattr(received_message, "is_error_frame", None) == getattr(sent_message, "is_error_frame", None)
            and getattr(received_message, "is_fd", None) == getattr(sent_message, "is_fd", None)
        )

    def _build_message(self, frame: CANFrame, is_fd: bool | None = None, check_message: bool | None = None):
        try:
            import can
        except ImportError as exc:
            raise RuntimeError("python-can is required for real CAN device testing") from exc
        return can.Message(
            arbitration_id=frame.identifier,
            data=frame.data,
            is_extended_id=frame.frame_format.value == "extended",
            is_remote_frame=frame.frame_type == FrameType.REMOTE,
            is_error_frame=frame.frame_type == FrameType.ERROR,
            is_fd=self.fd if is_fd is None else is_fd,
            check=self.check_message if check_message is None else check_message,
        )


def quiet_call(func, *args, **kwargs):
    previous_disable_level = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return func(*args, **kwargs)
    finally:
        logging.disable(previous_disable_level)


def quiet_shutdown(bus: Any) -> None:
    try:
        quiet_call(bus.shutdown)
    except Exception:
        return
