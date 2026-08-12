from __future__ import annotations

from typing import Any

from .models import CANFrame, FrameType


def should_auto_detect_bitrate(auto_bitrate: bool, timing: Any | None, bitrate: int | None, fd: bool, data_bitrate: int | None) -> bool:
    if not auto_bitrate:
        return False
    if timing is not None:
        return False
    return bitrate is None or (fd and data_bitrate is None)


def build_open_kwargs(
    interface: str | None,
    channel: str | None,
    bitrate: int | None,
    fd: bool,
    data_bitrate: int | None,
    timing: Any | None,
    check_message: bool,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"interface": interface, "channel": channel}
    if bitrate is not None:
        kwargs["bitrate"] = bitrate
    if fd:
        kwargs["fd"] = True
        if timing is not None:
            kwargs["timing"] = timing
        if data_bitrate is not None:
            kwargs["data_bitrate"] = data_bitrate
    if check_message is not None:
        kwargs["check"] = check_message
    return kwargs


def build_message(frame: CANFrame, fd: bool, check_message: bool, is_fd: bool | None = None, check_override: bool | None = None):
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
        is_fd=fd if is_fd is None else is_fd,
        check=check_message if check_override is None else check_override,
    )


def is_echo_message(sent_message: Any, received_message: Any) -> bool:
    return (
        getattr(received_message, "arbitration_id", None) == getattr(sent_message, "arbitration_id", None)
        and bytes(getattr(received_message, "data", b"")) == bytes(getattr(sent_message, "data", b""))
        and getattr(received_message, "is_extended_id", None) == getattr(sent_message, "is_extended_id", None)
        and getattr(received_message, "is_remote_frame", None) == getattr(sent_message, "is_remote_frame", None)
        and getattr(received_message, "is_error_frame", None) == getattr(sent_message, "is_error_frame", None)
        and getattr(received_message, "is_fd", None) == getattr(sent_message, "is_fd", None)
    )
