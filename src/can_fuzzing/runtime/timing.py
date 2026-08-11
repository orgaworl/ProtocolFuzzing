from __future__ import annotations

from .errors import CANConnectionError


def build_fd_timing(
    fd_clock: int,
    bitrate: int,
    data_bitrate: int,
    nominal_sample_point: float = 87.5,
    data_sample_point: float = 80.0,
):
    try:
        from can import BitTimingFd
    except ImportError as exc:
        raise CANConnectionError("python-can is required for CAN FD timing generation") from exc
    try:
        return BitTimingFd.from_sample_point(
            f_clock=fd_clock,
            nom_bitrate=bitrate,
            nom_sample_point=nominal_sample_point,
            data_bitrate=data_bitrate,
            data_sample_point=data_sample_point,
        )
    except ValueError as exc:
        raise CANConnectionError(f"invalid CAN FD timing parameters: {exc}") from exc
