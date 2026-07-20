from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import CANConnectionError, CANHardwareAdapter
from .discovery import list_can_interfaces
from .models import CANFrame, FrameFormat, FrameType


@dataclass(frozen=True)
class FDCheckConfig:
    interface: str
    channel: str
    bitrate: int | None = 500000
    data_bitrate: int | None = None
    output_dir: Path = Path("result")
    campaign: str = "can_fd_check"
    probe_timeout: float = 0.15
    probe_delay_ms: float = 20.0
    probe_lengths: tuple[int, ...] = (12, 16, 32)


@dataclass(frozen=True)
class FDCheckResult:
    campaign: str
    status: str
    interrupted: bool
    backend_reports_fd_support: bool | None
    hardware_fd_opened: bool
    hardware_fd_supported: bool
    hardware_fd_status: str
    hardware_error: str
    target_fd_supported: bool
    target_fd_status: str
    probe_count: int
    response_count: int
    csv_path: Path
    summary_path: Path


@dataclass
class FDProbeRow:
    probe_index: int
    request_id: str
    request_length: int
    request_payload: str
    response_count: int
    response_ids: str = ""
    response_payloads: str = ""
    error: str = ""


def run_fdcheck(config: FDCheckConfig, progress_callback=None) -> FDCheckResult:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = config.output_dir / f"{config.campaign}_probes.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    backend_reports_fd_support = detect_backend_fd_support(config.interface, config.channel)
    hardware_fd_opened = False
    hardware_error = ""
    interrupted = False
    target_fd_supported = False
    target_fd_status = "not_run"
    rows: list[FDProbeRow] = []
    response_count = 0

    try:
        with CANHardwareAdapter(
            interface=config.interface,
            channel=config.channel,
            bitrate=config.bitrate,
            receive_timeout=config.probe_timeout,
            fd=True,
            data_bitrate=config.data_bitrate,
        ) as adapter:
            hardware_fd_opened = True
            probes = build_fd_probes(config)
            total = len(probes)
            for index, probe in enumerate(probes, start=1):
                try:
                    adapter.drain_pending()
                    adapter.send_frame(probe)
                    responses = collect_responses(adapter, config.probe_timeout)
                    response_count += len(responses)
                    if responses:
                        target_fd_supported = True
                        target_fd_status = "response_observed"
                    elif target_fd_status != "response_observed":
                        target_fd_status = "no_response"
                    row = FDProbeRow(
                        probe_index=index,
                        request_id=f"0x{probe.identifier:x}",
                        request_length=probe.dlc,
                        request_payload=probe.to_hex_payload(),
                        response_count=len(responses),
                        response_ids=";".join(f"0x{msg.arbitration_id:x}" for msg in responses),
                        response_payloads=";".join(bytes(msg.data).hex() for msg in responses),
                    )
                except Exception as exc:
                    row = FDProbeRow(
                        probe_index=index,
                        request_id=f"0x{probe.identifier:x}",
                        request_length=probe.dlc,
                        request_payload=probe.to_hex_payload(),
                        response_count=0,
                        error=str(exc),
                    )
                    if target_fd_status != "response_observed":
                        target_fd_status = "send_error"
                rows.append(row)
                report_progress(progress_callback, index, total, target_fd_supported)
                if config.probe_delay_ms > 0:
                    time.sleep(config.probe_delay_ms / 1000.0)
    except KeyboardInterrupt:
        interrupted = True
    except CANConnectionError as exc:
        hardware_error = str(exc)
        if backend_reports_fd_support is None:
            backend_reports_fd_support = False

    if hardware_error and not hardware_fd_opened:
        hardware_fd_opened = False

    csv_path.write_text("", encoding="utf-8")
    write_probe_csv(csv_path, rows)

    hardware_fd_supported = bool(hardware_fd_opened and (backend_reports_fd_support is not False))
    summary = {
        "campaign": config.campaign,
        "status": "interrupted" if interrupted else "completed",
        "interrupted": interrupted,
        "interface": config.interface,
        "channel": config.channel,
        "bitrate": config.bitrate,
        "data_bitrate": config.data_bitrate,
        "backend_reports_fd_support": backend_reports_fd_support,
        "hardware_fd_opened": hardware_fd_opened,
        "hardware_fd_supported": hardware_fd_supported,
        "hardware_fd_status": hardware_status_text(backend_reports_fd_support, hardware_fd_opened),
        "hardware_error": hardware_error,
        "target_fd_supported": target_fd_supported,
        "target_fd_status": target_fd_status,
        "probe_count": len(rows),
        "response_count": response_count,
        "probe_lengths": list(config.probe_lengths),
        "csv_path": str(csv_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return FDCheckResult(
        campaign=config.campaign,
        status=summary["status"],
        interrupted=interrupted,
        backend_reports_fd_support=backend_reports_fd_support,
        hardware_fd_opened=hardware_fd_opened,
        hardware_fd_supported=hardware_fd_supported,
        hardware_fd_status=summary["hardware_fd_status"],
        hardware_error=hardware_error,
        target_fd_supported=target_fd_supported,
        target_fd_status=target_fd_status,
        probe_count=len(rows),
        response_count=response_count,
        csv_path=csv_path,
        summary_path=summary_path,
    )


def detect_backend_fd_support(interface: str, channel: str) -> bool | None:
    try:
        configs = list_can_interfaces(interfaces=[interface], include_virtual=False, verbose=False)
    except RuntimeError:
        return None
    for config in configs:
        if str(config.get("channel", "")) == channel:
            value = config.get("supports_fd")
            if isinstance(value, bool):
                return value
    return None


def hardware_status_text(backend_reports_fd_support: bool | None, hardware_fd_opened: bool) -> str:
    if hardware_fd_opened and backend_reports_fd_support is not False:
        return "supported"
    if backend_reports_fd_support is False:
        return "backend_does_not_report_fd"
    if hardware_fd_opened:
        return "opened_without_backend_confirmation"
    return "open_failed"


def build_fd_probes(config: FDCheckConfig) -> list[CANFrame]:
    frames: list[CANFrame] = []
    probe_payloads = [
        [0x02, 0x3E, 0x00],
        [0x02, 0x10, 0x01],
    ]
    for length in config.probe_lengths:
        for request_id in (0x7DF, 0x7E0):
            for base in probe_payloads:
                payload = pad_to_length(base, length)
                frames.append(
                    CANFrame.from_ints(
                        request_id,
                        payload,
                        FrameFormat.STANDARD,
                        FrameType.DATA,
                    )
                )
    return frames


def pad_to_length(base: list[int], length: int) -> list[int]:
    data = list(base)
    if len(data) < length:
        data.extend([0x00] * (length - len(data)))
    return data[:length]


def collect_responses(adapter: CANHardwareAdapter, timeout: float):
    responses = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        msg = adapter.receive_message(timeout=remaining)
        if msg is None:
            break
        if getattr(msg, "is_rx", True):
            responses.append(msg)
    return responses


def write_probe_csv(path: Path, rows: list[FDProbeRow]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["probe_index", "request_id", "request_length", "request_payload", "response_count", "response_ids", "response_payloads", "error"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "probe_index": row.probe_index,
                    "request_id": row.request_id,
                    "request_length": row.request_length,
                    "request_payload": row.request_payload,
                    "response_count": row.response_count,
                    "response_ids": row.response_ids,
                    "response_payloads": row.response_payloads,
                    "error": row.error,
                }
            )


def report_progress(progress_callback, completed: int, total: int, target_fd_supported: bool) -> None:
    if progress_callback is None:
        return
    progress_callback(
        {
            "phase": "fdcheck",
            "completed": completed,
            "total": total,
            "target_fd_supported": target_fd_supported,
        }
    )
