from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import CANHardwareAdapter
from .models import CANFrame, FrameFormat, FrameType


@dataclass(frozen=True)
class ScanConfig:
    interface: str
    channel: str
    bitrate: int | None = 500000
    output_dir: Path = Path("result")
    campaign: str = "can_scan"
    passive_duration: float = 10.0
    active_timeout: float = 0.25
    inter_probe_delay_ms: float = 50.0
    fd: bool = False
    data_bitrate: int | None = None
    active: bool = True
    passive: bool = True
    physical_start: int = 0x7E0
    physical_end: int = 0x7E7


@dataclass
class IdStats:
    arbitration_id: int
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    dlcs: set[int] = field(default_factory=set)
    samples: list[str] = field(default_factory=list)

    def update(self, timestamp: float, payload_hex: str, dlc: int) -> None:
        if self.count == 0:
            self.first_seen = timestamp
        self.count += 1
        self.last_seen = timestamp
        self.dlcs.add(dlc)
        if len(self.samples) < 5 and payload_hex not in self.samples:
            self.samples.append(payload_hex)


def run_scan(config: ScanConfig, progress_callback=None) -> dict[str, Any]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = config.output_dir / f"{config.campaign}_summary.json"
    ids_csv_path = config.output_dir / f"{config.campaign}_ids.csv"
    active_csv_path = config.output_dir / f"{config.campaign}_active.csv"

    id_stats: dict[int, IdStats] = {}
    active_rows: list[dict[str, Any]] = []
    interrupted = False

    with CANHardwareAdapter(
        interface=config.interface,
        channel=config.channel,
        bitrate=config.bitrate,
        receive_timeout=config.active_timeout,
        fd=config.fd,
        data_bitrate=config.data_bitrate,
    ) as adapter:
        try:
            adapter.drain_pending()
            if config.passive:
                passive_scan(adapter, config, id_stats, progress_callback)
            if config.active:
                active_rows = active_scan(adapter, config, id_stats, progress_callback)
        except KeyboardInterrupt:
            interrupted = True

    write_id_csv(ids_csv_path, id_stats)
    write_active_csv(active_csv_path, active_rows)
    summary = build_summary(config, id_stats, active_rows, ids_csv_path, active_csv_path, interrupted)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def passive_scan(adapter: CANHardwareAdapter, config: ScanConfig, id_stats: dict[int, IdStats], progress_callback) -> None:
    start = time.monotonic()
    deadline = start + max(0.0, config.passive_duration)
    while time.monotonic() < deadline:
        remaining = max(0.0, min(0.1, deadline - time.monotonic()))
        msg = adapter.receive_message(timeout=remaining)
        if msg is None:
            report(progress_callback, phase="passive", elapsed=time.monotonic() - start, total=config.passive_duration, ids=len(id_stats))
            continue
        record_message(id_stats, msg)
        report(progress_callback, phase="passive", elapsed=time.monotonic() - start, total=config.passive_duration, ids=len(id_stats))


def active_scan(adapter: CANHardwareAdapter, config: ScanConfig, id_stats: dict[int, IdStats], progress_callback) -> list[dict[str, Any]]:
    probes = build_active_probes(config)
    rows: list[dict[str, Any]] = []
    for index, probe in enumerate(probes, start=1):
        sent_at = time.monotonic()
        row = {
            "probe_index": index,
            "request_id": f"0x{probe.identifier:x}",
            "request_payload": probe.to_hex_payload(),
            "response_count": 0,
            "response_ids": "",
            "response_payloads": "",
            "error": "",
        }
        try:
            adapter.drain_pending()
            adapter.send_frame(probe)
            responses = collect_responses(adapter, config.active_timeout)
            for msg in responses:
                record_message(id_stats, msg)
            row["response_count"] = len(responses)
            row["response_ids"] = ";".join(f"0x{msg.arbitration_id:x}" for msg in responses)
            row["response_payloads"] = ";".join(bytes(msg.data).hex() for msg in responses)
        except Exception as exc:
            row["error"] = str(exc)
        rows.append(row)
        report(progress_callback, phase="active", elapsed=index, total=len(probes), ids=len(id_stats))
        delay = config.inter_probe_delay_ms / 1000.0
        if delay > 0:
            time.sleep(delay)
    return rows


def build_active_probes(config: ScanConfig) -> list[CANFrame]:
    probes: list[CANFrame] = []
    safe_payloads = [
        [0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ]
    for payload in safe_payloads:
        probes.append(CANFrame.from_ints(0x7DF, payload, FrameFormat.STANDARD, FrameType.DATA))
    for request_id in range(config.physical_start, config.physical_end + 1):
        probes.append(CANFrame.from_ints(request_id, [0x02, 0x10, 0x01, 0, 0, 0, 0, 0], FrameFormat.STANDARD, FrameType.DATA))
        probes.append(CANFrame.from_ints(request_id, [0x02, 0x3E, 0x00, 0, 0, 0, 0, 0], FrameFormat.STANDARD, FrameType.DATA))
    return probes


def collect_responses(adapter: CANHardwareAdapter, timeout: float):
    responses = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = adapter.receive_message(timeout=max(0.0, deadline - time.monotonic()))
        if msg is None:
            break
        if getattr(msg, "is_rx", True):
            responses.append(msg)
    return responses


def record_message(id_stats: dict[int, IdStats], msg) -> None:
    arbitration_id = int(msg.arbitration_id)
    payload_hex = bytes(msg.data).hex()
    timestamp = float(getattr(msg, "timestamp", time.time()))
    stats = id_stats.setdefault(arbitration_id, IdStats(arbitration_id=arbitration_id))
    stats.update(timestamp=timestamp, payload_hex=payload_hex, dlc=len(msg.data))


def write_id_csv(path: Path, id_stats: dict[int, IdStats]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "count", "first_seen", "last_seen", "dlcs", "samples"])
        writer.writeheader()
        for stats in sorted(id_stats.values(), key=lambda item: item.arbitration_id):
            writer.writerow(
                {
                    "id": f"0x{stats.arbitration_id:x}",
                    "count": stats.count,
                    "first_seen": f"{stats.first_seen:.6f}",
                    "last_seen": f"{stats.last_seen:.6f}",
                    "dlcs": ";".join(str(value) for value in sorted(stats.dlcs)),
                    "samples": ";".join(stats.samples),
                }
            )


def write_active_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["probe_index", "request_id", "request_payload", "response_count", "response_ids", "response_payloads", "error"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_summary(
    config: ScanConfig,
    id_stats: dict[int, IdStats],
    active_rows: list[dict[str, Any]],
    ids_csv_path: Path,
    active_csv_path: Path,
    interrupted: bool,
) -> dict[str, Any]:
    response_ids = sorted({item.arbitration_id for item in id_stats.values() if 0x7E8 <= item.arbitration_id <= 0x7EF})
    return {
        "campaign": config.campaign,
        "status": "interrupted" if interrupted else "completed",
        "interrupted": interrupted,
        "interface": config.interface,
        "channel": config.channel,
        "bitrate": config.bitrate,
        "passive_enabled": config.passive,
        "active_enabled": config.active,
        "passive_duration": config.passive_duration,
        "active_timeout": config.active_timeout,
        "unique_ids": len(id_stats),
        "total_frames_observed": sum(item.count for item in id_stats.values()),
        "active_probes": len(active_rows),
        "active_responses": sum(int(row["response_count"]) for row in active_rows),
        "suspected_diagnostic_response_ids": [f"0x{value:x}" for value in response_ids],
        "ids_csv_path": str(ids_csv_path),
        "active_csv_path": str(active_csv_path),
    }


def report(progress_callback, **snapshot) -> None:
    if progress_callback is not None:
        progress_callback(snapshot)
