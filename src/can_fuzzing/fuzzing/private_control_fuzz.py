from __future__ import annotations

import csv
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..protocol.private_control import build_request
from ..runtime.adapters import CANHardwareAdapter
from ..runtime.keepalive import KeepaliveConfig, KeepaliveSession
from ..runtime.models import CANFrame, FrameFormat, FrameType
from .utils import report_progress, should_report_progress


@dataclass(frozen=True)
class PrivateFuzzConfig:
    cases: int = 1000
    seed: int = 2026
    campaign: str = "private_control_baseline"
    output_dir: Path = Path("result")
    interface: str = "socketcan"
    channel: str = "can0"
    bitrate: int | None = 500000
    receive_timeout: float = 0.05
    inter_request_delay_ms: float = 10.0
    target_ids: tuple[int, ...] = (0x100, 0x101, 0x102, 0x1F0, 0x1F1, 0x200, 0x201, 0x300, 0x301, 0x3F0)
    opcodes: tuple[int, ...] = (0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x20, 0x21, 0x40, 0x41, 0x7F, 0x80, 0xFE, 0xFF)
    structured_rate: float = 0.7
    malformed_rate: float = 0.15
    min_payload_len: int = 1
    max_payload_len: int = 8
    extended: bool = False
    fd: bool = False
    data_bitrate: int | None = None
    auto_bitrate: bool = False
    bitrate_candidates: tuple[int, ...] = (500000, 250000, 125000, 1000000, 800000, 100000, 50000)
    data_bitrate_candidates: tuple[int, ...] = (2000000, 5000000, 4000000, 1000000)
    bitrate_probe_timeout: float = 0.2
    fd_clock: int = 80000000
    nominal_sample_point: float = 87.5
    data_sample_point: float = 80.0
    progress_interval: int = 100
    progress_seconds: float = 1.0
    keepalive: KeepaliveConfig = field(default_factory=KeepaliveConfig)


@dataclass(frozen=True)
class PrivateFuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    unique_targets: int
    unique_opcodes: int
    coverage_points: int
    csv_path: Path
    summary_path: Path


def run_private_fuzzing(config: PrivateFuzzConfig, progress_callback: Callable[[dict], None] | None = None) -> PrivateFuzzResult:
    rng = random.Random(config.seed)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = config.output_dir / f"{config.campaign}_cases.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    sent = 0
    faults = 0
    responses = 0
    completed_cases = 0
    interrupted = False
    targets_seen: set[str] = set()
    opcodes_seen: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    with CANHardwareAdapter(
        interface=config.interface,
        channel=config.channel,
        bitrate=config.bitrate,
        receive_timeout=config.receive_timeout,
        fd=config.fd,
        data_bitrate=config.data_bitrate,
        auto_bitrate=config.auto_bitrate,
        bitrate_candidates=config.bitrate_candidates,
        data_bitrate_candidates=config.data_bitrate_candidates,
        bitrate_probe_timeout=config.bitrate_probe_timeout,
        fd_clock=config.fd_clock,
        nominal_sample_point=config.nominal_sample_point,
        data_sample_point=config.data_sample_point,
    ) as adapter, KeepaliveSession(
        adapter,
        config.keepalive,
        config.output_dir / f"{config.campaign}_keepalive.csv",
        progress_callback,
    ), csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=result_fieldnames())
        writer.writeheader()
        fh.flush()

        try:
            for case_id in range(config.cases):
                request = build_request(rng, config, case_id)
                frame = CANFrame(
                    identifier=request.target_id,
                    data=request.payload,
                    frame_format=FrameFormat.EXTENDED if config.extended else FrameFormat.STANDARD,
                    frame_type=FrameType.DATA,
                    timestamp_ms=case_id,
                )
                observation = adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                responses += observation.response_count
                targets_seen.add(f"0x{request.target_id:x}")
                opcodes_seen.add(f"0x{request.opcode:02x}")
                coverage.update(build_coverage_points(request, observation))
                report_progress(
                    progress_callback,
                    event="can_exchange",
                    protocol="private",
                    case_id=case_id,
                    total_cases=config.cases,
                    tx_id=frame.identifier,
                    tx_payload=frame.to_hex_payload(),
                    tx_dlc=frame.dlc,
                    tx_format=frame.frame_format.value,
                    tx_type=frame.frame_type.value,
                    fd=config.fd,
                    sent=observation.sent,
                    fault=observation.fault,
                    state=observation.state,
                    reason=observation.reason,
                    response_count=observation.response_count,
                    response_ids=observation.response_ids,
                    response_payloads=observation.response_payloads,
                    latency_ms=observation.latency_ms,
                    error=observation.error,
                    target_id=request.target_id,
                    opcode=request.opcode,
                    strategy=request.strategy,
                    payload=request.payload.hex(),
                )

                writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": case_id,
                        "target_id": f"0x{request.target_id:x}",
                        "opcode": f"0x{request.opcode:02x}",
                        "strategy": request.strategy,
                        "is_malformed": int(request.is_malformed),
                        "dlc": frame.dlc,
                        "payload_hex": request.payload.hex(),
                        "sent": int(observation.sent),
                        "fault": int(observation.fault),
                        "state": observation.state,
                        "reason": observation.reason,
                        "response_count": observation.response_count,
                        "response_ids": ";".join(f"0x{value:x}" for value in observation.response_ids),
                        "response_payloads": ";".join(observation.response_payloads),
                        "latency_ms": f"{observation.latency_ms:.3f}",
                        "error": observation.error,
                        "coverage_count": len(coverage),
                    }
                )
                completed_cases += 1
                fh.flush()

                now = time.monotonic()
                if should_report_progress(config, completed_cases, now, last_progress):
                    last_progress = now
                    report_progress(
                        progress_callback,
                        campaign=config.campaign,
                        completed_cases=completed_cases,
                        requested_cases=config.cases,
                        sent=sent,
                        faults=faults,
                        responses=responses,
                        coverage_points=len(coverage),
                        interrupted=False,
                    )

                if config.inter_request_delay_ms > 0:
                    time.sleep(config.inter_request_delay_ms / 1000.0)
        except KeyboardInterrupt:
            interrupted = True
            fh.flush()
            report_progress(
                progress_callback,
                campaign=config.campaign,
                completed_cases=completed_cases,
                requested_cases=config.cases,
                sent=sent,
                faults=faults,
                responses=responses,
                coverage_points=len(coverage),
                interrupted=True,
            )

    write_summary(
        summary_path=summary_path,
        config=config,
        csv_path=csv_path,
        sent=sent,
        faults=faults,
        responses=responses,
        completed_cases=completed_cases,
        interrupted=interrupted,
        targets_seen=targets_seen,
        opcodes_seen=opcodes_seen,
        coverage=coverage,
    )

    return PrivateFuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        unique_targets=len(targets_seen),
        unique_opcodes=len(opcodes_seen),
        coverage_points=len(coverage),
        csv_path=csv_path,
        summary_path=summary_path,
    )


def build_coverage_points(request, observation) -> set[str]:
    points = {
        f"tx_id_{request.target_id:x}",
        f"opcode_{request.opcode:02x}",
        f"strategy_{request.strategy}",
        f"malformed_{int(request.is_malformed)}",
        f"reason_{observation.reason}",
    }
    for response_id in observation.response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points


def result_fieldnames() -> list[str]:
    return [
        "case_id",
        "timestamp_ms",
        "target_id",
        "opcode",
        "strategy",
        "is_malformed",
        "dlc",
        "payload_hex",
        "sent",
        "fault",
        "state",
        "reason",
        "response_count",
        "response_ids",
        "response_payloads",
        "latency_ms",
        "error",
        "coverage_count",
    ]


def write_summary(
    summary_path: Path,
    config: PrivateFuzzConfig,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    completed_cases: int,
    interrupted: bool,
    targets_seen: set[str],
    opcodes_seen: set[str],
    coverage: set[str],
) -> None:
    denominator = completed_cases or 1
    summary = {
        "campaign": config.campaign,
        "status": "interrupted" if interrupted else "completed",
        "interrupted": interrupted,
        "cases": config.cases,
        "requested_cases": config.cases,
        "completed_cases": completed_cases,
        "seed": config.seed,
        "interface": config.interface,
        "channel": config.channel,
        "bitrate": config.bitrate,
        "target_ids": [f"0x{value:x}" for value in config.target_ids],
        "opcodes": [f"0x{value:02x}" for value in config.opcodes],
        "structured_rate": config.structured_rate,
        "malformed_rate": config.malformed_rate,
        "min_payload_len": config.min_payload_len,
        "max_payload_len": config.max_payload_len,
        "extended": config.extended,
        "fd": config.fd,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "send_rate": sent / denominator,
        "fault_rate": faults / denominator,
        "response_rate": responses / denominator,
        "unique_targets": len(targets_seen),
        "unique_opcodes": len(opcodes_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

