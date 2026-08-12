from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..protocol.private_control import build_request
from ..runtime.keepalive import KeepaliveConfig
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from .runner import open_fuzz_run
from .utils import report_progress, should_report_progress


@dataclass(frozen=True)
class PrivateFuzzConfig:
    hardware: CANHardwareConfig
    cases: int
    seed: int
    campaign: str
    output_dir: Path
    inter_request_delay_ms: float
    target_ids: tuple[int, ...]
    opcodes: tuple[int, ...]
    structured_rate: float
    malformed_rate: float
    min_payload_len: int
    max_payload_len: int
    extended: bool
    progress_interval: int
    progress_seconds: float
    keepalive: KeepaliveConfig


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


def run_private_fuzzing(config: PrivateFuzzConfig, progress_callback: ProgressCallback | None = None) -> PrivateFuzzResult:
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

    with open_fuzz_run(config, csv_path, result_fieldnames(), progress_callback) as run:

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
                observation = run.adapter.transact(frame)

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
                    fd=config.hardware.fd,
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

                run.writer.writerow(
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
                run.csv_file.flush()

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
            run.csv_file.flush()
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
        "interface": config.hardware.interface,
        "channel": config.hardware.channel,
        "bitrate": config.hardware.bitrate,
        "target_ids": [f"0x{value:x}" for value in config.target_ids],
        "opcodes": [f"0x{value:02x}" for value in config.opcodes],
        "structured_rate": config.structured_rate,
        "malformed_rate": config.malformed_rate,
        "min_payload_len": config.min_payload_len,
        "max_payload_len": config.max_payload_len,
        "extended": config.extended,
        "fd": config.hardware.fd,
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
