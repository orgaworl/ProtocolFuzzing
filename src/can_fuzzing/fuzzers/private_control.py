from __future__ import annotations

import csv
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..adapters import CANHardwareAdapter
from ..common.fuzzing_utils import report_progress, should_report_progress
from ..common.protocol_dictionary import PRIVATE_OPCODES, PRIVATE_TARGET_IDS
from ..models import CANFrame, FrameFormat, FrameType


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
    target_ids: tuple[int, ...] = PRIVATE_TARGET_IDS
    opcodes: tuple[int, ...] = PRIVATE_OPCODES
    structured_rate: float = 0.7
    malformed_rate: float = 0.15
    min_payload_len: int = 1
    max_payload_len: int = 8
    extended: bool = False
    fd: bool = False
    data_bitrate: int | None = None
    progress_interval: int = 100
    progress_seconds: float = 1.0


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


@dataclass(frozen=True)
class PrivateControlRequest:
    target_id: int
    opcode: int
    payload: bytes
    strategy: str
    is_malformed: bool


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
    ) as adapter, csv_path.open("w", newline="", encoding="utf-8") as fh:
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

                writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": frame.timestamp_ms,
                        "target_id": f"0x{request.target_id:x}",
                        "opcode": f"0x{request.opcode:02x}",
                        "strategy": request.strategy,
                        "is_malformed": int(request.is_malformed),
                        "dlc": frame.dlc,
                        "payload_hex": frame.to_hex_payload(),
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


def build_request(rng: random.Random, config: PrivateFuzzConfig, case_id: int) -> PrivateControlRequest:
    target_id = rng.choice(config.target_ids)
    opcode = rng.choice(config.opcodes)
    is_malformed = rng.random() < config.malformed_rate
    if is_malformed:
        payload = build_malformed_payload(rng, config, opcode)
        return PrivateControlRequest(target_id, opcode, payload, "malformed", True)

    if rng.random() < config.structured_rate:
        payload = build_structured_payload(rng, config, opcode, case_id)
        return PrivateControlRequest(target_id, opcode, payload, "structured", False)

    payload = build_random_payload(rng, config, opcode)
    return PrivateControlRequest(target_id, opcode, payload, "random", False)


def build_structured_payload(rng: random.Random, config: PrivateFuzzConfig, opcode: int, case_id: int) -> bytes:
    length = clamp_payload_length(config, rng.choice([4, 5, 6, 7, 8, 12, 16]))
    payload = bytearray([opcode & 0xFF])
    if length >= 2:
        payload.append(case_id & 0xFF)
    if length >= 3:
        payload.append(rng.randrange(0x00, 0x100))
    if length >= 4:
        payload.append(length & 0xFF)
    while len(payload) < length:
        payload.append(rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, rng.randrange(0x00, 0x100)]))
    return bytes(payload)


def build_random_payload(rng: random.Random, config: PrivateFuzzConfig, opcode: int) -> bytes:
    length = random_payload_length(rng, config)
    payload = bytearray([opcode & 0xFF])
    while len(payload) < length:
        payload.append(rng.randrange(0x00, 0x100))
    return bytes(payload)


def build_malformed_payload(rng: random.Random, config: PrivateFuzzConfig, opcode: int) -> bytes:
    choices = [0, 1, config.max_payload_len]
    if config.fd:
        choices.extend([9, 15, 32, 64])
    length = clamp_payload_length(config, rng.choice(choices))
    if length == 0:
        return b""
    payload = bytearray([opcode & 0xFF])
    while len(payload) < length:
        payload.append(rng.choice([0x00, 0xFF, rng.randrange(0x00, 0x100)]))
    return bytes(payload)


def random_payload_length(rng: random.Random, config: PrivateFuzzConfig) -> int:
    minimum = max(0, config.min_payload_len)
    maximum = max(minimum, min(config.max_payload_len, 64 if config.fd else 8))
    return rng.randint(minimum, maximum)


def clamp_payload_length(config: PrivateFuzzConfig, length: int) -> int:
    upper = 64 if config.fd else 8
    minimum = max(0, min(config.min_payload_len, upper))
    maximum = max(minimum, min(config.max_payload_len, upper))
    return max(minimum, min(length, maximum))


def build_coverage_points(request: PrivateControlRequest, observation) -> set[str]:
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

