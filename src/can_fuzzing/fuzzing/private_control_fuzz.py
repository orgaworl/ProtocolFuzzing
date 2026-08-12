from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from scapy.packet import Raw
from ..runtime.keepalive import KeepaliveConfig
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from .results import build_common_summary, fieldnames_for, write_json_summary
from .runner import open_fuzz_run
from .utils import iter_case_ids, report_progress, should_report_progress


def raw_payload(first_byte: int, data: bytes = b'') -> bytes:
    return bytes(Raw(bytes([first_byte & 0xFF]) + bytes(data)))


@dataclass(frozen=True)
class PrivateControlRequest:
    target_id: int
    opcode: int
    payload: bytes
    strategy: str
    is_malformed: bool


def build_request(rng: random.Random, config, case_id: int) -> PrivateControlRequest:
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


def build_structured_payload(rng: random.Random, config, opcode: int, case_id: int) -> bytes:
    length = clamp_payload_length(config, rng.choice([4, 5, 6, 7, 8, 12, 16]))
    data: list[int] = []
    if length >= 2:
        data.append(case_id & 0xFF)
    if length >= 3:
        data.append(rng.randrange(0x00, 0x100))
    if length >= 4:
        data.append(length & 0xFF)
    while len(data) < max(0, length - 1):
        data.append(rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, rng.randrange(0x00, 0x100)]))
    return raw_payload(opcode, bytes(data))


def build_random_payload(rng: random.Random, config, opcode: int) -> bytes:
    length = random_payload_length(rng, config)
    data = bytes(rng.randrange(0x00, 0x100) for _ in range(max(0, length - 1)))
    return raw_payload(opcode, data)


def build_malformed_payload(rng: random.Random, config, opcode: int) -> bytes:
    choices = [0, 1, config.max_payload_len]
    if config.hardware.fd:
        choices.extend([9, 15, 32, 64])
    length = clamp_payload_length(config, rng.choice(choices))
    if length == 0:
        return b""
    data = bytes(rng.choice([0x00, 0xFF, rng.randrange(0x00, 0x100)]) for _ in range(max(0, length - 1)))
    return raw_payload(opcode, data)


def random_payload_length(rng: random.Random, config) -> int:
    minimum = max(0, config.min_payload_len)
    maximum = max(minimum, min(config.max_payload_len, 64 if config.hardware.fd else 8))
    return rng.randint(minimum, maximum)


def clamp_payload_length(config, length: int) -> int:
    upper = 64 if config.hardware.fd else 8
    minimum = max(0, min(config.min_payload_len, upper))
    maximum = max(minimum, min(config.max_payload_len, upper))
    return max(minimum, min(length, maximum))

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

    with open_fuzz_run(config, csv_path, fieldnames_for("private"), progress_callback) as run:

        try:
            for case_id in iter_case_ids(config.cases):
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
    summary = build_common_summary(config, csv_path, sent, faults, responses, completed_cases, interrupted)
    summary.update({
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
        "unique_targets": len(targets_seen),
        "unique_opcodes": len(opcodes_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    })
    write_json_summary(summary_path, summary)
