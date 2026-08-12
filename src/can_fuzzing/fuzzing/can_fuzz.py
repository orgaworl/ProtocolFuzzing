from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from .results import build_common_summary, fieldnames_for, write_json_summary
from .runner import open_fuzz_run
from .utils import report_progress, should_report_progress
from ..runtime.keepalive import KeepaliveConfig
from ..protocol.dictionary import COMMON_CAN_IDS, COMMON_CLASSIC_LENGTHS, COMMON_DIAGNOSTIC_TEMPLATES, COMMON_DIAGNOSTIC_TEMPLATES_FD, COMMON_FD_LENGTHS
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback

DIAGNOSTIC_IDS = COMMON_CAN_IDS

class CANFuzzingStrategyConfig:
    inter_frame_delay_ms: float
    fd: bool
    id_min: int
    id_max: int
    diagnostic_bias: float
    extended_probability: float
    include_remote: bool
    include_error: bool

@dataclass(frozen=True)
class FuzzConfig:
    hardware: CANHardwareConfig
    cases: int
    seed: int
    campaign: str
    output_dir: Path
    inter_frame_delay_ms: float
    id_min: int
    id_max: int
    diagnostic_bias: float
    extended_probability: float
    include_remote: bool
    include_error: bool
    progress_interval: int
    progress_seconds: float
    keepalive: KeepaliveConfig

@dataclass(frozen=True)
class FuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    unique_reasons: int
    coverage_points: int
    csv_path: Path
    summary_path: Path

def run_fuzzing(config: FuzzConfig, progress_callback: ProgressCallback | None = None) -> FuzzResult:
    rng = random.Random(config.seed)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = config.output_dir / f"{config.campaign}_cases.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    sent = 0
    faults = 0
    responses = 0
    completed_cases = 0
    interrupted = False
    reasons: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    with open_fuzz_run(config, csv_path, fieldnames_for("can"), progress_callback) as run:

        try:
            current_timestamp_ms = 0
            for case_id in range(config.cases):
                frame = generate_frame(rng, case_id, current_timestamp_ms, config)
                current_timestamp_ms = frame.timestamp_ms
                observation = run.adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                responses += observation.response_count
                reasons.add(observation.reason)
                coverage.update(classify_coverage(frame, observation))
                report_progress(
                    progress_callback,
                    event="can_exchange",
                    protocol="can",
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
                )

                run.writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": frame.timestamp_ms,
                        "identifier": frame.identifier,
                        "frame_format": frame.frame_format.value,
                        "frame_type": frame.frame_type.value,
                        "dlc": frame.dlc,
                        "payload_hex": frame.to_hex_payload(),
                        "sent": int(observation.sent),
                        "accepted": int(observation.sent),
                        "fault": int(observation.fault),
                        "state": observation.state,
                        "reason": observation.reason,
                        "response_count": observation.response_count,
                        "response_ids": encode_int_list(observation.response_ids),
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

                if config.inter_frame_delay_ms > 0:
                    time.sleep(config.inter_frame_delay_ms / 1000.0)
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
        reasons=reasons,
        coverage=coverage,
    )

    return FuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        unique_reasons=len(reasons),
        coverage_points=len(coverage),
        csv_path=csv_path,
        summary_path=summary_path,
    )

def generate_frame(rng: random.Random, case_id: int, current_timestamp_ms: int, config: CANFuzzingStrategyConfig) -> CANFrame:
    frame_format = choose_frame_format(rng, config)
    frame_type = choose_frame_type(rng, config)
    identifier = choose_identifier(rng, frame_format, config)
    data = choose_payload(rng, identifier, config)
    timestamp_ms = current_timestamp_ms + max(1, int(config.inter_frame_delay_ms))

    return CANFrame(
        identifier=identifier,
        data=data,
        frame_format=frame_format,
        frame_type=frame_type,
        timestamp_ms=timestamp_ms,
    )

def choose_frame_format(rng: random.Random, config: CANFuzzingStrategyConfig) -> FrameFormat:
    if rng.random() < config.extended_probability:
        return FrameFormat.EXTENDED
    return FrameFormat.STANDARD

def choose_frame_type(rng: random.Random, config: CANFuzzingStrategyConfig) -> FrameType:
    choices = [FrameType.DATA]
    weights = [1.0]
    if config.include_remote:
        choices.append(FrameType.REMOTE)
        weights.append(0.05)
    if config.include_error:
        choices.append(FrameType.ERROR)
        weights.append(0.02)
    return rng.choices(choices, weights=weights, k=1)[0]

def choose_identifier(rng: random.Random, frame_format: FrameFormat, config: CANFuzzingStrategyConfig) -> int:
    upper_limit = 0x7FF if frame_format == FrameFormat.STANDARD else 0x1FFFFFFF
    id_min = max(0, min(config.id_min, upper_limit))
    id_max = max(id_min, min(config.id_max, upper_limit))
    diagnostic_ids = [value for value in DIAGNOSTIC_IDS if id_min <= value <= id_max]
    if diagnostic_ids and rng.random() < config.diagnostic_bias:
        return rng.choice(diagnostic_ids)
    return rng.randint(id_min, id_max)

def choose_payload(rng: random.Random, identifier: int, config: CANFuzzingStrategyConfig) -> bytes:
    if identifier in DIAGNOSTIC_IDS and rng.random() < 0.75:
        templates = COMMON_DIAGNOSTIC_TEMPLATES_FD if config.hardware.fd else COMMON_DIAGNOSTIC_TEMPLATES
        data = rng.choice(templates)
        return bytes(pad_classic_payload(list(data), rng))

    max_len = 64 if config.hardware.fd else 8
    lengths = COMMON_FD_LENGTHS if config.hardware.fd else COMMON_CLASSIC_LENGTHS
    interesting_lengths = [value for value in lengths if value <= max_len]
    length = rng.choice(interesting_lengths)
    return bytes(rng.randrange(256) for _ in range(length))

def pad_classic_payload(data: list[int], rng: random.Random) -> list[int]:
    data = data[:8]
    if len(data) < 8 and rng.random() < 0.7:
        data = data + [0x00] * (8 - len(data))
    return data

def classify_coverage(frame: CANFrame, observation) -> set[str]:
    points = {
        f"tx_id_{frame.identifier:x}",
        f"format_{frame.frame_format.value}",
        f"type_{frame.frame_type.value}",
        f"reason_{observation.reason}",
    }
    if frame.data:
        if frame.data[0] <= 0x07 and len(frame.data) > 1:
            points.add(f"service_{frame.data[1]:02x}")
        else:
            points.add(f"byte0_{frame.data[0]:02x}")
    for response_id in observation.response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points

def encode_int_list(values: list[int]) -> str:
    return ";".join(f"0x{value:x}" for value in values)

def write_summary(
    summary_path: Path,
    config: FuzzConfig,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    completed_cases: int,
    interrupted: bool,
    reasons: set[str],
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
        "fd": config.hardware.fd,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "send_rate": sent / denominator,
        "fault_rate": faults / denominator,
        "response_rate": responses / denominator,
        "unique_reasons": len(reasons),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    })
    write_json_summary(summary_path, summary)
