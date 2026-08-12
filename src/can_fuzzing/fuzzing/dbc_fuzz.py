from __future__ import annotations

import csv
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..runtime.adapters import CANHardwareAdapter
from ..log import warning
from .utils import report_progress, should_report_progress
from ..runtime.keepalive import KeepaliveConfig, KeepaliveSession
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from ..protocol.dbc import DBCDatabase, DBCMessage, DBCSignal, coerce_number, load_dbc_database


@dataclass(frozen=True)
class DBCFuzzConfig:
    hardware: CANHardwareConfig
    dbc_file: Path
    cases: int
    seed: int
    campaign: str
    output_dir: Path
    inter_frame_delay_ms: float
    progress_interval: int
    progress_seconds: float
    keepalive: KeepaliveConfig


@dataclass(frozen=True)
class DBCFuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    decoded_responses: int
    unique_messages: int
    unique_signals: int
    coverage_points: int
    csv_path: Path
    summary_path: Path


def run_dbc_fuzzing(config: DBCFuzzConfig, progress_callback: ProgressCallback | None = None) -> DBCFuzzResult:
    rng = random.Random(config.seed)
    database = load_dbc_database(config.dbc_file)
    if not database.messages:
        raise ValueError(f"DBC file {config.dbc_file} does not define any BO_ messages")
    config.output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = config.output_dir / f"{config.campaign}_cases.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    use_fd = config.hardware.fd or database.requires_fd
    sent = 0
    faults = 0
    responses = 0
    decoded_responses = 0
    completed_cases = 0
    interrupted = False
    messages_seen: set[str] = set()
    signals_seen: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    if database.requires_fd and not config.hardware.fd:
        warning("DBC file contains frames larger than 8 bytes; enabling CAN FD automatically")

    with CANHardwareAdapter(config.hardware) as adapter, KeepaliveSession(
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
                request = build_request(rng, database)
                frame = CANFrame.from_ints(
                    request.message_id,
                    request.payload,
                    FrameFormat.EXTENDED if request.message_id > 0x7FF else FrameFormat.STANDARD,
                    FrameType.DATA,
                )
                observation = adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                responses += observation.response_count
                messages_seen.add(request.message_name)
                signals_seen.update(request.signal_values)

                decoded_response_rows: list[dict[str, object]] = []
                for response_id, payload_hex in zip(observation.response_ids, observation.response_payloads):
                    message, decoded = database.decode_frame(response_id, bytes.fromhex(payload_hex))
                    if message is not None:
                        decoded_responses += 1
                        coverage.add(f"rx_message_{message.name}")
                        for signal_name in decoded:
                            coverage.add(f"rx_signal_{signal_name}")
                    decoded_response_rows.append(
                        {
                            "id": response_id,
                            "payload": payload_hex,
                            "message_name": message.name if message is not None else "",
                            "signals": decoded,
                        }
                    )

                coverage.update(build_coverage_points(request, observation, decoded_response_rows))
                report_progress(
                    progress_callback,
                    event="can_exchange",
                    protocol="dbc",
                    case_id=case_id,
                    total_cases=config.cases,
                    tx_id=frame.identifier,
                    tx_payload=frame.to_hex_payload(),
                    tx_dlc=frame.dlc,
                    tx_format=frame.frame_format.value,
                    tx_type=frame.frame_type.value,
                    fd=use_fd,
                    message_name=request.message_name,
                    tx_signal_values=request.signal_values,
                    strategy=request.strategy,
                    sent=observation.sent,
                    fault=observation.fault,
                    state=observation.state,
                    reason=observation.reason,
                    response_count=observation.response_count,
                    response_ids=observation.response_ids,
                    response_payloads=observation.response_payloads,
                    response_messages=decoded_response_rows,
                    latency_ms=observation.latency_ms,
                    error=observation.error,
                )

                writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": frame.timestamp_ms,
                        "message_id": f"0x{request.message_id:x}",
                        "message_name": request.message_name,
                        "strategy": request.strategy,
                        "frame_format": frame.frame_format.value,
                        "dlc": frame.dlc,
                        "payload_hex": frame.to_hex_payload(),
                        "signal_values": json.dumps(request.signal_values, sort_keys=True, ensure_ascii=False),
                        "sent": int(observation.sent),
                        "fault": int(observation.fault),
                        "state": observation.state,
                        "reason": observation.reason,
                        "response_count": observation.response_count,
                        "response_ids": ";".join(f"0x{value:x}" for value in observation.response_ids),
                        "response_payloads": ";".join(observation.response_payloads),
                        "decoded_responses": json.dumps(decoded_response_rows, ensure_ascii=False, sort_keys=True),
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

                if config.inter_frame_delay_ms > 0:
                    time.sleep(config.inter_frame_delay_ms / 1000.0)
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
        database=database,
        csv_path=csv_path,
        sent=sent,
        faults=faults,
        responses=responses,
        decoded_responses=decoded_responses,
        completed_cases=completed_cases,
        interrupted=interrupted,
        messages_seen=messages_seen,
        signals_seen=signals_seen,
        coverage=coverage,
    )

    return DBCFuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        decoded_responses=decoded_responses,
        unique_messages=len(messages_seen),
        unique_signals=len(signals_seen),
        coverage_points=len(coverage),
        csv_path=csv_path,
        summary_path=summary_path,
    )


def build_coverage_points(request: DBCRequest, observation, decoded_responses: list[dict[str, object]]) -> set[str]:
    points = {
        f"tx_message_{request.message_name}",
        f"tx_strategy_{request.strategy}",
        f"tx_payload_len_{len(request.payload)}",
    }
    for signal_name in request.signal_values:
        points.add(f"tx_signal_{signal_name}")
    for response_id in observation.response_ids:
        points.add(f"rx_id_{response_id:x}")
    for response in decoded_responses:
        message_name = str(response.get("message_name", ""))
        if message_name:
            points.add(f"rx_message_{message_name}")
        signals = response.get("signals", {})
        if isinstance(signals, dict):
            for signal_name in signals:
                points.add(f"rx_signal_{signal_name}")
    return points


def result_fieldnames() -> list[str]:
    return [
        "case_id",
        "timestamp_ms",
        "message_id",
        "message_name",
        "strategy",
        "frame_format",
        "dlc",
        "payload_hex",
        "signal_values",
        "sent",
        "fault",
        "state",
        "reason",
        "response_count",
        "response_ids",
        "response_payloads",
        "decoded_responses",
        "latency_ms",
        "error",
        "coverage_count",
    ]


def write_summary(
    summary_path: Path,
    config: DBCFuzzConfig,
    database: DBCDatabase,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    decoded_responses: int,
    completed_cases: int,
    interrupted: bool,
    messages_seen: set[str],
    signals_seen: set[str],
    coverage: set[str],
) -> None:
    denominator = completed_cases or 1
    summary = {
        "campaign": config.campaign,
        "status": "interrupted" if interrupted else "completed",
        "interrupted": interrupted,
        "dbc_file": str(config.dbc_file),
        "message_count": len(database.messages),
        "signal_count": database.signal_count,
        "cases": config.cases,
        "requested_cases": config.cases,
        "completed_cases": completed_cases,
        "seed": config.seed,
        "interface": config.hardware.interface,
        "channel": config.hardware.channel,
        "bitrate": config.hardware.bitrate,
        "fd": config.hardware.fd or database.requires_fd,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "decoded_responses": decoded_responses,
        "send_rate": sent / denominator,
        "fault_rate": faults / denominator,
        "response_rate": responses / denominator,
        "unique_messages": len(messages_seen),
        "unique_signals": len(signals_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")







@dataclass(frozen=True)
class DBCRequest:
    message_id: int
    message_name: str
    payload: bytes
    signal_values: dict[str, Any]
    strategy: str


def choose_message(rng: random.Random, database: DBCDatabase) -> DBCMessage:
    weights = [max(1, len(message.signals)) + max(1, message.size) for message in database.messages]
    return rng.choices(database.messages, weights=weights, k=1)[0]


def build_request(rng: random.Random, database: DBCDatabase) -> DBCRequest:
    message = choose_message(rng, database)
    strategy = rng.choice(["baseline", "boundary", "random", "choices"])
    values = build_signal_values(rng, message, strategy)
    payload = message.encode(values)
    return DBCRequest(
        message_id=message.frame_id,
        message_name=message.name,
        payload=payload,
        signal_values=values,
        strategy=strategy,
    )


def build_signal_values(rng: random.Random, message: DBCMessage, strategy: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for signal in message.signals:
        values[signal.name] = choose_signal_value(rng, signal, strategy)
    return values


def choose_signal_value(rng: random.Random, signal: DBCSignal, strategy: str) -> Any:
    if signal.choices:
        choice_values = [value for value, _ in signal.choices]
        if strategy == "baseline":
            return choice_values[0]
        return rng.choice(choice_values)

    candidates = interesting_values(signal)
    if strategy == "baseline":
        return signal.baseline_value()
    if strategy == "boundary":
        return rng.choice(candidates)
    if strategy == "choices":
        return rng.choice(candidates[: max(1, min(4, len(candidates)))])
    return random_value(rng, signal)


def interesting_values(signal: DBCSignal) -> list[int | float]:
    values: list[int | float] = []
    raw_min = signal.raw_min
    raw_max = signal.raw_max
    for raw in (raw_min, raw_min + 1, -1, 0, 1, raw_max - 1, raw_max):
        if raw < raw_min or raw > raw_max:
            continue
        values.append(coerce_number(raw * signal.factor + signal.offset))
    if signal.minimum is not None:
        values.append(coerce_number(signal.minimum))
    if signal.maximum is not None:
        values.append(coerce_number(signal.maximum))
    if not values:
        values.append(signal.baseline_value())
    return dedupe(values)


def random_value(rng: random.Random, signal: DBCSignal) -> int | float:
    raw = rng.randint(signal.raw_min, signal.raw_max)
    return coerce_number(raw * signal.factor + signal.offset)


def dedupe(values: list[int | float]) -> list[int | float]:
    seen: set[tuple[type, Any]] = set()
    result: list[int | float] = []
    for value in values:
        key = (type(value), value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
