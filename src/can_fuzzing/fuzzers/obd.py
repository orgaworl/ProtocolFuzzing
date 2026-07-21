from __future__ import annotations

import csv
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..adapters import CANHardwareAdapter
from ..common.fuzzing_utils import (
    decode_isotp_payload,
    encode_isotp_single_frame,
    random_bytes,
    report_progress,
    should_report_progress,
)
from ..models import CANFrame, FrameFormat, FrameType


OBD_MODE_NAMES = {
    0x01: "current_powertrain_data",
    0x02: "freeze_frame_data",
    0x03: "stored_dtcs",
    0x04: "clear_dtcs",
    0x05: "oxygen_sensor_monitoring",
    0x06: "on_board_monitoring",
    0x07: "pending_dtcs",
    0x08: "control_operation",
    0x09: "vehicle_information",
    0x0A: "permanent_dtcs",
}

OBD_MODE_POOL = list(OBD_MODE_NAMES)

COMMON_PIDS = [
    0x00,
    0x01,
    0x04,
    0x05,
    0x0C,
    0x0D,
    0x0F,
    0x10,
    0x11,
    0x1C,
    0x20,
    0x2F,
    0x40,
    0x46,
    0x5C,
]


@dataclass(frozen=True)
class OBDFuzzConfig:
    cases: int = 1000
    seed: int = 2025
    campaign: str = "obd_baseline"
    output_dir: Path = Path("result")
    interface: str = "socketcan"
    channel: str = "can0"
    bitrate: int | None = 500000
    receive_timeout: float = 0.15
    inter_request_delay_ms: float = 20.0
    request_mode: str = "functional"
    functional_id: int = 0x7DF
    physical_start: int = 0x7E0
    physical_end: int = 0x7E7
    pid_bias: float = 0.8
    malformed_rate: float = 0.1
    progress_interval: int = 100
    progress_seconds: float = 1.0


@dataclass(frozen=True)
class OBDFuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    positive_responses: int
    negative_responses: int
    unique_modes: int
    unique_pids: int
    csv_path: Path
    summary_path: Path


@dataclass(frozen=True)
class OBDRequest:
    request_id: int
    request_mode: str
    obd_mode: int
    mode_name: str
    pid: int | None
    application_payload: bytes
    is_malformed: bool


def run_obd_fuzzing(config: OBDFuzzConfig, progress_callback: Callable[[dict], None] | None = None) -> OBDFuzzResult:
    rng = random.Random(config.seed)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = config.output_dir / f"{config.campaign}_cases.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    sent = 0
    faults = 0
    responses = 0
    positive_responses = 0
    negative_responses = 0
    completed_cases = 0
    interrupted = False
    modes_seen: set[str] = set()
    pids_seen: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    with CANHardwareAdapter(
        interface=config.interface,
        channel=config.channel,
        bitrate=config.bitrate,
        receive_timeout=config.receive_timeout,
        fd=False,
        data_bitrate=None,
    ) as adapter, csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=result_fieldnames())
        writer.writeheader()
        fh.flush()

        try:
            for case_id in range(config.cases):
                request = build_request(rng, config)
                isotp_payload = encode_isotp_single_frame(request.application_payload)
                frame = CANFrame.from_ints(request.request_id, isotp_payload, FrameFormat.STANDARD, FrameType.DATA)
                observation = adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                responses += observation.response_count

                response_summary = summarize_responses(observation.response_payloads, request.obd_mode)
                positive_responses += response_summary["positive"]
                negative_responses += response_summary["negative"]
                modes_seen.add(request.mode_name)
                if request.pid is not None:
                    pids_seen.add(f"0x{request.pid:02x}")
                coverage.update(build_coverage_points(request, response_summary, observation))

                writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": case_id,
                        "request_id": f"0x{request.request_id:x}",
                        "request_mode": request.request_mode,
                        "obd_mode": f"0x{request.obd_mode:02x}",
                        "mode_name": request.mode_name,
                        "pid": "" if request.pid is None else f"0x{request.pid:02x}",
                        "is_malformed": int(request.is_malformed),
                        "application_payload_hex": request.application_payload.hex(),
                        "isotp_payload_hex": isotp_payload.hex(),
                        "sent": int(observation.sent),
                        "fault": int(observation.fault),
                        "response_count": observation.response_count,
                        "response_ids": ";".join(f"0x{value:x}" for value in observation.response_ids),
                        "response_payloads": ";".join(observation.response_payloads),
                        "positive_responses": response_summary["positive"],
                        "negative_responses": response_summary["negative"],
                        "response_kind": response_summary["kind"],
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
                        positive_responses=positive_responses,
                        negative_responses=negative_responses,
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
                positive_responses=positive_responses,
                negative_responses=negative_responses,
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
        positive_responses=positive_responses,
        negative_responses=negative_responses,
        modes_seen=modes_seen,
        pids_seen=pids_seen,
        coverage=coverage,
    )

    return OBDFuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        positive_responses=positive_responses,
        negative_responses=negative_responses,
        unique_modes=len(modes_seen),
        unique_pids=len(pids_seen),
        csv_path=csv_path,
        summary_path=summary_path,
    )


def build_request(rng: random.Random, config: OBDFuzzConfig) -> OBDRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate
    obd_mode = choose_mode(rng)
    pid = choose_pid(rng, config) if mode_uses_pid(obd_mode) else None

    if malformed:
        payload_length = rng.randint(1, 7)
        payload = bytes([obd_mode, *random_bytes(rng, payload_length - 1)])
    else:
        payload = build_obd_payload(obd_mode, pid)

    return OBDRequest(
        request_id=request_id,
        request_mode=request_mode,
        obd_mode=obd_mode,
        mode_name=OBD_MODE_NAMES.get(obd_mode, f"mode_0x{obd_mode:02x}"),
        pid=pid,
        application_payload=payload,
        is_malformed=malformed,
    )


def choose_request_mode(rng: random.Random, config: OBDFuzzConfig) -> str:
    if config.request_mode in {"functional", "physical"}:
        return config.request_mode
    return rng.choices(["functional", "physical"], weights=[0.8, 0.2], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config: OBDFuzzConfig) -> int:
    if request_mode == "functional":
        return config.functional_id
    return rng.randint(config.physical_start, config.physical_end)


def choose_mode(rng: random.Random) -> int:
    if rng.random() < 0.9:
        return rng.choice(OBD_MODE_POOL)
    return rng.randrange(0x01, 0x10)


def choose_pid(rng: random.Random, config: OBDFuzzConfig) -> int:
    if rng.random() < config.pid_bias:
        return rng.choice(COMMON_PIDS)
    return rng.randrange(0x00, 0x100)


def mode_uses_pid(obd_mode: int) -> bool:
    return obd_mode in {0x01, 0x02, 0x05, 0x06, 0x08, 0x09}


def build_obd_payload(obd_mode: int, pid: int | None) -> bytes:
    if mode_uses_pid(obd_mode):
        return bytes([obd_mode, 0x00 if pid is None else pid])
    return bytes([obd_mode])


def summarize_responses(response_payloads: list[str], request_mode: int) -> dict[str, int | str]:
    positive = 0
    negative = 0
    kind = "no_response"
    expected_positive = (request_mode + 0x40) & 0xFF
    for raw_hex in response_payloads:
        raw = bytes.fromhex(raw_hex)
        frame_kind, app_payload = decode_isotp_payload(raw)
        if frame_kind != "single_frame" or not app_payload:
            kind = frame_kind
            continue
        service = app_payload[0]
        if service == expected_positive:
            positive += 1
            kind = "positive_response"
        elif service == 0x7F:
            negative += 1
            kind = "negative_response"
        else:
            kind = f"service_0x{service:02x}"
    return {"positive": positive, "negative": negative, "kind": kind}


def build_coverage_points(request: OBDRequest, response_summary: dict[str, int | str], observation) -> set[str]:
    points = {
        f"tx_request_id_{request.request_id:x}",
        f"tx_mode_{request.obd_mode:02x}",
        f"tx_addressing_{request.request_mode}",
        f"tx_malformed_{int(request.is_malformed)}",
        f"rx_kind_{response_summary['kind']}",
    }
    if request.pid is not None:
        points.add(f"tx_pid_{request.pid:02x}")
    for response_id in observation.response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points


def result_fieldnames() -> list[str]:
    return [
        "case_id",
        "timestamp_ms",
        "request_id",
        "request_mode",
        "obd_mode",
        "mode_name",
        "pid",
        "is_malformed",
        "application_payload_hex",
        "isotp_payload_hex",
        "sent",
        "fault",
        "response_count",
        "response_ids",
        "response_payloads",
        "positive_responses",
        "negative_responses",
        "response_kind",
        "latency_ms",
        "error",
        "coverage_count",
    ]


def write_summary(
    summary_path: Path,
    config: OBDFuzzConfig,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    completed_cases: int,
    interrupted: bool,
    positive_responses: int,
    negative_responses: int,
    modes_seen: set[str],
    pids_seen: set[str],
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
        "request_mode": config.request_mode,
        "functional_id": config.functional_id,
        "physical_start": config.physical_start,
        "physical_end": config.physical_end,
        "pid_bias": config.pid_bias,
        "malformed_rate": config.malformed_rate,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "positive_responses": positive_responses,
        "negative_responses": negative_responses,
        "send_rate": sent / denominator,
        "fault_rate": faults / denominator,
        "response_rate": responses / denominator,
        "unique_modes": len(modes_seen),
        "unique_pids": len(pids_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

