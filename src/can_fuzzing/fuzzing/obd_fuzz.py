from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..protocol.obd import OBDProtocol, build_request, summarize_responses
from ..runtime.keepalive import KeepaliveConfig
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from .results import build_common_summary, fieldnames_for, write_json_summary
from .runner import open_fuzz_run
from .utils import iter_case_ids, report_progress, should_report_progress

@dataclass(frozen=True)
class OBDFuzzConfig:
    hardware: CANHardwareConfig
    cases: int
    seed: int
    campaign: str
    output_dir: Path
    inter_request_delay_ms: float
    request_mode: str
    functional_id: int
    physical_start: int
    physical_end: int
    pid_bias: float
    malformed_rate: float
    progress_interval: int
    progress_seconds: float
    keepalive: KeepaliveConfig

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

def run_obd_fuzzing(config: OBDFuzzConfig, progress_callback: ProgressCallback | None = None) -> OBDFuzzResult:
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

    protocol = OBDProtocol()
    with open_fuzz_run(config, csv_path, fieldnames_for("obd"), progress_callback) as run:

        try:
            for case_id in iter_case_ids(config.cases):
                request = build_request(rng, config)
                isotp_payload = protocol.encode_request_frames(request.application_payload)[0]
                frame = CANFrame.from_ints(request.request_id, isotp_payload, FrameFormat.STANDARD, FrameType.DATA)
                observation = run.adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                response_ids = observation.response_ids
                response_payloads = observation.response_payloads
                response_count = len(response_payloads)
                responses += response_count

                response_summary = summarize_responses(response_payloads, request.obd_mode)
                positive_responses += response_summary["positive"]
                negative_responses += response_summary["negative"]
                modes_seen.add(request.mode_name)
                if request.pid is not None:
                    pids_seen.add(f"0x{request.pid:02x}")
                coverage.update(build_coverage_points(request, response_summary, response_ids))
                report_progress(
                    progress_callback,
                    event="can_exchange",
                    protocol="obd",
                    case_id=case_id,
                    total_cases=config.cases,
                    tx_id=frame.identifier,
                    tx_payload=frame.to_hex_payload(),
                    tx_dlc=frame.dlc,
                    tx_format=frame.frame_format.value,
                    tx_type=frame.frame_type.value,
                    fd=False,
                    sent=observation.sent,
                    fault=observation.fault,
                    state=observation.state,
                    reason=observation.reason,
                    response_count=response_count,
                    response_ids=response_ids,
                    response_payloads=response_payloads,
                    latency_ms=observation.latency_ms,
                    error=observation.error,
                    request_mode=request.request_mode,
                    obd_mode=request.obd_mode,
                    mode_name=request.mode_name,
                    pid=request.pid,
                    application_payload=request.application_payload.hex(),
                    response_kind=response_summary["kind"],
                )

                run.writer.writerow(
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
                        "response_count": response_count,
                        "response_ids": ";".join(f"0x{value:x}" for value in response_ids),
                        "response_payloads": ";".join(response_payloads),
                        "positive_responses": response_summary["positive"],
                        "negative_responses": response_summary["negative"],
                        "response_kind": response_summary["kind"],
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
                        positive_responses=positive_responses,
                        negative_responses=negative_responses,
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

def build_coverage_points(request, response_summary: dict[str, int | str], response_ids: list[int]) -> set[str]:
    points = {
        f"tx_request_id_{request.request_id:x}",
        f"tx_mode_{request.obd_mode:02x}",
        f"tx_addressing_{request.request_mode}",
        f"tx_malformed_{int(request.is_malformed)}",
        f"rx_kind_{response_summary['kind']}",
    }
    if request.pid is not None:
        points.add(f"tx_pid_{request.pid:02x}")
    for response_id in response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points

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
    })
    write_json_summary(summary_path, summary)
