from __future__ import annotations

import csv
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..protocol.isotp import encode_isotp_single_frame
from ..protocol.uds import build_request, summarize_responses
from ..runtime.adapters import CANHardwareAdapter
from ..runtime.keepalive import KeepaliveConfig, KeepaliveSession
from ..runtime.models import CANFrame, FrameFormat, FrameType
from .utils import report_progress, should_report_progress


@dataclass(frozen=True)
class UDSFuzzConfig:
    cases: int = 1000
    seed: int = 2024
    campaign: str = "uds_baseline"
    output_dir: Path = Path("result")
    interface: str = "socketcan"
    channel: str = "can0"
    bitrate: int | None = 500000
    auto_bitrate: bool = False
    bitrate_candidates: tuple[int, ...] = (500000, 250000, 125000, 1000000, 800000, 100000, 50000)
    bitrate_probe_timeout: float = 0.2
    receive_timeout: float = 0.15
    inter_request_delay_ms: float = 10.0
    request_mode: str = "mixed"
    functional_id: int = 0x7DF
    physical_start: int = 0x7E0
    physical_end: int = 0x7E7
    service_bias: float = 0.85
    malformed_rate: float = 0.15
    progress_interval: int = 100
    progress_seconds: float = 1.0
    keepalive: KeepaliveConfig = field(default_factory=KeepaliveConfig)


@dataclass(frozen=True)
class UDSFuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    positive_responses: int
    negative_responses: int
    multi_frame_responses: int
    unique_services: int
    unique_nrcs: int
    csv_path: Path
    summary_path: Path


def run_uds_fuzzing(config: UDSFuzzConfig, progress_callback: Callable[[dict], None] | None = None) -> UDSFuzzResult:
    rng = random.Random(config.seed)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = config.output_dir / f"{config.campaign}_cases.csv"
    summary_path = config.output_dir / f"{config.campaign}_summary.json"

    sent = 0
    faults = 0
    responses = 0
    positive_responses = 0
    negative_responses = 0
    multi_frame_responses = 0
    completed_cases = 0
    interrupted = False
    services_seen: set[str] = set()
    nrcs_seen: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    with CANHardwareAdapter(
        interface=config.interface,
        channel=config.channel,
        bitrate=config.bitrate,
        receive_timeout=config.receive_timeout,
        fd=False,
        data_bitrate=None,
        auto_bitrate=config.auto_bitrate,
        bitrate_candidates=config.bitrate_candidates,
        bitrate_probe_timeout=config.bitrate_probe_timeout,
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
                request = build_request(rng, config)
                isotp_payload = encode_isotp_single_frame(request.application_payload)
                frame = CANFrame.from_ints(
                    request.request_id,
                    isotp_payload,
                    FrameFormat.STANDARD,
                    FrameType.DATA,
                )
                observation = adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                response_ids = observation.response_ids
                response_payloads = observation.response_payloads
                response_count = len(response_payloads)
                responses += response_count

                response_summary = summarize_responses(response_payloads, request.service_id)
                positive_responses += response_summary["positive"]
                negative_responses += response_summary["negative"]
                multi_frame_responses += response_summary["multi_frame"]
                services_seen.add(request.service_name)
                nrcs_seen.update(response_summary["nrcs"])
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
                    service_id=request.service_id,
                    service_name=request.service_name,
                    pid=None,
                    application_payload=request.application_payload.hex(),
                    response_kind=response_summary["kind"],
                )

                writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": case_id,
                        "request_id": f"0x{request.request_id:x}",
                        "request_mode": request.request_mode,
                        "service_id": f"0x{request.service_id:02x}",
                        "service_name": request.service_name,
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
                        "multi_frame_responses": response_summary["multi_frame"],
                        "nrcs": ";".join(response_summary["nrcs"]),
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
        multi_frame_responses=multi_frame_responses,
        services_seen=services_seen,
        nrcs_seen=nrcs_seen,
        coverage=coverage,
    )

    return UDSFuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        positive_responses=positive_responses,
        negative_responses=negative_responses,
        multi_frame_responses=multi_frame_responses,
        unique_services=len(services_seen),
        unique_nrcs=len(nrcs_seen),
        csv_path=csv_path,
        summary_path=summary_path,
    )


def build_coverage_points(request, response_summary: dict[str, object], response_ids: list[int]) -> set[str]:
    points = {
        f"tx_request_id_{request.request_id:x}",
        f"tx_service_{request.service_id:02x}",
        f"tx_mode_{request.request_mode}",
        f"tx_malformed_{int(request.is_malformed)}",
        f"rx_kind_{response_summary['kind']}",
    }
    for response_id in response_ids:
        points.add(f"rx_id_{response_id:x}")
    for nrc in response_summary["nrcs"]:
        points.add(f"nrc_{nrc}")
    return points


def result_fieldnames() -> list[str]:
    return [
        "case_id",
        "timestamp_ms",
        "request_id",
        "request_mode",
        "service_id",
        "service_name",
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
        "multi_frame_responses",
        "nrcs",
        "response_kind",
        "latency_ms",
        "error",
        "coverage_count",
    ]


def write_summary(
    summary_path: Path,
    config: UDSFuzzConfig,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    completed_cases: int,
    interrupted: bool,
    positive_responses: int,
    negative_responses: int,
    multi_frame_responses: int,
    services_seen: set[str],
    nrcs_seen: set[str],
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
        "service_bias": config.service_bias,
        "malformed_rate": config.malformed_rate,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "positive_responses": positive_responses,
        "negative_responses": negative_responses,
        "multi_frame_responses": multi_frame_responses,
        "send_rate": sent / denominator,
        "fault_rate": faults / denominator,
        "response_rate": responses / denominator,
        "unique_services": len(services_seen),
        "unique_nrcs": len(nrcs_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

