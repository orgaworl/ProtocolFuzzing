from __future__ import annotations

import csv
import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .adapters import CANHardwareAdapter
from .models import CANFrame, FrameFormat, FrameType


UDS_SERVICE_NAMES = {
    0x10: "diagnostic_session_control",
    0x11: "ecu_reset",
    0x14: "clear_diagnostic_information",
    0x19: "read_dtc_information",
    0x22: "read_data_by_identifier",
    0x27: "security_access",
    0x28: "communication_control",
    0x2E: "write_data_by_identifier",
    0x31: "routine_control",
    0x3E: "tester_present",
    0x85: "control_dtc_setting",
}

UDS_SERVICE_POOL = [
    0x10,
    0x11,
    0x14,
    0x19,
    0x22,
    0x27,
    0x28,
    0x2E,
    0x31,
    0x3E,
    0x85,
]


@dataclass(frozen=True)
class UDSFuzzConfig:
    cases: int = 1000
    seed: int = 2024
    campaign: str = "uds_baseline"
    output_dir: Path = Path("result")
    interface: str = "socketcan"
    channel: str = "can0"
    bitrate: int | None = 500000
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


@dataclass(frozen=True)
class UDSRequest:
    request_id: int
    request_mode: str
    service_id: int
    service_name: str
    application_payload: bytes
    is_malformed: bool


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
    ) as adapter, csv_path.open("w", newline="", encoding="utf-8") as fh:
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
                responses += observation.response_count

                response_summary = summarize_responses(observation.response_payloads, request.service_id)
                positive_responses += response_summary["positive"]
                negative_responses += response_summary["negative"]
                multi_frame_responses += response_summary["multi_frame"]
                services_seen.add(request.service_name)
                nrcs_seen.update(response_summary["nrcs"])
                coverage.update(build_coverage_points(request, response_summary, observation))

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
                        "response_count": observation.response_count,
                        "response_ids": ";".join(f"0x{value:x}" for value in observation.response_ids),
                        "response_payloads": ";".join(observation.response_payloads),
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
                        config=config,
                        completed_cases=completed_cases,
                        sent=sent,
                        faults=faults,
                        responses=responses,
                        positive_responses=positive_responses,
                        negative_responses=negative_responses,
                        coverage_points=len(coverage),
                        interrupted=False,
                    )

                if config.inter_request_delay_ms > 0:
                    sleep_seconds(config.inter_request_delay_ms / 1000.0)
        except KeyboardInterrupt:
            interrupted = True
            fh.flush()
            report_progress(
                progress_callback,
                config=config,
                completed_cases=completed_cases,
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


def build_request(rng: random.Random, config: UDSFuzzConfig) -> UDSRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate

    if malformed:
        service_id = rng.choice(UDS_SERVICE_POOL + [rng.randrange(0x00, 0x100)])
        payload = build_malformed_payload(rng, service_id)
        return UDSRequest(
            request_id=request_id,
            request_mode=request_mode,
            service_id=service_id,
            service_name=UDS_SERVICE_NAMES.get(service_id, "malformed"),
            application_payload=payload,
            is_malformed=True,
        )

    service_id = choose_service_id(rng, config)
    payload = build_service_payload(rng, service_id)
    return UDSRequest(
        request_id=request_id,
        request_mode=request_mode,
        service_id=service_id,
        service_name=UDS_SERVICE_NAMES.get(service_id, f"service_0x{service_id:02x}"),
        application_payload=payload,
        is_malformed=False,
    )


def choose_request_mode(rng: random.Random, config: UDSFuzzConfig) -> str:
    if config.request_mode in {"functional", "physical"}:
        return config.request_mode
    return rng.choices(["functional", "physical"], weights=[0.7, 0.3], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config: UDSFuzzConfig) -> int:
    if request_mode == "functional":
        return config.functional_id
    return rng.randint(config.physical_start, config.physical_end)


def choose_service_id(rng: random.Random, config: UDSFuzzConfig) -> int:
    if rng.random() < config.service_bias:
        return rng.choice(UDS_SERVICE_POOL)
    return rng.randrange(0x00, 0x100)


def build_service_payload(rng: random.Random, service_id: int) -> bytes:
    if service_id == 0x10:
        return bytes([0x10, rng.choice([0x01, 0x02, 0x03, 0x04])])
    if service_id == 0x11:
        return bytes([0x11, rng.choice([0x01, 0x02, 0x03, 0x04, 0x05])])
    if service_id == 0x14:
        return bytes([0x14, *random_bytes(rng, 3)])
    if service_id == 0x19:
        return bytes([0x19, rng.choice([0x01, 0x02, 0x04, 0x06, 0x0A]), *random_bytes(rng, 3)])
    if service_id == 0x22:
        dids = [random_did(rng)]
        if rng.random() < 0.4:
            dids.append(random_did(rng))
        payload = bytearray([0x22])
        for did in dids:
            payload.extend(did)
        return bytes(payload[:7])
    if service_id == 0x27:
        subfunction = rng.choice([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        payload = bytearray([0x27, subfunction])
        payload.extend(random_bytes(rng, rng.randint(0, 5)))
        return bytes(payload[:7])
    if service_id == 0x28:
        return bytes([0x28, rng.choice([0x00, 0x01, 0x02, 0x03]), rng.choice([0x00, 0x01, 0x02, 0x03])])
    if service_id == 0x2E:
        payload = bytearray([0x2E])
        payload.extend(random_did(rng))
        payload.extend(random_bytes(rng, rng.randint(0, 4)))
        return bytes(payload[:7])
    if service_id == 0x31:
        payload = bytearray([0x31, rng.choice([0x01, 0x02, 0x03])])
        payload.extend(random_did(rng))
        payload.extend(random_bytes(rng, rng.randint(0, 3)))
        return bytes(payload[:7])
    if service_id == 0x3E:
        return bytes([0x3E, rng.choice([0x00, 0x80])])
    if service_id == 0x85:
        return bytes([0x85, rng.choice([0x00, 0x01, 0x02])])

    payload = bytearray([service_id])
    payload.extend(random_bytes(rng, rng.randint(0, 6)))
    return bytes(payload[:7])


def build_malformed_payload(rng: random.Random, service_id: int) -> bytes:
    payload = bytearray([service_id])
    payload.extend(random_bytes(rng, rng.randint(0, 6)))
    if len(payload) > 1 and rng.random() < 0.5:
        payload = payload[: rng.randint(1, len(payload))]
    return bytes(payload[:7])


def encode_isotp_single_frame(application_payload: bytes) -> bytes:
    if len(application_payload) > 7:
        raise ValueError("UDS request payload exceeds classic CAN ISO-TP single-frame capacity")
    frame = bytearray([len(application_payload) & 0x0F])
    frame.extend(application_payload)
    while len(frame) < 8:
        frame.append(0x00)
    return bytes(frame)


def summarize_responses(response_payloads: list[str], request_service: int) -> dict[str, object]:
    positive = 0
    negative = 0
    multi_frame = 0
    nrcs: list[str] = []
    kind = "no_response"

    for raw_hex in response_payloads:
        raw = bytes.fromhex(raw_hex)
        frame_kind, app_payload = decode_isotp_payload(raw)
        if frame_kind == "single_frame" and app_payload:
            kind = "single_frame"
            service_id = app_payload[0]
            if service_id == 0x7F and len(app_payload) >= 3:
                negative += 1
                nrc = app_payload[2]
                nrcs.append(f"0x{nrc:02x}")
                kind = "negative_response"
            elif service_id == ((request_service + 0x40) & 0xFF):
                positive += 1
                kind = "positive_response"
            else:
                kind = f"service_0x{service_id:02x}"
        elif frame_kind in {"first_frame", "consecutive_frame"}:
            multi_frame += 1
            kind = frame_kind
        elif frame_kind == "flow_control":
            kind = frame_kind
        else:
            kind = frame_kind

    return {
        "positive": positive,
        "negative": negative,
        "multi_frame": multi_frame,
        "nrcs": nrcs,
        "kind": kind,
    }


def decode_isotp_payload(raw: bytes) -> tuple[str, bytes]:
    if not raw:
        return "empty", b""
    pci_type = raw[0] >> 4
    if pci_type == 0:
        length = raw[0] & 0x0F
        return "single_frame", raw[1 : 1 + length]
    if pci_type == 1:
        return "first_frame", raw[2:]
    if pci_type == 2:
        return "consecutive_frame", raw[1:]
    if pci_type == 3:
        return "flow_control", raw[1:]
    return "unknown", raw


def build_coverage_points(request: UDSRequest, response_summary: dict[str, object], observation) -> set[str]:
    points = {
        f"tx_request_id_{request.request_id:x}",
        f"tx_service_{request.service_id:02x}",
        f"tx_mode_{request.request_mode}",
        f"tx_malformed_{int(request.is_malformed)}",
        f"rx_kind_{response_summary['kind']}",
    }
    for response_id in observation.response_ids:
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


def should_report_progress(config: UDSFuzzConfig, completed_cases: int, now: float, last_progress: float) -> bool:
    if completed_cases <= 0:
        return False
    if config.progress_interval > 0 and completed_cases % config.progress_interval == 0:
        return True
    if config.progress_seconds > 0 and now - last_progress >= config.progress_seconds:
        return True
    if completed_cases == config.cases:
        return True
    return False


def report_progress(
    progress_callback: Callable[[dict], None] | None,
    config: UDSFuzzConfig,
    completed_cases: int,
    sent: int,
    faults: int,
    responses: int,
    positive_responses: int,
    negative_responses: int,
    coverage_points: int,
    interrupted: bool,
) -> None:
    if progress_callback is None:
        return
    progress_callback(
        {
            "campaign": config.campaign,
            "completed_cases": completed_cases,
            "requested_cases": config.cases,
            "sent": sent,
            "faults": faults,
            "responses": responses,
            "positive_responses": positive_responses,
            "negative_responses": negative_responses,
            "coverage_points": coverage_points,
            "interrupted": interrupted,
        }
    )


def random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))


def random_did(rng: random.Random) -> bytes:
    did = rng.randrange(0x0000, 0xFFFF)
    return bytes([(did >> 8) & 0xFF, did & 0xFF])


def sleep_seconds(seconds: float) -> None:
    time.sleep(seconds)
