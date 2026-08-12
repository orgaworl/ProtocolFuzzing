from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..protocol.dictionary import COMMON_OBD_PIDS, OBD_MODE_NAMES, OBD_MODE_POOL
from ..protocol.isotp import IsoTp, decode_isotp_payload
from scapy.contrib.automotive.obd.obd import OBD
from scapy.contrib.automotive.obd.services import OBD_S01, OBD_S02, OBD_S06, OBD_S08, OBD_S09
from scapy.packet import Raw
from ..runtime.keepalive import KeepaliveConfig
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from .results import build_common_summary, fieldnames_for, write_json_summary
from .runner import open_fuzz_run
from .utils import iter_case_ids, random_bytes, report_progress, should_report_progress


def obd_payload(mode: int, pid: int | None = None) -> bytes:
    packet = OBD(service=mode)
    if pid is None:
        return bytes(packet)
    return bytes(packet / _obd_service_packet(mode, pid))


def raw_obd_payload(mode: int, data: bytes = b'') -> bytes:
    return bytes(OBD(service=mode) / Raw(bytes(data)))


def _obd_service_packet(mode: int, pid: int):
    if mode == 0x01:
        return OBD_S01(pid=pid)
    if mode == 0x02:
        return OBD_S02(pid=pid)
    if mode == 0x06:
        return OBD_S06(mid=pid)
    if mode == 0x08:
        return OBD_S08(tid=pid)
    if mode == 0x09:
        return OBD_S09(iid=pid)
    return Raw(bytes([pid & 0xFF]))


OBD_SUPPORTED_PID_MODES = {0x01, 0x02, 0x05, 0x06, 0x08, 0x09}


@dataclass(frozen=True)
class OBDPidInfo:
    mode: int
    pid: int
    value: bytes
    supports_bits: bytes | None = None


@dataclass(frozen=True)
class OBDNegativeInfo:
    request_mode: int
    nrc: int


@dataclass(frozen=True)
class OBDRequest:
    request_id: int
    request_mode: str
    obd_mode: int
    mode_name: str
    pid: int | None
    application_payload: bytes
    is_malformed: bool


@dataclass(frozen=True)
class OBDResponseFrame:
    frame_kind: str
    payload: bytes
    service_id: int | None = None
    positive: bool = False
    negative: bool = False
    pid_info: OBDPidInfo | None = None
    negative_info: OBDNegativeInfo | None = None


def encode_request_frames(application_payload: bytes, padding_value: int | None = 0x00) -> list[bytes]:
    return IsoTp(padding_value=padding_value).segment_message(application_payload)


def decode_response(raw: bytes, request_mode: int) -> OBDResponseFrame:
    frame_kind, app_payload = decode_isotp_payload(raw)
    if frame_kind != 'single_frame' or not app_payload:
        return OBDResponseFrame(frame_kind=frame_kind, payload=app_payload)
    service = app_payload[0]
    expected_positive = (request_mode + 0x40) & 0xFF
    if service == expected_positive:
        return OBDResponseFrame(
            frame_kind='positive_response',
            payload=app_payload,
            service_id=service,
            positive=True,
            pid_info=decode_positive_info(app_payload, request_mode),
        )
    if service == 0x7F and len(app_payload) >= 3:
        return OBDResponseFrame(
            frame_kind='negative_response',
            payload=app_payload,
            service_id=service,
            negative=True,
            negative_info=OBDNegativeInfo(request_mode=app_payload[1], nrc=app_payload[2]),
        )
    return OBDResponseFrame(frame_kind=f'service_0x{service:02x}', payload=app_payload, service_id=service)


def decode_positive_info(payload: bytes, request_mode: int) -> OBDPidInfo:
    if request_mode in OBD_SUPPORTED_PID_MODES and len(payload) >= 2:
        pid = payload[1]
        value = payload[2:]
        supports_bits = value if pid == 0x00 else None
        return OBDPidInfo(mode=request_mode, pid=pid, value=value, supports_bits=supports_bits)
    return OBDPidInfo(mode=request_mode, pid=payload[1] if len(payload) >= 2 else 0x00, value=payload[2:])


def build_request(rng: random.Random, config) -> OBDRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate
    obd_mode = choose_mode(rng)
    pid = choose_pid(rng, config) if mode_uses_pid(obd_mode) else None

    if malformed:
        payload_length = rng.randint(1, 7)
        payload = raw_obd_payload(obd_mode, random_bytes(rng, payload_length - 1))
    else:
        payload = build_obd_payload(obd_mode, pid)

    return OBDRequest(
        request_id=request_id,
        request_mode=request_mode,
        obd_mode=obd_mode,
        mode_name=OBD_MODE_NAMES.get(obd_mode, f'mode_0x{obd_mode:02x}'),
        pid=pid,
        application_payload=payload,
        is_malformed=malformed,
    )


def choose_request_mode(rng: random.Random, config) -> str:
    if config.request_mode in {'functional', 'physical'}:
        return config.request_mode
    return rng.choices(['functional', 'physical'], weights=[0.8, 0.2], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config) -> int:
    if request_mode == 'functional':
        return config.functional_id
    return rng.randint(config.physical_start, config.physical_end)


def choose_mode(rng: random.Random) -> int:
    if rng.random() < 0.9:
        return rng.choice(OBD_MODE_POOL)
    return rng.randrange(0x01, 0x10)


def choose_pid(rng: random.Random, config) -> int:
    if rng.random() < config.pid_bias:
        return rng.choice(COMMON_OBD_PIDS)
    return rng.randrange(0x00, 0x100)


def mode_uses_pid(obd_mode: int) -> bool:
    return obd_mode in OBD_SUPPORTED_PID_MODES


def build_obd_payload(obd_mode: int, pid: int | None) -> bytes:
    return obd_payload(obd_mode, 0x00 if mode_uses_pid(obd_mode) and pid is None else pid)


def summarize_responses(response_payloads: list[str], request_mode: int) -> dict[str, int | str]:
    positive = 0
    negative = 0
    kind = 'no_response'
    for raw_hex in response_payloads:
        response = decode_response(bytes.fromhex(raw_hex), request_mode)
        if response.positive:
            positive += 1
            kind = response.frame_kind
        elif response.negative:
            negative += 1
            kind = response.frame_kind
        else:
            kind = response.frame_kind
    return {'positive': positive, 'negative': negative, 'kind': kind}

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

    with open_fuzz_run(config, csv_path, fieldnames_for("obd"), progress_callback) as run:

        try:
            for case_id in iter_case_ids(config.cases):
                request = build_request(rng, config)
                isotp_payload = encode_request_frames(request.application_payload)[0]
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
        "unique_modes": len(modes_seen),
        "unique_pids": len(pids_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    })
    write_json_summary(summary_path, summary)
