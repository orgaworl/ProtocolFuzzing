from __future__ import annotations

import random
import time
from dataclasses import dataclass
from pathlib import Path

from ..runtime.keepalive import KeepaliveConfig
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType
from ..runtime.types import ProgressCallback
from .results import build_common_summary, fieldnames_for, write_json_summary
from .runner import open_fuzz_run
from .utils import iter_case_ids, random_bytes, report_progress, should_report_progress

from scapy.contrib.automotive.xcp.xcp import XCPOnCAN, CTORequest, CTOResponse
from scapy.contrib.automotive.xcp.cto_commands_master import (
    Connect,
    Disconnect,
    GetCommModeInfo,
    GetId,
    GetSeed,
    GetStatus,
    SetRequest,
    Synch,
    TransportLayerCmd,
    UserCmd,
)
from scapy.contrib.automotive.xcp.cto_commands_slave import (
    ConnectPositiveResponse,
    GenericResponse,
    NegativeResponse,
    TransportLayerCmdGetSlaveIdResponse,
)
from scapy.packet import Packet, Raw


XCP_COMMAND_SPECS = {
    0xFF: ("connect", Connect, ConnectPositiveResponse),
    0xFE: ("disconnect", Disconnect, GenericResponse),
    0xFD: ("get_status", GetStatus, GenericResponse),
    0xFC: ("synch", Synch, GenericResponse),
    0xFB: ("get_comm_mode_info", GetCommModeInfo, GenericResponse),
    0xFA: ("get_id", GetId, GenericResponse),
    0xF9: ("set_request", SetRequest, GenericResponse),
    0xF8: ("get_seed", GetSeed, GenericResponse),
    0xF7: ("unlock", None, GenericResponse),
    0xF2: ("transport_layer_cmd", TransportLayerCmd, GenericResponse),
    0xF1: ("user_cmd", UserCmd, GenericResponse),
}


@dataclass(frozen=True)
class XCPRequest:
    request_id: int
    request_mode: str
    command_code: int
    command_name: str
    payload: bytes
    is_malformed: bool
    transport_mode: int | None = None


@dataclass(frozen=True)
class XCPResponseFrame:
    frame_kind: str
    payload: bytes
    positive: bool = False
    negative: bool = False
    command_code: int | None = None
    command_name: str | None = None
    error_code: int | None = None


@dataclass(frozen=True)
class XCPFuzzConfig:
    hardware: CANHardwareConfig
    cases: int
    seed: int
    campaign: str
    output_dir: Path
    inter_request_delay_ms: float
    target_ids: tuple[int, ...]
    request_ids: tuple[int, ...]
    request_modes: tuple[str, ...]
    request_mix: float
    malformed_rate: float
    progress_interval: int
    progress_seconds: float
    keepalive: KeepaliveConfig


@dataclass(frozen=True)
class XCPFuzzResult:
    campaign: str
    cases: int
    completed_cases: int
    interrupted: bool
    sent: int
    faults: int
    responses: int
    positive_responses: int
    negative_responses: int
    unique_commands: int
    unique_targets: int
    csv_path: Path
    summary_path: Path


def build_request(rng: random.Random, config: XCPFuzzConfig) -> XCPRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate
    command_code = choose_command_code(rng)
    command_name, request_cls, _ = XCP_COMMAND_SPECS.get(command_code, (f"cmd_0x{command_code:02x}", None, GenericResponse))

    if malformed:
        payload = build_malformed_payload(rng, command_code)
    else:
        payload = build_payload(rng, command_code, request_cls)

    return XCPRequest(
        request_id=request_id,
        request_mode=request_mode,
        command_code=command_code,
        command_name=command_name,
        payload=payload,
        is_malformed=malformed,
        transport_mode=(0x01 if request_mode == "functional" else 0x00) if command_code == 0xF2 else None,
    )


def choose_request_mode(rng: random.Random, config: XCPFuzzConfig) -> str:
    if config.request_modes:
        return rng.choice(config.request_modes)
    if config.request_mix >= 1.0:
        return "physical"
    if config.request_mix <= 0.0:
        return "functional"
    return rng.choices(["functional", "physical"], weights=[1.0 - config.request_mix, config.request_mix], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config: XCPFuzzConfig) -> int:
    if request_mode == "functional" and config.request_ids:
        return rng.choice(config.request_ids)
    if config.target_ids:
        return rng.choice(config.target_ids)
    return 0x700


def choose_command_code(rng: random.Random) -> int:
    return rng.choice(list(XCP_COMMAND_SPECS))


def build_payload(rng: random.Random, command_code: int, request_cls: type[Packet] | None) -> bytes:
    if request_cls is None:
        return bytes(XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / Raw(random_bytes(rng, rng.randint(0, 4))))
    if command_code == 0xFF:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls(connection_mode=rng.choice([0x00, 0x01]))
    elif command_code == 0xFA:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls(identification_type=rng.choice([0x00, 0x01, 0x02, 0x03, 0x04]))
    elif command_code == 0xF9:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls(mode=rng.randrange(0x00, 0xFF), session_configuration_id=rng.randrange(0x0000, 0xFFFF))
    elif command_code == 0xF8:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls(mode=rng.choice([0x00, 0x01]), resource=rng.choice([0x00, 0x01]))
    elif command_code == 0xF2:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls(sub_command_code=rng.choice([0xFF, 0xFE, 0xFD]))
    else:
        packet = XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / request_cls()
    return bytes(packet)


def build_malformed_payload(rng: random.Random, command_code: int) -> bytes:
    return bytes(XCPOnCAN(identifier=0x700) / CTORequest(pid=command_code) / Raw(random_bytes(rng, rng.randint(0, 2))))


def decode_response(raw: bytes, request_code: int) -> XCPResponseFrame:
    packet = XCPOnCAN(raw)
    if CTOResponse not in packet:
        return XCPResponseFrame(frame_kind="unknown", payload=raw)
    response = packet[CTOResponse]
    if NegativeResponse in response:
        return XCPResponseFrame(
            frame_kind="negative_response",
            payload=raw,
            negative=True,
            command_code=request_code,
            command_name=XCP_COMMAND_SPECS.get(request_code, (None, None, None))[0],
            error_code=getattr(response[NegativeResponse], "code", None),
        )
    if ConnectPositiveResponse in response:
        return XCPResponseFrame(frame_kind="connect_positive_response", payload=raw, positive=True, command_code=request_code, command_name="connect")
    if TransportLayerCmdGetSlaveIdResponse in response:
        return XCPResponseFrame(frame_kind="transport_layer_cmd_get_slave_id_response", payload=raw, positive=True, command_code=request_code, command_name="transport_layer_cmd")
    if GenericResponse in response:
        return XCPResponseFrame(frame_kind="generic_response", payload=raw, positive=True, command_code=request_code, command_name=XCP_COMMAND_SPECS.get(request_code, (None, None, None))[0])
    return XCPResponseFrame(frame_kind=response.lastlayer().name.lower(), payload=raw, positive=True, command_code=request_code, command_name=XCP_COMMAND_SPECS.get(request_code, (None, None, None))[0])


def summarize_responses(response_payloads: list[str], request_code: int) -> dict[str, object]:
    positive = 0
    negative = 0
    kind = "no_response"
    for raw_hex in response_payloads:
        response = decode_response(bytes.fromhex(raw_hex), request_code)
        if response.positive:
            positive += 1
        if response.negative:
            negative += 1
        kind = response.frame_kind
    return {"positive": positive, "negative": negative, "kind": kind}


def run_xcp_fuzzing(config: XCPFuzzConfig, progress_callback: ProgressCallback | None = None) -> XCPFuzzResult:
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
    commands_seen: set[str] = set()
    targets_seen: set[str] = set()
    coverage: set[str] = set()
    last_progress = time.monotonic()

    with open_fuzz_run(config, csv_path, fieldnames_for("xcp"), progress_callback) as run:
        try:
            for case_id in iter_case_ids(config.cases):
                request = build_request(rng, config)
                frame = CANFrame.from_ints(request.request_id, request.payload, FrameFormat.STANDARD, FrameType.DATA)
                observation = run.adapter.transact(frame)

                sent += int(observation.sent)
                faults += int(observation.fault)
                response_ids = observation.response_ids
                response_payloads = observation.response_payloads
                response_count = len(response_payloads)
                responses += response_count

                response_summary = summarize_responses(response_payloads, request.command_code)
                positive_responses += int(response_summary["positive"])
                negative_responses += int(response_summary["negative"])
                commands_seen.add(request.command_name)
                targets_seen.add(f"0x{request.request_id:x}")
                coverage.update(build_coverage_points(request, response_summary, response_ids))
                report_progress(
                    progress_callback,
                    event="can_exchange",
                    protocol="xcp",
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
                    response_count=response_count,
                    response_ids=response_ids,
                    response_payloads=response_payloads,
                    latency_ms=observation.latency_ms,
                    error=observation.error,
                    request_mode=request.request_mode,
                    command_code=request.command_code,
                    command_name=request.command_name,
                    payload=request.payload.hex(),
                    response_kind=response_summary["kind"],
                )

                run.writer.writerow(
                    {
                        "case_id": case_id,
                        "timestamp_ms": case_id,
                        "request_id": f"0x{request.request_id:x}",
                        "request_mode": request.request_mode,
                        "command_code": f"0x{request.command_code:02x}",
                        "command_name": request.command_name,
                        "is_malformed": int(request.is_malformed),
                        "payload_hex": request.payload.hex(),
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
        commands_seen=commands_seen,
        targets_seen=targets_seen,
        coverage=coverage,
    )

    return XCPFuzzResult(
        campaign=config.campaign,
        cases=config.cases,
        completed_cases=completed_cases,
        interrupted=interrupted,
        sent=sent,
        faults=faults,
        responses=responses,
        positive_responses=positive_responses,
        negative_responses=negative_responses,
        unique_commands=len(commands_seen),
        unique_targets=len(targets_seen),
        csv_path=csv_path,
        summary_path=summary_path,
    )


def build_coverage_points(request: XCPRequest, response_summary: dict[str, object], response_ids: list[int]) -> set[str]:
    points = {
        f"tx_request_id_{request.request_id:x}",
        f"tx_command_{request.command_code:02x}",
        f"tx_mode_{request.request_mode}",
        f"tx_malformed_{int(request.is_malformed)}",
        f"rx_kind_{response_summary['kind']}",
    }
    for response_id in response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points


def write_summary(
    summary_path: Path,
    config: XCPFuzzConfig,
    csv_path: Path,
    sent: int,
    faults: int,
    responses: int,
    completed_cases: int,
    interrupted: bool,
    positive_responses: int,
    negative_responses: int,
    commands_seen: set[str],
    targets_seen: set[str],
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
        "target_ids": [f"0x{value:x}" for value in config.target_ids],
        "request_ids": [f"0x{value:x}" for value in config.request_ids],
        "request_modes": list(config.request_modes),
        "request_mix": config.request_mix,
        "malformed_rate": config.malformed_rate,
        "sent": sent,
        "faults": faults,
        "responses": responses,
        "positive_responses": positive_responses,
        "negative_responses": negative_responses,
        "unique_commands": len(commands_seen),
        "unique_targets": len(targets_seen),
        "coverage_points": len(coverage),
        "csv_path": str(csv_path),
    })
    write_json_summary(summary_path, summary)
