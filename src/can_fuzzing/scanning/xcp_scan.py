from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.contrib.automotive.xcp.xcp import XCPOnCAN, CTORequest, CTOResponse
from scapy.contrib.automotive.xcp.cto_commands_master import Connect
from scapy.contrib.automotive.xcp.cto_commands_slave import ConnectPositiveResponse, NegativeResponse
from scapy.packet import Raw

from ..runtime.adapters import CANHardwareAdapter
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType


XCP_ERROR_CODES = {
    0x00: "ERR_CMD_SYNCH",
    0x10: "ERR_CMD_BUSY",
    0x11: "ERR_DAQ_ACTIVE",
    0x12: "ERR_PGM_ACTIVE",
    0x20: "ERR_CMD_UNKNOWN",
    0x21: "ERR_CMD_SYNTAX",
    0x22: "ERR_OUT_OF_RANGE",
    0x23: "ERR_WRITE_PROTECTED",
    0x24: "ERR_ACCESS_DENIED",
    0x25: "ERR_ACCESS_LOCKED",
    0x26: "ERR_PAGE_NOT_VALID",
    0x27: "ERR_MODE_NOT_VALID",
    0x28: "ERR_SEGMENT_NOT_VALID",
    0x29: "ERR_SEQUENCE",
    0x2A: "ERR_DAQ_CONFIG",
    0x30: "ERR_MEMORY_OVERFLOW",
    0x31: "ERR_GENERIC",
    0x32: "ERR_VERIFY",
}


@dataclass(frozen=True)
class XCPScanConfig:
    hardware: CANHardwareConfig
    output_dir: Path
    campaign: str
    request_id_start: int
    request_id_end: int
    response_timeout: float
    inter_probe_delay_ms: float
    extended_can_id: bool


@dataclass(frozen=True)
class XCPNode:
    request_id: int
    response_id: int
    response_kind: str
    response_payload: str
    error_code: int | None
    error_name: str
    resource_protection: int | None
    comm_mode_basic: int | None
    max_cto: int | None
    max_dto: int | None
    protocol_version: int | None
    transport_version: int | None


def run_xcp_scan(config: XCPScanConfig, progress_callback=None) -> dict[str, Any]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = config.output_dir / f"{config.campaign}_summary.json"
    nodes_csv_path = config.output_dir / f"{config.campaign}_nodes.csv"
    nodes: list[XCPNode] = []
    interrupted = False

    with CANHardwareAdapter(config.hardware) as adapter:
        adapter.drain_pending()
        try:
            for index, request_id in enumerate(range(config.request_id_start, config.request_id_end + 1), start=1):
                frame = build_connect_frame(request_id, config.extended_can_id)
                sent_at = time.monotonic()
                adapter.send_frame(frame, is_fd=config.hardware.fd)
                responses = collect_responses(adapter, config.response_timeout, request_id)
                for response in responses:
                    node = classify_xcp_response(request_id, int(response.arbitration_id), bytes(response.data))
                    if node is not None:
                        nodes.append(node)
                if progress_callback is not None:
                    progress_callback({
                        "event": "can_exchange",
                        "protocol": "xcp_scan",
                        "probe_index": index,
                        "total_probes": config.request_id_end - config.request_id_start + 1,
                        "tx_id": frame.identifier,
                        "tx_payload": frame.to_hex_payload(),
                        "tx_dlc": frame.dlc,
                        "tx_format": frame.frame_format.value,
                        "tx_type": frame.frame_type.value,
                        "fd": config.hardware.fd,
                        "sent": True,
                        "fault": False,
                        "state": "response" if responses else "no_response",
                        "reason": "response_received" if responses else "no_response",
                        "response_count": len(responses),
                        "response_ids": [int(msg.arbitration_id) for msg in responses],
                        "response_payloads": [bytes(msg.data).hex() for msg in responses],
                        "latency_ms": (time.monotonic() - sent_at) * 1000.0,
                        "error": "",
                    })
                delay = config.inter_probe_delay_ms / 1000.0
                if delay > 0:
                    time.sleep(delay)
        except KeyboardInterrupt:
            interrupted = True

    nodes = dedupe_nodes(nodes)
    write_nodes_csv(nodes_csv_path, nodes)
    summary = build_summary(config, nodes, nodes_csv_path, interrupted)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def build_connect_frame(request_id: int, extended_can_id: bool) -> CANFrame:
    packet = XCPOnCAN(identifier=request_id) / CTORequest(pid=0xFF) / Connect(connection_mode=0x00)
    return CANFrame(
        identifier=request_id,
        data=bytes(packet.payload),
        frame_format=FrameFormat.EXTENDED if extended_can_id else FrameFormat.STANDARD,
        frame_type=FrameType.DATA,
    )


def collect_responses(adapter: CANHardwareAdapter, timeout: float, request_id: int):
    responses = []
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        msg = adapter.receive_message(timeout=max(0.0, deadline - time.monotonic()))
        if msg is None:
            break
        if int(getattr(msg, "arbitration_id", -1)) == request_id:
            continue
        data = bytes(getattr(msg, "data", b""))
        if is_xcp_like_response(data):
            responses.append(msg)
    return responses


def is_xcp_like_response(data: bytes) -> bool:
    return (len(data) > 1 and data[0] == 0xFF and any(data[1:])) or (len(data) > 0 and data[0] == 0xFE)


def classify_xcp_response(request_id: int, response_id: int, raw: bytes) -> XCPNode | None:
    if not is_xcp_like_response(raw):
        return None
    kind = "positive_connect" if raw[0] == 0xFF else "negative_response"
    error_code = raw[1] if raw[0] == 0xFE and len(raw) > 1 else None
    parsed = parse_connect_response(raw) if raw[0] == 0xFF else {}
    return XCPNode(
        request_id=request_id,
        response_id=response_id,
        response_kind=kind,
        response_payload=raw.hex(),
        error_code=error_code,
        error_name=XCP_ERROR_CODES.get(error_code, "") if error_code is not None else "",
        resource_protection=parsed.get("resource_protection"),
        comm_mode_basic=parsed.get("comm_mode_basic"),
        max_cto=parsed.get("max_cto"),
        max_dto=parsed.get("max_dto"),
        protocol_version=parsed.get("protocol_version"),
        transport_version=parsed.get("transport_version"),
    )


def parse_connect_response(raw: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        packet = XCPOnCAN(identifier=0) / CTOResponse() / ConnectPositiveResponse(raw[1:])
        response = packet[ConnectPositiveResponse]
        result["resource_protection"] = int(getattr(response, "resource", raw[1] if len(raw) > 1 else 0))
        result["comm_mode_basic"] = int(getattr(response, "comm_mode_basic", raw[2] if len(raw) > 2 else 0))
        result["max_cto"] = int(getattr(response, "max_cto", raw[3] if len(raw) > 3 else 0))
        result["max_dto"] = int(getattr(response, "max_dto", raw[4] if len(raw) > 4 else 0))
        result["protocol_version"] = int(getattr(response, "xcp_protocol_layer_version_number_msb", raw[6] if len(raw) > 6 else 0))
        result["transport_version"] = int(getattr(response, "xcp_transport_layer_version_number_msb", raw[7] if len(raw) > 7 else 0))
    except Exception:
        if len(raw) > 1:
            result["resource_protection"] = raw[1]
        if len(raw) > 2:
            result["comm_mode_basic"] = raw[2]
        if len(raw) > 3:
            result["max_cto"] = raw[3]
        if len(raw) > 4:
            result["max_dto"] = raw[4]
        if len(raw) > 6:
            result["protocol_version"] = raw[6]
        if len(raw) > 7:
            result["transport_version"] = raw[7]
    return result


def dedupe_nodes(nodes: list[XCPNode]) -> list[XCPNode]:
    deduped: dict[tuple[int, int, str], XCPNode] = {}
    for node in nodes:
        deduped.setdefault((node.request_id, node.response_id, node.response_kind), node)
    return [deduped[key] for key in sorted(deduped)]


def write_nodes_csv(path: Path, nodes: list[XCPNode]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "request_id",
                "response_id",
                "response_kind",
                "response_payload",
                "error_code",
                "error_name",
                "resource_protection",
                "comm_mode_basic",
                "max_cto",
                "max_dto",
                "protocol_version",
                "transport_version",
            ],
        )
        writer.writeheader()
        for node in nodes:
            writer.writerow(
                {
                    "request_id": f"0x{node.request_id:x}",
                    "response_id": f"0x{node.response_id:x}",
                    "response_kind": node.response_kind,
                    "response_payload": node.response_payload,
                    "error_code": "" if node.error_code is None else f"0x{node.error_code:02x}",
                    "error_name": node.error_name,
                    "resource_protection": "" if node.resource_protection is None else f"0x{node.resource_protection:02x}",
                    "comm_mode_basic": "" if node.comm_mode_basic is None else f"0x{node.comm_mode_basic:02x}",
                    "max_cto": "" if node.max_cto is None else node.max_cto,
                    "max_dto": "" if node.max_dto is None else node.max_dto,
                    "protocol_version": "" if node.protocol_version is None else f"0x{node.protocol_version:02x}",
                    "transport_version": "" if node.transport_version is None else f"0x{node.transport_version:02x}",
                }
            )


def build_summary(config: XCPScanConfig, nodes: list[XCPNode], nodes_csv_path: Path, interrupted: bool) -> dict[str, Any]:
    return {
        "campaign": config.campaign,
        "status": "interrupted" if interrupted else "completed",
        "interrupted": interrupted,
        "interface": config.hardware.interface,
        "channel": config.hardware.channel,
        "bitrate": config.hardware.bitrate,
        "fd": config.hardware.fd,
        "request_id_start": f"0x{config.request_id_start:x}",
        "request_id_end": f"0x{config.request_id_end:x}",
        "response_timeout": config.response_timeout,
        "inter_probe_delay_ms": config.inter_probe_delay_ms,
        "extended_can_id": config.extended_can_id,
        "node_count": len(nodes),
        "positive_nodes": sum(1 for node in nodes if node.response_kind == "positive_connect"),
        "negative_nodes": sum(1 for node in nodes if node.response_kind == "negative_response"),
        "nodes": [
            {
                "request_id": f"0x{node.request_id:x}",
                "response_id": f"0x{node.response_id:x}",
                "response_kind": node.response_kind,
                "response_payload": node.response_payload,
                "error_code": "" if node.error_code is None else f"0x{node.error_code:02x}",
                "error_name": node.error_name,
                "resource_protection": "" if node.resource_protection is None else f"0x{node.resource_protection:02x}",
                "comm_mode_basic": "" if node.comm_mode_basic is None else f"0x{node.comm_mode_basic:02x}",
                "max_cto": node.max_cto,
                "max_dto": node.max_dto,
                "protocol_version": "" if node.protocol_version is None else f"0x{node.protocol_version:02x}",
                "transport_version": "" if node.transport_version is None else f"0x{node.transport_version:02x}",
            }
            for node in nodes
        ],
        "nodes_csv_path": str(nodes_csv_path),
    }
