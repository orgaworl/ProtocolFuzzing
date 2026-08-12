from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any

from scapy.contrib.isotp.isotp_scanner import scan as scapy_isotp_scan
from scapy.layers.can import CAN, CANFD
from scapy.packet import Packet

from ..runtime.adapters import CANHardwareAdapter
from ..protocol.isotp import decode_isotp_payload, encode_isotp_single_frame
from ..runtime.models import CANFrame, CANHardwareConfig, FrameFormat, FrameType


@dataclass(frozen=True)
class IsoTpScanConfig:
    hardware: CANHardwareConfig
    output_dir: Path
    campaign: str
    request_id_start: int
    request_id_end: int
    sniff_time: float
    verify_results: bool
    extended_can_id: bool
    protocol_probe: bool = True
    protocol_probe_timeout: float = 0.2


@dataclass(frozen=True)
class IsoTpNode:
    request_id: int
    response_id: int
    response_payload: str
    frame_format: str
    addressing: str


@dataclass(frozen=True)
class ProtocolProbeResult:
    request_id: int
    response_id: int
    uds: bool
    obd: bool
    evidence: str
    response_payloads: tuple[str, ...]


class AdapterScapyCANSocket:
    def __init__(self, adapter: CANHardwareAdapter, fd: bool = False) -> None:
        self.adapter = adapter
        self.fd = fd

    def send(self, packet: Packet) -> None:
        frame = scapy_packet_to_can_frame(packet)
        self.adapter.send_frame(frame, is_fd=self.fd)

    def sniff(self, prn=None, timeout: float | None = None, store: bool = True, started_callback=None):
        if started_callback is not None:
            started_callback()
        packets = []
        deadline = time.monotonic() + max(0.0, float(timeout or 0.0))
        while time.monotonic() < deadline:
            msg = self.adapter.receive_message(timeout=max(0.0, deadline - time.monotonic()))
            if msg is None:
                break
            packet = can_message_to_scapy_packet(msg)
            if prn is not None:
                prn(packet)
            if store:
                packets.append(packet)
        return packets

    def close(self) -> None:
        return None


def scapy_packet_to_can_frame(packet: Packet) -> CANFrame:
    identifier = int(getattr(packet, "identifier", 0))
    flags = getattr(packet, "flags", "")
    extended = "extended" in str(flags)
    data = bytes(packet.payload)
    return CANFrame(
        identifier=identifier,
        data=data,
        frame_format=FrameFormat.EXTENDED if extended else FrameFormat.STANDARD,
        frame_type=FrameType.DATA,
    )


def can_message_to_scapy_packet(msg) -> Packet:
    cls = CANFD if bool(getattr(msg, "is_fd", False)) else CAN
    flags = "extended" if bool(getattr(msg, "is_extended_id", False)) else 0
    return cls(identifier=int(msg.arbitration_id), flags=flags, data=bytes(msg.data))


def run_isotp_scan(config: IsoTpScanConfig, progress_callback=None) -> dict[str, Any]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = config.output_dir / f"{config.campaign}_summary.json"
    nodes_csv_path = config.output_dir / f"{config.campaign}_nodes.csv"
    interrupted = False
    found: dict[int, tuple[Packet, int]] = {}
    stop_event = Event()
    scan_range = range(config.request_id_start, config.request_id_end + 1)

    with CANHardwareAdapter(config.hardware) as adapter:
        adapter.drain_pending()
        socket = AdapterScapyCANSocket(adapter, fd=config.hardware.fd)
        try:
            found = scapy_isotp_scan(
                socket,
                scan_range=scan_range,
                sniff_time=config.sniff_time,
                extended_can_id=config.extended_can_id,
                verify_results=config.verify_results,
                stop_event=stop_event,
                fd=config.hardware.fd,
            )
        except KeyboardInterrupt:
            interrupted = True
            stop_event.set()

    nodes = build_nodes(found, config.extended_can_id)
    probe_results: list[ProtocolProbeResult] = []
    protocol_csv_path = config.output_dir / f"{config.campaign}_protocols.csv"
    if config.protocol_probe and nodes and not interrupted:
        with CANHardwareAdapter(config.hardware) as adapter:
            adapter.drain_pending()
            probe_results = probe_protocols(adapter, nodes, config)

    write_nodes_csv(nodes_csv_path, nodes)
    write_protocol_csv(protocol_csv_path, probe_results)
    summary = build_summary(config, nodes, probe_results, nodes_csv_path, protocol_csv_path, interrupted)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if progress_callback is not None:
        progress_callback({"phase": "isotp_scan", "nodes": len(nodes), "protocol_probe_results": len(probe_results), "interrupted": interrupted})
    return summary


def build_nodes(found: dict[int, tuple[Packet, int]], extended_can_id: bool) -> list[IsoTpNode]:
    nodes: list[IsoTpNode] = []
    for request_id, (packet, response_id) in sorted(found.items()):
        nodes.append(
            IsoTpNode(
                request_id=int(request_id),
                response_id=int(response_id),
                response_payload=bytes(packet.payload).hex(),
                frame_format="extended" if extended_can_id else "standard",
                addressing="normal",
            )
        )
    return nodes


def probe_protocols(adapter: CANHardwareAdapter, nodes: list[IsoTpNode], config: IsoTpScanConfig) -> list[ProtocolProbeResult]:
    results: list[ProtocolProbeResult] = []
    for node in nodes:
        responses: list[bytes] = []
        uds = False
        obd = False
        evidence: list[str] = []
        for name, payload in protocol_probe_payloads():
            frame = CANFrame(
                identifier=node.request_id,
                data=encode_isotp_single_frame(payload),
                frame_format=FrameFormat.EXTENDED if config.extended_can_id else FrameFormat.STANDARD,
                frame_type=FrameType.DATA,
            )
            adapter.send_frame(frame, is_fd=config.hardware.fd)
            for response in collect_node_responses(adapter, node.response_id, config.protocol_probe_timeout):
                raw = bytes(response.data)
                responses.append(raw)
                frame_kind, application_payload = decode_isotp_payload(raw)
                if frame_kind != "single_frame" or not application_payload:
                    continue
                detected = classify_protocol_response(name, application_payload)
                if detected == "uds":
                    uds = True
                    evidence.append(f"uds:{application_payload.hex()}")
                elif detected == "obd":
                    obd = True
                    evidence.append(f"obd:{application_payload.hex()}")
        results.append(
            ProtocolProbeResult(
                request_id=node.request_id,
                response_id=node.response_id,
                uds=uds,
                obd=obd,
                evidence=";".join(dict.fromkeys(evidence)),
                response_payloads=tuple(dict.fromkeys(raw.hex() for raw in responses)),
            )
        )
    return results


def protocol_probe_payloads() -> list[tuple[str, bytes]]:
    return [
        ("uds_tester_present", bytes([0x3E, 0x00])),
        ("uds_default_session", bytes([0x10, 0x01])),
        ("obd_supported_pids", bytes([0x01, 0x00])),
        ("obd_vehicle_info", bytes([0x09, 0x00])),
    ]


def collect_node_responses(adapter: CANHardwareAdapter, response_id: int, timeout: float):
    responses = []
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        msg = adapter.receive_message(timeout=max(0.0, deadline - time.monotonic()))
        if msg is None:
            break
        if int(getattr(msg, "arbitration_id", -1)) == response_id:
            responses.append(msg)
    return responses


def classify_protocol_response(probe_name: str, payload: bytes) -> str | None:
    service = payload[0]
    if probe_name.startswith("uds"):
        if service in {0x50, 0x7E} or (service == 0x7F and len(payload) >= 2 and payload[1] in {0x10, 0x3E}):
            return "uds"
    if probe_name.startswith("obd"):
        if service in {0x41, 0x49} or (service == 0x7F and len(payload) >= 2 and payload[1] in {0x01, 0x09}):
            return "obd"
    return None


def write_nodes_csv(path: Path, nodes: list[IsoTpNode]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["request_id", "response_id", "response_payload", "frame_format", "addressing"])
        writer.writeheader()
        for node in nodes:
            writer.writerow(
                {
                    "request_id": f"0x{node.request_id:x}",
                    "response_id": f"0x{node.response_id:x}",
                    "response_payload": node.response_payload,
                    "frame_format": node.frame_format,
                    "addressing": node.addressing,
                }
            )


def write_protocol_csv(path: Path, rows: list[ProtocolProbeResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["request_id", "response_id", "uds", "obd", "evidence", "response_payloads"])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "request_id": f"0x{row.request_id:x}",
                    "response_id": f"0x{row.response_id:x}",
                    "uds": int(row.uds),
                    "obd": int(row.obd),
                    "evidence": row.evidence,
                    "response_payloads": ";".join(row.response_payloads),
                }
            )


def build_summary(config: IsoTpScanConfig, nodes: list[IsoTpNode], probe_results: list[ProtocolProbeResult], nodes_csv_path: Path, protocol_csv_path: Path, interrupted: bool) -> dict[str, Any]:
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
        "sniff_time": config.sniff_time,
        "verify_results": config.verify_results,
        "extended_can_id": config.extended_can_id,
        "node_count": len(nodes),
        "protocol_probe_enabled": config.protocol_probe,
        "protocol_probe_timeout": config.protocol_probe_timeout,
        "uds_node_count": sum(1 for item in probe_results if item.uds),
        "obd_node_count": sum(1 for item in probe_results if item.obd),
        "nodes": [
            {
                "request_id": f"0x{node.request_id:x}",
                "response_id": f"0x{node.response_id:x}",
                "response_payload": node.response_payload,
                "frame_format": node.frame_format,
                "addressing": node.addressing,
            }
            for node in nodes
        ],
        "protocols": [
            {
                "request_id": f"0x{item.request_id:x}",
                "response_id": f"0x{item.response_id:x}",
                "uds": item.uds,
                "obd": item.obd,
                "evidence": item.evidence,
                "response_payloads": ";".join(item.response_payloads),
            }
            for item in probe_results
        ],
        "nodes_csv_path": str(nodes_csv_path),
        "protocols_csv_path": str(protocol_csv_path),
    }
