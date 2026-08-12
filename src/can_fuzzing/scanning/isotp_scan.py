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


@dataclass(frozen=True)
class IsoTpNode:
    request_id: int
    response_id: int
    response_payload: str
    frame_format: str
    addressing: str


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
    write_nodes_csv(nodes_csv_path, nodes)
    summary = build_summary(config, nodes, nodes_csv_path, interrupted)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if progress_callback is not None:
        progress_callback({"phase": "isotp_scan", "nodes": len(nodes), "interrupted": interrupted})
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


def build_summary(config: IsoTpScanConfig, nodes: list[IsoTpNode], nodes_csv_path: Path, interrupted: bool) -> dict[str, Any]:
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
        "nodes_csv_path": str(nodes_csv_path),
    }
