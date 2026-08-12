from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CAN_CASE_FIELDS = [
    "case_id",
    "timestamp_ms",
    "identifier",
    "frame_format",
    "frame_type",
    "dlc",
    "payload_hex",
    "sent",
    "accepted",
    "fault",
    "state",
    "reason",
    "response_count",
    "response_ids",
    "response_payloads",
    "latency_ms",
    "error",
    "coverage_count",
]

DBC_CASE_FIELDS = [
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

UDS_CASE_FIELDS = [
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

OBD_CASE_FIELDS = [
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

PRIVATE_CASE_FIELDS = [
    "case_id",
    "timestamp_ms",
    "target_id",
    "opcode",
    "strategy",
    "is_malformed",
    "dlc",
    "payload_hex",
    "sent",
    "fault",
    "state",
    "reason",
    "response_count",
    "response_ids",
    "response_payloads",
    "latency_ms",
    "error",
    "coverage_count",
]

CASE_FIELDS_BY_PROTOCOL = {
    "can": CAN_CASE_FIELDS,
    "dbc": DBC_CASE_FIELDS,
    "uds": UDS_CASE_FIELDS,
    "obd": OBD_CASE_FIELDS,
    "private": PRIVATE_CASE_FIELDS,
}


def fieldnames_for(protocol: str) -> list[str]:
    return list(CASE_FIELDS_BY_PROTOCOL[protocol])


def write_json_summary(path: Path, summary: dict[str, Any]) -> None:
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
