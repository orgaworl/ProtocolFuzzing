from __future__ import annotations

import random
from dataclasses import dataclass

from .common import random_bytes
from .dictionary import (
    UDS_COMMUNICATION_SUBFUNCTIONS,
    UDS_DIDS,
    UDS_DTC_SETTING_VALUES,
    UDS_DTC_STATUS_MASKS,
    UDS_ECU_RESET_TYPES,
    UDS_ROUTINE_SUBFUNCTIONS,
    UDS_SECURITY_SUBFUNCTIONS,
    UDS_SESSION_LEVELS,
    UDS_SERVICE_NAMES,
    UDS_SERVICE_POOL,
    UDS_TESTER_PRESENT_SUBFUNCTIONS,
)
from .isotp import decode_isotp_payload


@dataclass(frozen=True)
class UDSRequest:
    request_id: int
    request_mode: str
    service_id: int
    service_name: str
    application_payload: bytes
    is_malformed: bool


def build_request(rng: random.Random, config) -> UDSRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate

    if malformed:
        service_id = rng.choice(UDS_SERVICE_POOL + (rng.randrange(0x00, 0x100),))
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


def choose_request_mode(rng: random.Random, config) -> str:
    if config.request_mode in {"functional", "physical"}:
        return config.request_mode
    return rng.choices(["functional", "physical"], weights=[0.7, 0.3], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config) -> int:
    if request_mode == "functional":
        return config.functional_id
    return rng.randint(config.physical_start, config.physical_end)


def choose_service_id(rng: random.Random, config) -> int:
    if rng.random() < config.service_bias:
        return rng.choice(UDS_SERVICE_POOL)
    return rng.randrange(0x00, 0x100)


def build_service_payload(rng: random.Random, service_id: int) -> bytes:
    if service_id == 0x10:
        return bytes([0x10, rng.choice(UDS_SESSION_LEVELS)])
    if service_id == 0x11:
        return bytes([0x11, rng.choice(UDS_ECU_RESET_TYPES)])
    if service_id == 0x14:
        return bytes([0x14, *random_bytes(rng, 3)])
    if service_id == 0x19:
        return bytes([0x19, rng.choice([0x01, 0x02, 0x04, 0x06, 0x0A]), *random_bytes(rng, 3)])
    if service_id == 0x22:
        dids = [choose_did(rng)]
        if rng.random() < 0.4:
            dids.append(choose_did(rng))
        payload = bytearray([0x22])
        for did in dids:
            payload.extend(did)
        return bytes(payload[:7])
    if service_id == 0x27:
        subfunction = rng.choice(UDS_SECURITY_SUBFUNCTIONS)
        payload = bytearray([0x27, subfunction])
        payload.extend(random_bytes(rng, rng.randint(0, 5)))
        return bytes(payload[:7])
    if service_id == 0x28:
        return bytes([0x28, rng.choice(UDS_COMMUNICATION_SUBFUNCTIONS), rng.choice(UDS_COMMUNICATION_SUBFUNCTIONS)])
    if service_id == 0x2E:
        payload = bytearray([0x2E])
        payload.extend(choose_did(rng))
        payload.extend(random_bytes(rng, rng.randint(0, 4)))
        return bytes(payload[:7])
    if service_id == 0x31:
        payload = bytearray([0x31, rng.choice(UDS_ROUTINE_SUBFUNCTIONS)])
        payload.extend(choose_did(rng))
        payload.extend(random_bytes(rng, rng.randint(0, 3)))
        return bytes(payload[:7])
    if service_id == 0x3E:
        return bytes([0x3E, rng.choice(UDS_TESTER_PRESENT_SUBFUNCTIONS)])
    if service_id == 0x85:
        return bytes([0x85, rng.choice(UDS_DTC_SETTING_VALUES)])

    payload = bytearray([service_id])
    payload.extend(random_bytes(rng, rng.randint(0, 6)))
    return bytes(payload[:7])


def build_malformed_payload(rng: random.Random, service_id: int) -> bytes:
    payload = bytearray([service_id])
    payload.extend(random_bytes(rng, rng.randint(0, 6)))
    if len(payload) > 1 and rng.random() < 0.5:
        payload = payload[: rng.randint(1, len(payload))]
    return bytes(payload[:7])


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


def choose_did(rng: random.Random) -> bytes:
    if rng.random() < 0.85:
        return rng.choice(UDS_DIDS)
    did = rng.randrange(0x0000, 0xFFFF)
    return bytes([(did >> 8) & 0xFF, did & 0xFF])

