from __future__ import annotations

import random
from dataclasses import dataclass

from ..fuzzing.utils import random_bytes
from .dictionary import COMMON_OBD_PIDS, OBD_MODE_NAMES, OBD_MODE_POOL
from .isotp import IsoTp, decode_isotp_payload, encode_isotp_single_frame


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


@dataclass(frozen=True)
class OBDResponseSummary:
    positive: int
    negative: int
    kind: str


class OBDProtocol:
    def __init__(self, padding_value: int | None = 0x00) -> None:
        self._isotp = IsoTp(padding_value=padding_value)

    def encode_request_frames(self, application_payload: bytes) -> list[bytes]:
        return self._isotp.segment_message(application_payload)

    def decode_response(self, raw: bytes, request_mode: int) -> OBDResponseFrame:
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

    def summarize_responses(self, response_payloads: list[str], request_mode: int) -> OBDResponseSummary:
        positive = 0
        negative = 0
        kind = 'no_response'
        for raw_hex in response_payloads:
            response = self.decode_response(bytes.fromhex(raw_hex), request_mode)
            if response.positive:
                positive += 1
                kind = response.frame_kind
            elif response.negative:
                negative += 1
                kind = response.frame_kind
            else:
                kind = response.frame_kind
        return OBDResponseSummary(positive=positive, negative=negative, kind=kind)


_OBD_PROTOCOL = OBDProtocol()


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
        payload = bytes([obd_mode, *random_bytes(rng, payload_length - 1)])
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
    if mode_uses_pid(obd_mode):
        return bytes([obd_mode, 0x00 if pid is None else pid])
    return bytes([obd_mode])


def summarize_responses(response_payloads: list[str], request_mode: int) -> dict[str, int | str]:
    summary = _OBD_PROTOCOL.summarize_responses(response_payloads, request_mode)
    return {'positive': summary.positive, 'negative': summary.negative, 'kind': summary.kind}
