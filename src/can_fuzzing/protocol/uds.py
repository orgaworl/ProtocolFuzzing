from __future__ import annotations

import random
from dataclasses import dataclass

from ..fuzzing.utils import random_bytes
from .dictionary import (
    UDS_COMMUNICATION_SUBFUNCTIONS,
    UDS_DIDS,
    UDS_DTC_SETTING_VALUES,
    UDS_ECU_RESET_TYPES,
    UDS_ROUTINE_SUBFUNCTIONS,
    UDS_SECURITY_SUBFUNCTIONS,
    UDS_SESSION_LEVELS,
    UDS_SERVICE_NAMES,
    UDS_SERVICE_POOL,
    UDS_TESTER_PRESENT_SUBFUNCTIONS,
)
from .isotp import IsoTp, decode_isotp_payload
from scapy.contrib.automotive.uds import UDS, UDS_CC, UDS_CDTCS, UDS_DSC, UDS_ER, UDS_RC, UDS_RDBI, UDS_RDTCI, UDS_SA, UDS_TP, UDS_WDBI
from scapy.packet import Raw


def uds_payload(service_id: int, *values: int | bytes) -> bytes:
    return bytes(UDS() / _uds_service_packet(service_id, *values))


def raw_uds_payload(service_id: int, data: bytes = b'') -> bytes:
    return bytes(UDS(service=service_id) / Raw(bytes(data)))


def _uds_service_packet(service_id: int, *values: int | bytes):
    if service_id == 0x10:
        return UDS_DSC(diagnosticSessionType=_value(values, 0))
    if service_id == 0x11:
        return UDS_ER(resetType=_value(values, 0))
    if service_id == 0x19:
        return UDS_RDTCI(reportType=_value(values, 0))
    if service_id == 0x22:
        return UDS_RDBI(identifiers=[_u16_value(values, 0)])
    if service_id == 0x27:
        return UDS_SA(securityAccessType=_value(values, 0))
    if service_id == 0x28:
        return UDS_CC(controlType=_value(values, 0))
    if service_id == 0x2E:
        return UDS_WDBI(dataIdentifier=_u16_value(values, 0))
    if service_id == 0x31:
        return UDS_RC(routineControlType=_value(values, 0), routineIdentifier=_u16_value(values, 1))
    if service_id == 0x3E:
        return UDS_TP(subFunction=_value(values, 0))
    if service_id == 0x85:
        return UDS_CDTCS(DTCSettingType=_value(values, 0))
    return Raw(bytes([service_id, *_flatten_values(values)]))


def _value(values: tuple[int | bytes, ...], index: int, default: int = 0) -> int:
    if index >= len(values):
        return default
    value = values[index]
    if isinstance(value, bytes):
        return int.from_bytes(value[:1] or b'\x00', 'big')
    return int(value) & 0xFF


def _u16_value(values: tuple[int | bytes, ...], index: int, default: int = 0) -> int:
    if index >= len(values):
        return default
    value = values[index]
    if isinstance(value, bytes):
        if len(value) >= 2:
            return int.from_bytes(value[:2], 'big')
        return _value((value,), 0, default)
    return int(value) & 0xFFFF


def _flatten_values(values: tuple[int | bytes, ...]) -> list[int]:
    flattened: list[int] = []
    for value in values:
        if isinstance(value, bytes):
            flattened.extend(value)
        else:
            flattened.append(value & 0xFF)
    return flattened

UDS_NEGATIVE_RESPONSE_NAMES = {
    0x10: 'general_reject',
    0x11: 'service_not_supported',
    0x12: 'sub_function_not_supported',
    0x13: 'incorrect_message_length_or_invalid_format',
    0x14: 'response_too_long',
    0x21: 'busy_repeat_request',
    0x22: 'conditions_not_correct',
    0x24: 'request_sequence_error',
    0x25: 'no_response_from_subnet_component',
    0x26: 'failure_prevents_execution_of_requested_action',
    0x31: 'request_out_of_range',
    0x33: 'security_access_denied',
    0x35: 'invalid_key',
    0x36: 'exceeded_number_of_attempts',
    0x37: 'required_time_delay_not_expired',
    0x70: 'upload_download_not_accepted',
    0x71: 'transfer_data_suspended',
    0x72: 'general_programming_failure',
    0x73: 'wrong_block_sequence_counter',
    0x78: 'request_correctly_received_response_pending',
    0x7E: 'sub_function_not_supported_in_active_session',
    0x7F: 'service_not_supported_in_active_session',
}


@dataclass(frozen=True)
class UDSPositiveInfo:
    response_service: int
    request_service: int
    subfunction: int | None = None
    data_identifier: int | None = None
    routine_identifier: int | None = None
    data: bytes = b''


@dataclass(frozen=True)
class UDSNegativeInfo:
    request_service: int
    nrc: int
    nrc_name: str


@dataclass(frozen=True)
class UDSRequest:
    request_id: int
    request_mode: str
    service_id: int
    service_name: str
    application_payload: bytes
    is_malformed: bool


@dataclass(frozen=True)
class UDSResponseFrame:
    frame_kind: str
    payload: bytes
    service_id: int | None = None
    positive: bool = False
    negative: bool = False
    nrc: int | None = None
    positive_info: UDSPositiveInfo | None = None
    negative_info: UDSNegativeInfo | None = None


@dataclass(frozen=True)
class UDSResponseSummary:
    positive: int
    negative: int
    multi_frame: int
    nrcs: tuple[str, ...]
    kind: str


class UDSProtocol:
    def __init__(self, padding_value: int | None = 0x00) -> None:
        self._isotp = IsoTp(padding_value=padding_value)

    def encode_request_frames(self, application_payload: bytes) -> list[bytes]:
        return self._isotp.segment_message(application_payload)

    def decode_response(self, raw: bytes, request_service: int) -> UDSResponseFrame:
        frame_kind, app_payload = decode_isotp_payload(raw)
        if frame_kind != 'single_frame' or not app_payload:
            return UDSResponseFrame(frame_kind=frame_kind, payload=app_payload)

        service_id = app_payload[0]
        if service_id == 0x7F and len(app_payload) >= 3:
            negative_request_service = app_payload[1]
            nrc = app_payload[2]
            return UDSResponseFrame(
                frame_kind='negative_response',
                payload=app_payload,
                service_id=service_id,
                negative=True,
                nrc=nrc,
                negative_info=UDSNegativeInfo(
                    request_service=negative_request_service,
                    nrc=nrc,
                    nrc_name=UDS_NEGATIVE_RESPONSE_NAMES.get(nrc, f'nrc_0x{nrc:02x}'),
                ),
            )
        if service_id == ((request_service + 0x40) & 0xFF):
            return UDSResponseFrame(
                frame_kind='positive_response',
                payload=app_payload,
                service_id=service_id,
                positive=True,
                positive_info=decode_positive_info(app_payload, request_service),
            )
        return UDSResponseFrame(frame_kind=f'service_0x{service_id:02x}', payload=app_payload, service_id=service_id)

    def summarize_responses(self, response_payloads: list[str], request_service: int) -> UDSResponseSummary:
        positive = 0
        negative = 0
        multi_frame = 0
        nrcs: list[str] = []
        kind = 'no_response'

        for raw_hex in response_payloads:
            response = self.decode_response(bytes.fromhex(raw_hex), request_service)
            if response.positive:
                positive += 1
                kind = response.frame_kind
            elif response.negative:
                negative += 1
                if response.nrc is not None:
                    nrcs.append(f'0x{response.nrc:02x}')
                kind = response.frame_kind
            elif response.frame_kind in {'first_frame', 'consecutive_frame'}:
                multi_frame += 1
                kind = response.frame_kind
            else:
                kind = response.frame_kind

        return UDSResponseSummary(
            positive=positive,
            negative=negative,
            multi_frame=multi_frame,
            nrcs=tuple(nrcs),
            kind=kind,
        )


class UDSRequestBuilder:
    @staticmethod
    def build_request_frames(application_payload: bytes, padding_value: int | None = 0x00) -> list[bytes]:
        return IsoTp(padding_value=padding_value).segment_message(application_payload)


_UDS_PROTOCOL = UDSProtocol()


def decode_positive_info(payload: bytes, request_service: int) -> UDSPositiveInfo:
    response_service = payload[0]
    subfunction = None
    data_identifier = None
    routine_identifier = None
    data_start = 1

    if request_service in {0x10, 0x11, 0x27, 0x28, 0x3E, 0x85} and len(payload) >= 2:
        subfunction = payload[1]
        data_start = 2
    elif request_service in {0x22, 0x2E} and len(payload) >= 3:
        data_identifier = (payload[1] << 8) | payload[2]
        data_start = 3
    elif request_service == 0x31 and len(payload) >= 4:
        routine_identifier = (payload[2] << 8) | payload[3]
        data_start = 4

    return UDSPositiveInfo(
        response_service=response_service,
        request_service=request_service,
        subfunction=subfunction,
        data_identifier=data_identifier,
        routine_identifier=routine_identifier,
        data=payload[data_start:],
    )


def build_request(rng: random.Random, config) -> UDSRequest:
    request_mode = choose_request_mode(rng, config)
    request_id = choose_request_id(rng, request_mode, config)
    malformed = rng.random() < config.malformed_rate

    if malformed:
        service_id = rng.choice(list(UDS_SERVICE_POOL) + [rng.randrange(0x00, 0x100)])
        payload = build_malformed_payload(rng, service_id)
        return UDSRequest(
            request_id=request_id,
            request_mode=request_mode,
            service_id=service_id,
            service_name=UDS_SERVICE_NAMES.get(service_id, 'malformed'),
            application_payload=payload,
            is_malformed=True,
        )

    service_id = choose_service_id(rng, config)
    payload = build_service_payload(rng, service_id)
    return UDSRequest(
        request_id=request_id,
        request_mode=request_mode,
        service_id=service_id,
        service_name=UDS_SERVICE_NAMES.get(service_id, f'service_0x{service_id:02x}'),
        application_payload=payload,
        is_malformed=False,
    )


def choose_request_mode(rng: random.Random, config) -> str:
    if config.request_mode in {'functional', 'physical'}:
        return config.request_mode
    return rng.choices(['functional', 'physical'], weights=[0.8, 0.2], k=1)[0]


def choose_request_id(rng: random.Random, request_mode: str, config) -> int:
    if request_mode == 'functional':
        return config.functional_id
    return rng.randint(config.physical_start, config.physical_end)


def choose_service_id(rng: random.Random, config) -> int:
    if rng.random() < 0.9:
        return rng.choice(UDS_SERVICE_POOL)
    return rng.randrange(0x00, 0x100)


def build_service_payload(rng: random.Random, service_id: int) -> bytes:
    if service_id == 0x10:
        return uds_payload(service_id, rng.choice(UDS_SESSION_LEVELS))
    if service_id == 0x11:
        return uds_payload(service_id, rng.choice(UDS_ECU_RESET_TYPES))
    if service_id == 0x19:
        return uds_payload(service_id, rng.choice([0x01, 0x02, 0x04, 0x06, 0x0A, 0x0F]))
    if service_id in {0x22, 0x2E}:
        return uds_payload(service_id, rng.choice(UDS_DIDS))
    if service_id == 0x27:
        return uds_payload(service_id, rng.choice(UDS_SECURITY_SUBFUNCTIONS))
    if service_id == 0x28:
        return uds_payload(service_id, rng.choice(UDS_COMMUNICATION_SUBFUNCTIONS))
    if service_id == 0x31:
        return uds_payload(service_id, rng.choice(UDS_ROUTINE_SUBFUNCTIONS), rng.choice(UDS_DIDS))
    if service_id == 0x3E:
        return uds_payload(service_id, rng.choice(UDS_TESTER_PRESENT_SUBFUNCTIONS))
    if service_id == 0x85:
        return uds_payload(service_id, rng.choice(UDS_DTC_SETTING_VALUES))
    return uds_payload(service_id, random_bytes(rng, rng.randint(0, 6)))

def build_malformed_payload(rng: random.Random, service_id: int) -> bytes:
    length = rng.randint(1, 7)
    return raw_uds_payload(service_id, random_bytes(rng, length - 1))


def summarize_responses(response_payloads: list[str], request_service: int) -> dict[str, object]:
    summary = _UDS_PROTOCOL.summarize_responses(response_payloads, request_service)
    return {
        'positive': summary.positive,
        'negative': summary.negative,
        'multi_frame': summary.multi_frame,
        'nrcs': summary.nrcs,
        'kind': summary.kind,
    }
