from __future__ import annotations

import random
from dataclasses import dataclass

from .dictionary import COMMON_CAN_IDS


XCP_COMMAND_NAMES = {
    0xFF: 'connect',
    0xFE: 'disconnect',
    0xFD: 'get_status',
    0xFC: 'synch',
    0xFB: 'get_comm_mode_info',
    0xFA: 'get_id',
    0xF9: 'set_request',
    0xF8: 'get_seed',
    0xF7: 'unlock',
    0xF6: 'set_mta',
    0xF5: 'upload',
    0xF4: 'short_upload',
    0xF3: 'build_checksum',
    0xF2: 'transport_layer_cmd',
    0xF1: 'user_cmd',
    0xF0: 'download',
    0xEF: 'download_next',
    0xEE: 'download_max',
    0xED: 'short_download',
    0xEC: 'modify_bits',
    0xEB: 'set_cal_page',
    0xEA: 'get_cal_page',
    0xE9: 'get_pag_processor_info',
    0xE8: 'get_segment_info',
    0xE7: 'get_page_info',
    0xE6: 'set_segment_mode',
    0xE5: 'get_segment_mode',
    0xE4: 'copy_cal_page',
    0xE3: 'clear_daq_list',
    0xE2: 'set_daq_ptr',
    0xE1: 'write_daq',
    0xE0: 'set_daq_list_mode',
    0xDF: 'get_daq_list_mode',
    0xDE: 'start_stop_daq_list',
    0xDD: 'start_stop_synch',
    0xDC: 'get_daq_clock',
    0xDB: 'read_daq',
    0xDA: 'get_daq_processor_info',
    0xD9: 'get_daq_resolution_info',
    0xD8: 'get_daq_list_info',
    0xD7: 'get_daq_event_info',
    0xD6: 'free_daq',
    0xD5: 'alloc_daq',
    0xD4: 'alloc_odt',
    0xD3: 'alloc_odt_entry',
    0xD2: 'program_start',
    0xD1: 'program_clear',
    0xD0: 'program',
    0xCF: 'program_reset',
    0xCE: 'get_pgm_processor_info',
    0xCD: 'get_sector_info',
    0xCC: 'program_prepare',
    0xCB: 'program_format',
    0xCA: 'program_next',
    0xC9: 'program_max',
    0xC8: 'program_verify',
}
XCP_COMMAND_POOL = tuple(XCP_COMMAND_NAMES)

XCP_ERROR_DESCRIPTIONS = {
    0x00: ('ERR_CMD_SYNC', 'Command processor synchronisation.'),
    0x10: ('ERR_CMD_BUSY', 'Command was not executed.'),
    0x11: ('ERR_DAQ_ACTIVE', 'Command rejected because DAQ is running.'),
    0x12: ('ERR_PGM_ACTIVE', 'Command rejected because PGM is running.'),
    0x20: ('ERR_CMD_UNKNOWN', 'Unknown command or not implemented optional command.'),
    0x21: ('ERR_CMD_SYNTAX', 'Command syntax invalid.'),
    0x22: ('ERR_OUT_OF_RANGE', 'Command parameter is out of range.'),
    0x23: ('ERR_WRITE_PROTECTED', 'The memory location is write protected.'),
    0x24: ('ERR_ACCESS_DENIED', 'The memory location is not accessible.'),
    0x25: ('ERR_ACCESS_LOCKED', 'Access denied, seed and key is required.'),
    0x26: ('ERR_PAGE_NOT_VALID', 'Selected page not available.'),
    0x27: ('ERR_MODE_NOT_VALID', 'Selected mode not available.'),
    0x28: ('ERR_SEGMENT_NOT_VALID', 'Selected segment not valid.'),
    0x29: ('ERR_SEQUENCE', 'Sequence error.'),
    0x2A: ('ERR_DAQ_CONFIG', 'DAQ configuration not valid.'),
    0x30: ('ERR_MEMORY_OVERFLOW', 'Memory overflow error.'),
    0x31: ('ERR_GENERIC', 'Generic error.'),
    0x32: ('ERR_VERIFY', 'The slave internal program verify routine detects an error.'),
}

XCP_RESOURCE_BITS = ('CAL/PAG', 'RESERVED_1', 'DAQ', 'STIM', 'PGM', 'RESERVED_5', 'RESERVED_6', 'RESERVED_7')
XCP_COMM_MODE_BASIC_BITS = ('BYTE_ORDER', 'ADDRESS_GRANULARITY_0', 'ADDRESS_GRANULARITY_1', 'RESERVED_3', 'RESERVED_4', 'RESERVED_5', 'SLAVE_BLOCK_MODE', 'OPTIONAL')
XCP_COMM_MODE_OPTIONAL_BITS = ('MASTER_BLOCK_MODE', 'INTERLEAVED_MODE', 'RESERVED_2', 'RESERVED_3', 'RESERVED_4', 'RESERVED_5', 'RESERVED_6', 'RESERVED_7')
XCP_SESSION_STATUS_BITS = ('STORE_CAL_REQ', 'RESERVED_1', 'STORE_DAQ_REQ', 'CLEAR_DAQ_REQ', 'RESERVED_4', 'RESERVED_5', 'DAQ_RUNNING', 'RESUME')


@dataclass(frozen=True)
class XCPRequest:
    request_id: int
    command_code: int
    command_name: str
    payload: bytes
    is_malformed: bool


@dataclass(frozen=True)
class XCPConnectInfo:
    resource_mask: int
    comm_mode_basic: int
    max_cto: int
    max_dto: int
    protocol_layer_version: int
    transport_layer_version: int
    address_granularity: int


@dataclass(frozen=True)
class XCPStatusInfo:
    session_status: int
    resource_mask: int
    reserved: int
    session_configuration_id: int


@dataclass(frozen=True)
class XCPCommModeInfo:
    reserved_1: int
    comm_mode_optional: int
    reserved_2: int
    max_bs: int
    min_st: int
    queue_size: int
    driver_version: int


@dataclass(frozen=True)
class XCPIdInfo:
    mode: int | None
    identifier: bytes


@dataclass(frozen=True)
class XCPResponseFrame:
    frame_kind: str
    payload: bytes
    command_code: int | None = None
    response_code: int | None = None
    error_code: int | None = None
    error_name: str | None = None
    positive: bool = False
    negative: bool = False
    connect_info: XCPConnectInfo | None = None
    status_info: XCPStatusInfo | None = None
    comm_mode_info: XCPCommModeInfo | None = None
    id_info: XCPIdInfo | None = None


@dataclass(frozen=True)
class XCPResponseSummary:
    positive: int
    negative: int
    kind: str


class XCPProtocol:
    def build_request_frame(self, payload: bytes) -> bytes:
        if len(payload) > 8:
            raise ValueError('XCP protocol requests must fit in one classic CAN frame')
        return payload.ljust(8, b'\x00')

    def decode_response(self, raw: bytes, request_command: int) -> XCPResponseFrame:
        if not raw:
            return XCPResponseFrame(frame_kind='empty', payload=b'')
        if len(raw) < 2:
            return XCPResponseFrame(frame_kind='truncated', payload=raw, response_code=raw[0])

        response_code = raw[0]
        if response_code == 0xFE:
            return self._decode_error(raw)
        if response_code != 0xFF:
            return XCPResponseFrame(frame_kind=f'response_0x{response_code:02x}', payload=raw, response_code=response_code)

        if request_command == 0xFF:
            return self._decode_connect_response(raw)
        if request_command == 0xFD:
            return self._decode_get_status_response(raw)
        if request_command == 0xFB:
            return self._decode_get_comm_mode_info_response(raw)
        if request_command == 0xFA:
            return self._decode_get_id_response(raw)
        return XCPResponseFrame(
            frame_kind='positive_response',
            payload=raw,
            command_code=request_command,
            response_code=response_code,
            positive=True,
        )
    def summarize_responses(self, response_payloads: list[str], request_command: int) -> XCPResponseSummary:
        positive = 0
        negative = 0
        kind = 'no_response'
        for raw_hex in response_payloads:
            response = self.decode_response(bytes.fromhex(raw_hex), request_command)
            if response.positive:
                positive += 1
                kind = response.frame_kind
            elif response.negative:
                negative += 1
                kind = response.frame_kind
            else:
                kind = response.frame_kind
        return XCPResponseSummary(positive=positive, negative=negative, kind=kind)

    def _decode_error(self, raw: bytes) -> XCPResponseFrame:
        error_code = raw[1]
        error_name, _ = XCP_ERROR_DESCRIPTIONS.get(error_code, ('UNKNOWN', 'Unknown error'))
        return XCPResponseFrame(
            frame_kind='negative_response',
            payload=raw,
            response_code=raw[0],
            error_code=error_code,
            error_name=error_name,
            negative=True,
        )

    def _decode_connect_response(self, raw: bytes) -> XCPResponseFrame:
        if len(raw) < 8:
            return XCPResponseFrame(frame_kind='truncated_connect_response', payload=raw, response_code=raw[0])
        resource_mask = raw[1]
        comm_mode_basic = raw[2]
        max_cto = raw[3]
        max_dto = (raw[5] << 8) | raw[4]
        protocol_layer_version = raw[6]
        transport_layer_version = raw[7]
        address_granularity = 1 << (((comm_mode_basic >> 2) & 0x01) * 2 + ((comm_mode_basic >> 1) & 0x01))
        return XCPResponseFrame(
            frame_kind='connect_response',
            payload=raw,
            command_code=0xFF,
            response_code=0xFF,
            positive=True,
            connect_info=XCPConnectInfo(
                resource_mask=resource_mask,
                comm_mode_basic=comm_mode_basic,
                max_cto=max_cto,
                max_dto=max_dto,
                protocol_layer_version=protocol_layer_version,
                transport_layer_version=transport_layer_version,
                address_granularity=address_granularity,
            ),
        )

    def _decode_get_status_response(self, raw: bytes) -> XCPResponseFrame:
        if len(raw) < 8:
            return XCPResponseFrame(frame_kind='truncated_get_status_response', payload=raw, response_code=raw[0])
        session_status = raw[1]
        resource_mask = raw[2]
        reserved = raw[3]
        session_configuration_id = 2 ** (((raw[5] & 0x04) * 2) + (raw[4] & 0x02))
        return XCPResponseFrame(
            frame_kind='get_status_response',
            payload=raw,
            command_code=0xFD,
            response_code=0xFF,
            positive=True,
            status_info=XCPStatusInfo(
                session_status=session_status,
                resource_mask=resource_mask,
                reserved=reserved,
                session_configuration_id=session_configuration_id,
            ),
        )

    def _decode_get_comm_mode_info_response(self, raw: bytes) -> XCPResponseFrame:
        if len(raw) < 8:
            return XCPResponseFrame(frame_kind='truncated_get_comm_mode_info_response', payload=raw, response_code=raw[0])
        return XCPResponseFrame(
            frame_kind='get_comm_mode_info_response',
            payload=raw,
            command_code=0xFB,
            response_code=0xFF,
            positive=True,
            comm_mode_info=XCPCommModeInfo(
                reserved_1=raw[1],
                comm_mode_optional=raw[2],
                reserved_2=raw[3],
                max_bs=raw[4],
                min_st=raw[5],
                queue_size=raw[6],
                driver_version=raw[7],
            ),
        )

    def _decode_get_id_response(self, raw: bytes) -> XCPResponseFrame:
        if len(raw) < 3:
            return XCPResponseFrame(frame_kind='truncated_get_id_response', payload=raw, response_code=raw[0])
        mode = raw[2]
        identifier = raw[3:]
        return XCPResponseFrame(
            frame_kind='get_id_response',
            payload=raw,
            command_code=0xFA,
            response_code=0xFF,
            positive=True,
            id_info=XCPIdInfo(mode=mode, identifier=identifier),
        )


_XCP_PROTOCOL = XCPProtocol()


def build_request(rng: random.Random, config) -> XCPRequest:
    command_code = choose_command(rng, config)
    request_id = choose_request_id(rng, config)
    malformed = rng.random() < config.malformed_rate
    if malformed:
        payload = build_malformed_payload(rng, command_code)
    else:
        payload = build_command_payload(rng, command_code, config)
    return XCPRequest(
        request_id=request_id,
        command_code=command_code,
        command_name=XCP_COMMAND_NAMES.get(command_code, f'command_0x{command_code:02x}'),
        payload=payload,
        is_malformed=malformed,
    )


def choose_command(rng: random.Random, config) -> int:
    command_pool = getattr(config, 'command_pool', None)
    if command_pool:
        return rng.choice(tuple(command_pool))
    if rng.random() < 0.9:
        return rng.choice(XCP_COMMAND_POOL)
    return rng.randrange(0x00, 0x100)


def choose_request_id(rng: random.Random, config) -> int:
    request_ids = getattr(config, 'request_ids', None)
    if request_ids:
        return rng.choice(tuple(request_ids))
    target_ids = getattr(config, 'target_ids', None)
    if target_ids:
        return rng.choice(tuple(target_ids))
    return rng.choice(COMMON_CAN_IDS)


def build_command_payload(rng: random.Random, command_code: int, config) -> bytes:
    length = max(1, min(8, getattr(config, 'max_payload_len', 8)))
    payload = bytearray([command_code & 0xFF])
    while len(payload) < length:
        payload.append(rng.randrange(0x00, 0x100))
    return bytes(payload)


def build_malformed_payload(rng: random.Random, command_code: int) -> bytes:
    length = rng.randint(0, 8)
    if length == 0:
        return b''
    payload = bytearray([command_code & 0xFF])
    while len(payload) < length:
        payload.append(rng.choice([0x00, 0xFF, rng.randrange(0x00, 0x100)]))
    return bytes(payload)


def summarize_responses(response_payloads: list[str], request_command: int) -> dict[str, int | str]:
    summary = _XCP_PROTOCOL.summarize_responses(response_payloads, request_command)
    return {'positive': summary.positive, 'negative': summary.negative, 'kind': summary.kind}
