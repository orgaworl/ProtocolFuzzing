from __future__ import annotations

import random
from dataclasses import dataclass

from ..fuzzing.utils import random_bytes
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

XCP_ERROR_NAMES = {
    0x10: 'ERR_CMD_BUSY',
    0x11: 'ERR_DAQ_ACTIVE',
    0x12: 'ERR_PGM_ACTIVE',
    0x20: 'ERR_CMD_UNKNOWN',
    0x21: 'ERR_CMD_SYNTAX',
    0x22: 'ERR_OUT_OF_RANGE',
    0x23: 'ERR_WRITE_PROTECTED',
    0x24: 'ERR_ACCESS_DENIED',
    0x25: 'ERR_ACCESS_LOCKED',
    0x26: 'ERR_PAGE_NOT_VALID',
    0x27: 'ERR_MODE_NOT_VALID',
    0x28: 'ERR_SEGMENT_NOT_VALID',
    0x29: 'ERR_SEQUENCE',
    0x2A: 'ERR_DAQ_CONFIG',
    0x30: 'ERR_MEMORY_OVERFLOW',
    0x31: 'ERR_GENERIC',
    0x32: 'ERR_VERIFY',
}


@dataclass(frozen=True)
class XCPRequest:
    request_id: int
    command_code: int
    command_name: str
    payload: bytes
    is_malformed: bool


@dataclass(frozen=True)
class XCPResponseFrame:
    frame_kind: str
    payload: bytes
    response_code: int | None = None
    error_name: str | None = None
    positive: bool = False
    negative: bool = False


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
        response_code = raw[0]
        if response_code == 0xFF and len(raw) >= 2 and raw[1] == request_command:
            return XCPResponseFrame(frame_kind='positive_response', payload=raw, response_code=response_code, positive=True)
        if response_code == 0xFE and len(raw) >= 2:
            error_code = raw[1]
            return XCPResponseFrame(
                frame_kind='negative_response',
                payload=raw,
                response_code=response_code,
                error_name=XCP_ERROR_NAMES.get(error_code, f'ERR_0x{error_code:02x}'),
                negative=True,
            )
        return XCPResponseFrame(frame_kind=f'response_0x{response_code:02x}', payload=raw, response_code=response_code)

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
