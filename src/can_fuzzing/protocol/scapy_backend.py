from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from scapy.contrib.automotive.obd.obd import OBD
from scapy.contrib.automotive.obd.services import OBD_S01, OBD_S02, OBD_S06, OBD_S08, OBD_S09
from scapy.contrib.automotive.uds import UDS, UDS_CC, UDS_CDTCS, UDS_DSC, UDS_ER, UDS_RC, UDS_RDBI, UDS_RDTCI, UDS_SA, UDS_TP, UDS_WDBI
from scapy.contrib.automotive.xcp.xcp import CTORequest
from scapy.contrib.isotp.isotp_packet import ISOTP
from scapy.layers.can import CAN, CANFD
from scapy.packet import Raw


def packet_bytes(packet: Any) -> bytes:
    return bytes(packet)


def can_packet(identifier: int, data: bytes | Iterable[int], *, extended: bool = False, fd: bool = False, remote: bool = False, error: bool = False):
    flags: list[str] = []
    if extended:
        flags.append('extended')
    if remote:
        flags.append('remote_transmission_request')
    if error:
        flags.append('error')
    packet_cls = CANFD if fd else CAN
    return packet_cls(identifier=identifier, flags='+'.join(flags), data=bytes(data))


def build_can_payload(data: bytes | Iterable[int]) -> bytes:
    return bytes(can_packet(0, data).data)


def segment_isotp_payload(application_payload: bytes, *, padding_value: int | None = 0x00, fd: bool = False) -> list[bytes]:
    frames = ISOTP(data=bytes(application_payload), rx_id=0).fragment(fd=fd)
    return [pad_can_payload(bytes(frame.data), padding_value, 64 if fd else 8) for frame in frames]


def encode_isotp_single_payload(application_payload: bytes, *, padding_value: int | None = 0x00) -> bytes:
    frames = segment_isotp_payload(application_payload, padding_value=padding_value, fd=False)
    if len(frames) != 1:
        raise ValueError(f'ISO-TP single frame supports at most 7 payload bytes, got {len(application_payload)}')
    return frames[0]


def pad_can_payload(payload: bytes, padding_value: int | None, frame_size: int) -> bytes:
    if padding_value is None:
        return payload
    if len(payload) > frame_size:
        return payload
    return payload + bytes([padding_value & 0xFF]) * (frame_size - len(payload))


def uds_payload(service_id: int, *values: int | bytes) -> bytes:
    packet = UDS() / _uds_service_packet(service_id, *values)
    return packet_bytes(packet)


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


def obd_payload(mode: int, pid: int | None = None) -> bytes:
    packet = OBD(service=mode)
    if pid is None:
        return packet_bytes(packet)
    return packet_bytes(packet / _obd_service_packet(mode, pid))


def _obd_service_packet(mode: int, pid: int):
    if mode == 0x01:
        return OBD_S01(pid=pid)
    if mode == 0x02:
        return OBD_S02(pid=pid)
    if mode == 0x06:
        return OBD_S06(mid=pid)
    if mode == 0x08:
        return OBD_S08(tid=pid)
    if mode == 0x09:
        return OBD_S09(iid=pid)
    return Raw(bytes([pid & 0xFF]))


def xcp_payload(command_code: int, data: bytes = b'') -> bytes:
    return packet_bytes(CTORequest(pid=command_code) / Raw(data))




def raw_payload(first_byte: int, data: bytes = b'') -> bytes:
    return packet_bytes(Raw(bytes([first_byte & 0xFF]) + bytes(data)))

def raw_uds_payload(service_id: int, data: bytes = b'') -> bytes:
    return packet_bytes(UDS(service=service_id) / Raw(bytes(data)))


def raw_obd_payload(mode: int, data: bytes = b'') -> bytes:
    return packet_bytes(OBD(service=mode) / Raw(bytes(data)))


def raw_xcp_payload(command_code: int, data: bytes = b'') -> bytes:
    return xcp_payload(command_code, data)

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
