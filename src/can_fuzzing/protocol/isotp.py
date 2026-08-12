from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from scapy.contrib.isotp.isotp_packet import ISOTP


@dataclass(frozen=True)
class IsoTpFrame:
    frame_type: str
    payload: bytes
    length: int | None = None
    sequence_number: int | None = None


class IsoTp:
    """Pure ISO-15765-2 helpers for CAN payload segmentation and parsing."""

    MAX_SF_LENGTH = 7
    MAX_FF_LENGTH = 6
    MAX_CF_LENGTH = 7
    MAX_FRAME_LENGTH = 8
    MAX_MESSAGE_LENGTH = 4095

    SF_PCI_LENGTH = 1
    CF_PCI_LENGTH = 1
    FF_PCI_LENGTH = 2
    FC_PCI_LENGTH = 3

    FC_FS_CTS = 0
    FC_FS_WAIT = 1
    FC_FS_OVFLW = 2

    SF_FRAME_ID = 0
    FF_FRAME_ID = 1
    CF_FRAME_ID = 2
    FC_FRAME_ID = 3

    def __init__(self, padding_value: int | None = 0x00) -> None:
        self.padding_value = _normalize_padding_value(padding_value)
        self.padding_enabled = self.padding_value is not None

    @staticmethod
    def decode_sf(frame: bytes) -> tuple[int | None, list[int] | None]:
        if len(frame) < IsoTp.SF_PCI_LENGTH:
            return None, None
        sf_dl = frame[0] & 0x0F
        return sf_dl, list(frame[1:])

    @staticmethod
    def decode_ff(frame: bytes) -> tuple[int | None, list[int] | None]:
        if len(frame) < IsoTp.FF_PCI_LENGTH:
            return None, None
        ff_dl = ((frame[0] & 0x0F) << 8) | frame[1]
        return ff_dl, list(frame[2:])

    @staticmethod
    def decode_cf(frame: bytes) -> tuple[int | None, list[int] | None]:
        if len(frame) < IsoTp.CF_PCI_LENGTH:
            return None, None
        sn = frame[0] & 0x0F
        return sn, list(frame[1:])

    @staticmethod
    def decode_fc(frame: bytes) -> tuple[int | None, int | None, int | None]:
        if len(frame) < IsoTp.FC_PCI_LENGTH:
            return None, None, None
        fs = frame[0] & 0x0F
        block_size = frame[1]
        st_min = frame[2]
        return fs, block_size, st_min

    @staticmethod
    def decode_frame(raw: bytes) -> tuple[str, bytes]:
        if not raw:
            return "empty", b""
        pci_type = raw[0] >> 4
        if pci_type == 0:
            length = raw[0] & 0x0F
            return "single_frame", raw[1 : 1 + length]
        if pci_type == 1:
            return "first_frame", raw[2:]
        if pci_type == 2:
            return "consecutive_frame", raw[1:]
        if pci_type == 3:
            return "flow_control", raw[1:]
        return "unknown", raw

    @staticmethod
    def encode_single_frame(application_payload: bytes) -> bytes:
        return encode_isotp_single_frame(application_payload)

    def segment_message(self, message: bytes | Iterable[int]) -> list[bytes]:
        return segment_isotp_message(message, self.padding_value)

    @staticmethod
    def get_frames_from_message(message: bytes | Iterable[int], padding_value: int | None = 0x00) -> list[bytes]:
        return segment_isotp_message(message, padding_value)


def encode_isotp_single_frame(application_payload: bytes) -> bytes:
    if len(application_payload) > IsoTp.MAX_SF_LENGTH:
        raise ValueError("payload exceeds classic CAN ISO-TP single-frame capacity")
    return _scapy_segment_isotp_payload(application_payload, padding_value=0x00)[0]

def decode_isotp_payload(raw: bytes) -> tuple[str, bytes]:
    return IsoTp.decode_frame(raw)


def segment_isotp_message(message: bytes | Iterable[int], padding_value: int | None = 0x00) -> list[bytes]:
    payload = bytes(message)
    if len(payload) > IsoTp.MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Message too long for ISO-TP. Max allowed length is {IsoTp.MAX_MESSAGE_LENGTH} bytes, received {len(payload)} bytes"
        )
    return _scapy_segment_isotp_payload(payload, padding_value=_normalize_padding_value(padding_value), fd=False)


def _scapy_segment_isotp_payload(application_payload: bytes, padding_value: int | None = 0x00, fd: bool = False) -> list[bytes]:
    frames = ISOTP(data=bytes(application_payload), rx_id=0).fragment(fd=fd)
    frame_size = 64 if fd else IsoTp.MAX_FRAME_LENGTH
    return [_pad_can_payload(bytes(frame.data), padding_value, frame_size) for frame in frames]


def _pad_can_payload(payload: bytes, padding_value: int | None, frame_size: int) -> bytes:
    if padding_value is None or len(payload) > frame_size:
        return payload
    return payload + bytes([padding_value & 0xFF]) * (frame_size - len(payload))

def _normalize_padding_value(padding_value: int | None) -> int | None:
    if padding_value is None:
        return None
    if not isinstance(padding_value, int):
        raise TypeError(f"IsoTp: padding must be an integer or None, received {padding_value!r}")
    if not 0x00 <= padding_value <= 0xFF:
        raise ValueError(f"IsoTp: padding must be in range 0x00-0xFF (0-255), got {padding_value!r}")
    return padding_value
