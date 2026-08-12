from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


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
    frame = bytearray([len(application_payload) & 0x0F])
    frame.extend(application_payload)
    while len(frame) < IsoTp.MAX_FRAME_LENGTH:
        frame.append(0x00)
    return bytes(frame)


def decode_isotp_payload(raw: bytes) -> tuple[str, bytes]:
    return IsoTp.decode_frame(raw)


def segment_isotp_message(message: bytes | Iterable[int], padding_value: int | None = 0x00) -> list[bytes]:
    payload = bytes(message)
    if len(payload) > IsoTp.MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Message too long for ISO-TP. Max allowed length is {IsoTp.MAX_MESSAGE_LENGTH} bytes, received {len(payload)} bytes"
        )

    normalized_padding = _normalize_padding_value(padding_value)
    padding_enabled = normalized_padding is not None
    pad_byte = 0x00 if normalized_padding is None else normalized_padding

    frame_list: list[bytes] = []
    message_length = len(payload)

    if message_length <= IsoTp.MAX_SF_LENGTH:
        if padding_enabled:
            frame = [pad_byte] * IsoTp.MAX_FRAME_LENGTH
        else:
            frame = [pad_byte] * (message_length + 1)
        frame[0] = (IsoTp.SF_FRAME_ID << 4) | message_length
        for index, value in enumerate(payload):
            frame[1 + index] = value
        frame_list.append(bytes(frame))
        return frame_list

    frame = [pad_byte] * IsoTp.MAX_FRAME_LENGTH
    frame[0] = (IsoTp.FF_FRAME_ID << 4) | (message_length >> 8)
    frame[1] = message_length & 0xFF
    for index in range(IsoTp.MAX_FF_LENGTH):
        frame[2 + index] = payload[index]
    frame_list.append(bytes(frame))

    bytes_copied = IsoTp.MAX_FF_LENGTH
    bytes_left_to_copy = message_length - bytes_copied
    sn = 0
    while bytes_left_to_copy > 0:
        sn = (sn + 1) % 16
        if not padding_enabled and bytes_left_to_copy < IsoTp.MAX_CF_LENGTH:
            frame = [pad_byte] * (bytes_left_to_copy + 1)
        else:
            frame = [pad_byte] * IsoTp.MAX_FRAME_LENGTH
        frame[0] = (IsoTp.CF_FRAME_ID << 4) | sn
        bytes_to_copy = min(IsoTp.MAX_CF_LENGTH, bytes_left_to_copy)
        for index in range(bytes_to_copy):
            frame[1 + index] = payload[bytes_copied]
            bytes_copied += 1
            bytes_left_to_copy -= 1
        frame_list.append(bytes(frame))

    return frame_list


def _normalize_padding_value(padding_value: int | None) -> int | None:
    if padding_value is None:
        return None
    if not isinstance(padding_value, int):
        raise TypeError(f"IsoTp: padding must be an integer or None, received {padding_value!r}")
    if not 0x00 <= padding_value <= 0xFF:
        raise ValueError(f"IsoTp: padding must be in range 0x00-0xFF (0-255), got {padding_value!r}")
    return padding_value
