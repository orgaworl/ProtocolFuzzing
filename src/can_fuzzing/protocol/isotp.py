from __future__ import annotations


def encode_isotp_single_frame(application_payload: bytes) -> bytes:
    if len(application_payload) > 7:
        raise ValueError("payload exceeds classic CAN ISO-TP single-frame capacity")
    frame = bytearray([len(application_payload) & 0x0F])
    frame.extend(application_payload)
    while len(frame) < 8:
        frame.append(0x00)
    return bytes(frame)


def decode_isotp_payload(raw: bytes) -> tuple[str, bytes]:
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

