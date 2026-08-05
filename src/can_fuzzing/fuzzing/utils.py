from __future__ import annotations

import random
from collections.abc import Callable
from typing import Protocol


class ProgressConfig(Protocol):
    cases: int
    progress_interval: int
    progress_seconds: float


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


def random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))


def should_report_progress(config: ProgressConfig, completed_cases: int, now: float, last_progress: float) -> bool:
    if completed_cases <= 0:
        return False
    if config.progress_interval > 0 and completed_cases % config.progress_interval == 0:
        return True
    if config.progress_seconds > 0 and now - last_progress >= config.progress_seconds:
        return True
    if completed_cases == config.cases:
        return True
    return False


def report_progress(progress_callback: Callable[[dict], None] | None, **snapshot: object) -> None:
    if progress_callback is None:
        return
    progress_callback(snapshot)

