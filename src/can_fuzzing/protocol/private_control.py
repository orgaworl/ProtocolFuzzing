from __future__ import annotations

import random
from dataclasses import dataclass

from .dictionary import PRIVATE_OPCODES, PRIVATE_TARGET_IDS


@dataclass(frozen=True)
class PrivateControlRequest:
    target_id: int
    opcode: int
    payload: bytes
    strategy: str
    is_malformed: bool


def build_request(rng: random.Random, config, case_id: int) -> PrivateControlRequest:
    target_id = rng.choice(config.target_ids)
    opcode = rng.choice(config.opcodes)
    is_malformed = rng.random() < config.malformed_rate
    if is_malformed:
        payload = build_malformed_payload(rng, config, opcode)
        return PrivateControlRequest(target_id, opcode, payload, "malformed", True)

    if rng.random() < config.structured_rate:
        payload = build_structured_payload(rng, config, opcode, case_id)
        return PrivateControlRequest(target_id, opcode, payload, "structured", False)

    payload = build_random_payload(rng, config, opcode)
    return PrivateControlRequest(target_id, opcode, payload, "random", False)


def build_structured_payload(rng: random.Random, config, opcode: int, case_id: int) -> bytes:
    length = clamp_payload_length(config, rng.choice([4, 5, 6, 7, 8, 12, 16]))
    payload = bytearray([opcode & 0xFF])
    if length >= 2:
        payload.append(case_id & 0xFF)
    if length >= 3:
        payload.append(rng.randrange(0x00, 0x100))
    if length >= 4:
        payload.append(length & 0xFF)
    while len(payload) < length:
        payload.append(rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, rng.randrange(0x00, 0x100)]))
    return bytes(payload)


def build_random_payload(rng: random.Random, config, opcode: int) -> bytes:
    length = random_payload_length(rng, config)
    payload = bytearray([opcode & 0xFF])
    while len(payload) < length:
        payload.append(rng.randrange(0x00, 0x100))
    return bytes(payload)


def build_malformed_payload(rng: random.Random, config, opcode: int) -> bytes:
    choices = [0, 1, config.max_payload_len]
    if config.fd:
        choices.extend([9, 15, 32, 64])
    length = clamp_payload_length(config, rng.choice(choices))
    if length == 0:
        return b""
    payload = bytearray([opcode & 0xFF])
    while len(payload) < length:
        payload.append(rng.choice([0x00, 0xFF, rng.randrange(0x00, 0x100)]))
    return bytes(payload)


def random_payload_length(rng: random.Random, config) -> int:
    minimum = max(0, config.min_payload_len)
    maximum = max(minimum, min(config.max_payload_len, 64 if config.fd else 8))
    return rng.randint(minimum, maximum)


def clamp_payload_length(config, length: int) -> int:
    upper = 64 if config.fd else 8
    minimum = max(0, min(config.min_payload_len, upper))
    maximum = max(minimum, min(config.max_payload_len, upper))
    return max(minimum, min(length, maximum))

