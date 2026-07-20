from __future__ import annotations

import random
from typing import Protocol

from .models import CANFrame, FrameFormat, FrameType


DIAGNOSTIC_IDS = [0x7DF, 0x7E0, 0x7E1, 0x7E2, 0x7E3, 0x7E4, 0x7E5, 0x7E6, 0x7E7]


class CANFuzzingStrategyConfig(Protocol):
    inter_frame_delay_ms: float
    fd: bool
    id_min: int
    id_max: int
    diagnostic_bias: float
    extended_probability: float
    include_remote: bool
    include_error: bool


def generate_frame(
    rng: random.Random,
    case_id: int,
    current_timestamp_ms: int,
    config: CANFuzzingStrategyConfig,
) -> CANFrame:
    frame_format = choose_frame_format(rng, config)
    frame_type = choose_frame_type(rng, config)
    identifier = choose_identifier(rng, frame_format, config)
    data = choose_payload(rng, identifier, config)
    timestamp_ms = current_timestamp_ms + max(1, int(config.inter_frame_delay_ms))

    return CANFrame(
        identifier=identifier,
        data=data,
        frame_format=frame_format,
        frame_type=frame_type,
        timestamp_ms=timestamp_ms,
    )


def choose_frame_format(rng: random.Random, config: CANFuzzingStrategyConfig) -> FrameFormat:
    if rng.random() < config.extended_probability:
        return FrameFormat.EXTENDED
    return FrameFormat.STANDARD


def choose_frame_type(rng: random.Random, config: CANFuzzingStrategyConfig) -> FrameType:
    choices = [FrameType.DATA]
    weights = [1.0]
    if config.include_remote:
        choices.append(FrameType.REMOTE)
        weights.append(0.05)
    if config.include_error:
        choices.append(FrameType.ERROR)
        weights.append(0.02)
    return rng.choices(choices, weights=weights, k=1)[0]


def choose_identifier(rng: random.Random, frame_format: FrameFormat, config: CANFuzzingStrategyConfig) -> int:
    upper_limit = 0x7FF if frame_format == FrameFormat.STANDARD else 0x1FFFFFFF
    id_min = max(0, min(config.id_min, upper_limit))
    id_max = max(id_min, min(config.id_max, upper_limit))
    diagnostic_ids = [value for value in DIAGNOSTIC_IDS if id_min <= value <= id_max]
    if diagnostic_ids and rng.random() < config.diagnostic_bias:
        return rng.choice(diagnostic_ids)
    return rng.randint(id_min, id_max)


def choose_payload(rng: random.Random, identifier: int, config: CANFuzzingStrategyConfig) -> bytes:
    if identifier in DIAGNOSTIC_IDS and rng.random() < 0.75:
        templates = [
            [0x02, 0x10, 0x01],
            [0x02, 0x10, 0x03],
            [0x02, 0x27, 0x01],
            [0x04, 0x27, 0x02, 0x12, 0x34],
            [0x03, 0x22, 0xF1, 0x90],
            [0x04, 0x31, 0x01, 0xFF, 0x00],
            [0x01, 0x3E],
        ]
        data = rng.choice(templates)
        return bytes(pad_classic_payload(data, rng))

    max_len = 64 if config.fd else 8
    interesting_lengths = [0, 1, 2, 3, 4, 7, 8]
    if config.fd:
        interesting_lengths.extend([12, 16, 32, 48, 64])
    length = rng.choice([value for value in interesting_lengths if value <= max_len])
    return bytes(rng.randrange(256) for _ in range(length))


def pad_classic_payload(data: list[int], rng: random.Random) -> list[int]:
    data = data[:8]
    if len(data) < 8 and rng.random() < 0.7:
        data = data + [0x00] * (8 - len(data))
    return data


def classify_coverage(frame: CANFrame, observation) -> set[str]:
    points = {
        f"tx_id_{frame.identifier:x}",
        f"format_{frame.frame_format.value}",
        f"type_{frame.frame_type.value}",
        f"reason_{observation.reason}",
    }
    if frame.data:
        if frame.data[0] <= 0x07 and len(frame.data) > 1:
            points.add(f"service_{frame.data[1]:02x}")
        else:
            points.add(f"byte0_{frame.data[0]:02x}")
    for response_id in observation.response_ids:
        points.add(f"rx_id_{response_id:x}")
    return points
