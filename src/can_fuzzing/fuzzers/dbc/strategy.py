from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from .database import DBCDatabase, DBCMessage, DBCSignal, coerce_number


@dataclass(frozen=True)
class DBCRequest:
    message_id: int
    message_name: str
    payload: bytes
    signal_values: dict[str, Any]
    strategy: str


def choose_message(rng: random.Random, database: DBCDatabase) -> DBCMessage:
    weights = [max(1, len(message.signals)) + max(1, message.size) for message in database.messages]
    return rng.choices(database.messages, weights=weights, k=1)[0]


def build_request(rng: random.Random, database: DBCDatabase) -> DBCRequest:
    message = choose_message(rng, database)
    strategy = rng.choice(["baseline", "boundary", "random", "choices"])
    values = build_signal_values(rng, message, strategy)
    payload = message.encode(values)
    return DBCRequest(
        message_id=message.frame_id,
        message_name=message.name,
        payload=payload,
        signal_values=values,
        strategy=strategy,
    )


def build_signal_values(rng: random.Random, message: DBCMessage, strategy: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for signal in message.signals:
        values[signal.name] = choose_signal_value(rng, signal, strategy)
    return values


def choose_signal_value(rng: random.Random, signal: DBCSignal, strategy: str) -> Any:
    if signal.choices:
        choice_values = [value for value, _ in signal.choices]
        if strategy == "baseline":
            return choice_values[0]
        return rng.choice(choice_values)

    candidates = interesting_values(signal)
    if strategy == "baseline":
        return signal.baseline_value()
    if strategy == "boundary":
        return rng.choice(candidates)
    if strategy == "choices":
        return rng.choice(candidates[: max(1, min(4, len(candidates)))])
    return random_value(rng, signal)


def interesting_values(signal: DBCSignal) -> list[int | float]:
    values: list[int | float] = []
    raw_min = signal.raw_min
    raw_max = signal.raw_max
    for raw in (raw_min, raw_min + 1, -1, 0, 1, raw_max - 1, raw_max):
        if raw < raw_min or raw > raw_max:
            continue
        values.append(coerce_number(raw * signal.factor + signal.offset))
    if signal.minimum is not None:
        values.append(coerce_number(signal.minimum))
    if signal.maximum is not None:
        values.append(coerce_number(signal.maximum))
    if not values:
        values.append(signal.baseline_value())
    return dedupe(values)


def random_value(rng: random.Random, signal: DBCSignal) -> int | float:
    raw = rng.randint(signal.raw_min, signal.raw_max)
    return coerce_number(raw * signal.factor + signal.offset)


def dedupe(values: list[int | float]) -> list[int | float]:
    seen: set[tuple[type, Any]] = set()
    result: list[int | float] = []
    for value in values:
        key = (type(value), value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
