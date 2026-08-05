from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


BO_RE = re.compile(r"^BO_\s+(?P<id>0x[0-9A-Fa-f]+|\d+)\s+(?P<name>[^\s:]+)\s*:\s*(?P<size>\d+)\s+(?P<tx>[^\s]+)")
SG_RE = re.compile(
    r"^SG_\s+(?P<name>[^\s:]+)(?:\s+(?P<mux>M|m\d+))?\s*:\s*"
    r"(?P<start>\d+)\|(?P<size>\d+)@(?P<byte_order>[01])(?P<sign>[+-])\s*"
    r"\((?P<factor>[-+0-9.eE]+)\s*,\s*(?P<offset>[-+0-9.eE]+)\)\s*"
    r"\[(?P<minimum>[-+0-9.eE]+)\|(?P<maximum>[-+0-9.eE]+)\]\s*"
    r'"(?P<unit>[^"]*)"\s*(?P<receivers>.*)$'
)
VAL_RE = re.compile(r"^VAL_\s+(?P<msg_id>0x[0-9A-Fa-f]+|\d+)\s+(?P<signal>[^\s]+)\s+(?P<body>.*);$")
VAL_PAIR_RE = re.compile(r'(-?\d+)\s+"([^"]*)"')


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_float(value: str) -> float:
    return float(value)


def normalize_names(raw: str) -> tuple[str, ...]:
    items = [item.strip() for item in re.split(r"[\s,]+", raw) if item.strip()]
    return tuple(items)


def coerce_number(value: float) -> int | float:
    rounded = round(value)
    if abs(value - rounded) < 1e-9:
        return int(rounded)
    return value


@dataclass
class DBCSignal:
    name: str
    start_bit: int
    size: int
    byte_order: str
    is_signed: bool
    factor: float
    offset: float
    minimum: float | None
    maximum: float | None
    unit: str = ""
    receivers: tuple[str, ...] = ()
    multiplex: str | None = None
    choices: tuple[tuple[int, str], ...] = ()

    @property
    def is_little_endian(self) -> bool:
        return self.byte_order == "little_endian"

    @property
    def raw_min(self) -> int:
        if self.is_signed:
            return -(1 << (self.size - 1))
        return 0

    @property
    def raw_max(self) -> int:
        if self.is_signed:
            return (1 << (self.size - 1)) - 1
        return (1 << self.size) - 1

    def bit_positions(self) -> list[int]:
        if self.is_little_endian:
            return [self.start_bit + index for index in range(self.size)]

        positions: list[int] = []
        bit = self.start_bit
        for _ in range(self.size):
            positions.append(bit)
            bit = bit + 15 if bit % 8 == 0 else bit - 1
        return positions

    def baseline_value(self) -> int | float:
        if self.choices:
            return self.choices[0][0]
        if self.minimum is not None:
            return coerce_number(self.minimum)
        if self.offset != 0:
            return coerce_number(self.offset)
        return 0


@dataclass
class DBCMessage:
    frame_id: int
    name: str
    size: int
    transmitter: str = ""
    signals: list[DBCSignal] = field(default_factory=list)
    is_extended_id: bool = False

    def encode(self, values: dict[str, Any]) -> bytes:
        payload = bytearray(self.size)
        for signal in self.signals:
            value = values.get(signal.name, signal.baseline_value())
            raw = encode_signal_value(signal, value)
            insert_signal_bits(payload, signal.bit_positions(), raw, signal.is_little_endian, signal.size)
        return bytes(payload)

    def decode(self, payload: bytes) -> dict[str, int | float]:
        padded = bytes(payload).ljust(self.size, b"\x00")
        decoded: dict[str, int | float] = {}
        for signal in self.signals:
            raw = extract_signal_raw(padded, signal.bit_positions(), signal.is_little_endian, signal.size)
            if signal.is_signed and signal.size > 0 and raw & (1 << (signal.size - 1)):
                raw -= 1 << signal.size
            value = raw * signal.factor + signal.offset
            decoded[signal.name] = coerce_number(value)
        return decoded

    def decode_raw(self, payload: bytes) -> dict[str, int]:
        padded = bytes(payload).ljust(self.size, b"\x00")
        decoded: dict[str, int] = {}
        for signal in self.signals:
            raw = extract_signal_raw(padded, signal.bit_positions(), signal.is_little_endian, signal.size)
            if signal.is_signed and signal.size > 0 and raw & (1 << (signal.size - 1)):
                raw -= 1 << signal.size
            decoded[signal.name] = raw
        return decoded


@dataclass
class DBCDatabase:
    path: Path
    messages: list[DBCMessage] = field(default_factory=list)
    messages_by_id: dict[int, DBCMessage] = field(default_factory=dict)
    messages_by_name: dict[str, DBCMessage] = field(default_factory=dict)

    @property
    def requires_fd(self) -> bool:
        return any(message.size > 8 for message in self.messages)

    @property
    def signal_count(self) -> int:
        return sum(len(message.signals) for message in self.messages)

    def message_for_id(self, frame_id: int) -> DBCMessage | None:
        return self.messages_by_id.get(frame_id)

    def encode_frame(self, frame_id: int, values: dict[str, Any]) -> bytes:
        message = self.message_for_id(frame_id)
        if message is None:
            raise KeyError(f"unknown DBC message id: 0x{frame_id:x}")
        return message.encode(values)

    def decode_frame(self, frame_id: int, payload: bytes) -> tuple[DBCMessage | None, dict[str, int | float]]:
        message = self.message_for_id(frame_id)
        if message is None:
            return None, {}
        return message, message.decode(payload)


def load_dbc_database(path: Path | str) -> DBCDatabase:
    file_path = Path(path)
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        raise FileNotFoundError(f"could not read DBC file {file_path}: {exc}") from exc

    messages: list[DBCMessage] = []
    message_by_id: dict[int, DBCMessage] = {}
    message_by_name: dict[str, DBCMessage] = {}
    pending_choices: dict[tuple[int, str], list[tuple[int, str]]] = {}
    current_message: DBCMessage | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("BO_"):
            match = BO_RE.match(stripped)
            if match is None:
                continue
            frame_id = parse_int(match.group("id"))
            current_message = DBCMessage(
                frame_id=frame_id,
                name=match.group("name"),
                size=parse_int(match.group("size")),
                transmitter=match.group("tx"),
                is_extended_id=frame_id > 0x7FF,
            )
            messages.append(current_message)
            message_by_id[frame_id] = current_message
            message_by_name[current_message.name] = current_message
            continue
        if stripped.startswith("SG_") and current_message is not None:
            match = SG_RE.match(stripped)
            if match is None:
                continue
            signal = DBCSignal(
                name=match.group("name"),
                start_bit=parse_int(match.group("start")),
                size=parse_int(match.group("size")),
                byte_order="little_endian" if match.group("byte_order") == "1" else "big_endian",
                is_signed=match.group("sign") == "-",
                factor=parse_float(match.group("factor")),
                offset=parse_float(match.group("offset")),
                minimum=parse_float(match.group("minimum")),
                maximum=parse_float(match.group("maximum")),
                unit=match.group("unit"),
                receivers=normalize_names(match.group("receivers")),
                multiplex=match.group("mux"),
            )
            current_message.signals.append(signal)
            continue
        if stripped.startswith("VAL_"):
            match = VAL_RE.match(stripped)
            if match is None:
                continue
            frame_id = parse_int(match.group("msg_id"))
            signal_name = match.group("signal")
            choices = [(parse_int(value), name) for value, name in VAL_PAIR_RE.findall(match.group("body"))]
            if choices:
                pending_choices.setdefault((frame_id, signal_name), []).extend(choices)

    for message in messages:
        for signal in message.signals:
            key = (message.frame_id, signal.name)
            if key in pending_choices:
                signal.choices = tuple(pending_choices[key])

    return DBCDatabase(
        path=file_path,
        messages=messages,
        messages_by_id=message_by_id,
        messages_by_name=message_by_name,
    )


def encode_signal_value(signal: DBCSignal, value: Any) -> int:
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            for raw_value, name in signal.choices:
                if name == value:
                    value = raw_value
                    break
            else:
                raise ValueError(f"cannot encode non-numeric value for signal {signal.name!r}: {value!r}")

    if signal.factor == 0:
        raise ValueError(f"invalid zero factor for signal {signal.name!r}")

    raw = int(round((float(value) - signal.offset) / signal.factor))
    if signal.size >= 64:
        return raw
    mask = (1 << signal.size) - 1
    return raw & mask


def insert_signal_bits(payload: bytearray, positions: list[int], raw: int, little_endian: bool, size: int) -> None:
    if little_endian:
        for bit_index, position in enumerate(positions):
            set_bit(payload, position, (raw >> bit_index) & 1)
        return

    for bit_index, position in enumerate(positions):
        shift = size - 1 - bit_index
        set_bit(payload, position, (raw >> shift) & 1)


def extract_signal_raw(payload: bytes, positions: list[int], little_endian: bool, size: int) -> int:
    if little_endian:
        raw = 0
        for bit_index, position in enumerate(positions):
            raw |= get_bit(payload, position) << bit_index
        return raw

    raw = 0
    for position in positions:
        raw = (raw << 1) | get_bit(payload, position)
    if size >= 64:
        return raw
    return raw & ((1 << size) - 1)


def set_bit(payload: bytearray, bit_index: int, bit: int) -> None:
    byte_index = bit_index // 8
    if byte_index < 0 or byte_index >= len(payload):
        return
    mask = 1 << (bit_index % 8)
    if bit:
        payload[byte_index] |= mask
    else:
        payload[byte_index] &= ~mask


def get_bit(payload: bytes, bit_index: int) -> int:
    byte_index = bit_index // 8
    if byte_index < 0 or byte_index >= len(payload):
        return 0
    return (payload[byte_index] >> (bit_index % 8)) & 1

