from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class FrameFormat(str, Enum):
    STANDARD = "standard"
    EXTENDED = "extended"


class FrameType(str, Enum):
    DATA = "data"
    REMOTE = "remote"
    ERROR = "error"


@dataclass(frozen=True)
class CANFrame:
    identifier: int
    data: bytes
    frame_format: FrameFormat = FrameFormat.STANDARD
    frame_type: FrameType = FrameType.DATA
    timestamp_ms: int = 0

    @property
    def dlc(self) -> int:
        return len(self.data)

    @property
    def max_identifier(self) -> int:
        if self.frame_format == FrameFormat.STANDARD:
            return 0x7FF
        return 0x1FFFFFFF

    def is_identifier_valid(self) -> bool:
        return 0 <= self.identifier <= self.max_identifier

    def is_dlc_valid(self) -> bool:
        if self.frame_type == FrameType.REMOTE:
            return 0 <= self.dlc <= 8
        return 0 <= self.dlc <= 64

    def to_hex_payload(self) -> str:
        return self.data.hex()

    @classmethod
    def from_ints(
        cls,
        identifier: int,
        values: Iterable[int],
        frame_format: FrameFormat = FrameFormat.STANDARD,
        frame_type: FrameType = FrameType.DATA,
        timestamp_ms: int = 0,
    ) -> "CANFrame":
        return cls(
            identifier=identifier,
            data=bytes(v & 0xFF for v in values),
            frame_format=frame_format,
            frame_type=frame_type,
            timestamp_ms=timestamp_ms,
        )



