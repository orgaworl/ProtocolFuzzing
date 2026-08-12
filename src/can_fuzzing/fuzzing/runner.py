from __future__ import annotations

import csv
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Iterator

from ..runtime.adapters import CANHardwareAdapter
from ..runtime.keepalive import KeepaliveConfig, KeepaliveSession
from ..runtime.models import CANHardwareConfig
from ..runtime.types import ProgressCallback


class FuzzRunConfig(Protocol):
    hardware: CANHardwareConfig
    campaign: str
    output_dir: Path
    keepalive: KeepaliveConfig


@dataclass(frozen=True)
class FuzzRunContext:
    adapter: CANHardwareAdapter
    writer: csv.DictWriter
    csv_file: object


@contextmanager
def open_fuzz_run(
    config: FuzzRunConfig,
    csv_path: Path,
    fieldnames: list[str],
    progress_callback: ProgressCallback | None = None,
) -> Iterator[FuzzRunContext]:
    with CANHardwareAdapter(config.hardware) as adapter, KeepaliveSession(
        adapter,
        config.keepalive,
        config.output_dir / f"{config.campaign}_keepalive.csv",
        progress_callback,
    ), csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        fh.flush()
        yield FuzzRunContext(adapter=adapter, writer=writer, csv_file=fh)
