from __future__ import annotations

import random
from collections.abc import Callable
from typing import Protocol


class ProgressConfig(Protocol):
    cases: int
    progress_interval: int
    progress_seconds: float


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


