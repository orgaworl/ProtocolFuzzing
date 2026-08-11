from __future__ import annotations

import random


def random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))

