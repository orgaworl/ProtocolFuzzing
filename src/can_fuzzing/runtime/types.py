from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeAlias

ProgressEvent: TypeAlias = dict[str, object]
ProgressCallback: TypeAlias = Callable[[ProgressEvent], None]
MessageCallback: TypeAlias = Callable[[Any], None]
