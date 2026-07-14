from __future__ import annotations

import contextlib
import io
import logging
from typing import Any


DEFAULT_DISCOVERY_INTERFACES = [
    "pcan",
    "vector",
    "kvaser",
    "slcan",
    "seeedstudio",
    "socketcan",
    "virtual",
]


def list_can_interfaces(
    interfaces: list[str] | None = None,
    include_virtual: bool = False,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    try:
        import can
    except ImportError as exc:
        raise RuntimeError(
            "python-can is required for CAN interface discovery. "
            "Install dependencies with pip install -e . or pip install python-can."
        ) from exc

    selected = interfaces or DEFAULT_DISCOVERY_INTERFACES
    if verbose:
        configs = can.detect_available_configs(interfaces=selected)
    else:
        previous_disable_level = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        with contextlib.redirect_stderr(io.StringIO()):
            configs = can.detect_available_configs(interfaces=selected)
        logging.disable(previous_disable_level)

    result: list[dict[str, Any]] = []
    for config in configs:
        if not include_virtual and config.get("interface") == "virtual":
            continue
        result.append(normalize_config(config))
    return sorted(result, key=lambda item: (str(item.get("interface", "")), str(item.get("channel", ""))))


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            normalized[key] = value
        else:
            normalized[key] = str(value)
    return normalized
