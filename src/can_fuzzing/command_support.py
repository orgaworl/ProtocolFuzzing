from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Iterator

from .config import build_hardware_config, parse_interface_names
from .log import log_structured, print_interface_table
from .runtime.errors import CANConnectionError
from .runtime.models import CANHardwareConfig
from .scanning.hardware_scan import list_can_interfaces


def resolve_hardware(args: SimpleNamespace, section: str) -> CANHardwareConfig:
    args.interface, args.channel = resolve_interface_and_channel(args, section)
    return build_hardware_config(vars(args))


def resolve_interface_and_channel(args: SimpleNamespace, section: str) -> tuple[str, str]:
    interface = getattr(args, "interface", None)
    channel = getattr(args, "channel", None)
    if interface and channel:
        return str(interface), str(channel)

    log_structured("warning", section, {"interface": "missing", "channel": "missing", "action": "running_interface_discovery"})
    configs = discover_interfaces(args, interface=interface)

    if getattr(args, "json", False):
        print(json.dumps(configs, indent=2, default=str))
    else:
        print_interface_table(configs)

    if not configs:
        raise SystemExit(2)
    if len(configs) == 1:
        selected = configs[0]
        log_structured("warning", "auto_selected", {"interface": selected.get("interface", ""), "channel": selected.get("channel", "")})
        return str(selected.get("interface", "")), str(selected.get("channel", ""))

    selected = prompt_interface_selection(configs)
    log_structured("warning", "selected", {"interface": selected.get("interface", ""), "channel": selected.get("channel", "")})
    return str(selected.get("interface", "")), str(selected.get("channel", ""))


def discover_interfaces(args: SimpleNamespace, interface: Any | None = None) -> list[dict[str, Any]]:
    interfaces = parse_interface_names(args.interfaces) if getattr(args, "interfaces", None) else None
    if interface and interfaces is None:
        interfaces = [str(interface)]
    try:
        return list_can_interfaces(
            interfaces=interfaces,
            include_virtual=getattr(args, "include_virtual", False),
            verbose=getattr(args, "verbose", False),
        )
    except RuntimeError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc


def prompt_interface_selection(configs: list[dict[str, Any]]) -> dict[str, Any]:
    while True:
        log_structured("info", "select_interface", {"action": "choose_by_index", "options": len(configs)})
        for index, config in enumerate(configs, start=1):
            log_structured(
                "info",
                f"option[{index}]",
                {
                    "interface": config.get("interface", ""),
                    "channel": config.get("channel", ""),
                    "device": config.get("device_name") or config.get("device") or "",
                },
            )
        try:
            choice = input(f"select CAN interface [1-{len(configs)}]: ").strip()
        except EOFError:
            raise SystemExit(2) from None
        if not choice:
            continue
        try:
            index = int(choice)
        except ValueError:
            log_structured("warning", "selection", {"value": choice, "reason": "numeric_index_required"})
            continue
        if 1 <= index <= len(configs):
            return configs[index - 1]
        log_structured("warning", "selection", {"value": choice, "range": f"1-{len(configs)}"})


@contextmanager
def command_errors() -> Iterator[None]:
    try:
        yield
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
