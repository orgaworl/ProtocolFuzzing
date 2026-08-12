from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from .runtime.keepalive import KeepaliveConfig


RESET = "\033[0m"
COLORS = {
    logging.DEBUG: "\033[32m",
    logging.INFO: "\033[37m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[31m",
}

LOGGER_NAME = "can_fuzzing"
_LOGGER = logging.getLogger(LOGGER_NAME)


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        stream = getattr(record, "stream", sys.stdout)
        if not color_enabled(stream):
            return message
        color = COLORS.get(record.levelno, COLORS[logging.INFO])
        return f"{color}{message}{RESET}"


class SplitStreamHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(ColorFormatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stream = sys.stderr if record.levelno >= logging.ERROR else sys.stdout
            record.stream = stream
            stream.write(self.format(record) + "\n")
            stream.flush()
        except Exception:
            self.handleError(record)


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
    except ImportError:
        return

    kernel32 = ctypes.windll.kernel32
    enable_virtual_terminal_processing = 0x0004
    for handle_id in (-11, -12):
        handle = kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            continue
        kernel32.SetConsoleMode(handle, mode.value | enable_virtual_terminal_processing)


def color_enabled(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def configure_logging(level: int = logging.DEBUG) -> logging.Logger:
    enable_windows_ansi()
    _LOGGER.handlers.clear()
    _LOGGER.addHandler(SplitStreamHandler())
    _LOGGER.setLevel(level)
    _LOGGER.propagate = False
    return _LOGGER


def set_debug(enabled: bool) -> None:
    _LOGGER.setLevel(logging.DEBUG if enabled else logging.INFO)


def log(message: Any, level: str = "normal", stream: TextIO | None = None, **kwargs: Any) -> None:
    if stream is not None:
        kwargs.pop("file", None)
    kwargs.pop("flush", None)
    if level == "debug":
        _LOGGER.debug(str(message))
    elif level in {"warning", "warn"}:
        _LOGGER.warning(str(message))
    elif level == "error":
        _LOGGER.error(str(message))
    else:
        _LOGGER.info(str(message))


def info(message: Any, **kwargs: Any) -> None:
    log(message, "normal", **kwargs)


def warning(message: Any, **kwargs: Any) -> None:
    log(message, "warning", **kwargs)


def error(message: Any, **kwargs: Any) -> None:
    log(message, "error", **kwargs)


def debug(message: Any, **kwargs: Any) -> None:
    log(message, "debug", **kwargs)


ACTIVE_RUN_SUMMARY: dict[str, Any] = {}


def log_structured(level: str, title: str, values: dict[str, Any]) -> None:
    message = f"{title} {format_structured_block(values)}"
    if level == "error":
        error(message)
    elif level == "warning":
        warning(message)
    elif level == "debug":
        debug(message)
    else:
        info(message)

def start_run_summary(command: str, protocol: str, campaign: str, requested_cases: int | None = None) -> None:
    ACTIVE_RUN_SUMMARY.clear()
    ACTIVE_RUN_SUMMARY.update(
        {
            "command": command,
            "protocol": protocol,
            "campaign": campaign,
            "requested_cases": requested_cases,
            "completed_cases": 0,
            "sent": 0,
            "faults": 0,
            "responses": 0,
            "last_tx_id": None,
            "last_tx_payload": "",
            "last_state": "",
            "last_error": "",
        }
    )


def record_run_event(snapshot: dict[str, Any]) -> None:
    if not ACTIVE_RUN_SUMMARY or snapshot.get("event") != "can_exchange":
        return
    if "case_id" in snapshot:
        completed = int(snapshot.get("case_id", -1)) + 1
    elif "probe_index" in snapshot:
        completed = int(snapshot.get("probe_index", 0))
    else:
        completed = int(ACTIVE_RUN_SUMMARY.get("completed_cases", 0)) + 1
    ACTIVE_RUN_SUMMARY["completed_cases"] = max(int(ACTIVE_RUN_SUMMARY.get("completed_cases", 0)), completed)
    ACTIVE_RUN_SUMMARY["sent"] = int(ACTIVE_RUN_SUMMARY.get("sent", 0)) + int(bool(snapshot.get("sent", False)))
    ACTIVE_RUN_SUMMARY["faults"] = int(ACTIVE_RUN_SUMMARY.get("faults", 0)) + int(bool(snapshot.get("fault", False)))
    ACTIVE_RUN_SUMMARY["responses"] = int(ACTIVE_RUN_SUMMARY.get("responses", 0)) + int(snapshot.get("response_count", 0) or 0)
    ACTIVE_RUN_SUMMARY["last_tx_id"] = snapshot.get("tx_id")
    ACTIVE_RUN_SUMMARY["last_tx_payload"] = snapshot.get("tx_payload", "")
    ACTIVE_RUN_SUMMARY["last_state"] = format_tx_result(snapshot)
    ACTIVE_RUN_SUMMARY["last_error"] = snapshot.get("error", "")


def print_keyboard_interrupt_summary(command: str) -> None:
    log_structured("warning", "interrupt", {"signal": "Ctrl+C"})
    summary = dict(ACTIVE_RUN_SUMMARY)
    if not summary:
        log_structured("warning", "interrupt", {"command": command, "status": "interrupted", "reason": "before_campaign_statistics"})
        return
    log_structured("info", "campaign", {"name": summary.get('campaign', '')})
    print_status_line(True)
    requested = summary.get("requested_cases")
    if requested is None:
        log_structured(
            "info",
            "summary",
            {
                "completed": summary.get('completed_cases', 0),
                "sent": summary.get('sent', 0),
                "faults": summary.get('faults', 0),
                "responses": summary.get('responses', 0),
            },
        )
    else:
        log_structured(
            "info",
            "summary",
            {
                "cases": f"{summary.get('completed_cases', 0)}/{requested}",
                "sent": summary.get('sent', 0),
                "faults": summary.get('faults', 0),
                "responses": summary.get('responses', 0),
            },
        )
    if summary.get("last_tx_id") is not None:
        log_structured(
            "info",
            "last_tx",
            {
                "frame": format_frame_block(summary.get('last_tx_id'), payload_dlc(summary.get('last_tx_payload', '')), summary.get('last_tx_payload', '')),
                "state": summary.get('last_state', ''),
            },
        )
    if summary.get("last_error"):
        log_structured("warning", "last_error", {"message": summary['last_error']})

def log_keepalive_response(message: Any) -> None:
    payload = bytes(getattr(message, "data", b""))
    log(
        f"<< [KEEPALIVE] {format_frame_block(getattr(message, 'arbitration_id', None), len(payload), payload, fd=getattr(message, 'is_fd', False))}",
        "rx",
    )


def log_can_event(snapshot: dict[str, Any]) -> None:
    event = snapshot.get("event")
    if event == "can_exchange":
        if str(snapshot.get("protocol", "can")) == "dbc":
            log_dbc_exchange(snapshot)
        else:
            log_can_exchange(snapshot)
    elif event == "can_rx":
        log_can_rx(snapshot)
    elif event == "keepalive_summary":
        log_keepalive_summary(snapshot)


def log_can_exchange(snapshot: dict[str, Any]) -> None:
    record_run_event(snapshot)
    protocol = str(snapshot.get("protocol", "can")).upper()
    context = format_context(snapshot, protocol)
    tags = format_frame_tags(snapshot)
    tag_text = f" {' '.join(tags)}" if tags else ""
    tx_block = format_frame_block(
        snapshot.get("tx_id"),
        snapshot.get("tx_dlc", 0),
        snapshot.get("tx_payload", ""),
        fd=bool(snapshot.get("fd", False)),
        suffix=tag_text.strip(),
    )
    tx_line = (
        f">> {context} {tx_block} "
        f"-> {format_tx_result(snapshot)}"
    )
    error = str(snapshot.get("error", ""))
    if error:
        error(f"{tx_line} error={error}")
    elif bool(snapshot.get("fault", False)):
        warning(tx_line)
    else:
        log(tx_line, "tx")

    response_count = int(snapshot.get("response_count", 0) or 0)
    response_ids = list(snapshot.get("response_ids", []) or [])
    response_payloads = list(snapshot.get("response_payloads", []) or [])
    if response_count == 0:
        return
    for index in range(max(response_count, len(response_ids), len(response_payloads))):
        rx_id = response_ids[index] if index < len(response_ids) else None
        payload = response_payloads[index] if index < len(response_payloads) else ""
        log(
            f"<< {context} {index + 1}/{response_count} {format_frame_block(rx_id, payload_dlc(payload), payload, fd=bool(snapshot.get('fd', False)))}",
            "rx",
        )


def log_dbc_exchange(snapshot: dict[str, Any]) -> None:
    record_run_event(snapshot)
    context = format_context(snapshot, "DBC")
    tx_signal_values = snapshot.get("tx_signal_values", {})
    message_name = str(snapshot.get("message_name", ""))
    strategy = str(snapshot.get("strategy", ""))
    tx_block = format_frame_block(
        snapshot.get("tx_id"),
        snapshot.get("tx_dlc", 0),
        snapshot.get("tx_payload", ""),
        fd=bool(snapshot.get("fd", False)),
    )
    extra_bits: list[str] = []
    if message_name:
        extra_bits.append(f"msg={message_name}")
    if strategy:
        extra_bits.append(f"strategy={strategy}")
    if isinstance(tx_signal_values, dict) and tx_signal_values:
        extra_bits.append(f"signals={format_mapping_block(tx_signal_values)}")
    tx_line = f">> {context} {tx_block}"
    if extra_bits:
        tx_line += " " + " ".join(extra_bits)
    tx_line += f" -> {format_tx_result(snapshot)}"
    error = str(snapshot.get("error", ""))
    if error:
        error(f"{tx_line} error={error}")
    elif bool(snapshot.get("fault", False)):
        warning(tx_line)
    else:
        log(tx_line, "tx")

    response_messages = list(snapshot.get("response_messages", []) or [])
    if response_messages:
        for index, response in enumerate(response_messages, start=1):
            if not isinstance(response, dict):
                continue
            rx_id = response.get("id")
            payload = response.get("payload", "")
            response_name = str(response.get("message_name", ""))
            signals = response.get("signals", {})
            pieces: list[str] = []
            if response_name:
                pieces.append(f"msg={response_name}")
            if isinstance(signals, dict) and signals:
                pieces.append(f"signals={format_mapping_block(signals)}")
            line = f"<< {context} {index}/{len(response_messages)} {format_frame_block(rx_id, payload_dlc(payload), payload, fd=bool(snapshot.get('fd', False)))}"
            if pieces:
                line += " " + " ".join(pieces)
            log(line, "rx")
        return

    response_count = int(snapshot.get("response_count", 0) or 0)
    response_ids = list(snapshot.get("response_ids", []) or [])
    response_payloads = list(snapshot.get("response_payloads", []) or [])
    if response_count == 0:
        return
    for index in range(max(response_count, len(response_ids), len(response_payloads))):
        rx_id = response_ids[index] if index < len(response_ids) else None
        payload = response_payloads[index] if index < len(response_payloads) else ""
        log(
            f"<< {context} {index + 1}/{response_count} {format_frame_block(rx_id, payload_dlc(payload), payload, fd=bool(snapshot.get('fd', False)))}",
            "rx",
        )


def log_can_rx(snapshot: dict[str, Any]) -> None:
    protocol = "KEEPALIVE" if snapshot.get("phase") == "keepalive" else "SCAN"
    context = format_context(snapshot, protocol)
    fd_text = " fd" if bool(snapshot.get("fd", False)) else ""
    log(
        f"<< {context} {format_frame_block(snapshot.get('rx_id'), snapshot.get('rx_dlc', 0), snapshot.get('rx_payload', ''), fd=bool(snapshot.get('fd', False)), suffix=fd_text.strip())}",
        "rx",
    )


def log_keepalive_summary(snapshot: dict[str, Any]) -> None:
    log_structured(
        "info",
        "keepalive_summary",
        {
            "sent": snapshot.get('sent', 0),
            "errors": snapshot.get('errors', 0),
            "responses": snapshot.get('responses', 0),
        },
    )
    if snapshot.get("csv_path"):
        log_structured("info", "keepalive_csv", {"path": snapshot['csv_path']})
    if snapshot.get("last_error"):
        log_structured("warning", "keepalive_last_error", {"message": snapshot['last_error']})


def log_shared_keepalive_config(config: KeepaliveConfig, csv_path: Path) -> None:
    if not config.enabled:
        log_structured("debug", "keepalive", {"enabled": False})
        return
    frame_format = "extended" if config.extended else "standard"
    log_structured(
        "info",
        "keepalive",
        {
            "enabled": True,
            "shared_adapter": True,
            "interval_ms": config.interval_ms,
            "listen": config.listen,
            "frame": format_frame_block(
                config.arbitration_id,
                len(config.payload),
                config.payload,
                fd=config.fd,
                suffix=' '.join(item for item in [frame_format if frame_format != 'standard' else '', 'fd' if config.fd else ''] if item),
            ),
            "csv": csv_path,
        },
    )


def format_context(snapshot: dict[str, Any], protocol: str) -> str:
    if "case_id" in snapshot:
        current = int(snapshot.get("case_id", 0)) + 1
        total = snapshot.get("total_cases")
        value = f"{current}/{total}" if total is not None else str(current)
        return f"[{protocol} {value}]"
    if "probe_index" in snapshot:
        current = int(snapshot.get("probe_index", 0))
        total = snapshot.get("total_probes")
        value = f"{current}/{total}" if total is not None else str(current)
        return f"[{protocol} probe {value}]"
    phase = snapshot.get("phase")
    if phase:
        return f"[{protocol} {phase}]"
    return f"[{protocol}]"


def format_frame_tags(snapshot: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    if str(snapshot.get("tx_format", "standard")) != "standard":
        tags.append(str(snapshot.get("tx_format")))
    frame_type = str(snapshot.get("tx_type", "data"))
    if frame_type != "data":
        tags.append(frame_type)
    if bool(snapshot.get("fd", False)):
        tags.append("fd")
    return tags


def format_tx_result(snapshot: dict[str, Any]) -> str:
    if not bool(snapshot.get("sent", False)):
        return "send_failed"
    reason = str(snapshot.get("reason", ""))
    state = str(snapshot.get("state", ""))
    if state == "response" and reason == "response_received":
        return "response"
    if state == "no_response" and reason == "no_response":
        return "no_response"
    if state == "send_error" and reason == "send_error":
        return "send_error"
    if reason and reason != state:
        return f"{state}/{reason}" if state else reason
    return state or reason or "sent"


def format_can_id(value: Any) -> str:
    if value is None or value == "":
        return "0x--------"
    try:
        return f"0x{int(value) & 0xFFFFFFFF:08X}"
    except (TypeError, ValueError):
        return str(value).ljust(10)[:10]


def format_frame_block(frame_id: Any, dlc: Any, payload: Any, fd: bool = False, suffix: str = "") -> str:
    suffix_text = f" {suffix}" if suffix else ""
    return f"{{ {format_can_id(frame_id)}{suffix_text} [{dlc}] {format_hex_payload(payload, fd=fd)} }}"


def format_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def format_hex_payload(value: Any, fd: bool = False) -> str:
    bytes_text = split_hex_payload(value)
    visible = bytes_text[:8]
    payload = " ".join(visible).ljust(23)
    if fd and len(bytes_text) > 8:
        return f"{payload} ..."
    return payload


def format_mapping_block(values: dict[str, Any], max_items: int = 6) -> str:
    if not values:
        return "{}"
    items = list(values.items())
    parts = [f"{key}={format_scalar(value)}" for key, value in items[:max_items]]
    if len(items) > max_items:
        parts.append("...")
    return "{ " + " ".join(parts) + " }"


def format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.6g}"
    return str(value)


def split_hex_payload(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, bytes):
        raw = value.hex()
    else:
        raw = str(value).replace(" ", "").replace(";", "")
    if not raw:
        return []
    return [raw[index : index + 2].upper() for index in range(0, len(raw), 2)]


def payload_dlc(value: Any) -> int:
    if isinstance(value, bytes):
        return len(value)
    return len(split_hex_payload(value))

def print_interface_table(configs: list[dict[str, Any]]) -> None:
    if not configs:
        log_structured("warning", "discovery", {"interfaces": 0, "result": "none"})
        return
    rows = [format_interface_row(config) for config in configs]
    headers = ["interface", "channel", "device", "fd", "condition"]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    debug("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    debug("  ".join("-" * width for width in widths))
    for row in rows:
        debug("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def print_scan_objects_table(objects: list[dict[str, Any]]) -> None:
    if not objects:
        log_structured("warning", "scan_objects", {"count": 0, "result": "none"})
        return

    headers = ["id", "count", "first_seen", "last_seen", "dlcs", "samples"]
    rows = [
        [
            str(item.get("id", "")),
            str(item.get("count", "")),
            str(item.get("first_seen", "")),
            str(item.get("last_seen", "")),
            str(item.get("dlcs", "")),
            str(item.get("samples", "")),
        ]
        for item in objects
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    log_structured("debug", "scan_objects", {"count": len(objects)})
    debug("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    debug("  ".join("-" * width for width in widths))
    for row in rows:
        debug("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))



def print_isotp_nodes_table(nodes: list[dict[str, Any]]) -> None:
    if not nodes:
        log_structured("warning", "isotp_nodes", {"count": 0, "result": "none"})
        return

    headers = ["request_id", "response_id", "frame_format", "addressing", "response_payload"]
    rows = [
        [
            str(item.get("request_id", "")),
            str(item.get("response_id", "")),
            str(item.get("frame_format", "")),
            str(item.get("addressing", "")),
            str(item.get("response_payload", "")),
        ]
        for item in nodes
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    log_structured("debug", "isotp_nodes", {"count": len(nodes)})
    debug("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    debug("  ".join("-" * width for width in widths))
    for row in rows:
        debug("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))

def format_interface_row(config: dict[str, Any]) -> list[str]:
    return [
        str(config.get("interface", "")),
        str(config.get("channel", "")),
        str(config.get("device_name") or config.get("device") or ""),
        format_unknown_bool(config.get("supports_fd")),
        format_condition(config),
    ]


def format_unknown_bool(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def format_condition(config: dict[str, Any]) -> str:
    condition = config.get("channel_condition")
    if config.get("interface") == "pcan":
        labels = {
            0: "unavailable",
            1: "available",
            2: "occupied",
            3: "occupied by PCAN-View",
        }
        return labels.get(condition, str(condition))
    if condition is None:
        return ""
    return str(condition)


def print_status_line(interrupted: bool) -> None:
    status = "interrupted" if interrupted else "completed"
    print_status_value(status)


def print_status_value(status: str) -> None:
    log_structured(status_level(status), "status", {"value": status})


def format_structured_block(values: dict[str, Any], max_items: int = 8) -> str:
    if not values:
        return "{}"
    items = list(values.items())
    parts = [f"{key}={format_scalar(value)}" for key, value in items[:max_items]]
    if len(items) > max_items:
        parts.append("...")
    return "{ " + " ".join(parts) + " }"


def status_level(status: str) -> str:
    lowered = status.lower()
    if "error" in lowered or "failed" in lowered or "fail" in lowered:
        return "error"


configure_logging()






