from __future__ import annotations

import logging
import os
import sys
from typing import Any, TextIO


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


configure_logging()

