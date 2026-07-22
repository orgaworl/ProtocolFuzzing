from __future__ import annotations

import os
import sys
from typing import Any, TextIO


RESET = "\033[0m"
COLORS = {
    "normal": "\033[37m",
    "warning": "\033[33m",
    "error": "\033[31m",
    "debug": "\033[32m",
    "tx": "\033[36m",
    "rx": "\033[32m",
}


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


def colorize(message: str, level: str, stream: TextIO) -> str:
    if not color_enabled(stream):
        return message
    return f"{COLORS[level]}{message}{RESET}"


def log(message: Any, level: str = "normal", stream: TextIO | None = None, **kwargs: Any) -> None:
    target = stream or sys.stdout
    print(colorize(str(message), level, target), file=target, **kwargs)


def info(message: Any, **kwargs: Any) -> None:
    log(message, "normal", **kwargs)


def warning(message: Any, **kwargs: Any) -> None:
    log(message, "warning", **kwargs)


def error(message: Any, **kwargs: Any) -> None:
    log(message, "error", stream=sys.stderr, **kwargs)


def debug(message: Any, **kwargs: Any) -> None:
    log(message, "debug", **kwargs)


enable_windows_ansi()
