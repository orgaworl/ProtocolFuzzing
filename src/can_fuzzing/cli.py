from __future__ import annotations

import logging
import sys
from typing import Any

import click

from .config import (
    CLEAN_KEYS,
    FDCHECK_KEYS,
    FUZZ_KEYS,
    KEEPALIVE_CLI_KEYS,
    LIST_KEYS,
    SCAN_KEYS,
    build_args,
    build_keepalive_args,
)
from .commands import (
    run_clean_from_args,
    run_fdcheck_from_args,
    run_fuzz_from_args,
    run_keepalive_from_args,
    run_list_from_args,
    run_scan_from_args,
)
from .log import configure_logging, print_keyboard_interrupt_summary


CLICK_CONTEXT = {"help_option_names": ["-h", "--help"]}
COMMON_CONFIG_OPTION = (("-c", "--config"), {"type": click.Path(dir_okay=False), "default": "config.toml", "show_default": True, "help": "TOML config file"})
SHORT_FUZZ_HELP = """Usage: fuzz [OPTIONS]

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        TOML config file; command line options override config values
  --protocol PROTOCOL   fuzzing protocol: can, dbc, uds, obd, private, or xcp
  --interface INTERFACE python-can interface, for example pcan, vector, slcan, socketcan
  --channel CHANNEL     CAN channel name used by the selected python-can interface
  --cases CASES         number of generated requests or frames
  --seed SEED           random seed
  --delay-ms DELAY_MS   delay between generated frames or requests
  --target-id TARGET_ID
                        target CAN ID for this fuzzing run
  --keepalive / --no-keepalive
                        send keepalive frames during fuzzing"""


def command_options(specs):
    def decorator(func):
        for declarations, kwargs in reversed(specs):
            func = click.option(*declarations, **kwargs)(func)
        return func
    return decorator


def click_invoked_without_options(ctx: click.Context) -> bool:
    return all(ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT for name in ctx.params)


def invoke_click(command: click.Command, prog_name: str) -> None:
    configure_logging(logging.DEBUG)
    try:
        command.main(prog_name=prog_name, standalone_mode=False)
    except (KeyboardInterrupt, click.Abort) as exc:
        print_keyboard_interrupt_summary(prog_name)
        raise SystemExit(130) from exc
    except click.ClickException as exc:
        exc.show(file=sys.stderr)
        raise SystemExit(exc.exit_code) from exc

FUZZ_OPTIONS = [
    COMMON_CONFIG_OPTION,
    (("--protocol",), {"default": None, "help": "fuzzing protocol: can, dbc, uds, obd, private, or xcp"}),
    (("--interface",), {"default": None, "help": "python-can interface"}),
    (("--channel",), {"default": None, "help": "python-can channel"}),
    (("--cases",), {"type": int, "default": None, "help": "number of generated requests or frames"}),
    (("--seed",), {"type": int, "default": None, "help": "random seed"}),
    (("--delay-ms",), {"type": float, "default": None, "help": "delay between generated frames or requests"}),
    (("--target-id",), {"default": None, "help": "target CAN ID for this fuzzing run, for example 0x7e0"}),
    (("--keepalive/--no-keepalive",), {"default": None, "help": "send keepalive frames during fuzzing"}),
]

SCAN_OPTIONS = [
    COMMON_CONFIG_OPTION,
    (("--protocol", "scan_protocol"), {"default": None, "help": "scan protocol: all, can, isotp, uds, obd, or xcp"}),
]

LIST_OPTIONS = [
    COMMON_CONFIG_OPTION,
    (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include virtual CAN backends"}),
    (("--json", "json"), {"is_flag": True, "default": None, "help": "print detected interfaces as JSON"}),
    (("--verbose",), {"is_flag": True, "default": None, "help": "print backend debug information during discovery"}),
]


@click.command(context_settings=CLICK_CONTEXT, help="Run a CAN or CAN-based protocol fuzzing campaign on a real device.")
@click.pass_context
@command_options(FUZZ_OPTIONS)
def _fuzz_click(ctx: click.Context, **params: Any) -> None:
    if click_invoked_without_options(ctx):
        click.echo(SHORT_FUZZ_HELP)
        return
    run_fuzz_from_args(build_args("fuzz", FUZZ_KEYS, params))


@click.command(context_settings=CLICK_CONTEXT, help="Remove generated files from result directory.")
@command_options([COMMON_CONFIG_OPTION])
def _clean_click(**params: Any) -> None:
    run_clean_from_args(build_args("clean", CLEAN_KEYS, params))


@click.command(context_settings=CLICK_CONTEXT, help="List available CAN interfaces detected by python-can.")
@command_options(LIST_OPTIONS)
def _list_click(**params: Any) -> None:
    run_list_from_args(build_args("list", LIST_KEYS, params))

@click.command(context_settings=CLICK_CONTEXT, help="Send periodic keepalive frames on a real CAN device.")
@command_options([COMMON_CONFIG_OPTION])
def _keepalive_click(**params: Any) -> None:
    run_keepalive_from_args(build_keepalive_args(params))


@click.command(context_settings=CLICK_CONTEXT, help="Test whether the CAN hardware and target device support CAN FD.")
@command_options([COMMON_CONFIG_OPTION])
def _fdcheck_click(**params: Any) -> None:
    run_fdcheck_from_args(build_args("fdcheck", FDCHECK_KEYS, params))


@click.command(context_settings=CLICK_CONTEXT, help="Scan devices and message IDs on a real CAN bus.")
@command_options(SCAN_OPTIONS)
def _scan_click(**params: Any) -> None:
    run_scan_from_args(build_args("scan", SCAN_KEYS, params))


def fuzz_main() -> None:
    invoke_click(_fuzz_click, "fuzz")


def clean_main() -> None:
    invoke_click(_clean_click, "clean")


def list_main() -> None:
    invoke_click(_list_click, "list")


def keepalive_main() -> None:
    invoke_click(_keepalive_click, "keepalive")


def fdcheck_main() -> None:
    invoke_click(_fdcheck_click, "fdcheck")


def scan_main() -> None:
    invoke_click(_scan_click, "scan")
