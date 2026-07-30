from __future__ import annotations

import logging
import sys
from typing import Any

import click

from .common import console
from .cli_config import (
    CLEAN_DEFAULTS,
    FDCHECK_DEFAULTS,
    FUZZ_DEFAULTS,
    KEEPALIVE_DEFAULTS,
    KEEPALIVE_PRESETS,
    LIST_DEFAULTS,
    PLOT_DEFAULTS,
    SCAN_DEFAULTS,
    build_args,
    build_keepalive_args,
)
from .commands import (
    run_clean_from_args,
    run_fdcheck_from_args,
    run_fuzz_from_args,
    run_keepalive_from_args,
    run_list_from_args,
    run_plot_from_args,
    run_scan_from_args,
)
from .log import print_keyboard_interrupt_summary


CLICK_CONTEXT = {"help_option_names": ["-h", "--help"]}
COMMON_CONFIG_OPTION = (("-c", "--config"), {"type": click.Path(dir_okay=False), "default": None, "help": "TOML config file"})
SHORT_FUZZ_HELP = """Usage: fuzz [OPTIONS]

Options:
  -h, --help            show this help message and exit

required arguments:
  --interface INTERFACE
                        python-can interface, for example pcan, vector, slcan, socketcan
  --channel CHANNEL     CAN channel name used by the selected python-can interface

optional arguments:
  -c CONFIG, --config CONFIG
                        TOML config file; command line options override config values"""


def command_options(specs):
    def decorator(func):
        for declarations, kwargs in reversed(specs):
            func = click.option(*declarations, **kwargs)(func)
        return func
    return decorator


def click_invoked_without_options(ctx: click.Context) -> bool:
    return all(ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT for name in ctx.params)


def invoke_click(command: click.Command, prog_name: str) -> None:
    console.configure_logging(logging.DEBUG)
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
    (("--protocol",), {"default": None, "help": "fuzzing protocol: can, dbc, uds, obd, or private"}),
    (("--interface",), {"default": None, "help": "python-can interface"}),
    (("--channel",), {"default": None, "help": "python-can channel"}),
    (("--interfaces",), {"default": None, "help": "comma separated interfaces to probe during auto discovery"}),
    (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include virtual interfaces during auto discovery"}),
    (("--json/--no-json",), {"default": None, "help": "print discovery results as JSON during auto discovery"}),
    (("--verbose/--no-verbose",), {"default": None, "help": "show backend discovery warnings"}),
    (("--bitrate",), {"default": None, "help": "arbitration bitrate, or none"}),
    (("--cases",), {"type": int, "default": None, "help": "number of generated requests or frames"}),
    (("--seed",), {"type": int, "default": None, "help": "random seed"}),
    (("--campaign",), {"default": None, "help": "campaign name used for output files"}),
    (("--output-dir",), {"default": None, "help": "directory for CSV and JSON results"}),
    (("--receive-timeout",), {"type": float, "default": None, "help": "seconds to collect response frames"}),
    (("--inter-frame-delay-ms",), {"type": float, "default": None, "help": "delay between CAN frames"}),
    (("--inter-request-delay-ms",), {"type": float, "default": None, "help": "delay between protocol requests"}),
    (("--dbc_file",), {"default": None, "help": "DBC file path for --protocol DBC"}),
    (("--request-mode",), {"type": click.Choice(["functional", "physical", "mixed"]), "default": None, "help": "diagnostic request addressing mode"}),
    (("--functional-id",), {"default": None, "help": "functional request ID"}),
    (("--physical-start",), {"default": None, "help": "first physical request ID"}),
    (("--physical-end",), {"default": None, "help": "last physical request ID"}),
    (("--service-bias",), {"type": float, "default": None, "help": "UDS structured service probability"}),
    (("--pid-bias",), {"type": float, "default": None, "help": "OBD common PID probability"}),
    (("--malformed-rate",), {"type": float, "default": None, "help": "malformed request probability"}),
    (("--fd/--no-fd",), {"default": None, "help": "send CAN FD frames"}),
    (("--data-bitrate",), {"default": None, "help": "CAN FD data bitrate, or none"}),
    (("--id-min",), {"default": None, "help": "minimum arbitration ID"}),
    (("--id-max",), {"default": None, "help": "maximum arbitration ID"}),
    (("--diagnostic-bias",), {"type": float, "default": None, "help": "CAN diagnostic ID probability"}),
    (("--extended-probability",), {"type": float, "default": None, "help": "extended ID probability"}),
    (("--include-remote/--no-include-remote",), {"default": None, "help": "include remote frames"}),
    (("--include-error/--no-include-error",), {"default": None, "help": "include error frames"}),
    (("--target-ids",), {"default": None, "help": "comma separated private target IDs"}),
    (("--opcodes",), {"default": None, "help": "comma separated private opcodes"}),
    (("--structured-rate",), {"type": float, "default": None, "help": "private structured payload probability"}),
    (("--min-payload-len",), {"type": int, "default": None, "help": "minimum payload length"}),
    (("--max-payload-len",), {"type": int, "default": None, "help": "maximum payload length"}),
    (("--extended/--no-extended",), {"default": None, "help": "use extended CAN identifiers"}),
    (("--progress-interval",), {"type": int, "default": None, "help": "count-based progress interval"}),
    (("--progress-seconds",), {"type": float, "default": None, "help": "time-based progress interval"}),
    (("--no-progress/--progress",), {"default": None, "help": "compatibility flag; logs are line-based"}),
    (("--keepalive/--no-keepalive",), {"default": None, "help": "send keepalive frames during fuzzing"}),
    (("--keepalive-preset",), {"type": click.Choice(sorted(KEEPALIVE_PRESETS)), "default": None, "help": "keepalive preset"}),
    (("--keepalive-id",), {"default": None, "help": "override keepalive arbitration ID"}),
    (("--keepalive-payload",), {"default": None, "help": "override keepalive payload"}),
    (("--keepalive-interval-ms",), {"type": float, "default": None, "help": "delay between keepalive frames"}),
    (("--keepalive-format",), {"type": click.Choice(["standard", "extended"]), "default": None, "help": "keepalive frame format"}),
    (("--keepalive-fd/--no-keepalive-fd",), {"default": None, "help": "send keepalive as CAN FD"}),
    (("--keepalive-listen/--no-keepalive-listen",), {"default": None, "help": "listen for keepalive responses"}),
    (("--keepalive-listen-timeout",), {"type": float, "default": None, "help": "keepalive response timeout"}),
    (("--keepalive-check-message/--no-keepalive-check-message",), {"default": None, "help": "validate keepalive messages"}),
]


@click.command(context_settings=CLICK_CONTEXT, help="Run a CAN or CAN-based protocol fuzzing campaign on a real device.")
@click.pass_context
@command_options(FUZZ_OPTIONS)
def _fuzz_click(ctx: click.Context, **params: Any) -> None:
    if click_invoked_without_options(ctx):
        click.echo(SHORT_FUZZ_HELP)
        return
    run_fuzz_from_args(build_args("fuzz", FUZZ_DEFAULTS, params))


@click.command(context_settings=CLICK_CONTEXT, help="Generate PDF plots from CAN fuzzing result files.")
@command_options([COMMON_CONFIG_OPTION, (("--input",), {"default": None, "help": "input CSV result file"}), (("--output-dir",), {"default": None, "help": "directory for generated PDF figures"})])
def _plot_click(**params: Any) -> None:
    run_plot_from_args(build_args("plot", PLOT_DEFAULTS, params))


@click.command(context_settings=CLICK_CONTEXT, help="Remove generated files from result and plot directories.")
@command_options([COMMON_CONFIG_OPTION, (("--result-dir",), {"default": None, "help": "result directory to clean"}), (("--plot-dir",), {"default": None, "help": "plot directory to clean"})])
def _clean_click(**params: Any) -> None:
    run_clean_from_args(build_args("clean", CLEAN_DEFAULTS, params))


@click.command(context_settings=CLICK_CONTEXT, help="List available CAN interfaces detected by python-can.")
@command_options([COMMON_CONFIG_OPTION, (("--interfaces",), {"default": None, "help": "comma separated python-can backends to probe"}), (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include python-can virtual channels"}), (("--json/--no-json",), {"default": None, "help": "print raw discovery results as JSON"}), (("--verbose/--no-verbose",), {"default": None, "help": "show backend discovery warnings"})])
def _list_click(**params: Any) -> None:
    run_list_from_args(build_args("list", LIST_DEFAULTS, params))

@click.command(context_settings=CLICK_CONTEXT, help="Send periodic keepalive frames on a real CAN device.")
@command_options([
    COMMON_CONFIG_OPTION,
    (("--preset",), {"type": click.Choice(sorted(KEEPALIVE_PRESETS)), "default": None, "help": "activation frame preset"}),
    (("--interface",), {"default": None, "help": "python-can interface"}),
    (("--channel",), {"default": None, "help": "python-can channel"}),
    (("--interfaces",), {"default": None, "help": "comma separated interfaces to probe during auto discovery"}),
    (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include virtual interfaces during auto discovery"}),
    (("--json/--no-json",), {"default": None, "help": "print discovery results as JSON during auto discovery"}),
    (("--verbose/--no-verbose",), {"default": None, "help": "show backend discovery warnings"}),
    (("--bitrate",), {"default": None, "help": "arbitration bitrate, or none"}),
    (("--data-bitrate",), {"default": None, "help": "CAN FD data bitrate, or none"}),
    (("--fd/--no-fd",), {"default": None, "help": "send the activation frame as CAN FD"}),
    (("--arbitration-id",), {"default": None, "help": "activation frame arbitration ID"}),
    (("--payload",), {"default": None, "help": "activation frame hex payload"}),
    (("--interval-ms",), {"type": float, "default": None, "help": "delay between activation frames"}),
    (("--format",), {"type": click.Choice(["standard", "extended"]), "default": None, "help": "activation frame format"}),
    (("--listen/--no-listen",), {"default": None, "help": "listen for responses"}),
    (("--listen-timeout",), {"type": float, "default": None, "help": "seconds to wait for responses"}),
    (("--check-message/--no-check-message",), {"default": None, "help": "validate CAN messages before sending"}),
])
def _keepalive_click(**params: Any) -> None:
    run_keepalive_from_args(build_keepalive_args(params))


@click.command(context_settings=CLICK_CONTEXT, help="Test whether the CAN hardware and target device support CAN FD.")
@command_options([
    COMMON_CONFIG_OPTION,
    (("--interface",), {"default": None, "help": "python-can interface"}),
    (("--channel",), {"default": None, "help": "python-can channel"}),
    (("--interfaces",), {"default": None, "help": "comma separated interfaces to probe during auto discovery"}),
    (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include virtual interfaces during auto discovery"}),
    (("--json/--no-json",), {"default": None, "help": "print discovery results as JSON during auto discovery"}),
    (("--verbose/--no-verbose",), {"default": None, "help": "show backend discovery warnings"}),
    (("--bitrate",), {"default": None, "help": "arbitration bitrate, or none"}),
    (("--data-bitrate",), {"default": None, "help": "CAN FD data-phase bitrate, or none"}),
    (("--fd-clock",), {"type": int, "default": None, "help": "CAN FD controller clock in Hz"}),
    (("--nominal-sample-point",), {"type": float, "default": None, "help": "nominal-phase sample point percent"}),
    (("--data-sample-point",), {"type": float, "default": None, "help": "data-phase sample point percent"}),
    (("--campaign",), {"default": None, "help": "campaign name used for output files"}),
    (("--output-dir",), {"default": None, "help": "directory for CSV and JSON results"}),
    (("--probe-timeout",), {"type": float, "default": None, "help": "seconds to wait after each FD probe"}),
    (("--probe-delay-ms",), {"type": float, "default": None, "help": "delay between FD probes"}),
    (("--no-progress/--progress",), {"default": None, "help": "compatibility flag; logs are line-based"}),
])
def _fdcheck_click(**params: Any) -> None:
    run_fdcheck_from_args(build_args("fdcheck", FDCHECK_DEFAULTS, params))


@click.command(context_settings=CLICK_CONTEXT, help="Scan devices and message IDs on a real CAN bus.")
@command_options([
    COMMON_CONFIG_OPTION,
    (("--interface",), {"default": None, "help": "python-can interface"}),
    (("--channel",), {"default": None, "help": "python-can channel"}),
    (("--interfaces",), {"default": None, "help": "comma separated interfaces to probe during auto discovery"}),
    (("--include-virtual/--no-include-virtual",), {"default": None, "help": "include virtual interfaces during auto discovery"}),
    (("--json/--no-json",), {"default": None, "help": "print discovery results as JSON during auto discovery"}),
    (("--verbose/--no-verbose",), {"default": None, "help": "show backend discovery warnings"}),
    (("--bitrate",), {"default": None, "help": "arbitration bitrate, or none"}),
    (("--campaign",), {"default": None, "help": "campaign name used for output files"}),
    (("--output-dir",), {"default": None, "help": "directory for CSV and JSON scan results"}),
    (("--passive-duration",), {"type": float, "default": None, "help": "seconds to passively listen"}),
    (("--active-timeout",), {"type": float, "default": None, "help": "active probe response window"}),
    (("--inter-probe-delay-ms",), {"type": float, "default": None, "help": "delay between active probes"}),
    (("--physical-start",), {"default": None, "help": "first physical diagnostic request ID"}),
    (("--physical-end",), {"default": None, "help": "last physical diagnostic request ID"}),
    (("--fd/--no-fd",), {"default": None, "help": "open CAN FD mode"}),
    (("--data-bitrate",), {"default": None, "help": "CAN FD data bitrate, or none"}),
    (("--passive-only/--no-passive-only",), {"default": None, "help": "run passive listening only"}),
    (("--active-only/--no-active-only",), {"default": None, "help": "run active probing only"}),
    (("--no-progress/--progress",), {"default": None, "help": "compatibility flag; logs are line-based"}),
])
def _scan_click(**params: Any) -> None:
    run_scan_from_args(build_args("scan", SCAN_DEFAULTS, params))


def fuzz_main() -> None:
    invoke_click(_fuzz_click, "fuzz")


def plot_main() -> None:
    invoke_click(_plot_click, "plot")


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


