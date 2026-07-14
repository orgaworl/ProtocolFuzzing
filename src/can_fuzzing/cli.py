from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from . import FuzzConfig, run_fuzzing
from .adapters import CANConnectionError
from .discovery import DEFAULT_DISCOVERY_INTERFACES, list_can_interfaces
from .plotting import plot_results
class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action: argparse.Action) -> str:
        help_text = action.help or ""
        if action.default is argparse.SUPPRESS or action.default is None:
            return help_text
        if action.option_strings and "%(default)" not in help_text:
            return f"{help_text} (default: %(default)s)"
        return help_text


def make_parser(description: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=description, formatter_class=HelpFormatter)
def fuzz_main() -> None:
    parser = make_parser(description="run a CAN fuzzing campaign on a real CAN device")
    add_fuzz_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    run_fuzz_from_args(args)


def plot_main() -> None:
    parser = make_parser(description="generate PDF plots from CAN fuzzing result files")
    add_plot_arguments(parser)
    args = parser.parse_args()
    run_plot_from_args(args)


def clean_main() -> None:
    parser = make_parser(description="remove generated files from result and plot")
    add_clean_arguments(parser)
    args = parser.parse_args()
    run_clean_from_args(args)


def list_main() -> None:
    parser = make_parser(description="list available CAN interfaces detected by python-can")
    add_list_arguments(parser)
    args = parser.parse_args()
    run_list_from_args(args)


def legacy_main() -> None:
    parser = make_parser(description="CAN protocol fuzzing framework")
    subparsers = parser.add_subparsers(dest="command")

    fuzz_parser = subparsers.add_parser("fuzz", help="run a CAN fuzzing campaign on a real CAN device", formatter_class=HelpFormatter)
    add_fuzz_arguments(fuzz_parser)

    run_parser = subparsers.add_parser("run", help="alias for fuzz", formatter_class=HelpFormatter)
    add_fuzz_arguments(run_parser)

    plot_parser = subparsers.add_parser("plot", help="generate PDF plots from result files", formatter_class=HelpFormatter)
    add_plot_arguments(plot_parser)

    clean_parser = subparsers.add_parser("clean", help="remove generated files from result and plot", formatter_class=HelpFormatter)
    add_clean_arguments(clean_parser)

    list_parser = subparsers.add_parser("list", help="list available CAN interfaces", formatter_class=HelpFormatter)
    add_list_arguments(list_parser)

    args = parser.parse_args()
    if args.command in {"fuzz", "run"}:
        run_fuzz_from_args(args)
        return
    if args.command == "plot":
        run_plot_from_args(args)
        return
    if args.command == "clean":
        run_clean_from_args(args)
        return
    if args.command == "list":
        run_list_from_args(args)
        return
    parser.print_help()



def run_fuzz_from_args(args: argparse.Namespace) -> None:
    config = FuzzConfig(
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_timeout=args.receive_timeout,
        inter_frame_delay_ms=args.inter_frame_delay_ms,
        fd=args.fd,
        data_bitrate=args.data_bitrate,
        id_min=args.id_min,
        id_max=args.id_max,
        diagnostic_bias=args.diagnostic_bias,
        extended_probability=args.extended_probability,
        include_remote=args.include_remote,
        include_error=args.include_error,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} "
        f"bitrate={config.bitrate} cases={config.cases}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_fuzzing(config)
        else:
            result = run_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={result.campaign}")
    print(f"status={'interrupted' if result.interrupted else 'completed'}")
    print(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    print(f"coverage_points={result.coverage_points} unique_reasons={result.unique_reasons}")
    print(f"csv={result.csv_path}")
    print(f"summary={result.summary_path}")

def run_fuzzing_with_tqdm(config: FuzzConfig):
    from tqdm import tqdm

    with tqdm(total=config.cases, unit="case", dynamic_ncols=True) as progress:
        last_completed = 0

        def update_progress(snapshot: dict) -> None:
            nonlocal last_completed
            completed = int(snapshot["completed_cases"])
            delta = completed - last_completed
            if delta > 0:
                progress.update(delta)
                last_completed = completed
            progress.set_postfix(
                sent=snapshot["sent"],
                faults=snapshot["faults"],
                responses=snapshot["responses"],
                coverage=snapshot["coverage_points"],
                refresh=False,
            )

        return run_fuzzing(config, progress_callback=update_progress)
def run_plot_from_args(args: argparse.Namespace) -> None:
    outputs = plot_results(Path(args.input), Path(args.output_dir))
    for output in outputs:
        print(f"wrote={output}")


def run_clean_from_args(args: argparse.Namespace) -> None:
    clean_directory(Path(args.result_dir))
    clean_directory(Path(args.plot_dir))
    print(f"cleaned={args.result_dir},{args.plot_dir}")


def run_list_from_args(args: argparse.Namespace) -> None:
    interfaces = parse_interface_names(args.interfaces) if args.interfaces else None
    try:
        configs = list_can_interfaces(
            interfaces=interfaces,
            include_virtual=args.include_virtual,
            verbose=args.verbose,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if args.json:
        print(json.dumps(configs, indent=2, default=str))
        return
    print_interface_table(configs)


def add_fuzz_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--cases", type=int, default=1000, help="number of generated CAN frames")
    optional.add_argument("--seed", type=int, default=1337, help="random seed")
    optional.add_argument("--campaign", default="can_baseline", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--receive-timeout", type=float, default=0.05, help="seconds to collect response frames after each send")
    optional.add_argument("--inter-frame-delay-ms", type=float, default=5.0, help="delay between transmitted fuzzing frames")
    optional.add_argument("--fd", action="store_true", default=False, help="send CAN FD frames")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--id-min", type=parse_int, default=0x000, help="minimum arbitration ID")
    optional.add_argument("--id-max", type=parse_int, default=0x7FF, help="maximum arbitration ID")
    optional.add_argument("--diagnostic-bias", type=float, default=0.6, help="probability of choosing diagnostic request IDs when they are in range")
    optional.add_argument("--extended-probability", type=float, default=0.0, help="probability of generating extended ID frames")
    optional.add_argument("--include-remote", action="store_true", default=False, help="include remote frames in the campaign")
    optional.add_argument("--include-error", action="store_true", default=False, help="include error frames in the campaign")
    optional.add_argument("--progress-interval", type=int, default=1, help="update progress after this many completed cases; 0 disables count-based updates")
    optional.add_argument("--progress-seconds", type=float, default=1.0, help="update progress after this many seconds; 0 disables time-based updates")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_plot_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    optional.add_argument("--input", default="result/can_baseline_cases.csv", help="input CSV result file")
    optional.add_argument("--output-dir", default="plot", help="directory for generated PDF figures")


def add_clean_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    optional.add_argument("--result-dir", default="result", help="result directory to clean")
    optional.add_argument("--plot-dir", default="plot", help="plot directory to clean")


def add_list_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    optional.add_argument(
        "--interfaces",
        default=",".join(DEFAULT_DISCOVERY_INTERFACES),
        help="comma separated python-can backends to probe",
    )
    optional.add_argument("--include-virtual", action="store_true", default=False, help="include python-can virtual channels")
    optional.add_argument("--json", action="store_true", default=False, help="print raw discovery results as JSON")
    optional.add_argument("--verbose", action="store_true", default=False, help="show backend discovery warnings")

def parse_int(value: str) -> int:
    return int(value, 0)


def parse_optional_int(value: str) -> int | None:
    if value.lower() in {"none", "null", ""}:
        return None
    return int(value, 0)


def parse_interface_names(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def clean_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def print_interface_table(configs: list[dict[str, Any]]) -> None:
    if not configs:
        print("No CAN interfaces detected.")
        return
    rows = [format_interface_row(config) for config in configs]
    headers = ["interface", "channel", "device", "fd", "condition"]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def format_interface_row(config: dict[str, Any]) -> list[str]:
    return [
        str(config.get("interface", "")),
        str(config.get("channel", "")),
        str(config.get("device_name") or config.get("device") or ""),
        format_bool(config.get("supports_fd")),
        format_condition(config),
    ]


def format_bool(value: Any) -> str:
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
            3: "pcanview",
        }
        return labels.get(condition, str(condition))
    if condition is None:
        return ""
    return str(condition)







