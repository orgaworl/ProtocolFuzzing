from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from .fuzzers.can import FuzzConfig, FuzzResult, run_fuzzing
from .adapters import CANConnectionError
from .discovery import DEFAULT_DISCOVERY_INTERFACES, list_can_interfaces
from .fdcheck import FDCheckConfig, run_fdcheck
from .plotting import plot_results
from .common.keepalive import KeepaliveConfig, KeepaliveWorker
from .fuzzers.obd import OBDFuzzConfig, run_obd_fuzzing
from .fuzzers.private_control import PrivateFuzzConfig, run_private_fuzzing
from .scanner import ScanConfig, run_scan
from .fuzzers.uds import UDSFuzzConfig, run_uds_fuzzing
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


def fdcheck_main() -> None:
    parser = make_parser(description="test whether the CAN hardware and target device support CAN FD")
    add_fdcheck_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    run_fdcheck_from_args(args)


def udsfuzz_main() -> None:
    parser = make_parser(description="run a UDS/ISO-TP fuzzing campaign on a real CAN device")
    add_udsfuzz_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    run_udsfuzz_from_args(args)


def obdfuzz_main() -> None:
    parser = make_parser(description="run an OBD-II fuzzing campaign on a real CAN device")
    add_obdfuzz_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    run_obdfuzz_from_args(args)


def privatefuzz_main() -> None:
    parser = make_parser(description="run a configurable private control protocol fuzzing campaign on CAN")
    add_privatefuzz_arguments(parser)
    if len(sys.argv) == 1:
        parser.print_help()
        return
    args = parser.parse_args()
    run_privatefuzz_from_args(args)



def scan_main() -> None:
    parser = make_parser(description="scan devices and message IDs on a real CAN bus")
    add_scan_arguments(parser)
    args = parser.parse_args()
    run_scan_from_args(args)

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

    fdcheck_parser = subparsers.add_parser("fdcheck", help="test whether the hardware and target support CAN FD", formatter_class=HelpFormatter)
    add_fdcheck_arguments(fdcheck_parser)

    udsfuzz_parser = subparsers.add_parser("udsfuzz", help="run a UDS/ISO-TP fuzzing campaign", formatter_class=HelpFormatter)
    add_udsfuzz_arguments(udsfuzz_parser)

    obdfuzz_parser = subparsers.add_parser("obdfuzz", help="run an OBD-II fuzzing campaign", formatter_class=HelpFormatter)
    add_obdfuzz_arguments(obdfuzz_parser)

    privatefuzz_parser = subparsers.add_parser("privatefuzz", help="run a configurable private control protocol fuzzing campaign", formatter_class=HelpFormatter)
    add_privatefuzz_arguments(privatefuzz_parser)

    scan_parser = subparsers.add_parser("scan", help="scan CAN bus devices and message IDs", formatter_class=HelpFormatter)
    add_scan_arguments(scan_parser)

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
    if args.command == "fdcheck":
        run_fdcheck_from_args(args)
        return
    if args.command == "udsfuzz":
        run_udsfuzz_from_args(args)
        return
    if args.command == "obdfuzz":
        run_obdfuzz_from_args(args)
        return
    if args.command == "privatefuzz":
        run_privatefuzz_from_args(args)
        return
    if args.command == "scan":
        run_scan_from_args(args)
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
        keepalive=args.keepalive,
        keepalive_id=args.keepalive_id,
        keepalive_payload=parse_hex_bytes(args.keepalive_payload),
        keepalive_interval_ms=args.keepalive_interval_ms,
        keepalive_extended=args.keepalive_format == "extended",
        keepalive_fd=args.keepalive_fd,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} "
        f"bitrate={config.bitrate} cases={config.cases}",
        flush=True,
    )
    if config.keepalive:
        print(
            f"keepalive=id=0x{config.keepalive_id:x} interval={config.keepalive_interval_ms}ms "
            f"format={'extended' if config.keepalive_extended else 'standard'} fd={config.keepalive_fd}",
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
    if config.keepalive:
        print(f"keepalive_sent={result.keepalive_sent} keepalive_errors={result.keepalive_errors}")
        if result.keepalive_errors:
            print(f"keepalive_last_error={result.keepalive_last_error}")
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



def run_scan_from_args(args: argparse.Namespace) -> None:
    passive = not args.active_only
    active = not args.passive_only
    config = ScanConfig(
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        output_dir=Path(args.output_dir),
        campaign=args.campaign,
        passive_duration=args.passive_duration,
        active_timeout=args.active_timeout,
        inter_probe_delay_ms=args.inter_probe_delay_ms,
        fd=args.fd,
        data_bitrate=args.data_bitrate,
        active=active,
        passive=passive,
        physical_start=args.physical_start,
        physical_end=args.physical_end,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} "
        f"passive={config.passive} active={config.active}",
        flush=True,
    )
    try:
        if args.no_progress:
            summary = run_scan(config)
        else:
            summary = run_scan_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={summary['campaign']}")
    print(f"status={summary['status']}")
    print(f"unique_ids={summary['unique_ids']} total_frames={summary['total_frames_observed']}")
    print(f"active_probes={summary['active_probes']} active_responses={summary['active_responses']}")
    print(f"diagnostic_response_ids={','.join(summary['suspected_diagnostic_response_ids']) or 'none'}")
    print(f"ids_csv={summary['ids_csv_path']}")
    print(f"active_csv={summary['active_csv_path']}")


def run_fdcheck_from_args(args: argparse.Namespace) -> None:
    config = FDCheckConfig(
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        data_bitrate=args.data_bitrate,
        output_dir=Path(args.output_dir),
        campaign=args.campaign,
        probe_timeout=args.probe_timeout,
        probe_delay_ms=args.probe_delay_ms,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} fd=True",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_fdcheck(config)
        else:
            result = run_fdcheck_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={result.campaign}")
    print(f"status={'interrupted' if result.interrupted else 'completed'}")
    print(f"hardware_fd_supported={format_bool(result.hardware_fd_supported)}")
    print(f"hardware_fd_opened={format_bool(result.hardware_fd_opened)}")
    print(f"hardware_fd_status={result.hardware_fd_status}")
    if result.hardware_error:
        print(f"hardware_error={result.hardware_error}")
    print(f"target_fd_supported={format_bool(result.target_fd_supported)}")
    print(f"target_fd_status={result.target_fd_status}")
    print(f"probe_count={result.probe_count} response_count={result.response_count}")
    print(f"csv={result.csv_path}")
    print(f"summary={result.summary_path}")


def run_udsfuzz_from_args(args: argparse.Namespace) -> None:
    config = UDSFuzzConfig(
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_timeout=args.receive_timeout,
        inter_request_delay_ms=args.inter_request_delay_ms,
        request_mode=args.request_mode,
        functional_id=args.functional_id,
        physical_start=args.physical_start,
        physical_end=args.physical_end,
        service_bias=args.service_bias,
        malformed_rate=args.malformed_rate,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_uds_fuzzing(config)
        else:
            result = run_uds_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={result.campaign}")
    print(f"status={'interrupted' if result.interrupted else 'completed'}")
    print(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    print(f"positive_responses={result.positive_responses} negative_responses={result.negative_responses} multi_frame_responses={result.multi_frame_responses}")
    print(f"unique_services={result.unique_services} unique_nrcs={result.unique_nrcs}")
    print(f"csv={result.csv_path}")
    print(f"summary={result.summary_path}")


def run_obdfuzz_from_args(args: argparse.Namespace) -> None:
    config = OBDFuzzConfig(
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_timeout=args.receive_timeout,
        inter_request_delay_ms=args.inter_request_delay_ms,
        request_mode=args.request_mode,
        functional_id=args.functional_id,
        physical_start=args.physical_start,
        physical_end=args.physical_end,
        pid_bias=args.pid_bias,
        malformed_rate=args.malformed_rate,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_obd_fuzzing(config)
        else:
            result = run_obd_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={result.campaign}")
    print(f"status={'interrupted' if result.interrupted else 'completed'}")
    print(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    print(f"positive_responses={result.positive_responses} negative_responses={result.negative_responses}")
    print(f"unique_modes={result.unique_modes} unique_pids={result.unique_pids}")
    print(f"csv={result.csv_path}")
    print(f"summary={result.summary_path}")


def run_obd_fuzzing_with_tqdm(config: OBDFuzzConfig):
    from tqdm import tqdm

    with tqdm(total=config.cases, unit="case", desc="obdfuzz", dynamic_ncols=True) as progress:
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
                responses=snapshot["responses"],
                positive=snapshot["positive_responses"],
                negative=snapshot["negative_responses"],
                refresh=False,
            )

        return run_obd_fuzzing(config, progress_callback=update_progress)


def run_privatefuzz_from_args(args: argparse.Namespace) -> None:
    config = PrivateFuzzConfig(
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_timeout=args.receive_timeout,
        inter_request_delay_ms=args.inter_request_delay_ms,
        target_ids=tuple(parse_int_list(args.target_ids)),
        opcodes=tuple(parse_int_list(args.opcodes)),
        structured_rate=args.structured_rate,
        malformed_rate=args.malformed_rate,
        min_payload_len=args.min_payload_len,
        max_payload_len=args.max_payload_len,
        extended=args.extended,
        fd=args.fd,
        data_bitrate=args.data_bitrate,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
    )
    print(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} targets={len(config.target_ids)} opcodes={len(config.opcodes)}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_private_fuzzing(config)
        else:
            result = run_private_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"campaign={result.campaign}")
    print(f"status={'interrupted' if result.interrupted else 'completed'}")
    print(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    print(f"unique_targets={result.unique_targets} unique_opcodes={result.unique_opcodes} coverage_points={result.coverage_points}")
    print(f"csv={result.csv_path}")
    print(f"summary={result.summary_path}")


def run_private_fuzzing_with_tqdm(config: PrivateFuzzConfig):
    from tqdm import tqdm

    with tqdm(total=config.cases, unit="case", desc="privatefuzz", dynamic_ncols=True) as progress:
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

        return run_private_fuzzing(config, progress_callback=update_progress)


def run_uds_fuzzing_with_tqdm(config: UDSFuzzConfig):
    from tqdm import tqdm

    with tqdm(total=config.cases, unit="case", desc="udsfuzz", dynamic_ncols=True) as progress:
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
                responses=snapshot["responses"],
                positive=snapshot["positive_responses"],
                negative=snapshot["negative_responses"],
                refresh=False,
            )

        return run_uds_fuzzing(config, progress_callback=update_progress)


def run_fdcheck_with_tqdm(config: FDCheckConfig):
    from tqdm import tqdm

    with tqdm(total=len(config.probe_lengths) * 4, unit="probe", desc="fdcheck", dynamic_ncols=True) as progress:
        last_completed = 0

        def update_progress(snapshot: dict) -> None:
            nonlocal last_completed
            completed = int(snapshot["completed"])
            delta = completed - last_completed
            if delta > 0:
                progress.update(delta)
                last_completed = completed
            progress.set_postfix(target=snapshot.get("target_fd_supported", False), refresh=False)

        return run_fdcheck(config, progress_callback=update_progress)


def run_scan_with_tqdm(config: ScanConfig):
    from tqdm import tqdm

    passive_bar = None
    active_bar = None
    active_total = max(0, (config.physical_end - config.physical_start + 1) * 2 + 2) if config.active else 0
    try:
        if config.passive:
            passive_bar = tqdm(total=config.passive_duration, unit="s", desc="passive", dynamic_ncols=True)
        if config.active:
            active_bar = tqdm(total=active_total, unit="probe", desc="active", dynamic_ncols=True)
        passive_seen = 0.0
        active_seen = 0

        def update(snapshot: dict) -> None:
            nonlocal passive_seen, active_seen
            phase = snapshot.get("phase")
            if phase == "passive" and passive_bar is not None:
                elapsed = min(float(snapshot.get("elapsed", 0.0)), config.passive_duration)
                delta = elapsed - passive_seen
                if delta > 0:
                    passive_bar.update(delta)
                    passive_seen = elapsed
                passive_bar.set_postfix(ids=snapshot.get("ids", 0), refresh=False)
            elif phase == "active" and active_bar is not None:
                elapsed = int(snapshot.get("elapsed", 0))
                delta = elapsed - active_seen
                if delta > 0:
                    active_bar.update(delta)
                    active_seen = elapsed
                active_bar.set_postfix(ids=snapshot.get("ids", 0), refresh=False)

        return run_scan(config, progress_callback=update)
    finally:
        if passive_bar is not None:
            passive_bar.close()
        if active_bar is not None:
            active_bar.close()
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
    optional.add_argument("--keepalive", action="store_true", default=False, help="send a periodic activation frame in a background thread")
    optional.add_argument("--keepalive-id", type=parse_int, default=0x7DF, help="arbitration ID for the periodic activation frame")
    optional.add_argument("--keepalive-payload", default="02 3E 00", help="hex payload for the periodic activation frame")
    optional.add_argument("--keepalive-interval-ms", type=float, default=500.0, help="delay between activation frames")
    optional.add_argument("--keepalive-format", choices=["standard", "extended"], default="standard", help="frame format for the activation frame")
    optional.add_argument("--keepalive-fd", action="store_true", default=False, help="send the activation frame as CAN FD")
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


def add_fdcheck_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--campaign", default="can_fd_check", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--probe-timeout", type=float, default=0.15, help="seconds to wait for responses after each FD probe")
    optional.add_argument("--probe-delay-ms", type=float, default=20.0, help="delay between FD probes")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_udsfuzz_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--cases", type=int, default=1000, help="number of diagnostic requests to generate")
    optional.add_argument("--seed", type=int, default=2024, help="random seed")
    optional.add_argument("--campaign", default="uds_baseline", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--receive-timeout", type=float, default=0.15, help="seconds to collect response frames after each diagnostic request")
    optional.add_argument("--inter-request-delay-ms", type=float, default=10.0, help="delay between diagnostic requests")
    optional.add_argument("--request-mode", choices=["functional", "physical", "mixed"], default="mixed", help="request addressing mode")
    optional.add_argument("--functional-id", type=parse_int, default=0x7DF, help="functional request ID")
    optional.add_argument("--physical-start", type=parse_int, default=0x7E0, help="first physical request ID to probe")
    optional.add_argument("--physical-end", type=parse_int, default=0x7E7, help="last physical request ID to probe")
    optional.add_argument("--service-bias", type=float, default=0.85, help="probability of generating a structured UDS service instead of a raw random request")
    optional.add_argument("--malformed-rate", type=float, default=0.15, help="probability of generating a malformed diagnostic request")
    optional.add_argument("--progress-interval", type=int, default=1, help="update progress after this many completed cases; 0 disables count-based updates")
    optional.add_argument("--progress-seconds", type=float, default=1.0, help="update progress after this many seconds; 0 disables time-based updates")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_obdfuzz_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--cases", type=int, default=1000, help="number of OBD requests to generate")
    optional.add_argument("--seed", type=int, default=2025, help="random seed")
    optional.add_argument("--campaign", default="obd_baseline", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--receive-timeout", type=float, default=0.15, help="seconds to collect response frames after each OBD request")
    optional.add_argument("--inter-request-delay-ms", type=float, default=20.0, help="delay between OBD requests")
    optional.add_argument("--request-mode", choices=["functional", "physical", "mixed"], default="functional", help="request addressing mode")
    optional.add_argument("--functional-id", type=parse_int, default=0x7DF, help="OBD functional request ID")
    optional.add_argument("--physical-start", type=parse_int, default=0x7E0, help="first physical request ID to probe")
    optional.add_argument("--physical-end", type=parse_int, default=0x7E7, help="last physical request ID to probe")
    optional.add_argument("--pid-bias", type=float, default=0.8, help="probability of choosing a common OBD PID")
    optional.add_argument("--malformed-rate", type=float, default=0.1, help="probability of generating a malformed OBD request")
    optional.add_argument("--progress-interval", type=int, default=1, help="update progress after this many completed cases; 0 disables count-based updates")
    optional.add_argument("--progress-seconds", type=float, default=1.0, help="update progress after this many seconds; 0 disables time-based updates")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_privatefuzz_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--cases", type=int, default=1000, help="number of private control frames to generate")
    optional.add_argument("--seed", type=int, default=2026, help="random seed")
    optional.add_argument("--campaign", default="private_control_baseline", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--receive-timeout", type=float, default=0.05, help="seconds to collect response frames after each private control frame")
    optional.add_argument("--inter-request-delay-ms", type=float, default=10.0, help="delay between private control frames")
    optional.add_argument("--target-ids", default="0x100,0x101,0x200,0x201,0x300,0x301", help="comma separated target arbitration IDs")
    optional.add_argument("--opcodes", default="0x00,0x01,0x02,0x03,0x10,0x11,0x20,0x21,0x7f,0x80,0xfe,0xff", help="comma separated private control opcodes")
    optional.add_argument("--structured-rate", type=float, default=0.7, help="probability of generating structured private control payloads")
    optional.add_argument("--malformed-rate", type=float, default=0.15, help="probability of generating malformed private control payloads")
    optional.add_argument("--min-payload-len", type=int, default=1, help="minimum payload length")
    optional.add_argument("--max-payload-len", type=int, default=8, help="maximum payload length")
    optional.add_argument("--extended", action="store_true", default=False, help="use extended CAN identifiers")
    optional.add_argument("--fd", action="store_true", default=False, help="send private control frames as CAN FD")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--progress-interval", type=int, default=1, help="update progress after this many completed cases; 0 disables count-based updates")
    optional.add_argument("--progress-seconds", type=float, default=1.0, help="update progress after this many seconds; 0 disables time-based updates")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    required.add_argument("--interface", required=True, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", required=True, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--campaign", default="can_scan", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON scan results")
    optional.add_argument("--passive-duration", type=float, default=10.0, help="seconds to passively listen before active probes")
    optional.add_argument("--active-timeout", type=float, default=0.25, help="seconds to collect responses after each active probe")
    optional.add_argument("--inter-probe-delay-ms", type=float, default=50.0, help="delay between active probes")
    optional.add_argument("--physical-start", type=parse_int, default=0x7E0, help="first physical diagnostic request ID to probe")
    optional.add_argument("--physical-end", type=parse_int, default=0x7E7, help="last physical diagnostic request ID to probe")
    optional.add_argument("--fd", action="store_true", default=False, help="open CAN FD mode")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--passive-only", action="store_true", default=False, help="run passive listening only")
    optional.add_argument("--active-only", action="store_true", default=False, help="run active probing only")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")
def parse_int(value: str) -> int:
    return int(value, 0)


def parse_optional_int(value: str) -> int | None:
    if value.lower() in {"none", "null", ""}:
        return None
    return int(value, 0)


def parse_int_list(value: str) -> list[int]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise argparse.ArgumentTypeError("at least one integer value is required")
    return [parse_int(item) for item in items]


def parse_hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


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
            3: "occupied by PCAN-View",
        }
        return labels.get(condition, str(condition))
    if condition is None:
        return ""
    return str(condition)









