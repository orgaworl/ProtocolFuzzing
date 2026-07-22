from __future__ import annotations

import argparse
import json
import shutil
import time
import sys
from pathlib import Path
from typing import Any

from .adapters import CANConnectionError, CANHardwareAdapter
from .common import console
from .common.config import (
    extract_config_path,
    load_parser_defaults_from_config,
    load_section_defaults_from_config,
    read_toml_config,
    relax_configured_required_args,
    validate_required_args,
)
from .common.keepalive import KeepaliveConfig, KeepaliveWorker
from .discovery import DEFAULT_DISCOVERY_INTERFACES, list_can_interfaces
from .fdcheck import FDCheckConfig, run_fdcheck
from .fuzzers.can import FuzzConfig, FuzzResult, run_fuzzing
from .fuzzers.obd import OBDFuzzConfig, run_obd_fuzzing
from .fuzzers.private_control import PrivateFuzzConfig, run_private_fuzzing
from .fuzzers.uds import UDSFuzzConfig, run_uds_fuzzing
from .plotting import plot_results
from .scanner import ScanConfig, run_scan


KEEPALIVE_PRESETS: dict[str, dict[str, Any]] = {
    "tester-present": {
        "arbitration_id": 0x7DF,
        "payload": "02 3E 00",
        "fd": False,
        "format": "standard",
        "listen": True,
        "listen_timeout": 0.05,
        "check_message": True,
    },
    "ff-fd-no-response": {
        "arbitration_id": 0xFFFFFFFF,
        "payload": "FF FF FF FF FF FF FF FF",
        "fd": True,
        "format": "extended",
        "listen": False,
        "listen_timeout": 0.05,
        "check_message": False,
    },
    "ff-classic-response": {
        "arbitration_id": 0xFFFFFFFF,
        "payload": "FF FF FF FF FF FF FF FF",
        "fd": False,
        "format": "extended",
        "listen": True,
        "listen_timeout": 0.05,
        "check_message": False,
    },
}
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


def parse_args_with_config(parser: argparse.ArgumentParser, section: str, argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    config_path = extract_config_path(argv)
    if config_path is not None:
        defaults = load_parser_defaults_from_config(parser, config_path, section)
        parser.set_defaults(**defaults)
        relax_configured_required_args(parser, defaults)
    args = parser.parse_args(argv)
    validate_required_args(parser, args, section)
    return args


def add_config_argument(optional: argparse._ArgumentGroup) -> None:
    optional.add_argument("-c", "--config", default=None, help="TOML config file; command line options override config values")


FUZZ_PROTOCOL_ALIASES = {
    "baseline": "can",
    "can_baseline": "can",
    "private_control": "private",
    "privatefuzz": "private",
    "udsfuzz": "uds",
    "obdfuzz": "obd",
}
FUZZ_PROTOCOL_SECTION_MAP = {
    "can": None,
    "uds": "udsfuzz",
    "obd": "obdfuzz",
    "private": "privatefuzz",
}


def normalize_protocol(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower().replace("-", "_")
    if not token:
        return None
    return FUZZ_PROTOCOL_ALIASES.get(token, token)


def normalize_keepalive_preset(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower().replace("_", "-")
    if not token:
        return None
    return token if token in KEEPALIVE_PRESETS else None


def parse_protocol(value: str) -> str:
    normalized = normalize_protocol(value)
    if normalized in {"can", "uds", "obd", "private"}:
        return normalized
    raise argparse.ArgumentTypeError("protocol must be one of: can, uds, obd, private")


def extract_protocol_hint(argv: list[str]) -> str | None:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--protocol")
    known, _ = pre_parser.parse_known_args(argv)
    return normalize_protocol(known.protocol)


def parse_fuzz_args_with_config(parser: argparse.ArgumentParser, argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    config_path = extract_config_path(argv)
    protocol = extract_protocol_hint(argv)
    defaults: dict[str, Any] = {}

    if config_path is not None:
        raw_config = read_toml_config(config_path)
        defaults.update(load_parser_defaults_from_config(parser, config_path, "fuzz"))
        if protocol is None:
            protocol = normalize_protocol(defaults.get("protocol"))
        protocol_section = FUZZ_PROTOCOL_SECTION_MAP.get(protocol or "can")
        if protocol_section is not None:
            defaults.update(load_section_defaults_from_config(parser, raw_config, protocol_section))

    protocol = protocol or "can"
    defaults["protocol"] = protocol
    parser.set_defaults(**defaults)
    relax_configured_required_args(parser, defaults)
    args = parser.parse_args(argv)
    args.protocol = normalize_protocol(getattr(args, "protocol", None)) or protocol
    return args


def parse_keepalive_args_with_config(parser: argparse.ArgumentParser, argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    config_path = extract_config_path(argv)
    cli_preset = extract_keepalive_preset(argv)
    defaults: dict[str, Any] = {}
    config_preset: str | None = None

    if config_path is not None:
        raw_config = read_toml_config(config_path)
        bitrate = raw_config.get("bitrate")
        if bitrate is not None:
            defaults["bitrate"] = parse_optional_int(str(bitrate))
        defaults.update(load_section_defaults_from_config(parser, raw_config, "keepalive"))
        config_preset = normalize_keepalive_preset(defaults.get("preset"))

    base_preset = cli_preset or config_preset or "tester-present"
    preset_defaults = dict(KEEPALIVE_PRESETS[base_preset])
    preset_defaults.update(defaults)
    defaults = preset_defaults
    defaults["preset"] = cli_preset or config_preset or base_preset

    parser.set_defaults(**defaults)
    args = parser.parse_args(argv)
    args.preset = normalize_keepalive_preset(getattr(args, "preset", None)) or "tester-present"
    return args


def extract_keepalive_preset(argv: list[str]) -> str | None:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--preset")
    known, _ = pre_parser.parse_known_args(argv)
    return normalize_keepalive_preset(known.preset)


def fuzz_main() -> None:
    parser = make_parser(description="run a CAN or CAN-based protocol fuzzing campaign on a real device")
    add_fuzz_arguments(parser)
    args = parse_fuzz_args_with_config(parser)
    run_fuzz_from_args(args)


def plot_main() -> None:
    parser = make_parser(description="generate PDF plots from CAN fuzzing result files")
    add_plot_arguments(parser)
    args = parse_args_with_config(parser, "plot")
    run_plot_from_args(args)


def clean_main() -> None:
    parser = make_parser(description="remove generated files from result and plot")
    add_clean_arguments(parser)
    args = parse_args_with_config(parser, "clean")
    run_clean_from_args(args)


def list_main() -> None:
    parser = make_parser(description="list available CAN interfaces detected by python-can")
    add_list_arguments(parser)
    args = parse_args_with_config(parser, "list")
    run_list_from_args(args)


def keepalive_main() -> None:
    parser = make_parser(description="send periodic keepalive frames on a real CAN device")
    add_keepalive_arguments(parser)
    args = parse_keepalive_args_with_config(parser)
    run_keepalive_from_args(args)


def fdcheck_main() -> None:
    parser = make_parser(description="test whether the CAN hardware and target device support CAN FD")
    add_fdcheck_arguments(parser)
    args = parse_args_with_config(parser, "fdcheck")
    run_fdcheck_from_args(args)


def udsfuzz_main() -> None:
    parser = make_parser(description="run a UDS/ISO-TP fuzzing campaign on a real CAN device")
    add_udsfuzz_arguments(parser)
    args = parse_args_with_config(parser, "udsfuzz")
    run_udsfuzz_from_args(args)


def obdfuzz_main() -> None:
    parser = make_parser(description="run an OBD-II fuzzing campaign on a real CAN device")
    add_obdfuzz_arguments(parser)
    args = parse_args_with_config(parser, "obdfuzz")
    run_obdfuzz_from_args(args)


def privatefuzz_main() -> None:
    parser = make_parser(description="run a configurable private control protocol fuzzing campaign on CAN")
    add_privatefuzz_arguments(parser)
    args = parse_args_with_config(parser, "privatefuzz")
    run_privatefuzz_from_args(args)



def scan_main() -> None:
    parser = make_parser(description="scan devices and message IDs on a real CAN bus")
    add_scan_arguments(parser)
    args = parse_args_with_config(parser, "scan")
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

    keepalive_parser = subparsers.add_parser("keepalive", help="send periodic keepalive frames", formatter_class=HelpFormatter)
    add_keepalive_arguments(keepalive_parser)

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
    if args.command == "keepalive":
        run_keepalive_from_args(args)
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


def parse_legacy_args_with_config(parser: argparse.ArgumentParser) -> argparse.Namespace:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("command", nargs="?")
    pre_parser.add_argument("-c", "--config")
    known, _ = pre_parser.parse_known_args()
    section = "fuzz" if known.command == "run" else known.command
    if known.config and section:
        subparser = get_legacy_subparser(parser, known.command)
        if subparser is not None:
            defaults = load_parser_defaults_from_config(subparser, Path(known.config), section)
            subparser.set_defaults(**defaults)
            relax_configured_required_args(subparser, defaults)
    args = parser.parse_args()
    validate_required_args(parser, args, section or "")
    return args


def get_legacy_subparser(parser: argparse.ArgumentParser, command: str | None) -> argparse.ArgumentParser | None:
    if command is None:
        return None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(command)
    return None



def run_fuzz_from_args(args: argparse.Namespace) -> None:
    protocol = normalize_protocol(getattr(args, "protocol", None)) or "can"
    args.protocol = protocol

    if protocol == "can":
        run_can_fuzz_from_args(args)
        return

    args.interface, args.channel = resolve_interface_and_channel(args, "fuzz")
    if protocol == "uds":
        run_udsfuzz_from_args(args)
        return
    if protocol == "obd":
        run_obdfuzz_from_args(args)
        return
    if protocol == "private":
        run_privatefuzz_from_args(args)
        return
    raise SystemExit(f"unsupported protocol: {protocol}")


def run_can_fuzz_from_args(args: argparse.Namespace) -> None:
    args.interface, args.channel = resolve_interface_and_channel(args, "fuzz")
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
    console.info(
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
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"coverage_points={result.coverage_points} unique_reasons={result.unique_reasons}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


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


def run_keepalive_from_args(args: argparse.Namespace) -> None:
    interface, channel = resolve_interface_and_channel(args, "keepalive")
    config = KeepaliveConfig(
        enabled=True,
        arbitration_id=args.arbitration_id,
        payload=parse_hex_bytes(args.payload),
        interval_ms=args.interval_ms,
        extended=args.format == "extended",
        fd=args.fd,
        listen=args.listen,
        listen_timeout=args.listen_timeout,
        check_message=args.check_message,
    )
    console.info(
        f"opening interface={interface} channel={channel} bitrate={args.bitrate} "
        f"interval={config.interval_ms}ms id=0x{config.arbitration_id:x} preset={args.preset}",
        flush=True,
    )
    try:
        with CANHardwareAdapter(
            interface=interface,
            channel=channel,
            bitrate=args.bitrate,
            receive_timeout=0.05,
            fd=args.fd,
            data_bitrate=args.data_bitrate,
            check_message=args.check_message,
        ) as adapter:
            worker = KeepaliveWorker(adapter, config, response_callback=log_keepalive_response)
            worker.start()
            console.info("keepalive running; press Ctrl+C to stop", flush=True)
            try:
                while worker.is_alive():
                    time.sleep(1.0)
            except KeyboardInterrupt:
                console.warning("keepalive interrupted by Ctrl+C; saving current results")
            stats = worker.stop()
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    else:
        console.info(f"keepalive_sent={stats.sent} keepalive_errors={stats.errors}")
        console.info(f"keepalive_responses={stats.responses}")
        if stats.response_ids:
            console.info("keepalive_response_ids=" + ",".join(f"0x{value:x}" for value in stats.response_ids))
        if stats.response_payloads:
            console.info("keepalive_response_payloads=" + ",".join(stats.response_payloads))
        if stats.errors:
            console.warning(f"keepalive_last_error={stats.last_error}")


def log_keepalive_response(message: Any) -> None:
    payload = bytes(getattr(message, "data", b""))
    console.info(
        f"keepalive_response id=0x{int(getattr(message, 'arbitration_id', 0)):x} "
        f"dlc={len(payload)} data={payload.hex()}"
    )


def run_plot_from_args(args: argparse.Namespace) -> None:
    outputs = plot_results(Path(args.input), Path(args.output_dir))
    for output in outputs:
        console.info(f"wrote={output}")


def run_clean_from_args(args: argparse.Namespace) -> None:
    clean_directory(Path(args.result_dir))
    clean_directory(Path(args.plot_dir))
    console.info(f"cleaned={args.result_dir},{args.plot_dir}")


def run_list_from_args(args: argparse.Namespace) -> None:
    interfaces = parse_interface_names(args.interfaces) if args.interfaces else None
    try:
        configs = list_can_interfaces(
            interfaces=interfaces,
            include_virtual=args.include_virtual,
            verbose=args.verbose,
        )
    except RuntimeError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    if args.json:
        print(json.dumps(configs, indent=2, default=str))
        return
    print_interface_table(configs)


def resolve_interface_and_channel(args: argparse.Namespace, section: str) -> tuple[str, str]:
    interface = getattr(args, "interface", None)
    channel = getattr(args, "channel", None)
    if interface and channel:
        return str(interface), str(channel)

    console.warning(
        f"{section}: interface and channel were not fully provided; running interface discovery",
        flush=True,
    )
    interfaces = parse_interface_names(args.interfaces) if getattr(args, "interfaces", None) else None
    if interface and interfaces is None:
        interfaces = [str(interface)]
    try:
        configs = list_can_interfaces(
            interfaces=interfaces,
            include_virtual=getattr(args, "include_virtual", False),
            verbose=getattr(args, "verbose", False),
        )
    except RuntimeError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc

    if getattr(args, "json", False):
        print(json.dumps(configs, indent=2, default=str))
    else:
        print_interface_table(configs)

    if not configs:
        raise SystemExit(2)
    if len(configs) == 1:
        selected = configs[0]
        console.warning(
            f"auto-selected interface={selected.get('interface', '')} channel={selected.get('channel', '')}",
            flush=True,
        )
        return str(selected.get("interface", "")), str(selected.get("channel", ""))

    selected = prompt_interface_selection(configs)
    console.warning(
        f"selected interface={selected.get('interface', '')} channel={selected.get('channel', '')}",
        flush=True,
    )
    return str(selected.get("interface", "")), str(selected.get("channel", ""))


def prompt_interface_selection(configs: list[dict[str, Any]]) -> dict[str, Any]:
    while True:
        console.info("select a CAN interface by index:", flush=True)
        for index, config in enumerate(configs, start=1):
            console.info(
                f"  [{index}] {config.get('interface', '')} {config.get('channel', '')} "
                f"{config.get('device_name') or config.get('device') or ''}",
                flush=True,
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
            console.warning("please enter a numeric selection", flush=True)
            continue
        if 1 <= index <= len(configs):
            return configs[index - 1]
        console.warning(f"selection must be between 1 and {len(configs)}", flush=True)


def run_scan_from_args(args: argparse.Namespace) -> None:
    args.interface, args.channel = resolve_interface_and_channel(args, "scan")
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
    console.info(
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
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={summary['campaign']}")
    print_status_value(str(summary["status"]))
    console.info(f"unique_ids={summary['unique_ids']} total_frames={summary['total_frames_observed']}")
    console.debug(f"active_probes={summary['active_probes']} active_responses={summary['active_responses']}")
    diagnostic_ids = ','.join(summary['suspected_diagnostic_response_ids']) or 'none'
    if diagnostic_ids == "none":
        console.warning(f"diagnostic_response_ids={diagnostic_ids}")
    else:
        console.debug(f"diagnostic_response_ids={diagnostic_ids}")
    console.info(f"ids_csv={summary['ids_csv_path']}")
    console.info(f"active_csv={summary['active_csv_path']}")
    print_scan_objects_table(summary.get("observed_objects", []))


def run_fdcheck_from_args(args: argparse.Namespace) -> None:
    args.interface, args.channel = resolve_interface_and_channel(args, "fdcheck")
    config = FDCheckConfig(
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        data_bitrate=args.data_bitrate,
        fd_clock=args.fd_clock,
        nominal_sample_point=args.nominal_sample_point,
        data_sample_point=args.data_sample_point,
        output_dir=Path(args.output_dir),
        campaign=args.campaign,
        probe_timeout=args.probe_timeout,
        probe_delay_ms=args.probe_delay_ms,
    )
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} "
        f"data_bitrate={config.data_bitrate} fd_clock={config.fd_clock} fd=True",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_fdcheck(config)
        else:
            result = run_fdcheck_with_tqdm(config)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.log(f"hardware_fd_supported={format_bool(result.hardware_fd_supported)}", "debug" if result.hardware_fd_supported else "warning")
    console.log(f"hardware_fd_opened={format_bool(result.hardware_fd_opened)}", "debug" if result.hardware_fd_opened else "warning")
    console.log(f"hardware_fd_status={result.hardware_fd_status}", status_level(result.hardware_fd_status))
    if result.hardware_error:
        console.error(f"hardware_error={result.hardware_error}")
    console.log(f"target_fd_supported={format_bool(result.target_fd_supported)}", "debug" if result.target_fd_supported else "warning")
    console.log(f"target_fd_status={result.target_fd_status}", status_level(result.target_fd_status))
    console.info(f"probe_count={result.probe_count} response_count={result.response_count}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


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
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_uds_fuzzing(config)
        else:
            result = run_uds_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"positive_responses={result.positive_responses} negative_responses={result.negative_responses} multi_frame_responses={result.multi_frame_responses}")
    console.debug(f"unique_services={result.unique_services} unique_nrcs={result.unique_nrcs}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


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
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_obd_fuzzing(config)
        else:
            result = run_obd_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"positive_responses={result.positive_responses} negative_responses={result.negative_responses}")
    console.debug(f"unique_modes={result.unique_modes} unique_pids={result.unique_pids}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


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
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} targets={len(config.target_ids)} opcodes={len(config.opcodes)}",
        flush=True,
    )
    try:
        if args.no_progress:
            result = run_private_fuzzing(config)
        else:
            result = run_private_fuzzing_with_tqdm(config)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"unique_targets={result.unique_targets} unique_opcodes={result.unique_opcodes} coverage_points={result.coverage_points}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


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
    add_config_argument(optional)
    optional.add_argument(
        "--protocol",
        type=parse_protocol,
        default="can",
        metavar="PROTOCOL",
        help="fuzzing protocol to run: can, uds, obd, or private",
    )
    required.add_argument(
        "--interface",
        default=None,
        help="python-can interface, for example pcan, vector, slcan, socketcan; if omitted, interfaces are discovered automatically",
    )
    required.add_argument(
        "--channel",
        default=None,
        help="CAN channel name used by the selected python-can interface; if omitted, interfaces are discovered automatically",
    )
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--cases", type=int, default=1000, help="number of generated requests or frames")
    optional.add_argument("--seed", type=int, default=1337, help="random seed")
    optional.add_argument("--campaign", default="can_baseline", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--receive-timeout", type=float, default=0.05, help="seconds to collect response frames after each send")
    optional.add_argument("--inter-frame-delay-ms", type=float, default=5.0, help="delay between transmitted fuzzing frames")
    optional.add_argument("--inter-request-delay-ms", type=float, default=10.0, help="delay between protocol requests")
    optional.add_argument("--request-mode", choices=["functional", "physical", "mixed"], default="mixed", help="request addressing mode")
    optional.add_argument("--functional-id", type=parse_int, default=0x7DF, help="functional request ID")
    optional.add_argument("--physical-start", type=parse_int, default=0x7E0, help="first physical request ID to probe")
    optional.add_argument("--physical-end", type=parse_int, default=0x7E7, help="last physical request ID to probe")
    optional.add_argument("--service-bias", type=float, default=0.85, help="probability of generating a structured UDS service instead of a raw random request")
    optional.add_argument("--pid-bias", type=float, default=0.8, help="probability of choosing a common OBD PID")
    optional.add_argument("--malformed-rate", type=float, default=0.15, help="probability of generating a malformed protocol request")
    optional.add_argument("--fd", action="store_true", default=False, help="send CAN FD frames")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--id-min", type=parse_int, default=0x000, help="minimum arbitration ID")
    optional.add_argument("--id-max", type=parse_int, default=0x7FF, help="maximum arbitration ID")
    optional.add_argument("--diagnostic-bias", type=float, default=0.6, help="probability of choosing diagnostic request IDs when they are in range")
    optional.add_argument("--extended-probability", type=float, default=0.0, help="probability of generating extended ID frames")
    optional.add_argument("--include-remote", action="store_true", default=False, help="include remote frames in the campaign")
    optional.add_argument("--include-error", action="store_true", default=False, help="include error frames in the campaign")
    optional.add_argument("--target-ids", type=parse_int_list, default=parse_int_list("0x100,0x101,0x200,0x201,0x300,0x301"), help="comma separated target arbitration IDs")
    optional.add_argument("--opcodes", type=parse_int_list, default=parse_int_list("0x00,0x01,0x02,0x03,0x10,0x11,0x20,0x21,0x7f,0x80,0xfe,0xff"), help="comma separated private control opcodes")
    optional.add_argument("--structured-rate", type=float, default=0.7, help="probability of generating structured private control payloads")
    optional.add_argument("--min-payload-len", type=int, default=1, help="minimum payload length")
    optional.add_argument("--max-payload-len", type=int, default=8, help="maximum payload length")
    optional.add_argument("--extended", action="store_true", default=False, help="use extended CAN identifiers")
    optional.add_argument("--progress-interval", type=int, default=1, help="update progress after this many completed cases; 0 disables count-based updates")
    optional.add_argument("--progress-seconds", type=float, default=1.0, help="update progress after this many seconds; 0 disables time-based updates")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_keepalive_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    add_config_argument(optional)
    optional.add_argument("--preset", choices=sorted(KEEPALIVE_PRESETS), default="tester-present", help="activation frame preset")
    optional.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan; if omitted, interfaces are discovered automatically")
    optional.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface; if omitted, interfaces are discovered automatically")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=None, help="CAN FD data bitrate")
    optional.add_argument("--fd", action=argparse.BooleanOptionalAction, default=False, help="send the activation frame as CAN FD")
    optional.add_argument("--arbitration-id", type=parse_int, default=0x7DF, help="arbitration ID for the periodic activation frame")
    optional.add_argument("--payload", default="02 3E 00", help="hex payload for the periodic activation frame")
    optional.add_argument("--interval-ms", type=float, default=500.0, help="delay between activation frames")
    optional.add_argument("--format", choices=["standard", "extended"], default="standard", help="frame format for the activation frame")
    optional.add_argument("--listen", action=argparse.BooleanOptionalAction, default=True, help="listen for responses after each activation frame")
    optional.add_argument("--listen-timeout", type=float, default=0.05, help="seconds to wait for activation responses")
    optional.add_argument("--check-message", action=argparse.BooleanOptionalAction, default=True, help="validate CAN messages before sending")


def add_plot_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    add_config_argument(optional)
    optional.add_argument("--input", default="result/can_baseline_cases.csv", help="input CSV result file")
    optional.add_argument("--output-dir", default="plot", help="directory for generated PDF figures")


def add_clean_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    add_config_argument(optional)
    optional.add_argument("--result-dir", default="result", help="result directory to clean")
    optional.add_argument("--plot-dir", default="plot", help="plot directory to clean")


def add_list_arguments(parser: argparse.ArgumentParser) -> None:
    optional = parser.add_argument_group("optional arguments")
    add_config_argument(optional)
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
    add_config_argument(optional)
    required.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface")
    optional.add_argument("--bitrate", type=parse_optional_int, default=500000, help="arbitration bitrate; use none if backend does not need it")
    optional.add_argument("--data-bitrate", type=parse_optional_int, default=2000000, help="CAN FD data-phase bitrate")
    optional.add_argument("--fd-clock", type=int, default=80000000, help="CAN FD controller clock in Hz")
    optional.add_argument("--nominal-sample-point", type=float, default=87.5, help="CAN FD nominal-phase sample point in percent")
    optional.add_argument("--data-sample-point", type=float, default=80.0, help="CAN FD data-phase sample point in percent")
    optional.add_argument("--campaign", default="can_fd_check", help="campaign name used for output files")
    optional.add_argument("--output-dir", default="result", help="directory for CSV and JSON results")
    optional.add_argument("--probe-timeout", type=float, default=0.15, help="seconds to wait for responses after each FD probe")
    optional.add_argument("--probe-delay-ms", type=float, default=20.0, help="delay between FD probes")
    optional.add_argument("--no-progress", action="store_true", default=False, help="disable tqdm progress output")


def add_udsfuzz_arguments(parser: argparse.ArgumentParser) -> None:
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")
    add_config_argument(optional)
    required.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface")
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
    add_config_argument(optional)
    required.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface")
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
    add_config_argument(optional)
    required.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface")
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
    add_config_argument(optional)
    required.add_argument("--interface", default=None, help="python-can interface, for example pcan, vector, slcan, socketcan")
    required.add_argument("--channel", default=None, help="CAN channel name used by the selected python-can interface")
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
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


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
        console.warning("No CAN interfaces detected.")
        return
    rows = [format_interface_row(config) for config in configs]
    headers = ["interface", "channel", "device", "fd", "condition"]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    console.debug("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    console.debug("  ".join("-" * width for width in widths))
    for row in rows:
        console.debug("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def print_scan_objects_table(objects: list[dict[str, Any]]) -> None:
    if not objects:
        console.warning("No CAN communication objects detected.")
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
    console.debug("scan objects:")
    console.debug("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    console.debug("  ".join("-" * width for width in widths))
    for row in rows:
        console.debug("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


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


def print_status_line(interrupted: bool) -> None:
    status = "interrupted" if interrupted else "completed"
    print_status_value(status)


def print_status_value(status: str) -> None:
    console.log(f"status={status}", status_level(status))


def status_level(status: str) -> str:
    lowered = status.lower()
    if "error" in lowered or "failed" in lowered or "fail" in lowered:
        return "error"
    if lowered in {"interrupted", "not_run", "no_response"} or "warning" in lowered:
        return "warning"
    return "normal"

