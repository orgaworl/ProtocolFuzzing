from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .adapters import CANConnectionError, CANHardwareAdapter
from .common import console
from .common.keepalive import KeepaliveConfig, KeepaliveWorker
from .cli_config import (
    build_fuzz_keepalive_config,
    normalize_protocol,
    parse_hex_bytes,
    parse_interface_names,
    parse_int_list,
)
from .discovery import list_can_interfaces
from .fdcheck import FDCheckConfig, run_fdcheck
from .fuzzers.can import FuzzConfig, run_fuzzing
from .fuzzers.dbc import DBCFuzzConfig, run_dbc_fuzzing
from .fuzzers.obd import OBDFuzzConfig, run_obd_fuzzing
from .fuzzers.private_control import PrivateFuzzConfig, run_private_fuzzing
from .fuzzers.uds import UDSFuzzConfig, run_uds_fuzzing
from .plotting import plot_results
from .scanner import ScanConfig, run_scan
from .log import (
    format_bool,
    log_can_event,
    log_keepalive_response,
    log_shared_keepalive_config,
    start_run_summary,
    print_interface_table,
    print_scan_objects_table,
    print_status_line,
    print_status_value,
    status_level,
)


def run_fuzz_from_args(args: SimpleNamespace) -> None:
    protocol = normalize_protocol(getattr(args, "protocol", None)) or "can"
    args.protocol = protocol

    if protocol == "can":
        run_can_fuzz_from_args(args)
        return
    if protocol == "dbc":
        run_dbcfuzz_from_args(args)
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


def run_can_fuzz_from_args(args: SimpleNamespace) -> None:
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
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("fuzz", "can", config.campaign, config.cases)
    console.info(
        f"opening interface={config.interface} channel={config.channel} "
        f"bitrate={config.bitrate} cases={config.cases}",
        flush=True,
    )
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"coverage_points={result.coverage_points} unique_reasons={result.unique_reasons}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


def run_dbcfuzz_from_args(args: SimpleNamespace) -> None:
    if not getattr(args, "dbc_file", None):
        raise SystemExit("missing required argument: --dbc_file")
    args.interface, args.channel = resolve_interface_and_channel(args, "fuzz")
    dbc_file = Path(str(args.dbc_file))
    if not dbc_file.exists():
        raise SystemExit(f"DBC file not found: {dbc_file}")
    campaign = args.campaign if getattr(args, "campaign", None) != "can_baseline" else "dbc_baseline"
    config = DBCFuzzConfig(
        dbc_file=dbc_file,
        cases=args.cases,
        seed=args.seed,
        campaign=campaign,
        output_dir=Path(args.output_dir),
        interface=args.interface,
        channel=args.channel,
        bitrate=args.bitrate,
        receive_timeout=args.receive_timeout,
        inter_frame_delay_ms=args.inter_frame_delay_ms,
        fd=args.fd,
        data_bitrate=args.data_bitrate,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("fuzz", "dbc", config.campaign, config.cases)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} dbc_file={config.dbc_file}",
        flush=True,
    )
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_dbc_fuzzing(config, progress_callback=log_can_event)
    except (CANConnectionError, ValueError) as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(
        f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses} decoded_responses={result.decoded_responses}"
    )
    console.debug(
        f"unique_messages={result.unique_messages} unique_signals={result.unique_signals} coverage_points={result.coverage_points}"
    )
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")


def run_keepalive_from_args(args: SimpleNamespace) -> None:
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

def run_plot_from_args(args: SimpleNamespace) -> None:
    outputs = plot_results(Path(args.input), Path(args.output_dir))
    for output in outputs:
        console.info(f"wrote={output}")


def run_clean_from_args(args: SimpleNamespace) -> None:
    clean_directory(Path(args.result_dir))
    clean_directory(Path(args.plot_dir))
    console.info(f"cleaned={args.result_dir},{args.plot_dir}")


def run_list_from_args(args: SimpleNamespace) -> None:
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


def resolve_interface_and_channel(args: SimpleNamespace, section: str) -> tuple[str, str]:
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


def run_scan_from_args(args: SimpleNamespace) -> None:
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
    start_run_summary("scan", "scan", config.campaign, None)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} "
        f"passive={config.passive} active={config.active}",
        flush=True,
    )
    try:
        summary = run_scan(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={summary['campaign']}")
    print_status_value(str(summary["status"]))
    console.info(f"unique_ids={summary['unique_ids']} total_frames={summary['total_frames_observed']}")
    console.debug(f"active_probes={summary['active_probes']} active_responses={summary['active_responses']}")
    if summary.get("background_traffic_detected"):
        console.warning(
            "background_traffic_detected=yes no probe-linked responses were found; scan results may come from unrelated bus activity"
        )
    diagnostic_ids = ','.join(summary['suspected_diagnostic_response_ids']) or 'none'
    if diagnostic_ids == "none":
        console.warning(f"diagnostic_response_ids={diagnostic_ids}")
    else:
        console.debug(f"diagnostic_response_ids={diagnostic_ids}")
    console.info(f"ids_csv={summary['ids_csv_path']}")
    console.info(f"active_csv={summary['active_csv_path']}")
    print_scan_objects_table(summary.get("observed_objects", []))


def run_fdcheck_from_args(args: SimpleNamespace) -> None:
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
    start_run_summary("fdcheck", "fdcheck", config.campaign, len(config.probe_lengths) * 4)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} "
        f"data_bitrate={config.data_bitrate} fd_clock={config.fd_clock} fd=True",
        flush=True,
    )
    try:
        result = run_fdcheck(config, progress_callback=log_can_event)
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


def run_udsfuzz_from_args(args: SimpleNamespace) -> None:
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
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("udsfuzz", "uds", config.campaign, config.cases)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_uds_fuzzing(config, progress_callback=log_can_event)
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


def run_obdfuzz_from_args(args: SimpleNamespace) -> None:
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
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("obdfuzz", "obd", config.campaign, config.cases)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} request_mode={config.request_mode}",
        flush=True,
    )
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_obd_fuzzing(config, progress_callback=log_can_event)
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


def run_privatefuzz_from_args(args: SimpleNamespace) -> None:
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
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("privatefuzz", "private", config.campaign, config.cases)
    console.info(
        f"opening interface={config.interface} channel={config.channel} bitrate={config.bitrate} cases={config.cases} targets={len(config.target_ids)} opcodes={len(config.opcodes)}",
        flush=True,
    )
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_private_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        console.error(f"error: {exc}")
        raise SystemExit(2) from exc
    console.info(f"campaign={result.campaign}")
    print_status_line(result.interrupted)
    console.info(f"cases={result.completed_cases}/{result.cases} sent={result.sent} faults={result.faults} responses={result.responses}")
    console.debug(f"unique_targets={result.unique_targets} unique_opcodes={result.unique_opcodes} coverage_points={result.coverage_points}")
    console.info(f"csv={result.csv_path}")
    console.info(f"summary={result.summary_path}")

def clean_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
