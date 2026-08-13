from __future__ import annotations

import json
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

from .runtime.adapters import CANHardwareAdapter
from .runtime.keepalive import KeepaliveConfig, KeepaliveWorker
from .runtime.errors import CANConnectionError
from .config import (
    build_fuzz_keepalive_config,
    build_hardware_config,
    normalize_protocol,
    parse_hex_bytes,
    parse_int_list,
    parse_interface_names,
)
from .scanning.can_fd_scan import FDCheckConfig, run_fdcheck
from .fuzzing.can_fuzz import FuzzConfig, run_fuzzing
from .fuzzing.dbc_fuzz import DBCFuzzConfig, run_dbc_fuzzing
from .fuzzing.obd_fuzz import OBDFuzzConfig, run_obd_fuzzing
from .fuzzing.private_control_fuzz import PrivateFuzzConfig, run_private_fuzzing
from .fuzzing.uds_fuzz import UDSFuzzConfig, run_uds_fuzzing
from .fuzzing.xcp_fuzz import XCPFuzzConfig, run_xcp_fuzzing
from .scanning.can_id_scan import ScanConfig, run_scan
from .scanning.isotp_scan import IsoTpScanConfig, run_isotp_scan
from .scanning.xcp_scan import XCPScanConfig, run_xcp_scan
from .scanning.hardware_scan import list_can_interfaces
from .log import (
    format_bool,
    log_can_event,
    log_keepalive_response,
    log_shared_keepalive_config,
    log_structured,
    start_run_summary,
    print_interface_table,
    print_scan_objects_table,
    print_isotp_nodes_table,
    print_isotp_protocols_table,
    print_xcp_nodes_table,
    print_status_line,
    print_status_value,
    status_level,
)


def resolve_hardware(args: SimpleNamespace, section: str):
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


def run_fuzz_from_args(args: SimpleNamespace) -> None:
    protocol = normalize_protocol(getattr(args, "protocol", None)) or "can"
    args.protocol = protocol

    if protocol == "can":
        run_can_fuzz_from_args(args)
        return
    if protocol == "dbc":
        run_dbcfuzz_from_args(args)
        return

    if protocol == "uds":
        run_udsfuzz_from_args(args)
        return
    if protocol == "obd":
        run_obdfuzz_from_args(args)
        return
    if protocol == "private":
        run_privatefuzz_from_args(args)
        return
    if protocol == "xcp":
        run_xcpfuzz_from_args(args)
        return
    raise SystemExit(f"unsupported protocol: {protocol}")


def cli_target_id(args: SimpleNamespace) -> int | None:
    return getattr(args, "target_id", None)


def override_targets_with_cli_id(args: SimpleNamespace) -> None:
    target_id = cli_target_id(args)
    if target_id is None:
        return
    args.id_min = target_id
    args.id_max = target_id
    args.request_mode = "physical"
    args.physical_start = target_id
    args.physical_end = target_id
    args.target_ids = str(target_id)
    args.request_ids = (target_id,)


def run_can_fuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    hardware = resolve_hardware(args, "fuzz")
    config = FuzzConfig(
        hardware=hardware,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        inter_frame_delay_ms=args.inter_frame_delay_ms,
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
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses})
    log_structured("debug", "coverage", {"points": result.coverage_points, "reasons": result.unique_reasons})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})


def run_dbcfuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    if not getattr(args, "dbc_file", None):
        raise SystemExit("missing required argument: --dbc_file")
    hardware = resolve_hardware(args, "fuzz")
    dbc_file = Path(str(args.dbc_file))
    if not dbc_file.exists():
        raise SystemExit(f"DBC file not found: {dbc_file}")
    config = DBCFuzzConfig(
        hardware=hardware,
        dbc_file=dbc_file,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        inter_frame_delay_ms=args.inter_frame_delay_ms,
        target_id=cli_target_id(args),
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("fuzz", "dbc", config.campaign, config.cases)
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases, "dbc_file": config.dbc_file})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_dbc_fuzzing(config, progress_callback=log_can_event)
    except (CANConnectionError, ValueError) as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses, "decoded_responses": result.decoded_responses})
    log_structured("debug", "coverage", {"messages": result.unique_messages, "signals": result.unique_signals, "points": result.coverage_points})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})




def run_xcpfuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    hardware = resolve_hardware(args, "fuzz")
    config = XCPFuzzConfig(
        hardware=hardware,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        inter_request_delay_ms=args.inter_request_delay_ms,
        target_ids=tuple(parse_int_list(args.target_ids)),
        request_ids=tuple(getattr(args, "request_ids", ()) or ()),
        request_modes=tuple(getattr(args, "request_modes", ()) or ()),
        request_mix=float(getattr(args, "request_mix", 0.5)),
        malformed_rate=args.malformed_rate,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("fuzz", "xcp", config.campaign, config.cases)
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_xcp_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses})
    log_structured("debug", "coverage", {"commands": result.unique_commands, "targets": result.unique_targets})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})

def run_keepalive_from_args(args: SimpleNamespace) -> None:
    hardware = resolve_hardware(args, "keepalive")
    keepalive_args = build_keepalive_args(vars(args))
    config = KeepaliveConfig(
        enabled=True,
        arbitration_id=keepalive_args.arbitration_id,
        payload=parse_hex_bytes(keepalive_args.payload),
        interval_ms=keepalive_args.interval_ms,
        extended=keepalive_args.format == "extended",
        fd=keepalive_args.fd,
        listen=keepalive_args.listen,
        listen_timeout=keepalive_args.listen_timeout,
        check_message=keepalive_args.check_message,
    )
    log_structured("info", "opening", {"interface": hardware.interface, "channel": hardware.channel, "bitrate": hardware.bitrate, "interval_ms": keepalive_args.interval_ms, "id": f"0x{keepalive_args.arbitration_id:x}"})
    try:
        with CANHardwareAdapter(hardware) as adapter:
            worker = KeepaliveWorker(adapter, config, response_callback=log_keepalive_response)
            worker.start()
            log_structured("info", "keepalive", {"status": "running", "action": "press_ctrl_c_to_stop"})
            try:
                while worker.is_alive():
                    time.sleep(1.0)
            except KeyboardInterrupt:
                log_structured("warning", "interrupt", {"signal": "Ctrl+C", "task": "keepalive", "action": "saving_results"})
            stats = worker.stop()
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    else:
        log_structured("info", "keepalive_summary", {"sent": stats.sent, "errors": stats.errors, "responses": stats.responses})
        if stats.response_ids:
            log_structured("info", "keepalive_response_ids", {"values": ",".join(f"0x{value:x}" for value in stats.response_ids)})
        if stats.response_payloads:
            log_structured("info", "keepalive_response_payloads", {"values": ",".join(stats.response_payloads)})
        if stats.errors:
            log_structured("warning", "keepalive_last_error", {"message": stats.last_error})

def run_clean_from_args(args: SimpleNamespace) -> None:
    clean_directory(Path(args.result_dir))
    log_structured("info", "cleaned", {"result_dir": args.result_dir})


def run_list_from_args(args: SimpleNamespace) -> None:
    configs = discover_interfaces(args)
    if args.json:
        import json

        print(json.dumps(configs, indent=2, default=str))
        return
    print_interface_table(configs)


def run_scan_from_args(args: SimpleNamespace) -> None:
    hardware = resolve_hardware(args, "scan")
    passive = bool(args.passive_scan)
    active = bool(args.active_scan)
    config = ScanConfig(
        hardware=hardware,
        output_dir=Path(args.output_dir),
        campaign=args.campaign,
        passive_duration=args.passive_duration,
        active_timeout=args.active_timeout,
        inter_probe_delay_ms=args.inter_probe_delay_ms,
        active=active,
        passive=passive,
        probe_id_start=args.probe_id_start,
        probe_id_end=args.probe_id_end,
    )
    start_run_summary("scan", "scan", config.campaign, None)
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "passive": config.passive, "active": config.active})
    try:
        summary = run_scan(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": summary['campaign']})
    print_status_value(str(summary["status"]))
    log_structured("info", "scan", {"unique_ids": summary['unique_ids'], "total_frames": summary['total_frames_observed']})
    log_structured("debug", "active", {"probes": summary['active_probes'], "responses": summary['active_responses']})
    if summary.get("background_traffic_detected"):
        log_structured("warning", "background_traffic_detected", {"value": True, "reason": "no_probe_linked_responses"})
    diagnostic_ids = ','.join(summary['suspected_diagnostic_response_ids']) or 'none'
    if diagnostic_ids == "none":
        log_structured("warning", "diagnostic_response_ids", {"value": diagnostic_ids})
    else:
        log_structured("debug", "diagnostic_response_ids", {"value": diagnostic_ids})
    log_structured("info", "files", {"ids_csv": summary['ids_csv_path'], "active_csv": summary['active_csv_path']})
    print_scan_objects_table(summary.get("observed_objects", []))

    scan_protocol = getattr(args, "scan_protocol", "all")
    run_isotp_stage = scan_protocol in {"all", "isotp", "uds", "obd"}
    run_xcp_stage = scan_protocol in {"all", "xcp"}
    isotp_probe_protocols = ("uds", "obd")
    if scan_protocol == "uds":
        isotp_probe_protocols = ("uds",)
    elif scan_protocol == "obd":
        isotp_probe_protocols = ("obd",)
    elif scan_protocol == "isotp":
        isotp_probe_protocols = ()

    if run_isotp_stage:
        isotp_config = IsoTpScanConfig(
            hardware=hardware,
            output_dir=Path(args.output_dir),
            campaign=f"{args.campaign}_isotp",
            request_id_start=args.isotp_request_id_start,
            request_id_end=args.isotp_request_id_end,
            sniff_time=args.isotp_sniff_time,
            verify_results=args.isotp_verify_results,
            extended_can_id=args.isotp_extended_can_id,
            protocol_probe=bool(args.isotp_protocol_probe and isotp_probe_protocols),
            protocol_probe_timeout=args.isotp_protocol_probe_timeout,
            protocols=isotp_probe_protocols,
        )
        log_structured("info", "isotp_scan", {"request_id_start": f"0x{isotp_config.request_id_start:x}", "request_id_end": f"0x{isotp_config.request_id_end:x}", "sniff_time": isotp_config.sniff_time})
        try:
            isotp_summary = run_isotp_scan(isotp_config, progress_callback=log_can_event)
        except CANConnectionError as exc:
            log_structured("error", "error", {"message": exc})
            raise SystemExit(2) from exc
        log_structured("info", "isotp_nodes", {"count": isotp_summary["node_count"], "uds": isotp_summary["uds_node_count"], "obd": isotp_summary["obd_node_count"]})
        log_structured("info", "files", {"isotp_nodes_csv": isotp_summary["nodes_csv_path"], "isotp_protocols_csv": isotp_summary["protocols_csv_path"]})
        print_isotp_nodes_table(isotp_summary.get("nodes", []))
        print_isotp_protocols_table(isotp_summary.get("protocols", []))

    if run_xcp_stage:
        xcp_config = XCPScanConfig(
            hardware=hardware,
            output_dir=Path(args.output_dir),
            campaign=f"{args.campaign}_xcp",
            request_id_start=args.xcp_request_id_start,
            request_id_end=args.xcp_request_id_end,
            response_timeout=args.xcp_response_timeout,
            inter_probe_delay_ms=args.inter_probe_delay_ms,
            extended_can_id=args.xcp_extended_can_id,
        )
        log_structured("info", "xcp_scan", {"request_id_start": f"0x{xcp_config.request_id_start:x}", "request_id_end": f"0x{xcp_config.request_id_end:x}", "response_timeout": xcp_config.response_timeout})
        try:
            xcp_summary = run_xcp_scan(xcp_config, progress_callback=log_can_event)
        except CANConnectionError as exc:
            log_structured("error", "error", {"message": exc})
            raise SystemExit(2) from exc
        log_structured("info", "xcp_nodes", {"count": xcp_summary["node_count"], "positive": xcp_summary["positive_nodes"], "negative": xcp_summary["negative_nodes"]})
        log_structured("info", "files", {"xcp_nodes_csv": xcp_summary["nodes_csv_path"]})
        print_xcp_nodes_table(xcp_summary.get("nodes", []))


def run_fdcheck_from_args(args: SimpleNamespace) -> None:
    hardware = resolve_hardware(args, "fdcheck")
    config = FDCheckConfig(
        hardware=hardware,
        output_dir=Path(args.output_dir),
        campaign=args.campaign,
        probe_timeout=args.probe_timeout,
        probe_delay_ms=args.probe_delay_ms,
    )
    start_run_summary("fdcheck", "fdcheck", config.campaign, len(config.probe_lengths) * 4)
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "data_bitrate": config.hardware.data_bitrate, "fd_timing_preset": config.hardware.fd_timing_preset, "fd_clock": config.hardware.fd_clock, "fd": True})
    try:
        result = run_fdcheck(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("debug" if result.hardware_fd_supported else "warning", "hardware_fd_supported", {"value": format_bool(result.hardware_fd_supported)})
    log_structured("debug" if result.hardware_fd_opened else "warning", "hardware_fd_opened", {"value": format_bool(result.hardware_fd_opened)})
    log_structured(status_level(result.hardware_fd_status), "hardware_fd_status", {"value": result.hardware_fd_status})
    if result.hardware_error:
        log_structured("error", "hardware_error", {"message": result.hardware_error})
    log_structured("debug" if result.target_fd_supported else "warning", "target_fd_supported", {"value": format_bool(result.target_fd_supported)})
    log_structured(status_level(result.target_fd_status), "target_fd_status", {"value": result.target_fd_status})
    log_structured("info", "result", {"probe_count": result.probe_count, "response_count": result.response_count})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})


def run_udsfuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    hardware = resolve_hardware(args, "fuzz")
    config = UDSFuzzConfig(
        hardware=hardware,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
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
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases, "request_mode": config.request_mode})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_uds_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses})
    log_structured("debug", "responses", {"positive": result.positive_responses, "negative": result.negative_responses, "multi_frame": result.multi_frame_responses})
    log_structured("debug", "coverage", {"services": result.unique_services, "nrcs": result.unique_nrcs})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})


def run_obdfuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    hardware = resolve_hardware(args, "fuzz")
    config = OBDFuzzConfig(
        hardware=hardware,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
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
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases, "request_mode": config.request_mode})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_obd_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses})
    log_structured("debug", "responses", {"positive": result.positive_responses, "negative": result.negative_responses})
    log_structured("debug", "coverage", {"modes": result.unique_modes, "pids": result.unique_pids})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})


def run_privatefuzz_from_args(args: SimpleNamespace) -> None:
    override_targets_with_cli_id(args)
    hardware = resolve_hardware(args, "fuzz")
    config = PrivateFuzzConfig(
        hardware=hardware,
        cases=args.cases,
        seed=args.seed,
        campaign=args.campaign,
        output_dir=Path(args.output_dir),
        inter_request_delay_ms=args.inter_request_delay_ms,
        target_ids=tuple(parse_int_list(args.target_ids)),
        opcodes=tuple(parse_int_list(args.opcodes)),
        structured_rate=args.structured_rate,
        malformed_rate=args.malformed_rate,
        min_payload_len=args.min_payload_len,
        max_payload_len=args.max_payload_len,
        extended=args.extended,
        progress_interval=args.progress_interval,
        progress_seconds=args.progress_seconds,
        keepalive=build_fuzz_keepalive_config(args),
    )
    start_run_summary("privatefuzz", "private", config.campaign, config.cases)
    log_structured("info", "opening", {"interface": config.hardware.interface, "channel": config.hardware.channel, "bitrate": config.hardware.bitrate, "cases": config.cases, "targets": len(config.target_ids), "opcodes": len(config.opcodes)})
    log_shared_keepalive_config(config.keepalive, config.output_dir / f"{config.campaign}_keepalive.csv")
    try:
        result = run_private_fuzzing(config, progress_callback=log_can_event)
    except CANConnectionError as exc:
        log_structured("error", "error", {"message": exc})
        raise SystemExit(2) from exc
    log_structured("info", "campaign", {"name": result.campaign})
    print_status_line(result.interrupted)
    log_structured("info", "summary", {"cases": f"{result.completed_cases}/{result.cases}", "sent": result.sent, "faults": result.faults, "responses": result.responses})
    log_structured("debug", "coverage", {"targets": result.unique_targets, "opcodes": result.unique_opcodes, "points": result.coverage_points})
    log_structured("info", "files", {"csv": result.csv_path, "summary": result.summary_path})


def clean_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
