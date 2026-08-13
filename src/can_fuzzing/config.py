from __future__ import annotations

import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import click

from .runtime.keepalive import KeepaliveConfig
from .runtime.models import CANHardwareConfig
from .scanning.hardware_scan import DEFAULT_DISCOVERY_INTERFACES


def read_toml_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except OSError as exc:
        raise click.ClickException(f"could not read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"could not parse config file {path}: {exc}") from exc


CAN_FD_TIMING_PRESETS: dict[str, dict[str, Any]] = {
    "sae-j2284": {
        "bitrate": 500000,
        "data_bitrate": 2000000,
        "fd_clock": 80000000,
        "nominal_sample_point": 87.5,
        "data_sample_point": 80.0,
    },
    "sae-j2284-5": {
        "bitrate": 500000,
        "data_bitrate": 5000000,
        "fd_clock": 80000000,
        "nominal_sample_point": 87.5,
        "data_sample_point": 80.0,
    },
}


def normalize_fd_timing_preset(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower().replace("_", "-")
    aliases = {
        "j2284": "sae-j2284",
        "sae-j2284-4": "sae-j2284",
        "500k-2m": "sae-j2284",
        "500k/2m": "sae-j2284",
        "j2284-5": "sae-j2284-5",
        "500k-5m": "sae-j2284-5",
        "500k/5m": "sae-j2284-5",
    }
    token = aliases.get(token, token)
    return token if token in CAN_FD_TIMING_PRESETS else None


def apply_fd_timing_preset(merged: dict[str, Any], cli_keys: set[str]) -> None:
    preset_name = normalize_fd_timing_preset(merged.get("fd_timing_preset"))
    if preset_name is None:
        return
    merged["fd_timing_preset"] = preset_name
    for key, value in CAN_FD_TIMING_PRESETS[preset_name].items():
        if key not in cli_keys:
            merged[key] = value


FUZZ_PROTOCOL_ALIASES = {
    "baseline": "can",
    "can_baseline": "can",
    "dbc_fuzz": "dbc",
    "dbcfuzz": "dbc",
    "dbc_fuzzing": "dbc",
    "private_control": "private",
    "privatefuzz": "private",
    "udsfuzz": "uds",
    "obdfuzz": "obd",
    "xcpfuzz": "xcp",
}
FUZZ_PROTOCOL_SECTION_MAP = {
    "can": None,
    "dbc": "dbcfuzz",
    "uds": "udsfuzz",
    "obd": "obdfuzz",
    "private": "privatefuzz",
    "xcp": "xcpfuzz",
}
FUZZ_PROTOCOL_CAMPAIGNS = {
    "can": "can_baseline",
    "dbc": "dbc_baseline",
    "uds": "uds_baseline",
    "obd": "obd_baseline",
    "private": "private_control_baseline",
    "xcp": "xcp_baseline",
}


def normalize_protocol(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower().replace("-", "_")
    if not token:
        return None
    return FUZZ_PROTOCOL_ALIASES.get(token, token)



def parse_protocol(value: str) -> str:
    normalized = normalize_protocol(value)
    if normalized in {"can", "dbc", "uds", "obd", "private", "xcp"}:
        return normalized
    raise click.BadParameter("protocol must be one of: can, dbc, uds, obd, private, xcp")


SUPPORTED_SCAN_PROTOCOLS = ("all", "can", "isotp", "uds", "obd", "xcp")
SCAN_PROTOCOL_ALIASES = {"iso-tp": "isotp", "iso_tp": "isotp", "iso15765-2": "isotp", "iso15765_2": "isotp"}


def normalize_scan_protocol(value: Any) -> str | None:
    if value is None:
        return None
    token = str(value).strip().lower().replace("_", "-")
    if not token:
        return None
    normalized = SCAN_PROTOCOL_ALIASES.get(token, token)
    if normalized not in SUPPORTED_SCAN_PROTOCOLS:
        raise click.BadParameter(f"scan protocol must be one of: {', '.join(SUPPORTED_SCAN_PROTOCOLS)}")
    return normalized


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_optional_int(value: str) -> int | None:
    if value.lower() in {"none", "null", "", "auto"}:
        return None
    return int(value, 0)


def is_auto_token(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() == "auto"


def parse_int_list(value: str) -> list[int]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise click.BadParameter("at least one integer value is required")
    return [parse_int(item) for item in items]


def parse_hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def parse_interface_names(value: str) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


HARDWARE_KEYS = {

    "interface",
    "channel",
    "bitrate",
    "receive_timeout",
    "fd",
    "data_bitrate",
    "auto_bitrate",
    "bitrate_candidates",
    "data_bitrate_candidates",
    "bitrate_probe_timeout",
    "fd_timing_preset",
    "fd_clock",
    "nominal_sample_point",
    "data_sample_point",
    "check_message",
    "drop_echo",
}
FUZZ_KEYS = {
    "protocol",
    "cases",
    "seed",
    "campaign",
    "output_dir",
    "receive_timeout",
    "inter_frame_delay_ms",
    "inter_request_delay_ms",
    "dbc_file",
    "request_mode",
    "functional_id",
    "physical_start",
    "physical_end",
    "service_bias",
    "pid_bias",
    "malformed_rate",
    "id_min",
    "id_max",
    "diagnostic_bias",
    "extended_probability",
    "include_remote",
    "include_error",
    "target_ids",
    "target_id",
    "opcodes",
    "structured_rate",
    "min_payload_len",
    "max_payload_len",
    "extended",
    "progress_interval",
    "progress_seconds",
    "keepalive",
    "keepalive_id",
    "keepalive_payload",
    "keepalive_interval_ms",
    "keepalive_format",
    "keepalive_fd",
    "keepalive_listen",
    "keepalive_listen_timeout",
    "keepalive_check_message",
}
LIST_KEYS = {"interfaces", "include_virtual", "json", "verbose"}
CLEAN_KEYS = {"result_dir"}
KEEPALIVE_FUZZ_KEYS = {"keepalive", "keepalive_id", "keepalive_payload", "keepalive_interval_ms", "keepalive_format", "keepalive_fd", "keepalive_listen", "keepalive_listen_timeout", "keepalive_check_message"}
KEEPALIVE_CLI_KEYS = {"fd", "arbitration_id", "payload", "interval_ms", "format", "listen", "listen_timeout", "check_message"}
FDCHECK_KEYS = {"campaign", "output_dir", "probe_timeout", "probe_delay_ms", "probe_lengths"}
SCAN_KEYS = {"campaign", "output_dir", "passive_duration", "active_timeout", "inter_probe_delay_ms", "probe_id_start", "probe_id_end", "passive_only", "active_only", "scan_protocol", "isotp_request_id_start", "isotp_request_id_end", "isotp_sniff_time", "isotp_verify_results", "isotp_extended_can_id", "isotp_protocol_probe", "isotp_protocol_probe_timeout", "xcp_request_id_start", "xcp_request_id_end", "xcp_response_timeout", "xcp_inter_probe_delay_ms", "xcp_extended_can_id"}
FUZZ_REQUIRED_KEYS_BY_PROTOCOL = {
    "can": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_frame_delay_ms", "id_min", "id_max", "diagnostic_bias", "extended_probability", "include_remote", "include_error", "progress_interval", "progress_seconds"},
    "dbc": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_frame_delay_ms", "dbc_file", "progress_interval", "progress_seconds"},
    "uds": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_request_delay_ms", "request_mode", "functional_id", "physical_start", "physical_end", "service_bias", "malformed_rate", "progress_interval", "progress_seconds"},
    "obd": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_request_delay_ms", "request_mode", "functional_id", "physical_start", "physical_end", "pid_bias", "malformed_rate", "progress_interval", "progress_seconds"},
    "private": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_request_delay_ms", "target_ids", "opcodes", "structured_rate", "malformed_rate", "min_payload_len", "max_payload_len", "extended", "progress_interval", "progress_seconds"},
    "xcp": {"protocol", "cases", "seed", "campaign", "output_dir", "inter_request_delay_ms", "target_ids", "request_ids", "request_modes", "request_mix", "malformed_rate", "progress_interval", "progress_seconds"},
}

CLICK_INT_KEYS = {"id_min", "id_max", "functional_id", "physical_start", "physical_end", "probe_id_start", "probe_id_end", "target_id", "isotp_request_id_start", "isotp_request_id_end", "xcp_request_id_start", "xcp_request_id_end", "keepalive_id", "arbitration_id"}
CLICK_OPTIONAL_INT_KEYS = {"bitrate", "data_bitrate"}
CLICK_LIST_AS_CSV_KEYS = {"interfaces", "target_ids", "opcodes", "bitrate_candidates", "data_bitrate_candidates", "probe_lengths"}


def normalize_config_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if key in CLICK_LIST_AS_CSV_KEYS and isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    if key in CLICK_OPTIONAL_INT_KEYS:
        return parse_optional_int(str(value)) if not isinstance(value, int) else value
    if key in CLICK_INT_KEYS:
        return parse_int(str(value)) if not isinstance(value, int) else value
    if key == "protocol":
        return parse_protocol(str(value))
    if key == "scan_protocol":
        return normalize_scan_protocol(value)
    if key == "fd_timing_preset":
        normalized = normalize_fd_timing_preset(str(value))
        if normalized is None:
            raise click.BadParameter("fd_timing_preset must be one of: sae-j2284, sae-j2284-5")
        return normalized
    return value


def extract_config(raw_config: dict[str, Any], allowed_keys: set[str], section: str) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    if section in {"hardware", "fuzz", "clean", "list", "keepalive", "fdcheck", "scan"}:
        for key, value in raw_config.items():
            if not isinstance(value, dict):
                normalized_key = key.replace("-", "_")
                if normalized_key in allowed_keys:
                    merged[normalized_key] = value
    section_config = raw_config.get(section, {})
    if isinstance(section_config, dict):
        for key, value in section_config.items():
            normalized_key = key.replace("-", "_")
            if section == "scan" and normalized_key == "protocol" and "scan_protocol" in allowed_keys:
                normalized_key = "scan_protocol"
            if normalized_key in allowed_keys:
                merged[normalized_key] = value
    return merged


def extract_keepalive_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    section = raw_config.get("keepalive", {})
    if not isinstance(section, dict):
        return {}
    mapping = {
        "enabled": "keepalive",
        "keepalive": "keepalive",
        "arbitration_id": "keepalive_id",
        "id": "keepalive_id",
        "payload": "keepalive_payload",
        "interval_ms": "keepalive_interval_ms",
        "format": "keepalive_format",
        "fd": "keepalive_fd",
        "listen": "keepalive_listen",
        "listen_timeout": "keepalive_listen_timeout",
        "check_message": "keepalive_check_message",
    }
    return {dest: section[key] for key, dest in mapping.items() if key in section}


def apply_auto_bitrate_tokens(merged: dict[str, Any]) -> None:
    if is_auto_token(merged.get("bitrate")):
        merged["bitrate"] = None
        merged["auto_bitrate"] = True
    if is_auto_token(merged.get("data_bitrate")):
        merged["data_bitrate"] = None
        merged["auto_bitrate"] = True


def hardware_required_keys(merged: dict[str, Any]) -> set[str]:
    required = {"receive_timeout", "fd", "auto_bitrate", "check_message", "drop_echo"}
    if merged.get("fd"):
        required.update({"data_bitrate", "fd_clock", "nominal_sample_point", "data_sample_point"})
    if merged.get("auto_bitrate"):
        required.update({"bitrate_candidates", "bitrate_probe_timeout"})
        if merged.get("fd"):
            required.add("data_bitrate_candidates")
    else:
        required.add("bitrate")
        if merged.get("fd"):
            required.add("data_bitrate")
    return required


def protocol_required_keys(section: str, protocol: str) -> set[str]:
    required = FUZZ_REQUIRED_KEYS_BY_PROTOCOL.get(protocol)
    if required is None:
        raise click.ClickException(f"unsupported protocol: {protocol}")
    return required


def _validate_required(section: str, merged: dict[str, Any], required_keys: set[str]) -> None:
    missing = sorted(key for key in required_keys if merged.get(key) is None)
    if missing:
        raise click.ClickException(f"missing required config value(s) for {section}: {', '.join(missing)}")


def _resolve_keepalive_values(source: Any, *, enabled: bool) -> tuple[int, bytes, float, bool, bool, bool, float, bool]:
    def pick(attr_name: str, required: bool = True) -> Any:
        value = getattr(source, attr_name, None)
        if value is None and required:
            raise click.ClickException(f"missing required config value: {attr_name}")
        return value

    if not enabled and all(getattr(source, name, None) is None for name in (
        "keepalive_id",
        "keepalive_payload",
        "keepalive_interval_ms",
        "keepalive_format",
        "keepalive_fd",
        "keepalive_listen",
        "keepalive_listen_timeout",
        "keepalive_check_message",
    )):
        return (0, b"", 0.0, False, False, False, 0.0, False)

    arbitration_id = int(pick("keepalive_id"))
    payload_raw = pick("keepalive_payload")
    interval_ms = float(pick("keepalive_interval_ms"))
    format_value = str(pick("keepalive_format"))
    fd_config_value = pick("keepalive_fd", required=False)
    fd_value = bool(getattr(source, "fd", False)) if fd_config_value is None else bool(fd_config_value)
    listen_value = bool(pick("keepalive_listen"))
    listen_timeout = float(pick("keepalive_listen_timeout"))
    check_message = bool(pick("keepalive_check_message"))
    return (arbitration_id, parse_hex_bytes(str(payload_raw)), interval_ms, format_value == "extended", fd_value, listen_value, listen_timeout, check_message)


def build_hardware_config(params: dict[str, Any]) -> CANHardwareConfig:
    args = build_args("hardware", HARDWARE_KEYS, params)
    merged = dict(vars(args))
    apply_fd_timing_preset(merged, {key for key, value in params.items() if value is not None})
    return CANHardwareConfig(
        interface=getattr(args, "interface", None),
        channel=getattr(args, "channel", None),
        bitrate=merged.get("bitrate"),
        receive_timeout=float(merged["receive_timeout"]),
        fd=bool(merged["fd"]),
        data_bitrate=merged.get("data_bitrate"),
        auto_bitrate=bool(merged["auto_bitrate"]),
        bitrate_candidates=tuple(parse_int_list(merged["bitrate_candidates"])) if merged.get("bitrate_candidates") is not None else (),
        data_bitrate_candidates=tuple(parse_int_list(merged["data_bitrate_candidates"])) if merged.get("data_bitrate_candidates") is not None else (),
        bitrate_probe_timeout=float(merged["bitrate_probe_timeout"]) if merged.get("bitrate_probe_timeout") is not None else 0.0,
        fd_timing_preset=normalize_fd_timing_preset(merged.get("fd_timing_preset")),
        fd_clock=int(merged["fd_clock"]) if merged.get("fd_clock") is not None else 0,
        nominal_sample_point=float(merged["nominal_sample_point"]) if merged.get("nominal_sample_point") is not None else 0.0,
        data_sample_point=float(merged["data_sample_point"]) if merged.get("data_sample_point") is not None else 0.0,
        check_message=bool(merged["check_message"]),
        drop_echo=bool(merged["drop_echo"]),
    )


def build_fuzz_keepalive_config(args: SimpleNamespace) -> KeepaliveConfig:
    enabled = bool(getattr(args, "keepalive", False))
    arbitration_id, payload, interval_ms, extended, fd, listen, listen_timeout, check_message = _resolve_keepalive_values(
        args,
        enabled=enabled,
    )
    return KeepaliveConfig(
        enabled=enabled,
        arbitration_id=arbitration_id,
        payload=payload,
        interval_ms=interval_ms,
        extended=extended,
        fd=fd,
        listen=listen,
        listen_timeout=listen_timeout,
        check_message=check_message,
    )


def build_args(section: str, allowed_keys: set[str], params: dict[str, Any]) -> SimpleNamespace:
    merged: dict[str, Any] = {}
    config_path = params.get("config")
    if config_path:
        raw_config = read_toml_config(Path(str(config_path)))
        if section in {"hardware", "fuzz", "fdcheck", "scan", "keepalive"}:
            merged.update(extract_config(raw_config, HARDWARE_KEYS, "hardware"))
        merged.update(extract_config(raw_config, allowed_keys, section))
        if section == "fuzz":
            protocol = normalize_protocol(params.get("protocol") or merged.get("protocol"))
            if protocol is None:
                raise click.ClickException("missing required config value: protocol")
            protocol_section = FUZZ_PROTOCOL_SECTION_MAP.get(protocol)
            if protocol_section is not None:
                merged.update(extract_config(raw_config, allowed_keys, protocol_section))
            if merged.get("campaign") is None:
                merged["campaign"] = FUZZ_PROTOCOL_CAMPAIGNS.get(protocol)
            merged.update(extract_keepalive_config(raw_config))
    cli_keys = {key for key, value in params.items() if value is not None}
    for key in cli_keys:
        merged[key] = params[key]

    if section == "hardware":
        apply_auto_bitrate_tokens(merged)
        apply_fd_timing_preset(merged, cli_keys)
        required_keys = hardware_required_keys(merged)
        _validate_required(section, merged, {key for key in required_keys if key not in {"interface", "channel"}})
    elif section == "fuzz":
        protocol = normalize_protocol(merged.get("protocol"))
        if protocol is None:
            raise click.ClickException("missing required config value: protocol")
        merged["protocol"] = protocol
        _validate_required(section, merged, protocol_required_keys(section, protocol))
    elif section == "keepalive":
        pass
    elif section == "list":
        _validate_required(section, merged, set())
    elif section == "clean":
        _validate_required(section, merged, CLEAN_KEYS)
    elif section == "fdcheck":
        _validate_required(section, merged, FDCHECK_KEYS)
    elif section == "scan":
        merged["scan_protocol"] = normalize_scan_protocol(merged.get("scan_protocol")) or "all"
        _validate_required(section, merged, SCAN_KEYS - {"scan_protocol"})
    else:
        _validate_required(section, merged, {key for key in allowed_keys if key != "config"})

    if section != "hardware":
        apply_auto_bitrate_tokens(merged)
        if section == "fuzz" and "fd_timing_preset" in merged:
            apply_fd_timing_preset(merged, cli_keys)
    return SimpleNamespace(**{key: normalize_config_value(key, value) for key, value in merged.items()})


def build_keepalive_args(params: dict[str, Any]) -> SimpleNamespace:
    args = build_args("keepalive", KEEPALIVE_CLI_KEYS, params)
    merged = dict(vars(args))
    _validate_required("keepalive", merged, {"arbitration_id", "payload", "interval_ms", "format", "listen", "listen_timeout", "check_message"})
    if merged.get("fd") is None:
        merged["fd"] = bool(merged.get("hardware_fd", False))
    return SimpleNamespace(**{key: normalize_config_value(key, value) for key, value in merged.items()})
