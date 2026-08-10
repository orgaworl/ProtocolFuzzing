from __future__ import annotations

import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import click

from .runtime.keepalive import KeepaliveConfig
from .runtime.discovery import DEFAULT_DISCOVERY_INTERFACES


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
}
FUZZ_PROTOCOL_SECTION_MAP = {
    "can": None,
    "dbc": "dbcfuzz",
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
    if normalized in {"can", "dbc", "uds", "obd", "private"}:
        return normalized
    raise click.BadParameter("protocol must be one of: can, dbc, uds, obd, private")



def build_fuzz_keepalive_config(args: SimpleNamespace) -> KeepaliveConfig:
    preset_name = normalize_keepalive_preset(getattr(args, "keepalive_preset", None)) or "tester-present"
    preset = KEEPALIVE_PRESETS[preset_name]
    frame_format = value_or_default(getattr(args, "keepalive_format", None), preset["format"])
    return KeepaliveConfig(
        enabled=bool(getattr(args, "keepalive", False)),
        arbitration_id=value_or_default(getattr(args, "keepalive_id", None), preset["arbitration_id"]),
        payload=parse_hex_bytes(value_or_default(getattr(args, "keepalive_payload", None), preset["payload"])),
        interval_ms=value_or_default(getattr(args, "keepalive_interval_ms", None), 500.0),
        extended=frame_format == "extended",
        fd=value_or_default(getattr(args, "keepalive_fd", None), preset["fd"]),
        listen=value_or_default(getattr(args, "keepalive_listen", None), preset["listen"]),
        listen_timeout=value_or_default(getattr(args, "keepalive_listen_timeout", None), preset["listen_timeout"]),
        check_message=value_or_default(getattr(args, "keepalive_check_message", None), preset["check_message"]),
    )


def value_or_default(value: Any, default: Any) -> Any:
    return default if value is None else value


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

CLICK_INT_KEYS = {"id_min", "id_max", "functional_id", "physical_start", "physical_end", "keepalive_id", "arbitration_id"}
CLICK_OPTIONAL_INT_KEYS = {"bitrate", "data_bitrate"}
CLICK_LIST_AS_CSV_KEYS = {"interfaces", "target_ids", "opcodes", "bitrate_candidates", "data_bitrate_candidates"}


FUZZ_DEFAULTS: dict[str, Any] = {
    "config": None,
    "protocol": "can",
    "interface": None,
    "channel": None,
    "interfaces": None,
    "include_virtual": False,
    "json": False,
    "verbose": False,
    "bitrate": 500000,
    "cases": 1000,
    "seed": 1337,
    "campaign": "can_baseline",
    "output_dir": "result",
    "receive_timeout": 0.05,
    "inter_frame_delay_ms": 5.0,
    "inter_request_delay_ms": 10.0,
    "dbc_file": None,
    "request_mode": "mixed",
    "functional_id": 0x7DF,
    "physical_start": 0x7E0,
    "physical_end": 0x7E7,
    "service_bias": 0.85,
    "pid_bias": 0.8,
    "malformed_rate": 0.15,
    "fd": False,
    "data_bitrate": None,
    "auto_bitrate": False,
    "bitrate_candidates": "500000,250000,125000,1000000,800000,100000,50000",
    "data_bitrate_candidates": "2000000,5000000,4000000,1000000",
    "bitrate_probe_timeout": 0.2,
    "fd_timing_preset": None,
    "fd_clock": 80000000,
    "nominal_sample_point": 87.5,
    "data_sample_point": 80.0,
    "id_min": 0x000,
    "id_max": 0x7FF,
    "diagnostic_bias": 0.6,
    "extended_probability": 0.0,
    "include_remote": False,
    "include_error": False,
    "target_ids": "0x100,0x101,0x200,0x201,0x300,0x301",
    "opcodes": "0x00,0x01,0x02,0x03,0x10,0x11,0x20,0x21,0x7f,0x80,0xfe,0xff",
    "structured_rate": 0.7,
    "min_payload_len": 1,
    "max_payload_len": 8,
    "extended": False,
    "progress_interval": 1,
    "progress_seconds": 1.0,
    "no_progress": False,
    "keepalive": False,
    "keepalive_preset": "tester-present",
    "keepalive_id": None,
    "keepalive_payload": None,
    "keepalive_interval_ms": None,
    "keepalive_format": None,
    "keepalive_fd": None,
    "keepalive_listen": None,
    "keepalive_listen_timeout": None,
    "keepalive_check_message": None,
}
LIST_DEFAULTS: dict[str, Any] = {"config": None, "interfaces": ",".join(DEFAULT_DISCOVERY_INTERFACES), "include_virtual": False, "json": False, "verbose": False}
CLEAN_DEFAULTS: dict[str, Any] = {"config": None, "result_dir": "result"}
KEEPALIVE_DEFAULTS: dict[str, Any] = {
    "config": None,
    "preset": "tester-present",
    "interface": None,
    "channel": None,
    "interfaces": None,
    "include_virtual": False,
    "json": False,
    "verbose": False,
    "bitrate": 500000,
    "data_bitrate": None,
    "auto_bitrate": False,
    "bitrate_candidates": "500000,250000,125000,1000000,800000,100000,50000",
    "data_bitrate_candidates": "2000000,5000000,4000000,1000000",
    "bitrate_probe_timeout": 0.2,
    "fd_timing_preset": None,
    "fd_clock": 80000000,
    "nominal_sample_point": 87.5,
    "data_sample_point": 80.0,
    "fd": False,
    "arbitration_id": 0x7DF,
    "payload": "02 3E 00",
    "interval_ms": 500.0,
    "format": "standard",
    "listen": True,
    "listen_timeout": 0.05,
    "check_message": True,
}
FDCHECK_DEFAULTS: dict[str, Any] = {
    "config": None,
    "interface": None,
    "channel": None,
    "interfaces": None,
    "include_virtual": False,
    "json": False,
    "verbose": False,
    "bitrate": 500000,
    "data_bitrate": 2000000,
    "auto_bitrate": False,
    "bitrate_candidates": "500000,250000,125000,1000000,800000,100000,50000",
    "data_bitrate_candidates": "2000000,5000000,4000000,1000000",
    "bitrate_probe_timeout": 0.2,
    "fd_timing_preset": "sae-j2284",
    "fd_clock": 80000000,
    "nominal_sample_point": 87.5,
    "data_sample_point": 80.0,
    "campaign": "can_fd_check",
    "output_dir": "result",
    "probe_timeout": 0.15,
    "probe_delay_ms": 20.0,
    "no_progress": False,
}
SCAN_DEFAULTS: dict[str, Any] = {
    "config": None,
    "interface": None,
    "channel": None,
    "interfaces": None,
    "include_virtual": False,
    "json": False,
    "verbose": False,
    "bitrate": 500000,
    "campaign": "can_scan",
    "output_dir": "result",
    "passive_duration": 10.0,
    "active_timeout": 0.25,
    "inter_probe_delay_ms": 50.0,
    "physical_start": 0x7E0,
    "physical_end": 0x7E7,
    "fd": False,
    "data_bitrate": None,
    "auto_bitrate": False,
    "bitrate_candidates": "500000,250000,125000,1000000,800000,100000,50000",
    "data_bitrate_candidates": "2000000,5000000,4000000,1000000",
    "bitrate_probe_timeout": 0.2,
    "fd_timing_preset": None,
    "fd_clock": 80000000,
    "nominal_sample_point": 87.5,
    "data_sample_point": 80.0,
    "passive_only": False,
    "active_only": False,
    "no_progress": False,
}


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
    if key == "fd_timing_preset":
        normalized = normalize_fd_timing_preset(str(value))
        if normalized is None:
            raise click.BadParameter("fd_timing_preset must be one of: sae-j2284, sae-j2284-5")
        return normalized
    return value


def build_args(section: str, defaults: dict[str, Any], params: dict[str, Any]) -> SimpleNamespace:
    merged = dict(defaults)
    config_path = params.get("config")
    if config_path:
        raw_config = read_toml_config(Path(str(config_path)))
        merged.update(extract_config(raw_config, defaults, section))
        if section == "fuzz":
            protocol = normalize_protocol(params.get("protocol") or merged.get("protocol")) or "can"
            protocol_section = FUZZ_PROTOCOL_SECTION_MAP.get(protocol)
            if protocol_section is not None:
                merged.update(extract_config(raw_config, defaults, protocol_section))
            merged.update(extract_keepalive_config(raw_config, defaults))
    cli_keys = {key for key, value in params.items() if value is not None}
    for key in cli_keys:
        merged[key] = params[key]
    if section == "fuzz":
        merged["protocol"] = normalize_protocol(merged.get("protocol")) or "can"
    if "fd_timing_preset" in defaults:
        apply_fd_timing_preset(merged, cli_keys)
    apply_auto_bitrate_tokens(merged)
    return SimpleNamespace(**{key: normalize_config_value(key, value) for key, value in merged.items()})


def build_keepalive_args(params: dict[str, Any]) -> SimpleNamespace:
    config_values: dict[str, Any] = {}
    config_path = params.get("config")
    if config_path:
        raw_config = read_toml_config(Path(str(config_path)))
        config_values.update(extract_config(raw_config, KEEPALIVE_DEFAULTS, "keepalive"))
    preset_name = normalize_keepalive_preset(params.get("preset") or config_values.get("preset")) or "tester-present"
    preset = KEEPALIVE_PRESETS[preset_name]
    merged = dict(KEEPALIVE_DEFAULTS)
    merged.update({"preset": preset_name, "arbitration_id": preset["arbitration_id"], "payload": preset["payload"], "fd": preset["fd"], "format": preset["format"], "listen": preset["listen"], "listen_timeout": preset["listen_timeout"], "check_message": preset["check_message"]})
    merged.update(config_values)
    cli_keys = {key for key, value in params.items() if value is not None}
    for key in cli_keys:
        merged[key] = params[key]
    merged["preset"] = normalize_keepalive_preset(merged.get("preset")) or preset_name
    apply_fd_timing_preset(merged, cli_keys)
    apply_auto_bitrate_tokens(merged)
    return SimpleNamespace(**{key: normalize_config_value(key, value) for key, value in merged.items()})


def apply_auto_bitrate_tokens(merged: dict[str, Any]) -> None:
    if is_auto_token(merged.get("bitrate")):
        merged["bitrate"] = None
        merged["auto_bitrate"] = True
    if is_auto_token(merged.get("data_bitrate")):
        merged["data_bitrate"] = None
        merged["auto_bitrate"] = True



def extract_config(raw_config: dict[str, Any], defaults: dict[str, Any], section: str) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    if section in {"fuzz", "clean", "list", "keepalive", "fdcheck", "scan"}:
        for key, value in raw_config.items():
            if not isinstance(value, dict):
                normalized_key = key.replace("-", "_")
                if normalized_key in defaults:
                    merged[normalized_key] = value
    section_config = raw_config.get(section, {})
    if isinstance(section_config, dict):
        for key, value in section_config.items():
            normalized_key = key.replace("-", "_")
            if normalized_key in defaults:
                merged[normalized_key] = value
    return merged


def extract_keepalive_config(raw_config: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    section = raw_config.get("keepalive", {})
    if not isinstance(section, dict):
        return {}
    mapping = {"enabled": "keepalive", "keepalive": "keepalive", "preset": "keepalive_preset", "arbitration_id": "keepalive_id", "id": "keepalive_id", "payload": "keepalive_payload", "interval_ms": "keepalive_interval_ms", "format": "keepalive_format", "fd": "keepalive_fd", "listen": "keepalive_listen", "listen_timeout": "keepalive_listen_timeout", "check_message": "keepalive_check_message"}
    return {dest: section[key] for key, dest in mapping.items() if key in section and dest in defaults}







