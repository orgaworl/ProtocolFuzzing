from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Any


def extract_config_path(argv: list[str]) -> Path | None:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("-c", "--config")
    known, _ = config_parser.parse_known_args(argv)
    if known.config is None:
        return None
    return Path(known.config)


def read_toml_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except OSError as exc:
        raise SystemExit(f"could not read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"could not parse config file {path}: {exc}") from exc


def normalize_config_key(key: str) -> str:
    return key.replace("-", "_")


def merge_config_sections(raw_config: dict[str, Any], section: str) -> dict[str, Any]:
    merged = {key: value for key, value in raw_config.items() if not isinstance(value, dict)}
    section_config = raw_config.get(section, {})
    if isinstance(section_config, dict):
        merged.update(section_config)
    return {normalize_config_key(key): value for key, value in merged.items()}


def config_action_map(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    result: dict[str, argparse.Action] = {}
    for action in parser._actions:
        if action.dest in {"help", argparse.SUPPRESS}:
            continue
        result[action.dest] = action
    return result


def convert_config_value(action: argparse.Action, value: Any) -> Any:
    if isinstance(action, argparse._StoreTrueAction):
        return bool(value)
    if isinstance(action, argparse._StoreFalseAction):
        return not bool(value)
    if action.dest in {"interfaces", "target_ids", "opcodes"} and isinstance(value, list):
        return ",".join(str(item) for item in value)
    if action.type is None or value is None:
        return value
    if isinstance(value, str):
        return action.type(value)
    return value


def load_parser_defaults_from_config(parser: argparse.ArgumentParser, path: Path, section: str) -> dict[str, Any]:
    raw_config = read_toml_config(path)
    config = merge_config_sections(raw_config, section)
    action_map = config_action_map(parser)
    unknown = sorted(key for key in config if key not in action_map)
    if unknown:
        parser.error(f"unknown config option(s) for {section}: {', '.join(unknown)}")
    return {key: convert_config_value(action_map[key], value) for key, value in config.items()}


def load_section_defaults_from_config(parser: argparse.ArgumentParser, raw_config: dict[str, Any], section: str) -> dict[str, Any]:
    section_config = raw_config.get(section, {})
    if not isinstance(section_config, dict):
        return {}
    action_map = config_action_map(parser)
    normalized = {normalize_config_key(key): value for key, value in section_config.items()}
    unknown = sorted(key for key in normalized if key not in action_map)
    if unknown:
        parser.error(f"unknown config option(s) for {section}: {', '.join(unknown)}")
    return {key: convert_config_value(action_map[key], value) for key, value in normalized.items()}


def relax_configured_required_args(parser: argparse.ArgumentParser, defaults: dict[str, Any]) -> None:
    for action in parser._actions:
        if action.required and action.dest in defaults:
            action.required = False


def required_args_for_section(section: str) -> list[str]:
    if section in {"udsfuzz", "obdfuzz", "privatefuzz"}:
        return ["interface", "channel"]
    return []


def validate_required_args(parser: argparse.ArgumentParser, args: argparse.Namespace, section: str) -> None:
    if section in {"fuzz", "scan", "fdcheck", "list"}:
        return
    missing = []
    for name in required_args_for_section(section):
        value = getattr(args, name, None)
        if value is None or value == "" or value == []:
            missing.append(f"--{name.replace('_', '-')}")
    if missing:
        parser.error("missing required argument(s): " + ", ".join(missing))
