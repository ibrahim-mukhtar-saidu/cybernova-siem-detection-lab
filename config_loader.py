"""YAML configuration and detection-rule loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

CONFIG_FILE = Path("config/siem_config.yaml")

REQUIRED_RULE_KEYS = {"threshold", "severity", "mitre"}


class ConfigError(Exception):
    """Raised when a configuration or rule file is missing or invalid."""


def load_yaml(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)

    if not file_path.exists():
        raise ConfigError(f"configuration file not found: {file_path}")

    if not file_path.is_file():
        raise ConfigError(f"expected a file, got: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file_path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"configuration file is not valid UTF-8: {file_path}"
        ) from exc
    except PermissionError as exc:
        raise ConfigError(
            f"permission denied reading configuration file: {file_path}"
        ) from exc

    if not isinstance(data, dict):
        raise ConfigError(
            f"expected a YAML mapping at top level: {file_path}"
        )

    return data


def load_config(path: str | Path = CONFIG_FILE) -> dict[str, Any]:
    return load_yaml(path)


def load_rule(path: str | Path) -> dict[str, Any]:
    rule = load_yaml(path)
    missing = REQUIRED_RULE_KEYS - rule.keys()

    if missing:
        raise ConfigError(
            f"rule file {path} is missing required keys: {sorted(missing)}"
        )

    threshold = rule["threshold"]
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold <= 0:
        raise ConfigError(
            f"rule file {path} has invalid threshold: expected a positive integer"
        )

    severity = rule["severity"]
    if not isinstance(severity, str) or not severity.strip():
        raise ConfigError(
            f"rule file {path} has invalid severity: expected a non-empty string"
        )

    mitre = rule["mitre"]
    if not isinstance(mitre, str) or not mitre.strip():
        raise ConfigError(
            f"rule file {path} has invalid mitre: expected a non-empty string"
        )

    if "window_minutes" in rule:
        window_minutes = rule["window_minutes"]
        if (
            isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or window_minutes <= 0
        ):
            raise ConfigError(
                f"rule file {path} has invalid window_minutes: "
                "expected a positive integer"
            )

    return rule
