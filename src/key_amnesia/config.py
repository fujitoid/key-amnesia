"""Configuration load/save for key-amnesia."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from key_amnesia.paths import config_path

DEFAULTS: dict[str, Any] = {
    "session-mode": "per-call",
    "session-timeout-minutes": 30,
    "prompt-timeout-seconds": 90,
}

VALID_SESSION_MODES = frozenset({"per-call", "cached"})


class ConfigError(Exception):
    """Invalid configuration value."""


def load_config(path: Path | None = None) -> dict[str, Any]:
    p = path or config_path()
    if not p.exists():
        return dict(DEFAULTS)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    merged = dict(DEFAULTS)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def save_config(cfg: dict[str, Any], path: Path | None = None) -> None:
    p = path or config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)
        f.write("\n")


def set_config_value(key: str, value: str, path: Path | None = None) -> dict[str, Any]:
    cfg = load_config(path)
    if key == "session-mode":
        if value not in VALID_SESSION_MODES:
            raise ConfigError(
                f"Invalid session-mode {value!r}; expected one of {sorted(VALID_SESSION_MODES)}"
            )
        cfg[key] = value
    elif key == "session-timeout-minutes":
        try:
            minutes = int(value)
        except ValueError as e:
            raise ConfigError("session-timeout-minutes must be an integer") from e
        if minutes < 1:
            raise ConfigError("session-timeout-minutes must be >= 1")
        cfg[key] = minutes
    elif key == "prompt-timeout-seconds":
        try:
            seconds = int(value)
        except ValueError as e:
            raise ConfigError("prompt-timeout-seconds must be an integer") from e
        if seconds < 1:
            raise ConfigError("prompt-timeout-seconds must be >= 1")
        cfg[key] = seconds
    else:
        raise ConfigError(
            f"Unknown config key {key!r}; "
            "supported: session-mode, session-timeout-minutes, prompt-timeout-seconds"
        )
    save_config(cfg, path)
    return cfg
