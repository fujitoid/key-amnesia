"""JSONL audit log — never records secret values."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from key_amnesia.paths import audit_log_path

VALID_ROUTES = frozenset({"inline", "spawned-console", "guard-session"})
VALID_RESULTS = frozenset({"allowed", "denied", "timeout"})

# Browser-fill taxonomy (WS-D): action encodes outcome; never log passwords.
BROWSER_FILL_ACTIONS = frozenset(
    {"browser-fill", "browser-fill-denied", "browser-fill-timeout"}
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def audit_event(
    action: str,
    *,
    secret_names: Iterable[str] | None = None,
    command: list[str] | str | None = None,
    route: str,
    result: str,
    reason: str = "",
    url: str | None = None,
    username: str | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Append one audit record. Never includes secret values or passwords."""
    if route not in VALID_ROUTES:
        raise ValueError(f"Invalid audit route: {route}")
    if result not in VALID_RESULTS:
        raise ValueError(f"Invalid audit result: {result}")

    if isinstance(command, list):
        cmd_field: str | list[str] | None = list(command)
    else:
        cmd_field = command

    record: dict[str, Any] = {
        "timestamp": _utc_now_iso(),
        "action": action,
        "secret_names": list(secret_names or []),
        "command": cmd_field,
        "route": route,
        "result": result,
        "reason": reason,
    }
    # Optional browser-fill context — url/host and username only; never password.
    if url is not None:
        record["url"] = url
    if username is not None:
        record["username"] = username

    p = path or audit_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record


def audit_browser_fill(
    *,
    result: str,
    url: str = "",
    username: str | None = None,
    secret_names: Iterable[str] | None = None,
    route: str = "inline",
    reason: str = "",
    path: Path | None = None,
) -> dict[str, Any]:
    """Record a browser-fill attempt.

    Actions: ``browser-fill`` (allowed), ``browser-fill-denied``,
    ``browser-fill-timeout``. Fields may include ``url`` and optional
    ``username``; never a password.
    """
    if result == "allowed":
        action = "browser-fill"
        result_norm = "allowed"
    elif result == "timeout":
        action = "browser-fill-timeout"
        result_norm = "timeout"
    else:
        action = "browser-fill-denied"
        result_norm = "denied"

    return audit_event(
        action,
        secret_names=secret_names,
        route=route,
        result=result_norm,
        reason=reason,
        url=url if url else None,
        username=username,
        path=path,
    )
