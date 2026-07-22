#!/usr/bin/env python3
"""Claude Code PreToolUse hook: flag inline credential-shaped tokens.

Fail open on parse/IO errors so a broken hook never bricks the agent.
When a clear credential-shaped token is found in a Bash (or similar) command,
deny with guidance to use `ka set` / `ka run` instead of pasting secrets.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from typing import Any, Iterable

# Already routing secrets through key-amnesia — do not nag.
_KA_SAFE = re.compile(
    r"\b(?:ka|key-amnesia)\s+(?:run|set|reveal|copy|remove)\b",
    re.IGNORECASE,
)

# Well-known API key / token prefixes (value starts immediately after).
_PREFIX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
]

_BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9._\-+=/]{16,})", re.IGNORECASE)

# ENV-style assignments that often carry secrets.
_ASSIGN = re.compile(
    r"""(?ix)
    (?:^|[\s;&|])
    (?:export\s+)?
    (?P<name>
        (?:[A-Z][A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)
        |(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|AUTH)
        )
    )
    \s*=\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{12,}|[^'"]{12,}?)
    (?P=q)
    """
)

_SENSITIVE_NAME = re.compile(
    r"(?i)(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|^AUTH$)"
)

_SUGGESTION = (
    "Inline credential-shaped token detected ({kind}). "
    "Do not paste secrets into commands. Store with `ka set NAME`, then run with "
    "`ka run --secret NAME --as ENV_VAR -- <command>` so the value never appears "
    "on argv or in chat."
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_high_entropy(value: str) -> bool:
    """True for long random-looking strings (not plain words / paths)."""
    if len(value) < 20:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/=_\-.]{20,}", value) is None:
        return False
    # Paths and simple words tend to have low character variety.
    if value.count("/") + value.count("\\") >= 2:
        return False
    return _entropy(value) >= 3.5


def _collect_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _collect_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _collect_strings(item)


def _command_text(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        for key in ("command", "cmd", "script", "code", "content"):
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                return val
        return "\n".join(_collect_strings(tool_input))
    if isinstance(tool_input, str):
        return tool_input
    return ""


def _find_finding(text: str) -> str | None:
    if not text or _KA_SAFE.search(text):
        return None

    for kind, pattern in _PREFIX_PATTERNS:
        if pattern.search(text):
            return kind

    if _BEARER.search(text):
        return "Bearer token"

    for match in _ASSIGN.finditer(text):
        name = match.group("name")
        value = match.group("value")
        if not _SENSITIVE_NAME.search(name):
            continue
        if _looks_high_entropy(value) or len(value) >= 24:
            return f"{name} assignment"

    return None


def _deny(kind: str) -> dict[str, Any]:
    reason = _SUGGESTION.format(kind=kind)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        payload = json.loads(raw)
    except Exception:
        # Fail open: never brick the agent on parse/IO errors.
        return 0

    try:
        tool_name = str(payload.get("tool_name") or "")
        # Matcher usually limits to Bash; still only inspect shell-like tools.
        if tool_name and tool_name not in ("Bash", "Shell", "bash", "shell"):
            # Also scan Write/Edit content if someone broadens the matcher.
            if tool_name not in ("Write", "Edit", "MultiEdit"):
                return 0

        text = _command_text(payload if isinstance(payload, dict) else {})
        finding = _find_finding(text)
        if finding:
            json.dump(_deny(finding), sys.stdout)
            sys.stdout.write("\n")
            return 0
    except Exception:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
