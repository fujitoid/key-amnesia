#!/usr/bin/env python3
"""PreToolUse / preToolUse secret guard: blocking hook for Claude Code and Cursor.

Inspects a pending tool call (Bash/Shell command, or Write/Edit file content) for
inline credential-shaped tokens and **denies** the call when one is found,
pointing the agent at ``ka set`` / ``ka run`` instead.

Two host contracts are implemented from the same detection logic:

- Claude Code ``PreToolUse``: stdin JSON with ``tool_name`` / ``tool_input``;
  deny reply uses ``hookSpecificOutput.permissionDecision``.
- Cursor ``preToolUse``: stdin JSON with ``tool_name`` / ``tool_input`` (plus
  Cursor-only fields like ``cursor_version`` / ``conversation_id``); deny
  reply uses the flatter ``{"permission": "deny", ...}`` shape.

Fails **open** on JSON/IO errors or unexpected shapes — a broken hook must
never brick the agent. Set ``KEY_AMNESIA_HOOK_DISABLE=1`` to skip all checks
(e.g. temporarily, or in environments that manage secrets a different way).
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from collections import Counter
from typing import Any, Iterable

DISABLE_ENV = "KEY_AMNESIA_HOOK_DISABLE"

# Already routing secrets through key-amnesia — do not nag.
_KA_SAFE = re.compile(
    r"\b(?:ka|key-amnesia)\s+(?:run|set|reveal|copy|remove)\b",
    re.IGNORECASE,
)

# Well-known API key / token prefixes (value starts immediately after).
# Anthropic-style checked before the more general OpenAI-style pattern so the
# reported "kind" is the more specific one.
_PREFIX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic-style key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("GitHub PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
]

_BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9._\-+=/]{16,})", re.IGNORECASE)

# ENV-style assignments that often carry secrets: NAME (optionally prefixed,
# e.g. MY_API_KEY) = / : value. Bare mentions with no value never match.
_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|secret|password|passwd|private[_-]?key))
    \s*[:=]\s*
    (?P<q>['"]?)
    (?P<value>[^\s'"]{8,})
    (?P=q)
    """
)

_PLACEHOLDER_VALUES = {
    "test123",
    "test1234",
    "changeme",
    "change_me",
    "changethis",
    "password",
    "password123",
    "secret",
    "yourkey",
    "your_api_key",
    "your-api-key",
    "placeholder",
    "example",
    "dummy",
    "fake",
    "sample",
    "xxxxxxxx",
    "12345678",
}

_SUGGESTION = (
    "Inline credential-shaped token detected ({kind}). "
    "Do not paste secrets into commands or files. Store with `ka set NAME`, "
    "then run with `ka run --secret NAME --as NAME=ENVVAR -- <command>` so "
    "the value never appears on argv, in files, or in chat. "
    "(Set KEY_AMNESIA_HOOK_DISABLE=1 to bypass this hook.)"
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    v = value.strip("'\"").lower()
    if v in _PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"x{6,}", v):
        return True
    if re.fullmatch(r"0{6,}|1{6,}", v):
        return True
    return False


def _assignment_is_secret(value: str) -> bool:
    """High-entropy heuristic: mixed case + digits, not an obvious placeholder."""
    v = value.strip("'\"")
    if len(v) < 8:
        return False
    if _is_placeholder(v):
        return False
    has_upper = any(c.isupper() for c in v)
    has_lower = any(c.islower() for c in v)
    has_digit = any(c.isdigit() for c in v)
    mixed = sum([has_upper, has_lower, has_digit]) >= 2
    if not mixed:
        return False
    return _entropy(v) >= 3.0


def _collect_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _collect_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _collect_strings(item)


def _command_text(tool_input: Any) -> str:
    """Extract the text to scan from Bash/Shell `command` or Write/Edit content."""
    if isinstance(tool_input, dict):
        for key in (
            "command",
            "cmd",
            "script",
            "code",
            "contents",
            "new_string",
            "content",
        ):
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                return val
        return "\n".join(_collect_strings(tool_input))
    if isinstance(tool_input, str):
        return tool_input
    return ""


def find_finding(text: str) -> str | None:
    """Return a short human-readable finding kind, or None if text looks clean."""
    if not text or _KA_SAFE.search(text):
        return None

    for kind, pattern in _PREFIX_PATTERNS:
        if pattern.search(text):
            return kind

    if _BEARER.search(text):
        return "Bearer token"

    for match in _ASSIGN.finditer(text):
        value = match.group("value")
        if _assignment_is_secret(value):
            return f"{match.group('name').upper()} assignment"

    return None


def detect_host(payload: dict[str, Any]) -> str:
    """Distinguish Cursor's flatter preToolUse payload from Claude's PreToolUse."""
    if "cursor_version" in payload or "conversation_id" in payload:
        return "cursor"
    event = str(payload.get("hook_event_name") or "")
    if event == "preToolUse":
        return "cursor"
    return "claude"


def deny_claude(kind: str) -> dict[str, Any]:
    reason = _SUGGESTION.format(kind=kind)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason,
    }


def deny_cursor(kind: str) -> dict[str, Any]:
    reason = _SUGGESTION.format(kind=kind)
    return {
        "permission": "deny",
        "agent_message": reason,
        "user_message": (
            f"key-amnesia hook blocked a possible secret ({kind}). "
            "Use `ka set` / `ka run --secret ... --as NAME=ENVVAR -- ...` instead."
        ),
    }


_ALLOWED_TOOL_NAMES = {"bash", "shell", "write", "edit", "multiedit"}


def main() -> int:
    if os.environ.get(DISABLE_ENV):
        return 0

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        payload = json.loads(raw)
    except Exception:
        # Fail open: never brick the agent on parse/IO errors.
        return 0

    try:
        if not isinstance(payload, dict):
            return 0

        tool_name = str(payload.get("tool_name") or "")
        if tool_name and tool_name.lower() not in _ALLOWED_TOOL_NAMES:
            return 0

        text = _command_text(payload.get("tool_input"))
        finding = find_finding(text)
        if finding:
            host = detect_host(payload)
            reply = deny_cursor(finding) if host == "cursor" else deny_claude(finding)
            json.dump(reply, sys.stdout)
            sys.stdout.write("\n")
            return 0
    except Exception:
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
