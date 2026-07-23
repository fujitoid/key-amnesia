"""Guard IPC verb set is frozen — hard guarantee of the two-tier model."""

from __future__ import annotations

import sys
import time

from key_amnesia.guard import AdmittedSession, GuardState, guard_handle_message

# Exact dispatch set — must not grow without a deliberate design change.
GUARD_VERBS = frozenset({"run", "list", "lock", "status", "renew"})

ADMITTED_TOKEN = "test-admitted-token"


def _state() -> GuardState:
    state = GuardState(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"g" * 32,
    )
    # Pre-seed admission so this file exercises verb dispatch itself, not the
    # (separately tested) admission-consent prompt.
    state.admitted = AdmittedSession(
        token=ADMITTED_TOKEN, first_seen="2026-01-01T00:00:00+00:00"
    )
    return state


def test_guard_verb_set_exactly_five() -> None:
    """Regression: guard recognizes exactly {run, list, lock, status, renew}."""
    state = _state()
    recognized: set[str] = set()
    probes = sorted(GUARD_VERBS | {"get-value", "reveal", "get", "copy", "browser-fill"})
    for verb in probes:
        msg: dict = {"verb": verb, "admission_token": ADMITTED_TOKEN}
        if verb == "run":
            msg.update(
                {
                    "secret_names": ["api_key"],
                    "inject_as": {"api_key": "API_KEY"},
                    "command": [sys.executable, "-c", "print('ok')"],
                }
            )
        if verb == "renew":
            msg["minutes"] = 5
        reply = guard_handle_message(msg, state)
        reason = str(reply.get("reason") or "")
        if reason.startswith("unknown verb"):
            continue
        # Explicit value-return denials still "recognize" the probe as rejected.
        if verb in ("get-value", "reveal", "get", "copy"):
            assert reply.get("ok") is False
            continue
        recognized.add(verb)
    assert recognized == GUARD_VERBS


def test_guard_value_return_probes_fail() -> None:
    state = _state()
    secret = "super-secret-value-123"
    for verb in ("get-value", "reveal", "get", "copy", "get-logins-for-url"):
        reply = guard_handle_message(
            {
                "verb": verb,
                "name": "api_key",
                "url": "https://x",
                "admission_token": ADMITTED_TOKEN,
            },
            state,
        )
        assert reply.get("ok") is False
        blob = str(reply)
        assert secret not in blob
        assert "password" not in reply or reply.get("password") in (None, "")


def test_guard_run_never_returns_raw_secret() -> None:
    state = _state()
    secret = "super-secret-value-123"
    code = "import os; print(os.environ['API_KEY'])"
    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "inject_as": {"api_key": "API_KEY"},
            "command": [sys.executable, "-c", code],
            "admission_token": ADMITTED_TOKEN,
        },
        state,
    )
    assert reply["ok"] is True
    assert secret not in reply["scrubbed_stdout"]
    assert "***REDACTED(api_key)***" in reply["scrubbed_stdout"]
    assert secret not in str(reply)
