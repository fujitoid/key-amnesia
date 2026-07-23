"""Prompt routing: CREATE_NEW_CONSOLE, bare argv, env handoff."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from key_amnesia import prompt_route
from key_amnesia.prompt_route import (
    ENV_ADDRESS,
    ENV_AUTHKEY,
    ENV_PARENT_PID,
    ENV_REQUEST,
    PromptRequest,
    require_browser_fill_approval,
    require_human_auth,
)


def test_noninteractive_spawns_create_new_console_bare_argv_env(
    ka_home, monkeypatch
) -> None:
    if sys.platform != "win32":
        pytest.skip("CREATE_NEW_CONSOLE is Windows-primary")

    captured: dict[str, Any] = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        # Immediately "exit" so parent doesn't hang forever — we also
        # won't connect, so expect denied/helper-exited.
        proc = MagicMock()
        proc.poll.return_value = 1
        proc.terminate = MagicMock()
        return proc

    req = PromptRequest(action="reveal", secret_names=["api_key"])
    outcome = require_human_auth(
        req,
        timeout_s=2,
        popen_fn=fake_popen,
        isatty_fn=lambda: False,
    )
    assert outcome.ok is False
    assert outcome.route == "spawned-console"

    cmd = captured["cmd"]
    assert cmd[-1] == "_prompt-helper" or (
        len(cmd) >= 2 and cmd[-1] == "_prompt-helper"
    )
    # Bare argv: no request JSON, no authkey, no secret names as args
    joined = " ".join(cmd)
    assert "api_key" not in joined
    assert ENV_REQUEST not in joined
    assert "authkey" not in joined.lower()

    kwargs = captured["kwargs"]
    assert kwargs.get("creationflags") == subprocess.CREATE_NEW_CONSOLE
    # No stdio kwargs
    assert "stdin" not in kwargs
    assert "stdout" not in kwargs
    assert "stderr" not in kwargs

    env = kwargs["env"]
    assert ENV_REQUEST in env
    assert ENV_AUTHKEY in env
    assert ENV_ADDRESS in env
    assert ENV_PARENT_PID in env
    req_payload = json.loads(env[ENV_REQUEST])
    assert req_payload["action"] == "reveal"
    assert req_payload["secret_names"] == ["api_key"]
    # Authkey is hex in env, not on argv
    assert len(env[ENV_AUTHKEY]) == 64


def test_posix_noninteractive_fail_closed(monkeypatch) -> None:
    """Headless / non-Linux POSIX still fails closed (no insecure fallback)."""
    if sys.platform == "win32":
        pytest.skip("POSIX fail-closed path")
    # Force headless so Linux CI with a display still hits fail-closed.
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    req = PromptRequest(action="reveal", secret_names=["x"])
    outcome = require_human_auth(req, timeout_s=1, isatty_fn=lambda: False)
    assert outcome.ok is False
    reason = (outcome.reason or "").lower()
    assert (
        "fail closed" in reason
        or "display" in reason
        or "not implemented" in reason
        or "terminal emulator" in reason
    )


def test_inline_auth_returns_password(ka_home) -> None:
    req = PromptRequest(action="auth", secret_names=[])
    outcome = require_human_auth(
        req,
        timeout_s=5,
        isatty_fn=lambda: True,
        password_provider=lambda: "inline-secret-pw",
    )
    assert outcome.ok is True
    assert outcome.route == "inline"
    assert outcome.password == "inline-secret-pw"


def test_inline_auth_times_out_when_tty_but_nobody_answers(ka_home, monkeypatch) -> None:
    """A tty-shaped stdin doesn't guarantee an attentive human (e.g. a pty

    allocated for a subprocess with nobody actually watching it). Must fail
    closed within timeout_s rather than hang on a getpass() that will never
    return.
    """

    def hanging_getpass(prompt: str = "") -> str:
        time.sleep(5)
        return "too-late"

    monkeypatch.setattr(prompt_route.getpass, "getpass", hanging_getpass)

    req = PromptRequest(action="reveal", secret_names=["x"])
    start = time.monotonic()
    outcome = require_human_auth(req, timeout_s=1, isatty_fn=lambda: True)
    elapsed = time.monotonic() - start

    assert outcome.ok is False
    assert "timed out" in (outcome.reason or "").lower()
    assert elapsed < 3  # bounded by timeout_s, not the 5s hang


def test_browser_fill_approve_times_out_when_tty_but_nobody_answers(monkeypatch) -> None:
    """Same tty-shaped-but-nobody-there risk applies to the approval prompt."""

    def hanging_input(prompt: str = "") -> str:
        time.sleep(5)
        return "y"

    monkeypatch.setattr("builtins.input", hanging_input)

    req = PromptRequest(action="browser-fill-approve", secret_names=["x"])
    start = time.monotonic()
    outcome = require_browser_fill_approval(req, timeout_s=1, isatty_fn=lambda: True)
    elapsed = time.monotonic() - start

    assert outcome.ok is False
    assert "timed out" in (outcome.reason or "").lower()
    assert outcome.status_only == {"approved": False, "action": "browser-fill-approve"}
    assert elapsed < 3


def test_helper_parent_death_cancels(monkeypatch) -> None:
    from key_amnesia.prompt_route import parent_alive, run_prompt_helper

    # Missing env → helper fails closed quickly
    for k in (
        "KEY_AMNESIA_PROMPT_REQUEST",
        "KEY_AMNESIA_PROMPT_AUTHKEY",
        "KEY_AMNESIA_PROMPT_ADDRESS",
        "KEY_AMNESIA_PROMPT_PARENT_PID",
        "KEY_AMNESIA_PROMPT_TIMEOUT",
    ):
        monkeypatch.delenv(k, raising=False)

    # parent_alive for bogus pid
    assert parent_alive(0) is False
    assert parent_alive(-1) is False

    # Without env, helper should exit non-zero. It may try to input() —
    # patch input.
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")
    rc = run_prompt_helper()
    assert rc != 0
