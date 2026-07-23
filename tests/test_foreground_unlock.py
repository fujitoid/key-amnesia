"""`ka unlock` is the guard: no detached child process, no bootstrap handoff.

Replaces v2's `start_guard_process` / `run_guard_main` / `_guard` subcommand
regression coverage — those no longer exist. Also covers the spawned-helper
refusal: a console spawned for a non-interactive unlock attempt cannot
become the caller's own foreground guard, so it must refuse cleanly instead
of trying to start anything.
"""

from __future__ import annotations

import subprocess

import pytest

from key_amnesia.cli import main
from key_amnesia.paths import guard_lock_path
from key_amnesia.prompt_route import AuthOutcome


def test_cmd_unlock_calls_foreground_guard_no_subprocess(
    seeded_vault, password, monkeypatch
) -> None:
    """cmd_unlock must never Popen anything — it decrypts, then blocks
    in-process in run_foreground_guard."""
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: False)

    def _no_popen(*a, **k):
        raise AssertionError("cmd_unlock must not spawn a subprocess")

    monkeypatch.setattr(subprocess, "Popen", _no_popen)

    calls: dict = {}

    def fake_run_foreground_guard(payload, timeout_minutes):
        calls["payload"] = payload
        calls["timeout_minutes"] = timeout_minutes
        return 0

    monkeypatch.setattr(
        "key_amnesia.guard.run_foreground_guard", fake_run_foreground_guard
    )

    rc = main(["unlock"])
    assert rc == 0
    assert calls["payload"]["secrets"]["api_key"] == "super-secret-value-123"
    assert calls["timeout_minutes"] == 30


def test_cmd_unlock_already_active_soft_warns(
    seeded_vault, password, monkeypatch, capsys
) -> None:
    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: True)
    rc = main(["unlock"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "already active" in err.lower()
    assert not guard_lock_path().exists()


def test_helper_unlock_refuses_clear_error(ka_home, seeded_vault, password, monkeypatch) -> None:
    """A spawned prompt-helper handling action=unlock must refuse outright —
    it never calls anything guard-starting, since it can't be this caller's
    foreground terminal."""
    from key_amnesia.prompt_route import (
        ENV_ADDRESS,
        ENV_AUTHKEY,
        ENV_PARENT_PID,
        ENV_REQUEST,
        ENV_TIMEOUT,
        PromptRequest,
        run_prompt_helper,
    )
    from key_amnesia import ipc
    from dataclasses import asdict
    import getpass
    import json
    import os
    import threading

    request = PromptRequest(
        action="unlock",
        detail=json.dumps({"session-timeout-minutes": 30}),
        vault_path=str(seeded_vault),
    )
    listener, address, authkey = ipc.start_listener()
    monkeypatch.setenv(ENV_REQUEST, json.dumps(asdict(request)))
    monkeypatch.setenv(ENV_AUTHKEY, ipc.authkey_to_hex(authkey))
    monkeypatch.setenv(ENV_ADDRESS, address)
    monkeypatch.setenv(ENV_PARENT_PID, str(os.getpid()))
    monkeypatch.setenv(ENV_TIMEOUT, "5")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": password)

    replies: list[dict] = []

    def collect() -> None:
        conn = listener.accept()
        try:
            replies.append(ipc.recv_msg(conn, timeout=5))
        finally:
            conn.close()

    t = threading.Thread(target=collect, daemon=True)
    t.start()

    rc = run_prompt_helper()
    t.join(timeout=5)
    listener.close()

    assert rc == 1
    assert len(replies) == 1
    assert replies[0]["ok"] is False
    assert "foreground terminal" in replies[0]["reason"]
    assert not guard_lock_path().exists()
