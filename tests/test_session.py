"""End-to-end session: unlock → run → lock → fallback; non-interactive status-only."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from key_amnesia.cli import main
from key_amnesia.guard import (
    GuardState,
    clear_guard_lock,
    guard_handle_message,
    write_guard_lock,
)
from key_amnesia.prompt_route import AuthOutcome, PromptRequest, require_human_auth
from key_amnesia.run_exec import run_with_secrets
from key_amnesia.vault import load_vault


def test_per_call_run_with_inline_auth(
    seeded_vault: Path, password: str, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    monkeypatch.setattr(
        "key_amnesia.guard.guard_is_alive", lambda *a, **k: False
    )
    code = "import os; print('X=' + os.environ['API_KEY'])"
    rc = main(
        [
            "run",
            "--secret",
            "api_key",
            "--as",
            "api_key=API_KEY",
            "--",
            sys.executable,
            "-c",
            code,
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "super-secret-value-123" not in out
    assert "***REDACTED(api_key)***" in out


def test_guard_run_path_scrubs(seeded_vault: Path, password: str) -> None:
    payload = load_vault(seeded_vault, password)
    state = GuardState(
        secrets={k: str(v) for k, v in payload["secrets"].items()},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"a" * 32,
    )
    code = (
        "import os, sys\n"
        "sys.stdout.write(os.environ['API_KEY'] + '\\n')\n"
        "sys.stderr.write(os.environ['DB'] + '\\n')\n"
    )
    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key", "db_pass"],
            "inject_as": {"api_key": "API_KEY", "db_pass": "DB"},
            "command": [sys.executable, "-c", code],
        },
        state,
    )
    assert reply["ok"] is True
    assert "super-secret-value-123" not in reply["scrubbed_stdout"]
    assert "p@ssw0rd" not in reply["scrubbed_stderr"]
    assert "***REDACTED(api_key)***" in reply["scrubbed_stdout"]
    assert "***REDACTED(db_pass)***" in reply["scrubbed_stderr"]


def test_unlock_run_lock_fallback(
    seeded_vault: Path, password: str, monkeypatch, capsys
) -> None:
    """Simulate unlock→run via guard→lock→fallback to per-call."""
    from key_amnesia import guard as guard_mod
    from key_amnesia import ipc

    payload = load_vault(seeded_vault, password)
    secrets = {k: str(v) for k, v in payload["secrets"].items()}

    listener, address, authkey = ipc.start_listener()
    state = GuardState(
        secrets=secrets,
        expires_at=time.time() + 600,
        address=address,
        authkey=authkey,
        pid=0,
    )
    write_guard_lock(address, authkey, 0, state.expires_at)

    # Make guard_is_alive True without needing a real PID check
    monkeypatch.setattr(guard_mod, "guard_is_alive", lambda *a, **k: True)

    import threading

    stop = threading.Event()

    def serve_one() -> None:
        while not stop.is_set():
            try:
                conn = listener.accept()
            except Exception:
                break
            try:
                msg = ipc.recv_msg(conn, timeout=5)
                reply = guard_handle_message(msg, state)
                ipc.send_msg(conn, reply)
                if reply.get("lock"):
                    stop.set()
            finally:
                conn.close()

    t = threading.Thread(target=serve_one, daemon=True)
    t.start()

    code = "import os; print(os.environ['API_KEY'])"
    rc = main(
        [
            "run",
            "--secret",
            "api_key",
            "--as",
            "api_key=API_KEY",
            "--",
            sys.executable,
            "-c",
            code,
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "***REDACTED(api_key)***" in out
    assert "super-secret-value-123" not in out

    # Lock
    rc = main(["lock"])
    assert rc == 0
    stop.set()
    clear_guard_lock()
    monkeypatch.setattr(guard_mod, "guard_is_alive", lambda *a, **k: False)

    # Fallback: per-call with password
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    rc = main(
        [
            "run",
            "--secret",
            "api_key",
            "--as",
            "api_key=API_KEY",
            "--",
            sys.executable,
            "-c",
            code,
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "***REDACTED(api_key)***" in out
    try:
        listener.close()
    except Exception:
        pass


def test_reveal_noninteractive_status_only(monkeypatch, capsys) -> None:
    """Non-interactive reveal returns status flag only — no raw value to caller."""
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(
            ok=True,
            route="spawned-console",
            password=None,
            status_only={"shown": True, "action": "reveal", "name": "api_key"},
        ),
    )
    rc = main(["reveal", "api_key"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "super-secret" not in out
    assert "displayed in authentication console" in out


def test_copy_noninteractive_status_only(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(
            ok=True,
            route="spawned-console",
            password=None,
            status_only={"copied": True, "action": "copy", "name": "api_key"},
        ),
    )
    rc = main(["copy", "api_key"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "super-secret" not in out
    assert "copied in authentication console" in out


def test_names_sidecar_updated_on_set_remove(
    ka_home: Path, password: str, monkeypatch
) -> None:
    from key_amnesia.vault import read_names, save_vault

    save_vault(None, password, {"secrets": {"a": "1"}})
    assert read_names() == ["a"]

    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )
    assert main(["set", "b", "2"]) == 0
    assert set(read_names()) == {"a", "b"}
    assert main(["remove", "a"]) == 0
    assert read_names() == ["b"]
