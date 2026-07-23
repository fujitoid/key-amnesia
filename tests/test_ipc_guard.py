"""IPC authkey-only tests — never leak passwords or raw secret values."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

from key_amnesia import ipc
from key_amnesia.guard import GuardState, guard_handle_message


def test_ipc_round_trip_authkey_only() -> None:
    listener, address, authkey = ipc.start_listener()
    try:
        result: dict = {}

        def server() -> None:
            conn = listener.accept()
            try:
                msg = ipc.recv_msg(conn, timeout=5)
                result["got"] = msg
                ipc.send_msg(conn, {"ok": True, "echo": msg.get("x")})
            finally:
                conn.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        client = ipc.connect(address, authkey)
        try:
            ipc.send_msg(client, {"x": 42, "verb": "status"})
            reply = ipc.recv_msg(client, timeout=5)
            assert reply["ok"] is True
            assert reply["echo"] == 42
        finally:
            client.close()
        t.join(timeout=5)
        assert result["got"]["x"] == 42
    finally:
        listener.close()


def test_guard_handle_never_returns_raw_values() -> None:
    state = GuardState(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"x" * 32,
    )
    # Crafted client asking for values
    for verb in ("get-value", "reveal", "get", "copy"):
        reply = guard_handle_message({"verb": verb, "name": "api_key"}, state)
        assert reply.get("ok") is False
        blob = str(reply)
        assert "super-secret-value-123" not in blob

    # run returns scrubbed only
    code = "import os; print(os.environ['API_KEY'])"
    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": ["api_key"],
            "inject_as": {"api_key": "API_KEY"},
            "command": [sys.executable, "-c", code],
        },
        state,
    )
    assert reply["ok"] is True
    assert "super-secret-value-123" not in reply["scrubbed_stdout"]
    assert "***REDACTED(api_key)***" in reply["scrubbed_stdout"]
    assert "super-secret-value-123" not in str(reply)


def test_guard_run_honors_caller_cwd() -> None:
    """A cached-session `run` must execute in the caller's cwd, not the guard's own.

    Regression: the guard is a long-lived process started by `ka unlock`, wherever
    that happened to run from. Without threading the caller's cwd through the IPC
    message, `ka run` silently executed in the guard's directory instead of the
    directory the `run` command was actually issued from.
    """
    state = GuardState(
        secrets={},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"c" * 32,
    )
    target_dir = tempfile.mkdtemp()
    code = "import os, sys; sys.stdout.write(os.getcwd())"
    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": [],
            "command": [sys.executable, "-c", code],
            "cwd": target_dir,
        },
        state,
    )
    assert reply["ok"] is True
    got = os.path.normcase(os.path.realpath(reply["scrubbed_stdout"]))
    want = os.path.normcase(os.path.realpath(target_dir))
    assert got == want


def test_guard_run_without_cwd_falls_back_to_guard_process_cwd() -> None:
    """Omitting `cwd` (older client / explicit choice) must not raise or misbehave."""
    state = GuardState(
        secrets={},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"d" * 32,
    )
    reply = guard_handle_message(
        {
            "verb": "run",
            "secret_names": [],
            "command": [sys.executable, "-c", "print('ok')"],
        },
        state,
    )
    assert reply["ok"] is True
    assert "ok" in reply["scrubbed_stdout"]


def test_guard_list_names_only() -> None:
    state = GuardState(
        secrets={"a": "secretA", "b": "secretB"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"y" * 32,
    )
    reply = guard_handle_message({"verb": "list"}, state)
    assert reply["ok"] is True
    assert reply["names"] == ["a", "b"]
    assert "secretA" not in str(reply)
    assert "secretB" not in str(reply)


def test_password_never_in_ipc_payloads() -> None:
    """Guard handler responses must not contain password-like fields."""
    state = GuardState(
        secrets={"k": "v"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"z" * 32,
    )
    for msg in (
        {"verb": "status"},
        {"verb": "list"},
        {"verb": "renew", "minutes": 5},
    ):
        reply = guard_handle_message(msg, state)
        assert "password" not in reply
        assert "secrets" not in reply
        assert "secret_value" not in reply
