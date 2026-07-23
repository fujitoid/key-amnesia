"""Admission-consent layer on top of the guard's authkey trust boundary.

A live authkey alone lets any same-user process talk to the guard (the
ssh-agent-style limit documented in DESIGN.md). Admission adds a UX/consent
gate on top: the *first* request from any client is a yes/no prompt on the
guard's own foreground TTY; approval mints an opaque token that skips the
prompt for the rest of this guard run.
"""

from __future__ import annotations

import time

from key_amnesia.guard import (
    AdmittedSession,
    GuardState,
    admitted_session_token_path,
    guard_handle_message,
    guard_request,
    read_admission_token,
    write_admission_token,
    write_guard_lock,
)
from key_amnesia import ipc


def _state(**overrides) -> GuardState:
    kwargs = dict(
        secrets={"api_key": "super-secret-value-123"},
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"m" * 32,
    )
    kwargs.update(overrides)
    return GuardState(**kwargs)


def test_unknown_token_prompts_and_approves() -> None:
    state = _state()
    calls: list[tuple[int, str]] = []

    def approve(caller_pid: int, summary: str) -> bool:
        calls.append((caller_pid, summary))
        return True

    reply = guard_handle_message(
        {"verb": "list", "caller_pid": 4242},
        state,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert reply["names"] == ["api_key"]
    assert "admission_token" in reply  # freshly minted
    assert calls == [(4242, "list secret names")]
    assert state.admitted is not None
    assert state.admitted.token == reply["admission_token"]
    assert state.admitted.request_count == 1


def test_unknown_token_denies_on_no() -> None:
    state = _state()
    reply = guard_handle_message(
        {"verb": "list", "caller_pid": 1},
        state,
        admit_prompt=lambda pid, summary: False,
    )
    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert "admission_token" not in reply
    assert state.admitted is None


def test_unknown_token_denies_on_timeout(monkeypatch) -> None:
    """A real (unmocked) prompt that never answers must fail closed quickly."""
    state = _state()
    monkeypatch.setattr("key_amnesia.guard.ADMISSION_TIMEOUT_S", 0.2)
    monkeypatch.setattr("builtins.input", lambda *a, **k: (time.sleep(5), "y")[1])

    start = time.monotonic()
    reply = guard_handle_message({"verb": "list", "caller_pid": 1}, state)
    elapsed = time.monotonic() - start

    assert reply["ok"] is False
    assert reply["reason"] == "admission denied"
    assert elapsed < 3  # bounded by ADMISSION_TIMEOUT_S, not the 5s hang


def test_admitted_token_skips_prompt_no_reprompt() -> None:
    state = _state()
    state.admitted = AdmittedSession(token="tok-123", first_seen="2026-01-01T00:00:00+00:00")

    def fail_if_called(*_a, **_k):
        raise AssertionError("admit_prompt must not be called for a known token")

    reply = guard_handle_message(
        {"verb": "list", "admission_token": "tok-123"},
        state,
        admit_prompt=fail_if_called,
    )
    assert reply["ok"] is True
    # Known-token replies never re-mint a token.
    assert "admission_token" not in reply
    assert state.admitted.request_count == 1


def test_stale_token_after_new_guard_reprompts() -> None:
    """A token minted by a previous guard run is unknown to a fresh GuardState."""
    state = _state()
    calls = {"n": 0}

    def approve(*_a, **_k):
        calls["n"] += 1
        return True

    reply = guard_handle_message(
        {"verb": "status", "admission_token": "stale-token-from-old-guard"},
        state,
        admit_prompt=approve,
    )
    assert reply["ok"] is True
    assert calls["n"] == 1  # prompted despite a (wrong) token being present


def test_admission_token_round_trip_via_guard_request(ka_home, monkeypatch) -> None:
    """guard_request centralizes token plumbing: attach cached token, persist
    a freshly-minted one, wire caller_pid — call sites stay thin."""
    listener, address, authkey = ipc.start_listener()
    state = _state(address=address, authkey=authkey, pid=4242)
    write_guard_lock(address, authkey, 4242, state.expires_at)

    monkeypatch.setattr("key_amnesia.guard.guard_is_alive", lambda *a, **k: True)

    import threading

    def serve_one() -> None:
        conn = listener.accept()
        try:
            msg = ipc.recv_msg(conn, timeout=5)
            assert msg["caller_pid"] > 0  # guard_request wires this automatically
            reply = guard_handle_message(msg, state, admit_prompt=lambda *a, **k: True)
            ipc.send_msg(conn, reply)
        finally:
            conn.close()

    t = threading.Thread(target=serve_one, daemon=True)
    t.start()

    assert read_admission_token() is None
    reply = guard_request({"verb": "list"})
    t.join(timeout=5)

    assert reply is not None and reply.get("ok") is True
    minted = reply["admission_token"]
    # guard_request persisted the freshly-minted token to disk.
    assert read_admission_token() == minted
    assert admitted_session_token_path().exists()

    # A second round trip attaches the cached token and does not re-prompt.
    def serve_two() -> None:
        conn = listener.accept()
        try:
            msg = ipc.recv_msg(conn, timeout=5)
            assert msg.get("admission_token") == minted
            reply = guard_handle_message(
                msg,
                state,
                admit_prompt=lambda *a, **k: (_ for _ in ()).throw(
                    AssertionError("must not re-prompt for a known token")
                ),
            )
            ipc.send_msg(conn, reply)
        finally:
            conn.close()

    t2 = threading.Thread(target=serve_two, daemon=True)
    t2.start()
    reply2 = guard_request({"verb": "list"})
    t2.join(timeout=5)
    assert reply2 is not None and reply2.get("ok") is True

    listener.close()


def test_status_reports_admission_state() -> None:
    state = _state()
    state.admitted = AdmittedSession(
        token="tok", first_seen="2026-01-01T00:00:00+00:00", request_count=3
    )
    reply = guard_handle_message(
        {"verb": "status", "admission_token": "tok"}, state
    )
    assert reply["ok"] is True
    assert reply["admitted"] is True
    assert reply["admitted_since"] == "2026-01-01T00:00:00+00:00"
    assert reply["request_count"] == 4  # incremented by this very request


def test_write_read_clear_admission_token_file(ka_home) -> None:
    assert read_admission_token() is None
    write_admission_token("abc123")
    assert read_admission_token() == "abc123"
    from key_amnesia.guard import clear_admission_token

    clear_admission_token()
    assert read_admission_token() is None
