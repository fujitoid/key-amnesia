"""Browser-fill IPC co-lifecycle with guard — lock/expiry clear fill; audit never logs passwords."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from key_amnesia import ipc
from key_amnesia.audit import BROWSER_FILL_ACTIONS, audit_browser_fill
from key_amnesia.browser_fill import (
    FillState,
    browser_fill_request,
    clear_browser_fill_lock,
    fill_handle_message,
    fill_is_alive,
    fill_serve,
    read_browser_fill_lock,
    write_browser_fill_lock,
)
from key_amnesia.cli import main
from key_amnesia.guard import (
    clear_guard_lock,
)
from key_amnesia.paths import audit_log_path, browser_fill_lock_path, guard_lock_path
from key_amnesia.prompt_route import AuthOutcome, PromptRequest
from key_amnesia.vault import load_vault


def _auto_approve(request: PromptRequest) -> AuthOutcome:
    return AuthOutcome(
        ok=True,
        route="inline",
        status_only={"approved": True, "action": "browser-fill-approve"},
    )


def _deny(request: PromptRequest) -> AuthOutcome:
    return AuthOutcome(
        ok=False,
        route="inline",
        reason="denied",
        status_only={"approved": False, "action": "browser-fill-approve"},
    )


def _timeout(request: PromptRequest) -> AuthOutcome:
    return AuthOutcome(
        ok=False,
        route="spawned-console",
        reason="approval timed out",
        status_only={"approved": False, "action": "browser-fill-approve"},
    )


def _fill_state(**kwargs) -> FillState:
    base = dict(
        secrets={"api_key": "super-secret-value-123"},
        logins=[
            {
                "url": "https://example.com",
                "username": "alice",
                "secret_name": "api_key",
            }
        ],
        browser_associations=[],
        database_id="abc",
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"f" * 32,
    )
    base.update(kwargs)
    return FillState(**base)


def test_fill_handle_get_logins_after_approve(ka_home: Path) -> None:
    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://app.example.com/login"},
        _fill_state(),
        approve_fn=_auto_approve,
    )
    assert reply["ok"] is True
    assert reply["entries"][0]["password"] == "super-secret-value-123"
    assert reply["entries"][0]["login"] == "alice"

    # Password may be in the IPC reply — never in audit.log.
    text = audit_log_path().read_text(encoding="utf-8")
    assert "super-secret-value-123" not in text
    records = [json.loads(line) for line in text.strip().splitlines()]
    fill_recs = [r for r in records if r["action"] in BROWSER_FILL_ACTIONS]
    assert fill_recs
    last = fill_recs[-1]
    assert last["action"] == "browser-fill"
    assert last["result"] == "allowed"
    assert last["url"] == "https://app.example.com/login"
    assert last.get("username") == "alice"
    assert "password" not in last


def test_fill_handle_denied_without_approve(ka_home: Path) -> None:
    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://example.com"},
        _fill_state(),
        approve_fn=_deny,
    )
    assert reply["ok"] is False
    assert "entries" not in reply

    records = [
        json.loads(line)
        for line in audit_log_path().read_text(encoding="utf-8").strip().splitlines()
    ]
    last = [r for r in records if r["action"] in BROWSER_FILL_ACTIONS][-1]
    assert last["action"] == "browser-fill-denied"
    assert last["result"] == "denied"
    assert "super-secret-value-123" not in json.dumps(last)


def test_fill_handle_timeout_audited(ka_home: Path) -> None:
    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://example.com"},
        _fill_state(),
        approve_fn=_timeout,
    )
    assert reply["ok"] is False
    records = [
        json.loads(line)
        for line in audit_log_path().read_text(encoding="utf-8").strip().splitlines()
    ]
    last = [r for r in records if r["action"] in BROWSER_FILL_ACTIONS][-1]
    assert last["action"] == "browser-fill-timeout"
    assert last["result"] == "timeout"
    assert "password" not in last


def test_audit_browser_fill_helper_never_password(ka_home: Path) -> None:
    rec = audit_browser_fill(
        result="allowed",
        url="https://example.com",
        username="alice",
        secret_names=["api_key"],
        route="inline",
    )
    assert rec["action"] == "browser-fill"
    assert "password" not in rec
    text = audit_log_path().read_text(encoding="utf-8")
    assert "password" not in text or '"password"' not in text
    assert "super-secret" not in text


def test_lock_clears_browser_fill_lock(
    seeded_vault: Path, password: str, monkeypatch
) -> None:
    """After unlock, fill lock exists; after ka lock, fill is unreachable."""
    payload = load_vault(seeded_vault, password)
    payload["logins"] = [
        {
            "url": "https://example.com",
            "username": "alice",
            "secret_name": "api_key",
        }
    ]
    from key_amnesia.vault import save_vault

    save_vault(seeded_vault, password, payload)

    clear_guard_lock()
    clear_browser_fill_lock()

    monkeypatch.setattr(
        "key_amnesia.cli.require_human_auth",
        lambda *a, **k: AuthOutcome(ok=True, route="inline", password=password),
    )

    assert main(["unlock"]) == 0
    assert guard_lock_path().exists()
    assert browser_fill_lock_path().exists()
    fill_lock = read_browser_fill_lock()
    assert fill_lock is not None
    assert fill_is_alive(fill_lock)

    status = browser_fill_request({"verb": "status"}, timeout=5.0)
    assert status is not None
    assert status.get("ok") is True
    assert status.get("login_count") == 1

    assert main(["lock"]) == 0

    # Allow child teardown
    deadline = time.time() + 5
    while time.time() < deadline and browser_fill_lock_path().exists():
        time.sleep(0.05)

    assert not browser_fill_lock_path().exists()
    assert browser_fill_request({"verb": "status"}, timeout=1.0) is None
    assert browser_fill_request(
        {"verb": "get-logins-for-url", "url": "https://example.com"},
        timeout=1.0,
    ) is None


def test_expiry_kills_fill_ipc(ka_home: Path) -> None:
    """After session expiry, fill IPC cannot complete get-logins-for-url."""
    listener, address, authkey = ipc.start_listener(
        address=ipc.make_fill_pipe_address()
    )
    stop = threading.Event()
    # Already expired — serve loop should exit; handle rejects credential verbs.
    state = FillState(
        secrets={"api_key": "super-secret-value-123"},
        logins=[
            {
                "url": "https://example.com",
                "username": "alice",
                "secret_name": "api_key",
            }
        ],
        browser_associations=[],
        database_id="id",
        expires_at=time.time() - 1,
        address=address,
        authkey=authkey,
        pid=0,
        stop=stop,
    )
    write_browser_fill_lock(address, authkey, 0, state.expires_at)

    # Direct handle: expired session refuses credential pull.
    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://example.com"},
        state,
        approve_fn=_auto_approve,
    )
    assert reply.get("ok") is False
    assert reply.get("expired") is True
    assert "entries" not in reply
    assert "super-secret-value-123" not in str(reply)

    # fill_is_alive treats past expires_at as dead.
    assert fill_is_alive(read_browser_fill_lock()) is False

    t = threading.Thread(
        target=fill_serve,
        args=(state, listener),
        kwargs={"approve_fn": _auto_approve},
        daemon=True,
    )
    t.start()
    t.join(timeout=3)
    assert stop.is_set() or not t.is_alive()
    clear_browser_fill_lock()


def test_fill_lock_verb_stops_listener(ka_home: Path) -> None:
    """Fill IPC lock verb shuts down the fill listener and clears its lock."""
    listener, address, authkey = ipc.start_listener(
        address=ipc.make_fill_pipe_address()
    )
    stop = threading.Event()
    state = FillState(
        secrets={"k": "v"},
        logins=[],
        browser_associations=[],
        database_id="id",
        expires_at=time.time() + 600,
        address=address,
        authkey=authkey,
        pid=0,
        stop=stop,
    )
    write_browser_fill_lock(address, authkey, 0, state.expires_at)

    t = threading.Thread(
        target=fill_serve,
        args=(state, listener),
        kwargs={"approve_fn": _auto_approve},
        daemon=True,
    )
    t.start()
    time.sleep(0.1)

    # Bypass pid liveness for this unit test
    conn = ipc.connect(address, authkey)
    try:
        ipc.send_msg(conn, {"verb": "lock"})
        reply = ipc.recv_msg(conn, timeout=5)
        assert reply.get("ok") is True
        assert reply.get("lock") is True
    finally:
        conn.close()

    t.join(timeout=5)
    assert stop.is_set()
    clear_browser_fill_lock()
