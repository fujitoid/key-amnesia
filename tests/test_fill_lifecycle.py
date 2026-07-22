"""Browser-fill IPC co-lifecycle with guard — lock clears fill."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from key_amnesia import ipc
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
from key_amnesia.paths import browser_fill_lock_path, guard_lock_path
from key_amnesia.prompt_route import AuthOutcome, PromptRequest
from key_amnesia.vault import load_vault


def _auto_approve(request: PromptRequest) -> AuthOutcome:
    return AuthOutcome(
        ok=True,
        route="inline",
        status_only={"approved": True, "action": "browser-fill-approve"},
    )


def test_fill_handle_get_logins_after_approve() -> None:
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
        database_id="abc",
        expires_at=time.time() + 600,
        address="dummy",
        authkey=b"f" * 32,
    )
    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://app.example.com/login"},
        state,
        approve_fn=_auto_approve,
    )
    assert reply["ok"] is True
    assert reply["entries"][0]["password"] == "super-secret-value-123"
    assert reply["entries"][0]["login"] == "alice"


def test_fill_handle_denied_without_approve() -> None:
    state = FillState(
        secrets={"api_key": "secret"},
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

    def deny(_req: PromptRequest) -> AuthOutcome:
        return AuthOutcome(
            ok=False,
            route="inline",
            reason="denied",
            status_only={"approved": False, "action": "browser-fill-approve"},
        )

    reply = fill_handle_message(
        {"verb": "get-logins-for-url", "url": "https://example.com"},
        state,
        approve_fn=deny,
    )
    assert reply["ok"] is False
    assert "entries" not in reply


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


def test_fill_lock_verb_stops_listener(ka_home: Path) -> None:
    """Fill IPC lock verb shuts down the fill listener and clears its lock."""
    listener, address, authkey = ipc.start_listener(
        address=ipc.make_fill_pipe_address()
    )
    stop = __import__("threading").Event()
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
