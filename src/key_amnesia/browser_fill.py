"""Browser-fill IPC — second Listener co-hosted with the guard child.

Authkey only (no session_key). May return credentials to native_host after
in-process approval. Dies with ka lock / guard expiry / fill lock.
Requires ka unlock — no per-call fill path.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Callable

from key_amnesia import ipc
from key_amnesia.audit import audit_browser_fill
from key_amnesia.logins import find_logins_for_url
from key_amnesia.paths import browser_fill_lock_path
from key_amnesia.prompt_route import PromptRequest, require_browser_fill_approval


def _utc_iso(ts: float | None = None) -> str:
    t = ts if ts is not None else time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class FillState:
    """Shared with guard child: secrets + login metadata for fill verbs."""

    secrets: dict[str, str]
    logins: list[dict[str, Any]]
    browser_associations: list[dict[str, Any]]
    database_id: str
    expires_at: float
    address: str
    authkey: bytes
    pid: int = field(default_factory=os.getpid)
    stop: threading.Event = field(default_factory=threading.Event)


def write_browser_fill_lock(
    address: str,
    authkey: bytes,
    pid: int,
    expires_at: float,
    path: Path | None = None,
) -> None:
    p = path or browser_fill_lock_path()
    data = {
        "address": address,
        "authkey_hex": ipc.authkey_to_hex(authkey),
        "pid": pid,
        "expires_at": _utc_iso(expires_at),
        "expires_at_epoch": expires_at,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_browser_fill_lock(path: Path | None = None) -> dict[str, Any] | None:
    p = path or browser_fill_lock_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def clear_browser_fill_lock(path: Path | None = None) -> None:
    p = path or browser_fill_lock_path()
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def fill_is_alive(lock: dict[str, Any] | None = None) -> bool:
    lock = lock if lock is not None else read_browser_fill_lock()
    if not lock:
        return False
    pid = int(lock.get("pid") or 0)
    expires = float(lock.get("expires_at_epoch") or 0)
    if expires and time.time() > expires:
        return False
    if pid <= 0:
        return False
    from key_amnesia.prompt_route import parent_alive

    return parent_alive(pid)


def connect_fill(lock: dict[str, Any] | None = None) -> Connection | None:
    lock = lock if lock is not None else read_browser_fill_lock()
    if not lock or not fill_is_alive(lock):
        return None
    try:
        authkey = ipc.authkey_from_hex(lock["authkey_hex"])
        return ipc.connect(lock["address"], authkey)
    except Exception:
        return None


def browser_fill_request(
    msg: dict[str, Any], timeout: float = 120.0
) -> dict[str, Any] | None:
    """Send a message to the live fill IPC; return response or None."""
    conn = connect_fill()
    if conn is None:
        return None
    try:
        ipc.send_msg(conn, msg)
        return ipc.recv_msg(conn, timeout=timeout)
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_fill_listener(
    address: str | None = None, authkey: bytes | None = None
) -> tuple[Any, str, bytes]:
    return ipc.start_listener(
        address=address or ipc.make_fill_pipe_address(),
        authkey=authkey,
    )


def fill_handle_message(
    msg: dict[str, Any],
    state: FillState,
    *,
    approve_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Handle one browser-fill IPC message."""
    if not isinstance(msg, dict):
        return {"ok": False, "reason": "invalid message"}

    verb = str(msg.get("verb") or msg.get("action") or "")

    if time.time() > state.expires_at and verb not in ("lock", "status"):
        return {"ok": False, "reason": "session expired", "expired": True}

    if verb == "status":
        return {
            "ok": True,
            "expires_at": _utc_iso(state.expires_at),
            "expires_at_epoch": state.expires_at,
            "login_count": len(state.logins),
            "associated": bool(state.browser_associations),
            "database_id": state.database_id,
            "expired": time.time() > state.expires_at,
        }

    if verb == "lock":
        state.stop.set()
        return {"ok": True, "lock": True}

    if verb == "test-associate":
        assoc_id = str(msg.get("id") or "")
        for entry in state.browser_associations:
            if str(entry.get("id") or "") == assoc_id:
                return {"ok": True, "associated": True, "id": assoc_id}
        return {"ok": False, "associated": False, "reason": "not associated"}

    if verb == "associate-store":
        assoc_id = str(msg.get("id") or "")
        id_key_b64 = str(msg.get("id_key_b64") or "")
        if not assoc_id or not id_key_b64:
            return {"ok": False, "reason": "id and id_key_b64 required"}
        # Replace same id if present.
        state.browser_associations = [
            e for e in state.browser_associations if str(e.get("id") or "") != assoc_id
        ]
        state.browser_associations.append({"id": assoc_id, "id_key_b64": id_key_b64})
        return {"ok": True, "associated": True, "id": assoc_id}

    if verb == "get-logins-for-url":
        url = str(msg.get("url") or "")
        if not url:
            return {"ok": False, "reason": "url required"}
        matched = find_logins_for_url(state.logins, url)
        if not matched:
            return {"ok": False, "reason": "no matching logins"}

        usernames = [str(e.get("username") or "") for e in matched]
        secret_names = [str(e.get("secret_name") or "") for e in matched]
        request = PromptRequest(
            action="browser-fill-approve",
            secret_names=secret_names,
            detail=json.dumps(
                {
                    "url": url,
                    "usernames": usernames,
                    "secret_names": secret_names,
                }
            ),
        )
        approver = approve_fn or require_browser_fill_approval
        outcome = approver(request)
        so = getattr(outcome, "status_only", None) or {}
        if "approved" in so:
            approved = bool(so["approved"])
        else:
            approved = bool(getattr(outcome, "ok", False))
        route = str(getattr(outcome, "route", None) or "inline")
        if route not in ("inline", "spawned-console", "guard-session"):
            route = "inline"
        primary_user = usernames[0] if usernames else None
        reason = str(getattr(outcome, "reason", "") or "")
        if not approved:
            reason = reason or "denied"
            fill_result = (
                "timeout"
                if "timeout" in reason.lower() or "timed out" in reason.lower()
                else "denied"
            )
            audit_browser_fill(
                result=fill_result,
                url=url,
                username=primary_user,
                secret_names=secret_names,
                route=route,
                reason=reason,
            )
            return {"ok": False, "reason": reason}

        entries: list[dict[str, Any]] = []
        for entry in matched:
            sname = str(entry.get("secret_name") or "")
            password = state.secrets.get(sname)
            if password is None:
                continue
            entries.append(
                {
                    "login": str(entry.get("username") or ""),
                    "name": sname,
                    "password": password,
                    "uuid": sname,
                }
            )
        if not entries:
            audit_browser_fill(
                result="denied",
                url=url,
                username=primary_user,
                secret_names=secret_names,
                route=route,
                reason="no resolvable secrets",
            )
            return {"ok": False, "reason": "no resolvable secrets"}
        audit_browser_fill(
            result="allowed",
            url=url,
            username=primary_user,
            secret_names=secret_names,
            route=route,
        )
        return {"ok": True, "entries": entries}

    return {"ok": False, "reason": f"unknown verb: {verb}"}


def fill_serve(
    state: FillState,
    listener: Any,
    *,
    approve_fn: Callable[..., Any] | None = None,
) -> None:
    """Accept fill connections until stop / lock / expiry."""
    while not state.stop.is_set():
        now = time.time()
        if now > state.expires_at:
            state.stop.set()
            break

        accepted: list[Any] = []

        def _accept() -> None:
            try:
                accepted.append(listener.accept())
            except Exception as e:  # noqa: BLE001
                accepted.append(e)

        t = threading.Thread(target=_accept, daemon=True)
        t.start()
        while t.is_alive():
            if state.stop.is_set() or time.time() > state.expires_at:
                break
            t.join(timeout=0.5)
        if not accepted:
            if state.stop.is_set() or time.time() > state.expires_at:
                break
            continue
        item = accepted[0]
        if isinstance(item, Exception):
            continue
        conn: Connection = item
        try:
            msg = ipc.recv_msg(conn, timeout=30.0)
            # Keep expires_at in sync if guard renews (shared mutable float via ref —
            # callers should mutate state.expires_at on the same object).
            reply = fill_handle_message(msg, state, approve_fn=approve_fn)
            ipc.send_msg(conn, reply)
            if reply.get("lock"):
                state.stop.set()
                break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        listener.close()
    except Exception:
        pass
